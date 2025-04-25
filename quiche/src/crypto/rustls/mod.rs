use crate::crypto::Algorithm;
use crate::{rand, Error};
use crate::Result;

use rustls::quic::DirectionalKeys;
use rustls::quic::HeaderProtectionKey;
use rustls::quic::Keys;
use rustls::quic::PacketKey as RustlsPacketKey;
use rustls::quic::Secrets;
use rustls::quic::Version;
use rustls::CipherSuite;
use rustls::Side;
use std::sync::Arc;
use std::sync::Mutex;

// TODO:
//#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
// use aws_lc_rs::aead;

use ring::aead::Aad;
use ring::aead::LessSafeKey;
use ring::aead::Nonce;
use ring::aead::UnboundKey;
use ring::aead::AES_128_GCM;
use ring::aead::MAX_TAG_LEN;
use rustls::crypto::CryptoProvider;

pub struct PacketKey {
    key: LessSafeKey,
    nonce: Vec<u8>,
}

#[allow(unused_variables)]
impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_128_GCM, &key).map_err(|_| Error::CryptoFail)?,
        );

        Ok(Self { key, nonce: iv })
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let nonce = <[u8; 12]>::try_from(self.nonce.clone()).map_err(|e| {
            error!("failed to convert nonce: {:?}", e);
            Error::CryptoFail
        })?;

        let nonce = Nonce::assume_unique_for_key(nonce);
        let aad = Aad::from(ad);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(ad), &mut [])
            .map_err(|e| {
                error!("failed to seal with packet key: {}", e);
                Error::CryptoFail
            })?;

        buf.copy_from_slice(tag.as_ref());
        Ok(MAX_TAG_LEN)
    }
}

pub struct Open {
    packet_key: Box<dyn RustlsPacketKey>,
    header_protection_key: Arc<dyn HeaderProtectionKey>,
    algorithm: Algorithm,
    secrets: Option<Arc<SecretsNextKeys>>,
}

pub struct SecretsNextKeys {
    inner: Mutex<(
        Secrets,
        Option<Box<dyn RustlsPacketKey>>,
        Option<Box<dyn RustlsPacketKey>>,
        usize
    )>,
}

impl SecretsNextKeys {
    fn next_local_key(&self) -> Result<Option<Box<dyn RustlsPacketKey>>> {
        let mut inner =
            self.inner.lock().map_err(|e| {
                error!("failed to acquire mutex: {:?}", e);
                Error::CryptoFail
            })?;

        if inner.1.is_none() && inner.2.is_none() {
            let keys = inner.0.next_packet_keys();
            inner.1 = Some(keys.local);
            inner.2 = Some(keys.remote);
            inner.3 = inner.3 + 1;
        };

        error!("consumed local key {}", inner.3);
        Ok(inner.1.take())
    }

    fn next_remote_key(&self) -> Result<Option<Box<dyn RustlsPacketKey>>> {
        let mut inner =
            self.inner.lock().map_err(|e| {
                error!("failed to acquire mutex: {:?}", e);
                Error::CryptoFail
            })?;

        if inner.1.is_none() && inner.2.is_none() {
            let keys = inner.0.next_packet_keys();
            inner.1 = Some(keys.local);
            inner.2 = Some(keys.remote);
            inner.3 = inner.3 + 1;
        };

        error!("consumed remote key {}", inner.3);
        Ok(inner.2.take())
    }

    fn return_next_remote_key(&self, remote_key: Box<dyn RustlsPacketKey>) -> Result<()> {
        let mut inner =
            self.inner.lock().map_err(|e| {
                error!("failed to acquire mutex: {:?}", e);
                Error::CryptoFail
            })?;

        inner.2 = Some(remote_key);
        error!("returned remote key {}", inner.3);
        Ok(())
    }

    fn return_next_local_key(&self, local_key: Box<dyn RustlsPacketKey>) -> Result<()> {
        let mut inner =
            self.inner.lock().map_err(|e| {
                error!("failed to acquire mutex: {:?}", e);
                Error::CryptoFail
            })?;

        inner.1 = Some(local_key);
        error!("returned local key {}", inner.3);
        Ok(())
    }
}

#[allow(unused_variables)]
impl Open {
    pub(crate) fn from(keys: DirectionalKeys) -> Self {
        Self {
            packet_key: keys.packet,
            header_protection_key: Arc::from(keys.header),
            algorithm: Algorithm::AES128_GCM,
            secrets: None,
        }
    }

    pub fn decrypt_hdr(
        &self, sample: &[u8], first: &mut u8, packet_number: &mut [u8],
    ) -> Result<()> {
        self.header_protection_key
            .decrypt_in_place(sample, first, packet_number)
            .map_err(|e| {
                error!("failed to decrypt packet header: {:?}", e);
                Error::CryptoFail
            })
    }

    pub fn open_with_u64_counter(
        &self, packet_number: u64, header: &[u8], payload: &mut [u8],
    ) -> Result<usize> {
        let decrypted = self.packet_key
            .decrypt_in_place(packet_number, header, payload)
            .map_err(|e| {
                error!("failed to decrypt packet: {:?}", e);
                Error::CryptoFail
            })?;

        Ok(decrypted.len())
    }

    pub fn alg(&self) -> Algorithm {
        self.algorithm
    }

    pub fn derive_next_packet_key(&mut self) -> Result<Open> {
        let Some(secrets) = &mut self.secrets else {
            error!("no secrets present for next packet key");
            return Err(Error::CryptoFail);
        };

        let Some(remote_key) = secrets.next_remote_key()? else {
            error!("no remote key available for next packet key, previous local key was not consumed");
            return Err(Error::CryptoFail);
        };

        Ok(Open {
            packet_key: remote_key,
            header_protection_key: self.header_protection_key.clone(),
            algorithm: Algorithm::AES128_GCM,
            secrets: Some(secrets.clone()),
        })
    }

    pub fn return_next_key(self) -> Result<()> {
        let Some(secrets) = &self.secrets else {
            error!("no secrets present to return packet key");
            return Err(Error::CryptoFail);
        };

        secrets.return_next_remote_key(self.packet_key)
    }
}

pub struct Seal {
    packet_key:Box<dyn RustlsPacketKey>,
    header_protection_key: Arc<dyn HeaderProtectionKey>,
    algorithm: Algorithm,
    secrets: Option<Arc<SecretsNextKeys>>,
}

#[allow(unused_variables)]
impl Seal {
    pub const ENCRYPT: u32 = 1;

    pub(crate) fn from(keys: DirectionalKeys) -> Self {
        Self {
            packet_key: keys.packet,
            header_protection_key: Arc::from(keys.header),
            algorithm: Algorithm::AES128_GCM,
            secrets: None,
        }
    }

    pub fn encrypt_hdr(
        &self, sample: &[u8], first: &mut u8, packet_number: &mut [u8],
    ) -> Result<()> {
        self.header_protection_key
            .encrypt_in_place(sample, first, packet_number)
            .map_err(|e| {
                error!("failed to encrypt packet header: {:?}", e);
                Error::CryptoFail
            })
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        if (in_len + self.packet_key.tag_len()) > buf.len() {
            error!("provided buffer size not sufficient for data and tag");
            return Err(Error::CryptoFail);
        }

        let tag = self.packet_key
            .encrypt_in_place(counter, ad, &mut buf[..in_len])
            .map_err(|e| {
                error!("failed to encrypt packet: {:?}", e);
                Error::CryptoFail
            })?;

        let tag_len = tag.as_ref().len();
        let tag = tag.as_ref();
        for ti in 0..tag_len {
            buf[in_len + ti] = tag[ti];
        }

        Ok(in_len + tag_len)
    }

    pub fn alg(&self) -> Algorithm {
        self.algorithm
    }

    pub fn derive_next_packet_key(&mut self) -> Result<Seal> {
        let Some(secrets) = &mut self.secrets else {
            error!("no secrets present for next packet key");
            return Err(Error::CryptoFail);
        };

        let Some(local_key) = secrets.next_local_key()? else {
            error!("no local key available for next packet key, previous remote key was not consumed");
            return Err(Error::CryptoFail);
        };

        Ok(Seal {
            packet_key: local_key,
            header_protection_key: self.header_protection_key.clone(),
            algorithm: Algorithm::AES128_GCM,
            secrets: Some(secrets.clone()),
        })
    }

    pub fn return_next_key(self) -> Result<()> {
        let Some(secrets) = &self.secrets else {
            error!("no secrets present to return packet key");
            return Err(Error::CryptoFail);
        };

        secrets.return_next_local_key(self.packet_key)
    }
}

pub(crate) fn key_material_from_keys(
    keys: Keys, next: Option<Secrets>,
) -> Result<(Open, Seal)> {
    let next_secrets = if let Some(next) = next {
        let offset = rand::rand_u64() as usize;
        error!("creating key material from keys with secrets: offset {}", offset);

        Some(Arc::new(SecretsNextKeys {
            inner: Mutex::new((next, None, None, offset))
        }))
    } else {
        None
    };

    let open = Open {
        packet_key: keys.remote.packet,
        header_protection_key: Arc::from(keys.remote.header),
        algorithm: Algorithm::AES128_GCM,
        secrets: next_secrets.clone(),
    };
    let seal = Seal {
        packet_key: keys.local.packet,
        header_protection_key: Arc::from(keys.local.header),
        algorithm: Algorithm::AES128_GCM,
        secrets: next_secrets,
    };

    Ok((open, seal))
}

pub fn derive_initial_key_material(
    cid: &[u8],
    version: u32,
    is_server: bool,
    did_reset: bool, // TODO: check & respect effects of did_reset
) -> Result<(Open, Seal)> {
    let provider = init_crypto_provider();

    let suite = provider
        .cipher_suites
        .iter()
        .find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .ok_or_else(|| {
            error!("default crypto suite not available");
            Error::CryptoFail
        })?;

    let tls_13_suite = suite.tls13().ok_or_else(|| {
        error!("crypto suite not a TLS 1.3 suite");
        Error::CryptoFail
    })?;
    tls_13_suite.quic_suite();

    let quic_suite = tls_13_suite.quic_suite().ok_or_else(|| {
        error!("crypto suite not a TLS 1.3 suite");
        Error::CryptoFail
    })?;

    let side = if is_server {
        Side::Server
    } else {
        Side::Client
    };

    let version = match version {
        1 => Version::V1,
        _ => Version::V1,
    };

    let keys =
        Keys::initial(version, quic_suite.suite, quic_suite.quic, cid, side);

    let open = Open {
        packet_key: keys.remote.packet,
        header_protection_key: Arc::from(keys.remote.header),
        algorithm: Algorithm::AES128_GCM,
        secrets: None,
    };
    let seal = Seal {
        packet_key: keys.local.packet,
        header_protection_key: Arc::from(keys.local.header),
        algorithm: Algorithm::AES128_GCM,
        secrets: None,
    };

    Ok((open, seal))
}

pub fn init_crypto_provider() -> &'static Arc<CryptoProvider> {
    let mut provider = CryptoProvider::get_default();
    if provider.is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        provider = CryptoProvider::get_default();
    };

    provider.expect("failed to init crypto provider")
}

pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<()> {
    if a.len() != b.len() {
        return Err(Error::CryptoFail);
    }

    match a == b {
        true => Ok(()),
        false => Err(Error::CryptoFail),
    }
}
