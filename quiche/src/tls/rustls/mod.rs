use crate::crypto;
use crate::tls::ExData;
use crate::Error;
use crate::Result;
use std::fs::DirEntry;
use std::sync::Arc;

use crate::crypto::Level;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::quic::ClientConnection;
use rustls::quic::ServerConnection;
use rustls::quic::Version;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::CipherSuite;
use rustls::ClientConfig;
use rustls::HandshakeKind;
use rustls::KeyLogFile;
use rustls::RootCertStore;
use rustls::ServerConfig;

pub struct Context {
    client_config: Option<Arc<ClientConfig>>,
    server_config: Option<Arc<ServerConfig>>,
    // required to build the above configs
    // are consumed during configs building
    private_key_client: Option<PrivateKeyDer<'static>>,
    private_key_server: Option<PrivateKeyDer<'static>>,
    ca_certificates: Option<Vec<CertificateDer<'static>>>,
    verify_ca_certificates_store: Option<RootCertStore>,
    alpns: Vec<Vec<u8>>,
    enable_verify_ca_certificates: bool,
    enable_keylog: bool,
    enable_early_data: bool,
    quic_version: Version,
}

// fn early_data_enabled(&self) -> bool {
// match self {
// Config::Server(cfg) => cfg.max_early_data_size > 0,
// Config::Client(cfg) => cfg.enable_early_data
// }
// }

// mod implementation
impl Context {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client_config: None,
            server_config: None,
            private_key_client: None,
            private_key_server: None,
            ca_certificates: None,
            enable_verify_ca_certificates: false,
            verify_ca_certificates_store: None,
            enable_keylog: false,
            enable_early_data: false,
            quic_version: Default::default(),
            alpns: vec![],
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        let verify_store = if self.enable_verify_ca_certificates {
            let Some(verify_store) = self.verify_ca_certificates_store.take()
            else {
                // enabled but no store available
                return Err(Error::TlsFail);
            };
            Some(Arc::new(verify_store))
        } else {
            None
        };

        if self.server_config.is_none() {
            let builder = ServerConfig::builder_with_protocol_versions(&[&TLS13]);
            let builder = if let Some(verify_store) = verify_store.clone() {
                let client_vierifier =
                    WebPkiClientVerifier::builder(verify_store)
                        .build()
                        .map_err(|_| Error::TlsFail)?;

                builder.with_client_cert_verifier(client_vierifier)
            } else {
                builder.with_no_client_auth()
            };

            let mut config = if let (Some(certs), Some(key)) =
                (self.ca_certificates.clone(), self.private_key_server.take())
            {
                builder
                    .with_single_cert(certs, key)
                    .map_err(|_| Error::TlsFail)?
            } else {
                // server without ca & key config
                // not supported in QUIC, TLS is mandatory
                return Err(Error::TlsFail);
            };

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }
            if self.enable_early_data {
                // matching boringssl default
                //
                // kMaxEarlyDataAccepted is the advertised number of plaintext
                // bytes of early data that will be accepted.
                config.max_early_data_size = 14336;
            }

            if self.alpns.len() > 0 {
                config.alpn_protocols = self.alpns.clone();
            }

            self.server_config = Some(Arc::new(config));
        };

        if self.client_config.is_none() {
            let builder = ClientConfig::builder_with_protocol_versions(&[&TLS13]);

            let builder = if let Some(verify_store) = verify_store.clone() {
                let server_verifier = WebPkiServerVerifier::builder(verify_store)
                    .build()
                    .map_err(|_| Error::TlsFail)?;

                builder.with_webpki_verifier(server_verifier)
            } else {
                // default to env variables or system store
                // this behaviour differs as no-verification on client side is not
                // intended on rustls
                let certificates_result =
                    rustls_native_certs::load_native_certs();
                let mut store = RootCertStore::empty();
                store.add_parsable_certificates(certificates_result.certs);

                builder.with_root_certificates(store)
            };

            let mut config = if let (Some(certs), Some(key)) =
                (self.ca_certificates.take(), self.private_key_client.take())
            {
                builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|_| Error::TlsFail)?
            } else {
                builder.with_no_client_auth()
            };

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }
            if self.enable_early_data {
                config.enable_early_data = true;
            }

            if self.alpns.len() > 0 {
                config.alpn_protocols = self.alpns.clone();
            }

            self.client_config = Some(Arc::new(config))
        }

        Ok(Handshake {
            client_config: self.client_config.clone().ok_or(Error::TlsFail)?,
            server_config: self.server_config.clone().ok_or(Error::TlsFail)?,
            hostname: None,
            quic_version: self.quic_version.clone(),
            client_conn: None,
            server_conn: None,
            is_server: false,
            quic_transport_params: vec![],
            provided_data_outstanding: false,
        })
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let verify_certificates = Self::load_ca_certificates_from_file(file)?;
        self.extend_verify_ca_certificates(verify_certificates);
        Ok(())
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let files: Result<Vec<DirEntry>> = std::fs::read_dir(path)
            .map_err(|_| Error::TlsFail)?
            .into_iter()
            .map(|rd| rd.map_err(|_| Error::TlsFail))
            .collect();

        let verify_certificates: Vec<CertificateDer> = files?
            .into_iter()
            .flat_map(|f| Self::load_ca_certificates_from_file(f.path()))
            .flatten()
            .collect();

        self.extend_verify_ca_certificates(verify_certificates);
        Ok(())
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        self.ca_certificates = Some(Self::load_ca_certificates_from_file(file)?);
        Ok(())
    }

    fn load_ca_certificates_from_file(
        file: impl AsRef<std::path::Path>,
    ) -> Result<Vec<CertificateDer<'static>>> {
        let certificates: Result<Vec<CertificateDer>> =
            CertificateDer::pem_file_iter(file)
                .map_err(|_| Error::TlsFail)?
                .map(|r| r.map_err(|_| Error::TlsFail))
                .collect();
        Ok(certificates?)
    }

    fn extend_verify_ca_certificates(
        &mut self, verify_certificates: Vec<CertificateDer<'static>>,
    ) {
        if let Some(cert_store) = &mut self.verify_ca_certificates_store {
            cert_store.add_parsable_certificates(verify_certificates);
        } else {
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(verify_certificates);
            self.verify_ca_certificates_store = Some(store);
        }
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let private_key_client =
            PrivateKeyDer::from_pem_file(file).map_err(|_| Error::TlsFail)?;
        let private_key_server =
            PrivateKeyDer::from_pem_file(file).map_err(|_| Error::TlsFail)?;

        // NOTE: storing it twice as PrivateKeyDer cannot be copied/cloned
        // ClientConfig & ServerConfig are built in new_handshake()
        self.private_key_client = Some(private_key_client);
        self.private_key_server = Some(private_key_server);
        Ok(())
    }

    pub fn set_verify(&mut self, verify: bool) {
        self.enable_verify_ca_certificates = verify;
    }

    /// uses env variable SSLKEYLOGFILE
    pub fn enable_keylog(&mut self) {
        self.enable_keylog = true;
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        let alpns: Vec<Vec<u8>> = v.iter().map(|a| a.to_vec()).collect();
        self.alpns = alpns;
        Ok(())
    }

    // TODO: remove method
    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {
        // not supported in rustls
        Err(Error::TlsFail)
    }
}

// specific implementation
impl Context {
    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        self.enable_early_data = enabled;
    }
}

pub struct Handshake {
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    hostname: Option<ServerName<'static>>,
    quic_version: Version,

    is_server: bool,
    quic_transport_params: Vec<u8>,

    client_conn: Option<ClientConnection>,
    server_conn: Option<ServerConnection>,

    provided_data_outstanding: bool,
}

// mod implementation
impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.is_server = is_server;
        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, _use_legacy: bool) {
        () // noop for rustls
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let name = ServerName::try_from(name)
            .map_err(|_| Error::TlsFail)?
            .to_owned();

        self.hostname = Some(name);
        Ok(())
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        self.quic_transport_params = buf.to_vec();
        Ok(())
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        if let Some(client_conn) = &self.client_conn {
            if let Some(params) = client_conn.quic_transport_parameters() {
                return params;
            }
        }
        if let Some(server_conn) = &self.server_conn {
            if let Some(params) = server_conn.quic_transport_parameters() {
                return params;
            }
        }

        self.quic_transport_params.as_slice()
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        if let Some(client_conn) = &self.client_conn {
            if let Some(alpns) = client_conn.alpn_protocol() {
                return alpns;
            }
        }
        if let Some(server_conn) = &self.server_conn {
            if let Some(alpns) = server_conn.alpn_protocol() {
                return alpns;
            }
        }

        &[]
    }

    pub fn server_name(&self) -> Option<&str> {
        if let Some(server_conn) = &self.server_conn {
            server_conn.server_name()
        } else {
            None
        }
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        // TODO: right before do_handshake in
        // process_frame -> Frame::Crypto -> provide_data -> do_handshake
        println!("provide_data level: {:?}, buf: {:?}", level, buf);
        self.provided_data_outstanding = true;
        // check level
        // https://github.com/google/boringssl/blob/99bd1df99b2ada05877f36f85ff2f7f37e176fd6/ssl/ssl_lib.cc#L695

        // FIXME: unify to quic::Connection for ease of use

        match level {
            Level::Initial => {},
            Level::ZeroRTT => {},
            Level::Handshake => {},
            Level::OneRTT => {},
        }

        // tls_append_handshake_data(ssl, Span(data, len));
        Ok(())
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        if self.is_server {
            let server_conn = ServerConnection::new(
                self.server_config.clone(),
                self.quic_version.clone(),
                self.quic_transport_params.clone(),
            )
            .map_err(|_| Error::TlsFail)?;
            self.server_conn = Some(server_conn)
        } else {
            let Some(hostname) = &self.hostname else {
                return Err(Error::TlsFail);
            };
            let client_conn = ClientConnection::new(
                self.client_config.clone(),
                self.quic_version.clone(),
                hostname.to_owned(),
                self.quic_transport_params.clone(),
            )
            .map_err(|_| Error::TlsFail)?;
            self.client_conn = Some(client_conn)
        }

        Ok(())
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        // If SSL_provide_quic_data hasn't been called since we last called
        // SSL_process_quic_post_handshake, then there's nothing to do.
        if !self.provided_data_outstanding {
            return Ok(());
        }
        self.provided_data_outstanding = false;

        // https://github.com/google/boringssl/blob/99bd1df99b2ada05877f36f85ff2f7f37e176fd6/ssl/ssl_lib.cc#L767
        // read additional messages
        // check alerts
        // check renegotiate
        // check transport errors
        todo!()
    }

    pub fn write_level(&self) -> crypto::Level {
        todo!()
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let suite = if let Some(server_conn) = &self.server_conn {
            server_conn.negotiated_cipher_suite()
        } else if let Some(client_conn) = &self.client_conn {
            client_conn.negotiated_cipher_suite()
        } else {
            None
        };

        let Some(suite) = suite else { return None };

        match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 =>
                Some(crypto::Algorithm::AES128_GCM),
            CipherSuite::TLS13_AES_256_GCM_SHA384 =>
                Some(crypto::Algorithm::AES256_GCM),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 =>
                Some(crypto::Algorithm::ChaCha20_Poly1305),
            _ => None,
        }
    }

    pub fn is_completed(&self) -> bool {
        if let Some(client_conn) = &self.client_conn {
            return !client_conn.is_handshaking();
        }
        if let Some(server_conn) = &self.server_conn {
            return !server_conn.is_handshaking();
        }

        false
    }

    pub fn is_resumed(&self) -> bool {
        if let Some(client_conn) = &self.client_conn {
            if let Some(kind) = client_conn.handshake_kind() {
                return matches!(kind, HandshakeKind::Resumed);
            }
        }
        if let Some(server_conn) = &self.server_conn {
            if let Some(kind) = server_conn.handshake_kind() {
                return matches!(kind, HandshakeKind::Resumed);
            }
        }

        false
    }

    pub fn clear(&mut self) -> Result<()> {
        todo!()
    }
}

#[allow(unused_variables)]
// mod implementation
impl Handshake {
    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn curve(&self) -> Option<String> {
        // TODO: only used for logging
        None
    }

    pub fn sigalg(&self) -> Option<String> {
        // TODO: only used for logging
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        todo!()
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        todo!()
    }

    pub fn is_in_early_data(&self) -> bool {
        todo!()
    }
}
