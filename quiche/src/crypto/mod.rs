#[cfg(any(feature = "boringssl-vendored", feature = "boringssl-boring-crate", feature = "openssl"))]
mod boringssl_openssl;
#[cfg(any(feature = "boringssl-vendored", feature = "boringssl-boring-crate", feature = "openssl"))]
pub use boringssl_openssl::*;

use crate::packet;

// All the AEAD algorithms we support use 96-bit nonces.
pub const MAX_NONCE_LEN: usize = 12;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Initial   = 0,
    ZeroRTT   = 1,
    Handshake = 2,
    OneRTT    = 3,
}

impl Level {
    pub fn from_epoch(e: packet::Epoch) -> Level {
        match e {
            packet::Epoch::Initial => Level::Initial,

            packet::Epoch::Handshake => Level::Handshake,

            packet::Epoch::Application => Level::OneRTT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    #[allow(non_camel_case_types)]
    AES128_GCM,

    #[allow(non_camel_case_types)]
    AES256_GCM,

    #[allow(non_camel_case_types)]
    ChaCha20_Poly1305,
}

impl Algorithm {
    pub const fn key_len(self) -> usize {
        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 32,
            Algorithm::ChaCha20_Poly1305 => 32,
        }
    }

    pub const fn tag_len(self) -> usize {
        if cfg!(feature = "fuzzing") {
            return 0;
        }

        match self {
            Algorithm::AES128_GCM => 16,
            Algorithm::AES256_GCM => 16,
            Algorithm::ChaCha20_Poly1305 => 16,
        }
    }
}

fn make_nonce(iv: &[u8], counter: u64) -> [u8; MAX_NONCE_LEN] {
    let mut nonce = [0; MAX_NONCE_LEN];
    nonce.copy_from_slice(iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}