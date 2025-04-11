#[cfg(not(feature = "rustls"))]
mod boringssl_openssl;
#[cfg(not(feature = "rustls"))]
pub use boringssl_openssl::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use rustls::*;

use crate::packet;

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