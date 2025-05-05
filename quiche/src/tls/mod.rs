#[cfg(not(feature = "__rustls"))]
mod boringssl_openssl;
#[cfg(not(feature = "__rustls"))]
pub use boringssl_openssl::*;

#[cfg(feature = "__rustls")]
mod rustls;
#[cfg(feature = "__rustls")]
pub use rustls::*;

use crate::packet;
use crate::ConnectionError;

pub struct ExData<'a> {
    #[cfg(not(feature = "__rustls"))]
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    #[cfg(not(feature = "__rustls"))]
    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    #[cfg(not(feature = "__rustls"))]
    pub trace_id: &'a str,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    #[cfg(not(feature = "__rustls"))]
    pub is_server: bool,
}
