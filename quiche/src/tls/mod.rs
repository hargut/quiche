#[cfg(not(feature = "rustls"))]
mod boringssl_openssl;
#[cfg(not(feature = "rustls"))]
pub use boringssl_openssl::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use rustls::*;

use crate::packet;
use crate::ConnectionError;

pub struct ExData<'a> {
    #[cfg(not(feature = "rustls"))]
    pub application_protos: &'a Vec<Vec<u8>>,

    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    #[cfg(not(feature = "rustls"))]
    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    #[cfg(not(feature = "rustls"))]
    pub trace_id: &'a str,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    #[cfg(not(feature = "rustls"))]
    pub is_server: bool,
}
