#[cfg(any(feature = "boringssl-vendored", feature = "boringssl-boring-crate", feature = "openssl"))]
mod boringssl_openssl;
#[cfg(any(feature = "boringssl-vendored", feature = "boringssl-boring-crate", feature = "openssl"))]
pub use boringssl_openssl::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
pub use rustls::*;

use crate::packet;
use crate::ConnectionError;

pub struct ExData<'a> {
    pub application_protos: &'a Vec<Vec<u8>>,

    pub pkt_num_spaces: &'a mut [packet::PktNumSpace; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    pub keylog: Option<&'a mut Box<dyn std::io::Write + Send + Sync>>,

    pub trace_id: &'a str,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub is_server: bool,
}
