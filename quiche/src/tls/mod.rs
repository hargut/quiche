#[cfg(not(feature = "rustls"))]
mod boringssl_openssl_quictls_common;
#[cfg(not(feature = "rustls"))]
use boringssl_openssl_quictls_common as tls;
#[cfg(not(feature = "rustls"))]
use tls::*;

#[cfg(feature = "rustls")]
mod rustls;
#[cfg(feature = "rustls")]
use rustls as tls;

#[cfg(not(feature = "openssl"))]
mod boringssl;

#[cfg(not(feature = "openssl"))]
use boringssl::*;
