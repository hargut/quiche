use std::sync::Arc;
use rustls::{CipherSuite, ClientConfig, ServerConfig, SupportedCipherSuite};
use rustls::quic::{ClientConnection, ServerConnection};

use rustls::quic::Version;
use crate::{crypto, Error, Result};
use crate::tls::ExData;

struct Context {
    config: Option<Config>,
    params: Parameters<'_>
}

struct Parameters<'a> {
    is_server: bool,
    ca_file: Option<&'a str>, // TODO: read files
    key_file: Option<&'a str>, // TODO: read files
    enable_keylog: bool,
    enable_early_data: bool,
    ticket_key: &'a [u8],
    set_verify: bool,
    verify_locations_file: Option<&'a str>,
    verify_locations_directory: Option<&'a str>,
    quic_version: Version,
}

#[derive(Clone)]
enum Config {
    Server(Arc<ServerConfig>),
    Client(Arc<ClientConfig>)
}

impl Config {
    fn new(params: &mut Parameters) -> Result<Self> {
        match params.is_server {
            true => {
                let builder = ServerConfig::builder();
                let config = builder.with_no_client_auth()
                    .with_single_cert()?;

                Ok(Self::Server(Arc::new(config)))
            }
            false => {
                let builder = ClientConfig::builder();
                let config = builder.with_root_certificates()
                    .with_no_client_auth();

                Ok(Self::Client(Arc::new(config)))
            }
        }
    }

    fn early_data_enabled(&self) -> bool {
        match self {
            Config::Server(cfg) => cfg.max_early_data_size > 0,
            Config::Client(cfg) => cfg.enable_early_data
        }
    }
}

impl Context {
    pub fn enable_keylog(&mut self) {
        self.params.enable_keylog = true;
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        self.params.enable_early_data = enabled;
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        self.params.ticket_key = key;
        Ok(())
    }

    pub fn set_verify(&mut self, verify: bool) {
        self.params.set_verify = verify;
    }

    fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        self.params.verify_locations_file = Some(file);
        Ok(())
    }

    fn load_verify_locations_from_directory(&mut self, directory: &str) -> Result<()> {
        self.params.verify_locations_directory = Some(directory);
        Ok(())
    }

    fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        self.params.ca_file = Some(file);
        Ok(())
    }

    fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        self.params.key_file = Some(file);
        Ok(())
    }

    fn build_config(&mut self) -> Result<Config> {
        let Some(config) = &self.config else {
            self.config = Config::new(&mut self.params).into()?;
            Ok(self.config.clone())
        };
        Ok(config.clone())
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        let config = self.build_config()?;

        // FIXME: transport params
        let conn = match &config {
            Config::Server(cfg) => {
                let conn = ServerConnection::new(cfg.clone(), self.params.quic_version, vec![])
                    .map_err(|e| e.into())?;
                Connection::Server(conn)
            }
            Config::Client(cfg) => {
                // FIXME: ServerName
                let conn = ClientConnection::new(cfg.clone(), self.params.quic_version, "myname.org".into(),vec![])
                    .map_err(|e| e.into())?;
                Connection::Client(conn)
            }
        };

        Ok(Handshake {
            connection: None,
            config: config.clone()
        })
    }
}

struct Handshake {
    connection: Option<Connection>,
    config: Config
}

enum Connection {
    Server(ServerConnection),
    Client(ClientConnection)
}

impl Connection {
    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Connection::Server(conn) => conn.alpn_protocol(),
            Connection::Client(conn) => conn.alpn_protocol()
        }
    }

    fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        match self {
            Connection::Server(conn) => conn.negotiated_cipher_suite(),
            Connection::Client(conn) => conn.negotiated_cipher_suite()
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Connection::Server(conn) => conn.is_handshaking(),
            Connection::Client(conn) => conn.is_handshaking()
        }
    }
}

impl Handshake {
    pub fn alpn_protocol(&self) -> &[u8] {
        let Some(conn) = &self.connection else {
            return &[]
        };

        match conn.alpn_proto() {
            None => &[],
            Some(alpn) => alpn
        }
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        let Some(conn) = &self.connection else {
            return None
        };

        let Some(suite) = conn.negotiated_cipher_suite() else {
            return None
        };

        match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(crypto::Algorithm::AES128_GCM),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(crypto::Algorithm::AES256_GCM),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => Some(crypto::Algorithm::ChaCha20_Poly1305),
            _ => None
        }
    }

    pub fn clear(&mut self) -> Result<()> {
        Ok(())
    }

    pub fn curve(&self) -> Option<String> {
        // FIXME: as of now only used for logging
        None
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        let Some(conn) = &self.connection else {
              Err(Error::InvalidState)
        };

        conn
    }

    pub fn is_completed(&self) -> bool {
        let Some(conn) = &self.connection else {
            false
        };
        conn.is_handshaking()
    }

    pub fn is_in_early_data(&self) -> bool {
        let Some(conn) = &self.connection else {
            false
        };
        match conn {
            Connection::Server(conn) => self.config.early_data_enabled(),
            Connection::Client(conn) => self.config.early_data_enabled() && conn.is_early_data_accepted()
        }
    }

    pub fn is_resumed(&self) -> bool {
        let Some(conn) = &self.connection else {
            return false
        };
        matches!(self.config.)
    }


    pub fn peer_cert(&self) -> Option<&[u8]> {

    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {

    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {

    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {

    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {

    }

    pub fn server_name(&self) -> Option<&str> {

    }

    pub fn set_session(&mut self, session: &[u8]) -> std::result::Result<()> {

    }

    pub fn sigalg(&self) -> Option<String> {

    }

    pub fn write_level(&self) -> crypto::Level {

    }
}