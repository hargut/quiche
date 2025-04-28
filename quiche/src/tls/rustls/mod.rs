use crate::crypto;
use crate::tls::ExData;
use crate::Result;

pub struct Context {}

impl Context {
    pub fn new() -> Result<Self> {
        todo!()
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        todo!()
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        todo!()
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        todo!()
    }

    pub fn set_verify(&mut self, verify: bool) {
        todo!()
    }

    pub fn enable_keylog(&mut self) {
        todo!()
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        todo!()
    }

    pub fn set_ticket_key(&mut self, key: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        todo!()
    }
}

pub struct Handshake {}

impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        todo!()
    }

    pub fn use_legacy_codepoint(&mut self, use_legacy: bool) {
        todo!()
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        todo!()
    }

    pub fn set_quic_transport_params(&mut self, buf: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        todo!()
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        todo!()
    }

    pub fn server_name(&self) -> Option<&str> {
        todo!()
    }

    pub fn provide_data(
        &mut self, level: crypto::Level, buf: &[u8],
    ) -> Result<()> {
        todo!()
    }

    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        todo!()
    }

    pub fn process_post_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        todo!()
    }

    pub fn write_level(&self) -> crypto::Level {
        todo!()
    }

    pub fn cipher(&self) -> Option<crypto::Algorithm> {
        todo!()
    }

    pub fn is_completed(&self) -> bool {
        todo!()
    }

    pub fn is_resumed(&self) -> bool {
        todo!()
    }

    pub fn clear(&mut self) -> Result<()> {
        todo!()
    }

    pub fn set_session(&mut self, session: &[u8]) -> Result<()> {
        todo!()
    }

    pub fn curve(&self) -> Option<String> {
        todo!()
    }

    pub fn sigalg(&self) -> Option<String> {
        todo!()
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
