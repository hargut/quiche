use crate::crypto::Algorithm;
use crate::Error;
use crate::Result;

pub struct PacketKey {}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        todo!()
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        todo!()
    }
}

pub struct Open {}

impl Open {
    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        todo!()
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        todo!()
    }

    pub fn alg(&self) -> Algorithm {
        // self.alg
        todo!()
    }

    pub fn derive_next_packet_key(&self) -> Result<Open> {
        todo!()
    }
}

pub struct Seal {}

impl Seal {
    pub const ENCRYPT: u32 = 1;

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        todo!()
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        todo!()
    }

    pub fn alg(&self) -> Algorithm {
        // self.alg
        todo!()
    }

    pub fn derive_next_packet_key(&self) -> Result<Seal> {
        todo!()
    }
}

pub fn derive_initial_key_material(
    cid: &[u8], version: u32, is_server: bool, did_reset: bool,
) -> Result<(Open, Seal)> {
    let open = Open {};
    let seal = Seal {};

    Ok((open, seal))
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
