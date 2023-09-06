use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use base64::{Engine};
use num_bigint::BigUint;
use crate::Bytes;

/// Struct to store public key
#[derive(Debug, Default, Clone)]
pub struct ZotPublicKey {
    pub n: BigUint,
    e: BigUint,
    keylen: usize
}

impl ZotPublicKey {
    pub fn init(n: BigUint, e: BigUint, keylen: usize) -> Self{
        Self{
            n,
            e,
            keylen,
        }
    }
    pub fn encrypt(&self, msg: &Bytes) -> Option<String>{
        let len = msg.len();
        if len > 24 || len > (self.keylen>>3) {
            return None;
        }
        let bi = BigUint::from_bytes_le(msg);
        let bi = bi.modpow(&self.e,&self.n);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bi.to_bytes_le());
        Some(b64)
    }
    pub fn decrypt(&self, msg: &Bytes) -> Option<Vec<u8>> {
        let dec = match base64::engine::general_purpose::STANDARD_NO_PAD.decode(msg) {
            Ok(v) => {
                v
            }
            Err(_) => {
                return None;
            }
        };
        let bi = BigUint::from_bytes_le(&*dec);
        drop(dec);
        let bi = bi.modpow(&self.e,&self.n);
        Some(bi.to_bytes_le())
    }
    pub fn enc_pk(&self) -> String {
        let mut nb = self.n.to_bytes_le();
        let nbl = nb.len();
        let mut s: Vec<u8> = vec![];
        s.append(&mut nb);
        s.append(&mut self.e.to_bytes_le());
        s.push(nbl as u8);
        // let b64 = hex::encode(s);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(&*s);
        b64
    }
    pub fn get_keylen(&self) -> &usize {
        &self.keylen
    }
}