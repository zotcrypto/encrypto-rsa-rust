use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Mul;
use base64::{Engine};
use num::{One, Zero};
use num::traits::FromBytes;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_primes::Generator;
use crate::Bytes;
use crate::pubkey::ZotPublicKey;

/// Struct to store private key
#[derive(Debug, Default, Clone)]
pub struct ZotPrivateKey {
    d: BigUint,
    p: BigUint,
    q: BigUint,
    on: BigUint,
    pubkey: ZotPublicKey,
}
impl ZotPrivateKey {
    pub fn init(key_len: usize) -> Self {
        let sz = key_len >> 1;
        let pb = Generator::new_prime(sz).to_bytes_le();
        let qb = Generator::new_prime(sz).to_bytes_le();
        let p = BigUint::from_bytes_le(&*pb);
        let q = BigUint::from_bytes_le(&*qb);
        drop(pb);
        drop(qb);
        let n = (&p).mul(&q);
        let e = BigUint::from(65537u32);
        let bone = BigUint::one();
        let on = (&p - &bone).mul(&q - bone);
        let d = modinv(e.to_bigint().unwrap(), on.to_bigint().unwrap()).unwrap();
        assert_eq!(&d * &e % &on, BigUint::one());
        let pubkey = ZotPublicKey::init(n,e, key_len);
        Self {
            d,
            p,
            q,
            on,
            pubkey,
        }
    }
    pub fn get_pub_key(&self) -> &ZotPublicKey{
        &self.pubkey
    }
    pub fn get_sharable_pub_key(&self) -> String {
        self.pubkey.enc_pk()
    }
    pub fn decode_shared_pub_key(b64: String) -> ZotPublicKey {
        // let dec = hex::decode(b64).unwrap();
        let dec = base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64).unwrap();
        let mut e = vec![];
        let keylen = *dec.last().unwrap() as usize;
        let mut n = vec![0;keylen];
        for i in 0..keylen {
            let cur = dec.get(i).unwrap();
            n[i] = *cur;
        }
        let lmo = dec.len()-1;
        for i in keylen..lmo {
            let cur = dec.get(i).unwrap();
            e.push(*cur);
        }
        let n = BigUint::from_le_bytes(&*n);
        let e = BigUint::from_le_bytes(&*e);
        ZotPublicKey::init(n,e,keylen)
    }
    pub fn enc_priv(&self, msg: &Bytes) -> Option<String> {
        let len = msg.len();
        if len > 24 || len > (self.pubkey.get_keylen()>>3) {
            return None;
        }
        let bi = BigUint::from_bytes_le(msg);
        let bi = bi.modpow(&self.d,&self.pubkey.n);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bi.to_bytes_le());
        Some(b64)
    }

    pub fn dec_priv(&self, msg: &Bytes) -> Option<Vec<u8>> {
        let dec = match base64::engine::general_purpose::STANDARD_NO_PAD.decode(msg){
            Ok(v) => v,
            Err(_) => return None
        };
        let bi = BigUint::from_bytes_le(&*dec);
        drop(dec);
        let bi = bi.modpow(&self.d,&self.pubkey.n);
        Some(bi.to_bytes_le())
    }

    pub fn enc_public(&self, msg: &Bytes) -> Option<String> {
       self.pubkey.encrypt(msg)
    }

    pub fn dec_public(&self, msg: &Bytes) -> Option<Vec<u8>> {
        self.pubkey.decrypt(msg)
    }
}

fn egcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    if a == BigInt::zero() {
        (b, BigInt::zero(), BigInt::one())
    } else {
        let (g, x, y) = egcd(b.clone() % a.clone(), a.clone());
        (g, y - (b / a) * x.clone(), x)
    }
}

/// Returns modulo inverse
pub fn modinv(a: BigInt, m: BigInt) -> Option<BigUint> {
    let (g, x, _) = egcd(a, m.clone());
    if g != BigInt::one() {
        None
    } else {
        Some(((x % m.clone() + m.clone()) % m).to_biguint().unwrap())
    }
}