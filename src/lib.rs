mod bigint;

use std::collections::HashMap;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use serde_json::Value;
use crate::bigint::Generator;

#[cfg(test)]
mod tests{
    // use crate::aes::{AES128, Cipher};
    use crate::EncryptoRSA;

    #[test]
    fn idk(){
        let e = EncryptoRSA::init(1024);
        let enc = e.encrypt_from_string("alo".to_string(),
                                                   e.pbl.clone());
        let dec = e.decrypt_as_string(enc);
        println!("{}", dec);
    }
}

/// This struct is used to store your generated PrivateKey and PublicKeys, click for demo code
///
/// # Uses
/// ```
/// use encrypto_rust::EncryptoRSA;
///
/// fn main() {
///     let encrypto = EncryptoRSA::init(1024);
///     let public_key = encrypto.get_public_key(); //returns PublicKey struct
///     let msg = "Alo".to_string(); // sample message to be encrypted
///     let enc = e.encrypt_from_string(msg.clone(), public_key.clone()); // returns encrypted msg as base64 string
///     let dec = encrypto.decrypt_as_string(enc); // returns decoded msg as string
///
///     let public_key_string = encrypto.sterilize_pub_key(); // IMPORTANT - returns base64 encoded public key which is to be sent to other client for encryption
///
///     let enc_from_bytes = EncryptoRSA::encrypt_from_bytes(bytes, public_key); // returns encrypted bytes as base64 string
///     let dec_from_bytes = encrypto.decrypt_as_bytes(enc_from_bytes); // returns bytes as Vec<u8>
///
///     assert_eq!(msg, dec);
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct EncryptoRSA {
    pbl: PublicKey,
    pri: PrivateKey,
}

/// Struct to store public key
#[derive(Debug, Default, Clone)]
pub struct PublicKey {
    e: BigUint,
    n: BigUint,
}

/// Struct to store private key
#[derive(Debug, Default, Clone)]
struct PrivateKey {
    on: BigUint,
    d: BigUint,
}

impl EncryptoRSA {

    /// * `bit_len` - it's better to use bit length >= 2048
    pub fn init(bit_len: usize) -> Self {
        let e = BigUint::from(65537 as u32);
        let p =  Generator::new_prime(bit_len);
        // t.join().unwrap();
        let  q =  Generator::new_prime(bit_len);
        // t.join().unwrap();

        let n = p.clone() * q.clone();
        let on = (p - BigUint::one()) * (q - BigUint::one());
        let d = modinv(e.clone().to_bigint().unwrap(), on.clone().to_bigint().unwrap()).unwrap();

        assert_eq!(BigUint::one(), (d.clone() * e.clone()) % on.clone());

        let pbl: PublicKey = PublicKey {
            e,
            n,
        };

        let pri: PrivateKey = PrivateKey {
            on,
            d,
        };

        Self {
            pbl,
            pri,
        }
    }

    pub fn get_public_key(&self) -> PublicKey {
        self.pbl.clone()
    }

    pub fn desterilize_pub_key(encoded: String) -> PublicKey {
        let x = base64::decode(encoded).unwrap();
        let json: Value = serde_json::from_slice(&*x).unwrap();
        let x = json.get("on").unwrap().as_str().unwrap();
        let xx = x.as_bytes();
        let n = BigUint::parse_bytes(xx, 10).unwrap();
        let x = json.get("pe").unwrap().as_str().unwrap();
        let xx = x.as_bytes();
        let e = BigUint::parse_bytes(xx, 10).unwrap();

        PublicKey {
            e,
            n,
        }
    }

    pub fn sterilize_pub_key(&self) -> String {
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("pe", self.pbl.e.clone().to_string());
        hm.insert("on", self.pbl.n.clone().to_string());
        let json = serde_json::to_value(hm).unwrap().to_string();
        base64::encode(json.as_bytes())
    }

    pub fn encrypt_from_string(&self, val: String, pub_key: PublicKey) -> String {
        let bi = convert_bytes_to_big_int(val.as_bytes());
        let enc = (bi * pub_key.e) % pub_key.n;
        let enc = (enc * self.pri.d.clone()) % self.pri.on.clone();
        let by = convert_bigint_to_bytes(enc);
        base64::encode(by)
    }

    pub fn encrypt_from_bytes(&self, bytes: &[u8], pub_key: PublicKey) -> String {
        let bi = convert_bytes_to_big_int(bytes);
        let enc = (bi * pub_key.e) % pub_key.n;
        let enc = (enc * self.pri.d.clone()) % self.pri.on.clone();
        base64::encode(convert_bigint_to_bytes(enc))
    }

    pub fn decrypt_as_string(&self, val: String) -> String {
        let by = base64::decode(val.as_bytes()).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        let dec = (bi*self.pbl.e.clone()) % self.pbl.n.clone();
        let dec = (dec * self.pri.d.clone()) % self.pri.on.clone();
        let by = convert_bigint_to_bytes(dec);
        match String::from_utf8(by.clone()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}\n\n{:?}", e, by);
                return "".to_string();
            }
        }
    }

    pub fn decrypt_as_bytes(&self, val: String) -> Vec<u8> {
        convert_bigint_to_bytes((convert_bytes_to_big_int(&*base64::decode(val).unwrap()) * self.pri.d.clone()) % self.pri.on.clone())
    }
}

/// Custom common method to convert Bytes to BigInteger
fn convert_bytes_to_big_int(bytes: &[u8]) -> BigUint {
    let mut result = BigUint::zero();
    for z in bytes {
        result = (result << 8) | BigUint::from(z & 0xff);
    }
    return result;
}

/// Custom common method to convert BigInteger to Bytes
fn convert_bigint_to_bytes(mut number: BigUint) -> Vec<u8> {
    let bytes = (number.clone().bits() + 7) >> 3;
    let b256 = BigUint::from_i32(256).unwrap();
    let mut result = Vec::new();
    for _ in 0..bytes {
        result.push(u8::try_from((number.clone() % b256.clone()).to_i64().unwrap()).unwrap());
        number >>= 8;
    }
    let idk: Vec<u8> = result.iter().copied().rev().collect();
    idk
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
fn modinv(a: BigInt, m: BigInt) -> Option<BigUint> {
    let (g, x, _) = egcd(a, m.clone());
    if g != BigInt::one() {
        None
    } else {
        Some(((x % m.clone() + m.clone()) % m).to_biguint().unwrap())
    }
}