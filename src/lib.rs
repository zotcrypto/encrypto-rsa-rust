mod bigint;

use std::collections::HashMap;
use std::{error, usize};
use std::str::FromStr;
use num::{FromPrimitive, One, ToPrimitive, Zero};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
// use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
use serde_json::Value;
use crate::bigint::Generator;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[cfg(test)]
mod tests{
    use crate::EncryptoRSA;

    #[test]
    fn encrypto_tests(){

        let mut x = Vec::new();

        let encrypto = EncryptoRSA::init(512);
        let encrypto1 = EncryptoRSA::init(512);
        let msg = b"abc".as_slice();

        let enc = encrypto.encrypt(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.decrypt(enc);
        x.push(dec);

        let enc = encrypto.encrypt_with_pkcsv1_15(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.decrypt_with_pkcsv1_15(enc);
        x.push(dec);

        let enc = encrypto.double_encrypt(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.double_decrypt(enc, encrypto.pbl.clone());
        x.push(dec);

        let enc = encrypto.double_encrypt_with_pkcsv1_15(msg, encrypto1.pbl.clone()).unwrap();
        let dec = encrypto1.double_decrypt_with_pkcsv1_15(enc, encrypto.pbl.clone());
        x.push(dec);

        for f in x.iter() {
            assert_eq!(&msg.to_vec(), f);
        }

    }
}

#[cfg(test)]
mod private_tests{
    use num_bigint::{BigUint, ToBigInt};
    use crate::{Generator, modinv, One};

    #[test]
    fn idk(){
        let bit_len = 1024  ;
        //bob
        let e = BigUint::from(65537 as u32);
        let p = Generator::new_prime(bit_len);
        let q = Generator::new_prime(bit_len);
        let n = p.clone() * q.clone();
        let on = (p - BigUint::one()) * (q - BigUint::one());
        let d = modinv(e.clone().to_bigint().unwrap(), on.clone().to_bigint().unwrap()).unwrap();
        assert_eq!(BigUint::one(), (d.clone()*e.clone())%on.clone());

        //alice
        let p1 = Generator::new_prime(bit_len);
        let q1 = Generator::new_prime(bit_len);
        let n1 = p1.clone() * q1.clone();
        let on1 = (p1 - BigUint::one()) * (q1 - BigUint::one());
        let d1 = modinv(e.clone().to_bigint().unwrap(), on1.clone().to_bigint().unwrap()).unwrap();

        let a = BigUint::from(97 as u32);

        let enc = a.modpow(&e, &n); // msg^e % n
        let enc1 = enc.modpow(&d1, &n1); // c1 ^ d1 % n1

        let dec = enc1.modpow(&e,&n1); // c2 ^ e % n1
        let dec1 = dec.modpow(&d, &n); // c3 ^ d % n

        assert_eq!(a, dec1);

    }
}

/// This struct is used to store your generated PrivateKey and PublicKeys, click for demo code
///
/// # Uses
/// ```
///
/// fn main() {
///     use encrypto_rsa::EncryptoRSA;
/// let encrypto = EncryptoRSA::init(1024);
///     let public_key = encrypto.get_public_key(); //returns PublicKey struct
///     let msg = "Alo".to_string(); // sample message to be encrypted
///     let enc = e.encrypt_from_string(msg.clone(), public_key.clone()); // returns encrypted msg as base64 string
///     let dec = encrypto.decrypt_as_string(enc); // returns decoded msg as string
///
///     let public_key_string = encrypto.sterilize_pub_key(); // IMPORTANT - returns base64 encoded public key which is to be sent to other client for encryption
///
///     let enc_from_bytes = encrypto.encrypt(bytes, public_key); // returns encrypted bytes as base64 string
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
    keylen: usize
}

/// Struct to store private key
#[derive(Debug, Default, Clone)]
struct PrivateKey {
    n: BigUint,
    d: BigUint,
}

impl EncryptoRSA {

    /// * `bit_len` - it's better to use bit length >= 2048
    pub fn init(bit_len: usize) -> Self {
        let e = BigUint::from(65537 as u32);
        let p = Generator::new_prime(bit_len);
        let q = Generator::new_prime(bit_len);
        let n = p.clone() * q.clone();
        let on = (p - BigUint::one()) * (q - BigUint::one());
        let d = modinv(e.clone().to_bigint().unwrap(), on.clone().to_bigint().unwrap()).unwrap();

        assert_eq!(BigUint::one(), (d.clone() * e.clone()) % on);

        let pbl: PublicKey = PublicKey {
            e,
            n: n.clone(),
            keylen: bit_len
        };

        let pri: PrivateKey = PrivateKey {
            n,
            d
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
        let x = json.get("n").unwrap().as_str().unwrap();
        let xx = x.as_bytes();
        let n = BigUint::parse_bytes(xx, 10).unwrap();
        let x = json.get("pe").unwrap().as_str().unwrap();
        let xx = x.as_bytes();
        let e = BigUint::parse_bytes(xx, 10).unwrap();
        let bit_len = usize::from_str(json.get("pe").unwrap().as_str().unwrap()).unwrap();
        PublicKey {
            e,
            n,
            keylen: bit_len
        }
    }

    pub fn get_sterilized_pub_key(&self) -> String {
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("pe", self.pbl.e.clone().to_string());
        hm.insert("n", self.pbl.n.clone().to_string());
        let json = serde_json::to_value(hm).unwrap().to_string();
        base64::encode(json.as_bytes())
    }

/*    pub fn encrypt_from_string(&self, val: String, pub_key: PublicKey) -> String {
        let bi = convert_bytes_to_big_int(val.as_bytes());
        let enc = (bi * pub_key.e) % pub_key.n;
        let enc = (enc * self.pri.d.clone()) % self.pri.on.clone();
        let by = convert_bigint_to_bytes(enc);
        base64::encode(by)
    }*/

    ///This method encrypts with the `pub_key` and again encrypts that with your private key.
    ///
    /// You can decrypt it using double_decrypt(...) method
    pub fn double_encrypt(&self, bytes: &[u8], pub_key: PublicKey) -> Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let bi = convert_bytes_to_big_int(bytes);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        let enc = enc.modpow(&self.pri.d, &self.pri.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }

    ///This method encrypts with the `pub_key`, adds random bytes to the string.
    ///
    /// You can decrypt it using decrypt_with_pkcsv1_15(...) method
    pub fn encrypt_with_pkcsv1_15(&self, bytes: &[u8], pub_key: PublicKey) ->  Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let mut v = rand::thread_rng().gen_biguint(128).to_bytes_le();
        v.append(&mut bytes.to_vec());
        let bi = convert_bytes_to_big_int(&*v);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }

    pub fn double_encrypt_with_pkcsv1_15(&self, bytes: &[u8], pub_key: PublicKey) -> Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let mut v = rand::thread_rng().gen_biguint(128).to_bytes_le();
        v.append(&mut bytes.to_vec());
        let bi = convert_bytes_to_big_int(&*v);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        let enc = enc.modpow(&self.pri.d, &self.pri.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }

    ///This method encrypts with the `pub_key`.
    ///
    /// You can decrypt it using decrypt(...) method
    pub fn encrypt(&self, bytes: &[u8], pub_key: PublicKey) ->  Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let bi = convert_bytes_to_big_int(bytes);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }

    ///This method decrypts value twice, once with public key and then with private key.
    ///
    /// this way you know that the public key is from the designated sender
    pub fn double_decrypt(&self, val: String, pub_key: PublicKey) -> Vec<u8> {
        let by = base64::decode(val.as_bytes()).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        let dec = bi.modpow(&pub_key.e, &pub_key.n);
        let dec = dec.modpow(&self.pri.d, &self.pri.n);
        convert_bigint_to_bytes(dec)
    }

    pub fn double_decrypt_with_pkcsv1_15(&self, val: String, pub_key: PublicKey) -> Vec<u8> {
        let by = base64::decode(val.as_bytes()).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        let dec = bi.modpow(&pub_key.e, &pub_key.n);
        let dec = dec.modpow(&self.pri.d, &self.pri.n);
        let mut x = convert_bigint_to_bytes(dec);
        x.drain(0..16);
        x
    }

    ///This method decrypts value with private key.
    pub fn decrypt(&self, val: String) -> Vec<u8> {
        let by = base64::decode(val.as_bytes()).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        // let dec = (bi*self.pbl.e.clone()) % self.pbl.n.clone();
        let dec = bi.modpow(&self.pri.d.clone(), &self.pri.n.clone());
        convert_bigint_to_bytes(dec)
    }

    /// This method decrypts value with private key and returns decoded value of pkcsv1 1.5 padding.
    pub fn decrypt_with_pkcsv1_15(&self, val: String) -> Vec<u8> {
        let by = base64::decode(val.as_bytes()).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        // let dec = (bi*self.pbl.e.clone()) % self.pbl.n.clone();
        let dec = bi.modpow(&self.pri.d.clone(), &self.pri.n.clone());
        let mut x = convert_bigint_to_bytes(dec);
        x.drain(0..16);
        x
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