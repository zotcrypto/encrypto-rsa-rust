mod bigint;

use std::collections::HashMap;
use std::{error, usize};
use std::str::FromStr;
use num::{FromPrimitive, One, ToPrimitive, Zero};
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use serde_json::Value;
use crate::bigint::Generator;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

#[cfg(test)]
mod tests{
    use num_bigint::BigUint;
    use crate::{EncryptoRSA, Generator, One};

    #[test]
    fn foox(){
        println!("{}", 0x10);
    }

    #[test]
    fn encrypto_tests(){
        let c = BigUint::parse_bytes("861270243527190895777142537838333832920579264010533029282104230006461420086153423".as_bytes(), 10).unwrap();
        let n = BigUint::parse_bytes("1311097532562595991877980619849724606784164430105441327897358800116889057763413423".as_bytes(), 10).unwrap();
        let e = BigUint::parse_bytes("65537".as_bytes(), 10).unwrap();

        println!("{}", c.modpow(&n, &e));

        /*//29329910984667111668698655637818737335150278953697889411613371939678947564721136189355438568499715776963467791924170712468382877544862676115129685014796720016362374716002936880408902090892990110715659120207495854365051339106405607318567460641209540060903987224813697125337686240065295060748518483892816811089217073863560993386552806111000416661028596519930847932759070529862887234415643686990441277249722114110301213080169821499693026604664073773056594900899391540646777145266698605869343033207736619528293708523985002390293641933265245787779900591773848698907339399218748495990024797759753087538276697216466593947233
        let encrypto = EncryptoRSA::init(512);
        let encrypto1 = EncryptoRSA::init(512);
        let msg = b"abc".as_slice();

        let enc = encrypto.double_encrypt(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.double_decrypt(enc.as_bytes(), encrypto.pbl.clone());*/
    }

    #[test]
    fn cross_platform(){
        let encrypto = EncryptoRSA::init(512);
        println!("{}", encrypto.get_sterilized_pub_key());
        println!("Enter message: ");
        let mut msg = String::new();
        std::io::stdin().read_line(&mut msg).unwrap();
        println!("Choose decryption method decrypt, double_decrypt, double_decrypt_with_pkcsv1_15, decrypt_with_pkcsv1_15: ");
        let mut dec_method = String::new();
        std::io::stdin().read_line(&mut dec_method).unwrap();

        if "decrypt".to_string() == dec_method {
            println!("{:?}",encrypto.decrypt(msg));
        }else if "double_decrypt".to_string() == dec_method {
            let mut pubkey = String::new();
            std::io::stdin().read_line(&mut pubkey).unwrap();
            println!("{:?}",encrypto.double_decrypt(msg.as_bytes(), EncryptoRSA::desterilize_pub_key(pubkey)));
        }else if "double_decrypt_with_pkcsv1_15".to_string() == dec_method {
            let mut pubkey = String::new();
            std::io::stdin().read_line(&mut pubkey).unwrap();
            println!("{:?}",encrypto.double_decrypt_with_pkcsv1_15(msg, EncryptoRSA::desterilize_pub_key(pubkey)));
        }else if "decrypt_with_pkcsv1_15".to_string() == dec_method {
            println!("{:?}", encrypto.decrypt_with_pkcsv1_15(msg));
        }
    }

}

#[cfg(test)]
mod private_tests{
    use num_bigint::{BigUint, RandBigInt, ToBigInt};
    use crate::{EncryptoRSA, Generator, modinv, One};

    #[test]
    fn b64check(){
        //[67, 84, 116, 100, 77, 88, 87, 73, 100, 72, 103, 73, 84, 85, 119, 83, 72, 50, 74, 51, 67, 122, 50, 76, 56, 111, 85, 104, 49, 83, 82, 104, 120, 112, 103, 79, 72, 99, 80, 73, 73, 50, 69, 61, 10]
        let b64 = base64::decode("eyJwZSI6NjU1MzcsIm4iOjcwOTQ0NzU1MDgwNjM0OTIzNzI3NTQ0NzkwMjM0Mzg3MzE0NTQ4NTQ0OTIzNjAwMjQ1NzA1NjM1ODYxNDg4NjIxNDU3MzgwOTI3MjA3LCJrZXlsZW4iOjEyOH0=").unwrap();
        // let b641 = base64::decode("aLTdPaIP8v5YA3bwETeM4OP88/+28dfzkshLkP5tOqk=".as_bytes()).unwrap();
        //
        let v = [101, 121, 74, 119, 90, 83, 73, 54, 78, 106, 85, 49, 77, 122, 99, 115, 73, 109, 52, 105, 79, 106, 99, 119, 79, 84, 81, 48, 78, 122, 85, 49, 77, 68, 103, 119, 78, 106, 77, 48, 79, 84, 73, 122, 78, 122, 73, 51, 78, 84, 81, 48, 78, 122, 107, 119, 77, 106, 77, 48, 77, 122, 103, 51, 77, 122, 69, 48, 78, 84, 81, 52, 78, 84, 81, 48, 79, 84, 73, 122, 78, 106, 65, 119, 77, 106, 81, 49, 78, 122, 65, 49, 78, 106, 77, 49, 79, 68, 89, 120, 78, 68, 103, 52, 78, 106, 73, 120, 78, 68, 85, 51, 77, 122, 103, 119, 79, 84, 73, 51, 77, 106, 65, 51, 76, 67, 74, 114, 90, 88, 108, 115, 90, 87, 52, 105, 79, 106, 69, 121, 79, 72, 48, 61];
        assert_eq!("eyJwZSI6NjU1MzcsIm4iOjcwOTQ0NzU1MDgwNjM0OTIzNzI3NTQ0NzkwMjM0Mzg3MzE0NTQ4NTQ0OTIzNjAwMjQ1NzA1NjM1ODYxNDg4NjIxNDU3MzgwOTI3MjA3LCJrZXlsZW4iOjEyOH0=".as_bytes(), v);
        let xx = "eyJrZXlsZW4iOiIxMjgiLCJuIjoiNzI3ODQwMjEwOTAyMzcxMzMyNjQ1NzMzNDQ2MTQzMTk3NTQxODE0MTEwNzMyNzI1NzQ4MjM1MjY4NjY5OTM3OTI4ODI0OTUwODE1MSIsInBlIjoiNjU1MzcifQ==";
        let pk = EncryptoRSA::desterilize_pub_key(xx.to_string());
        println!("{:?}", pk);
        let x = "eyJwZSI6NjU1MzcsIm4iOjcwOTQ0NzU1MDgwNjM0OTIzNzI3NTQ0NzkwMjM0Mzg3MzE0NTQ4NTQ0OTIzNjAwMjQ1NzA1NjM1ODYxNDg4NjIxNDU3MzgwOTI3MjA3LCJrZXlsZW4iOjEyOH0=".to_string();
        let pk = EncryptoRSA::desterilize_pub_key(x);
    }

    #[test]
    fn check_len(){
        let mut v = rand::thread_rng().gen_biguint(128).to_bytes_le();
        println!("{:?}", v);
    }
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
    pub pbl: ZotPublicKey,
    pub pri: ZotPrivateKey,
}

/// Struct to store public key
#[derive(Debug, Default, Clone)]
pub struct ZotPublicKey {
    e: BigUint,
    n: BigUint,
    keylen: usize
}

/// Struct to store private key
#[derive(Debug, Default, Clone)]
pub struct ZotPrivateKey {
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

        if BigUint::one() != (d.clone()*e.clone())%on.clone() {
            return EncryptoRSA::init(bit_len);
        }
        let pbl: ZotPublicKey = ZotPublicKey {
            e,
            n: n.clone(),
            keylen: bit_len
        };

        let pri: ZotPrivateKey = ZotPrivateKey {
            n,
            d
        };

        Self {
            pbl,
            pri,
        }
    }

    /// Returns public key struct (can't be used for sharing to other languages)
    pub fn get_public_key(&self) -> ZotPublicKey {
        self.pbl.clone()
    }

    /// Returns private key struct (can't be used for sharing to other languages)
    pub fn get_private_key(&self) -> ZotPrivateKey {
        self.pri.clone()
    }

    /// Converts recieved base64 encoded public key to PublicKey struct
    pub fn desterilize_pub_key(encoded: String) -> ZotPublicKey {
        let x = base64::decode(encoded).unwrap();
        let json: Value = serde_json::from_slice(&*x).unwrap();
        let x = json.get("n").unwrap().as_str().unwrap().as_bytes();
        let n = BigUint::parse_bytes(x, 10).unwrap();
        let x = json.get("pe").unwrap().as_str().unwrap().as_bytes();
        let e = BigUint::parse_bytes(x, 10).unwrap();
        let bit_len = usize::from_str(json.get("keylen").unwrap().as_str().unwrap()).unwrap();
        ZotPublicKey {
            e,
            n,
            keylen: bit_len
        }
    }

    ///Returns base64 encoded public key which can be shared to other app which uses Encrypto-RSA
    pub fn get_sterilized_pub_key(&self) -> String {
        let mut hm = HashMap::<&str, String>::new();
        hm.insert("pe", self.pbl.e.clone().to_string());
        hm.insert("n", self.pbl.n.clone().to_string());
        hm.insert("keylen", self.pbl.keylen.clone().to_string());
        let json = serde_json::to_value(hm).unwrap().to_string();
        base64::encode(json.to_string().as_bytes())
    }

    /// This method adds random bytes to the message, encrypts with the `pub_key` and again encrypts it with your private key.
    ///
    /// You can decrypt it using double_decrypt(...) method
    pub fn double_encrypt(&self, bytes: &[u8], pub_key: ZotPublicKey) -> Result<String> {
        ZotPublicKey::double_encrypt(bytes, pub_key, self)
    }

    /// This method adds random bytes to the message, encrypts with the `pub_key`.
    ///
    /// You can decrypt it using decrypt_with_pkcsv1_15(...) method
    pub fn encrypt_with_pkcsv1_15(&self, bytes: &[u8], pub_key: ZotPublicKey) ->  Result<String> {
        ZotPublicKey::encrypt_with_pkcsv1_15(bytes, pub_key)
    }

    /// This method adds random bytes to the message, encrypts with the `pub_key` and again encrypts it with your private key.
    ///
    /// You can decrypt it using double_decrypt_with_pkcsv1_15(...) method
    pub fn double_encrypt_with_pkcsv1_15(&self, bytes: &[u8], pub_key: ZotPublicKey) -> Result<String> {
        ZotPublicKey::double_encrypt_with_pkcsv1_15(bytes, pub_key, self)
    }

    ///This method encrypts with the `pub_key`.
    ///
    /// You can decrypt it using decrypt(...) method
    pub fn encrypt(&self, bytes: &[u8], pub_key: ZotPublicKey) ->  Result<String> {
        ZotPublicKey::encrypt(bytes, pub_key)
    }

    ///This method decrypts value twice, once with public key and then with private key.
    ///
    /// this way you know that the public key is from the designated sender
    pub fn double_decrypt<T: AsRef<[u8]>>(&self, val: T, pub_key: ZotPublicKey) -> Vec<u8> {
        let by = base64::decode(val).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        let dec = bi.modpow(&pub_key.e, &pub_key.n);
        let dec = dec.modpow(&self.pri.d, &self.pri.n);
        convert_bigint_to_bytes(dec)
    }

    ///This method decrypts value twice, once with public key and then with private key.
    ///
    /// this way you know that the public key is from the designated sender
    ///
    /// It removes first 16 bytes, which were used to increase message length to protect it against attacks
    pub fn double_decrypt_with_pkcsv1_15<T: AsRef<[u8]>>(&self, val: T, pub_key: ZotPublicKey) -> Vec<u8> {
        let by = base64::decode(val).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        let dec = bi.modpow(&pub_key.e, &pub_key.n);
        let dec = dec.modpow(&self.pri.d, &self.pri.n);
        let mut x = convert_bigint_to_bytes(dec);
        x.drain(0..16);
        x
    }

    /// This method decrypts value with private key.
    pub fn decrypt<T: AsRef<[u8]>>(&self, val: T) -> Vec<u8> {
        // let val = val.as_bytes();
        let by = &base64::decode(val).unwrap()[..];
        // println!("{:?} {:?}", val, by.clone());
        let bi = convert_bytes_to_big_int(by);
        // let dec = (bi*self.pbl.e.clone()) % self.pbl.n.clone();
        let dec = bi.modpow(&self.pri.d.clone(), &self.pri.n.clone());
        convert_bigint_to_bytes(dec)
    }

    /// This method decrypts value with private key and returns decoded value of pkcsv1 1.5 padding.
    pub fn decrypt_with_pkcsv1_15<T: AsRef<[u8]>>(&self, val: T) -> Vec<u8> {
        /*let by = base64::decode(val).unwrap();
        let bi = convert_bytes_to_big_int(&*by);
        // let dec = (bi*self.pbl.e.clone()) % self.pbl.n.clone();
        let dec = bi.modpow(&self.pri.d.clone(), &self.pri.n.clone());*/
        let mut x = self.decrypt(val);
        x.drain(0..16);
        x
    }
}

impl ZotPublicKey {
    pub fn encrypt(bytes: &[u8], pub_key: ZotPublicKey) ->  Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let bi = convert_bytes_to_big_int(bytes);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }
    pub fn double_encrypt_with_pkcsv1_15(bytes: &[u8], pub_key: ZotPublicKey, encrypto: &EncryptoRSA) -> Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let mut v = rand::thread_rng().gen_biguint(128).to_bytes_le();
        v.append(&mut bytes.to_vec());
        let bi = convert_bytes_to_big_int(&*v);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        let enc = enc.modpow(&encrypto.pri.d, &encrypto.pri.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }
    pub fn encrypt_with_pkcsv1_15(bytes: &[u8], pub_key: ZotPublicKey) ->  Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let mut v = rand::thread_rng().gen_biguint(128).to_bytes_le();
        v.append(&mut bytes.to_vec());
        let bi = convert_bytes_to_big_int(&*v);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
    }
    pub fn double_encrypt(bytes: &[u8], pub_key: ZotPublicKey, encrypto: &EncryptoRSA) -> Result<String> {
        if pub_key.keylen - 11 < bytes.len() {
            panic!("Msg bigger than key-length, use at least 2048 bit key");
        }
        let bi = convert_bytes_to_big_int(bytes);
        let enc = bi.modpow(&pub_key.e, &pub_key.n);
        let enc = enc.modpow(&encrypto.pri.d, &encrypto.pri.n);
        Ok(base64::encode(convert_bigint_to_bytes(enc)))
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