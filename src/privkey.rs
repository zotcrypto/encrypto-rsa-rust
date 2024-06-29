use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use rand::rngs::OsRng;
use rsa::rand_core::CryptoRngCore;
use rsa::traits::PaddingScheme;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::pubkey::ZotPublicKey;
use crate::B64_ENGINE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZotPrivateKey {
    pub(crate) private_key: RsaPrivateKey,
}

// TODO: impl TryFrom<&str> for ZotPrivateKey
impl ZotPrivateKey {
    pub fn init(key_len: usize) -> anyhow::Result<Self> {
        let mut rng = OsRng;
        let key = Self::init_rng(&mut rng, key_len)?;
        Ok(key)
    }
    pub fn init_rng<R: CryptoRngCore + ?Sized>(
        rng: &mut R,
        key_len: usize,
    ) -> anyhow::Result<Self> {
        let private_key = RsaPrivateKey::new(rng, key_len)?;
        Ok(Self { private_key })
    }

    pub fn decrypt<T: AsRef<[u8]>>(&mut self, msg: T) -> anyhow::Result<Vec<u8>> {
        self.decrypt_with_padding(msg, Pkcs1v15Encrypt)
    }
    pub fn decrypt_with_padding<T: AsRef<[u8]>, P: PaddingScheme>(
        &mut self,
        msg: T,
        padding: P,
    ) -> anyhow::Result<Vec<u8>> {
        let dec = B64_ENGINE.decode(msg)?;
        let result = self.private_key.decrypt(padding, dec.as_ref())?;
        Ok(result)
    }

    pub fn to_public_key(&self) -> ZotPublicKey {
        ZotPublicKey::init(self)
    }

    pub fn serialize(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(&self.private_key)?)
    }
    pub fn deserialize(serialized: &str) -> anyhow::Result<Self> {
        let private_key = serde_json::from_str(serialized)?;
        Ok(Self { private_key })
    }
}

impl TryFrom<&str> for ZotPrivateKey {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let private_key = Self::deserialize(value)?;
        Ok(private_key)
    }
}

impl TryInto<String> for ZotPrivateKey {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<String, Self::Error> {
        let serialized = self.serialize()?;
        Ok(serialized)
    }
}
