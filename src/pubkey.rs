use alloc::string::String;

use base64::Engine;
use rand::rngs::OsRng;
use rsa::traits::PaddingScheme;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

use crate::privkey::ZotPrivateKey;
use crate::B64_ENGINE;

/// Struct to store public key
#[derive(Debug, Clone)]
pub struct ZotPublicKey {
    public_key: RsaPublicKey,
    rng: OsRng,
}

impl PartialEq for ZotPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl ZotPublicKey {
    pub fn init(priv_key: &ZotPrivateKey) -> Self {
        Self {
            public_key: priv_key.private_key.to_public_key(),
            rng: OsRng,
        }
    }
    pub fn encrypt<T: AsRef<[u8]>>(&mut self, msg: T) -> anyhow::Result<String> {
        self.encrypt_with_padding(msg, Pkcs1v15Encrypt)
    }
    pub fn encrypt_with_padding<T: AsRef<[u8]>, P: PaddingScheme>(
        &mut self,
        msg: T,
        padding: P,
    ) -> anyhow::Result<String> {
        let enc = self
            .public_key
            .encrypt(&mut self.rng, padding, msg.as_ref())?;
        Ok(B64_ENGINE.encode(enc))
    }
    pub fn serialize(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string(&self.public_key)?)
    }
    pub fn deserialize(serialized: &str) -> anyhow::Result<Self> {
        let public_key = serde_json::from_str(serialized)?;
        Ok(Self {
            public_key,
            rng: OsRng,
        })
    }
}
