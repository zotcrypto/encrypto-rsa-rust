use crate::privkey::ZotPrivateKey;
use crate::pubkey::ZotPublicKey;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptoRSA {
    private_key: ZotPrivateKey,
    public_key: ZotPublicKey,
}

impl EncryptoRSA {
    pub fn init(key_len: usize) -> anyhow::Result<Self> {
        let private_key = ZotPrivateKey::init(key_len)?;
        let public_key = private_key.to_public_key();
        Ok(Self {
            private_key,
            public_key,
        })
    }
    pub fn encrypt<T: AsRef<[u8]>>(&mut self, msg: T) -> anyhow::Result<String> {
        self.public_key.encrypt(msg)
    }
    pub fn decrypt<T: AsRef<[u8]>>(&mut self, msg: T) -> anyhow::Result<Vec<u8>> {
        self.private_key.decrypt(msg)
    }
    pub fn pub_key(&self) -> &ZotPublicKey {
        &self.public_key
    }
    pub fn serialize(&self) -> anyhow::Result<String> {
        self.private_key.serialize()
    }
    pub fn deserialize(serialized: &str) -> anyhow::Result<Self> {
        let private_key = ZotPrivateKey::deserialize(serialized)?;
        let public_key = private_key.to_public_key();
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

impl TryFrom<&str> for EncryptoRSA {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let key_store = Self::deserialize(value)?;
        Ok(key_store)
    }
}
