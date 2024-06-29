mod tests {
    use encrypto_rsa::keystore::EncryptoRSA;

    #[test]
    fn test_key_store() {
        let mut key_store = EncryptoRSA::init(2048).unwrap();
        let msg = "Hello, world!";
        let encrypted = key_store.encrypt(msg).unwrap();
        let decrypted = key_store.decrypt(&encrypted).unwrap();
        assert_eq!(msg.as_bytes(), decrypted.as_slice());
    }
    #[test]
    fn test_serde_key_store() {
        let key_store = EncryptoRSA::init(2048).unwrap();
        let serialized = key_store.serialize().unwrap();
        let deserialized = EncryptoRSA::try_from(serialized.as_str()).unwrap();
        assert_eq!(key_store, deserialized);
    }
}
