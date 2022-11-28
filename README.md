![Visitor Badge](https://visitor-badge.laobi.icu/badge?page_id=encrypto-rsa)
![Crates Badge](https://img.shields.io/crates/v/encrypto_rsa)
![Crates Downloads](https://img.shields.io/crates/d/encrypto_rsa)

# About Project
End to End encryption (RSA) for multiple languages (cross-platform) with [double encryption](https://www.ssdd.dev/ssdd/zot/crypto/posts/rsa#doubleenc) and [double decryption methods](https://www.ssdd.dev/ssdd/zot/crypto/posts/rsa#doubledec)

| Icon |             Item              |
|:----:|:-----------------------------:|
|  🥳  |   [**Upcoming**](#Upcoming)   |
|  ⚖️  |    [**License**](#License)    |
|  📝  | [**ChangeLog**](CHANGELOG.md) |

# Usage (rust)

## Implementation
### Cargo
`encrypto_rsa =` [latest](https://crates.io/crates/encrypto_rsa)


## RSA


### Documentation will be published soon at our [website](https://www.ssdd.dev/zot/crypto/rsa/rust)

## You can try:

```rust
        let mut x = Vec::new();

        let encrypto = EncryptoRSA::init(512);
        let encrypto1 = EncryptoRSA::init(512);
        let msg = b"abc".as_slice();

        let enc = encrypto.encrypt(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.decrypt(enc.as_bytes());
        x.push(dec);

        let enc = encrypto.encrypt_with_pkcsv1_15(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.decrypt_with_pkcsv1_15(enc.as_bytes());
        x.push(dec);

        let enc = encrypto.double_encrypt(msg, EncryptoRSA::desterilize_pub_key(encrypto1.get_sterilized_pub_key())).unwrap();
        let dec = encrypto1.double_decrypt(enc.as_bytes(), encrypto.get_public_key());
        x.push(dec);

        let enc = encrypto.double_encrypt_with_pkcsv1_15(msg, encrypto1.pbl.clone()).unwrap();
        let dec = encrypto1.double_decrypt_with_pkcsv1_15(enc, encrypto.pbl.clone());
        x.push(dec);

        for f in x.iter() {
            assert_eq!(&msg.to_vec(), f);
        }
```

### Please raise an issue [here](https://github.com/zotcrypto/encrypto-rsa-rust/issues) if the documentation isn't uploaded in long time

## Upcoming

| Supported Languages | Status                                                                                                    |
|---------------------|-----------------------------------------------------------------------------------------------------------|
| Flutter             | Completed and available [here](https://github.com/ssddcodes/stunning-encrypto/edit/encrypto/tree/flutter) |
| Java                | Completed and available [here](https://github.com/ssddcodes/stunning-encrypto/)                           |
| JavaScript          | Completed and available [here](https://github.com/ssddcodes/stunning-encrypto/edit/encrypto/tree/js)      |

* Amazing encrypto with prevention against man in the middle attacks and AES-CBC with RSA key exchange for multiple language

## License

### Click [here](https://github.com/ssddcodes/stunning-encryptio/blob/encrypto/LICENSE.md)
