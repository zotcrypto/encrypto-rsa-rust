![Visitor Badge](https://visitor-badge.laobi.icu/badge?page_id=encrypto-rsa)
![Crates Badge](https://img.shields.io/crates/v/encrypto_rsa)
![Crates Downloads](https://img.shields.io/crates/d/encrypto_rsa)

# About Project

End to End NO STD, WASM supported, platform independent RSA encryption and decryption library for High Level Usage

| Icon |           Item            |
| :--: | :-----------------------: |
|  🥳  | [**Upcoming**](#Upcoming) |
|  ⚖️  |  [**License**](#License)  |

# Usage (rust)

## Implementation

### Cargo

```shell
cargo add encrypto_rsa
```

## RSA

### Documentation will be published soon at our [website](https://www.ssdd.dev/zot/crypto/rsa/rust)

## You can try:

```rust
use encrypto_rsa::keystore::EncryptoRSA;
fn main() {
    use encrypto_rsa::EncryptoRSA;
    let mut key_store = EncryptoRSA::init(2048).unwrap();
    let msg = "Alo";
    let encrypted = key_store.encrypt(msg).unwrap();
    let decrypted = key_store.decrypt(&encrypted).unwrap();
    assert_eq!(msg.as_bytes(), decrypted.as_slice());
}
```

### Please raise an issue [here](https://github.com/zotcrypto/encrypto-rsa-rust/issues) for bug/feature report or documentation error

## Upcoming

| Supported Languages | Status |
| ------------------- | ------ |
| Flutter             | WIP    |
| Java                | WIP    |
| JavaScript          | WIP    |

- Amazing encrypto with prevention against man in the middle attacks and AES-CBC with RSA key exchange for multiple language

## License

### Click [here](https://github.com/ssddcodes/stunning-encryptio/blob/encrypto/LICENSE.md)
