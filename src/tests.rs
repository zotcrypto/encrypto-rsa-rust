mod tests {
    #[test]
    fn genkey() {
        // let privk = ZotPrivateKey::init(512);
        // let ec = privk.get_sharable_pub_key();
        // println!("{}",ec);
        // // let d = &privk.d;
        // let pk = privk.get_pub_key();
        // // let n = &privk.on;
        // // let e = modinv(d.to_bigint().unwrap(), n.to_bigint().unwrap()).unwrap();
        // let dc = ZotPrivateKey::decode_shared_pub_key(ec);
        // assert_eq!(dc.n, pk.n);
        // assert_eq!(dc.e, pk.e);
        // // assert_eq!(privk.pubkey.e, e);
        // let enc = privk.enc_priv("alo".as_bytes()).unwrap();
        // println!("{}",enc);
        // let dec = privk.dec_public(enc.as_bytes()).unwrap();
        // println!("{}", String::from_utf8(dec).unwrap());
        // println!("{:?}", Verification::is_prime(&num_primes::BigUint::from_bytes_le(&*privk.q.to_bytes_le())));
    }
}