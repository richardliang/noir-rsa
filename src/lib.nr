mod Rsa {
    use dep::noir_bigint::{BigUint56};
    use dep::std::println;

    fn verify_sha256_pkcs1v15(msg: BigUint56, sig: BigUint56, pubkey: BigUint56) -> bool {
        // TODO: implement
        println("TODO: implement Rsa::verify with args: msg, sig, pubkey");
        true
    }

    #[test]
    fn test_verify_sha256_pkcs1v15() {
        assert(verify_sha256_pkcs1v15(
            BigUint56::from_bytes([1,2,3]),
            BigUint56::from_bytes([1,2,3]),
            BigUint56::from_bytes([1,2,3]),
        ));
    }
}
