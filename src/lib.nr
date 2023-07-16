mod Rsa {
    use dep::noir_bigint::{BigUint56};
    use dep::std::println;

    fn verify_sha256_pkcs1v15(msg: BigUint56, sig: BigUint56, pubkey_e: BigUint56, pubkey_n: BigUint56) -> bool {
        // TODO: implement
        // pubkey_e is usually set to 65537 from keygen

        println("TODO: implement Rsa::verify with args: msg, sig, pubkey");
        true
    }

    #[test]
    fn test_verify_sha256_pkcs1v15() {
        // TODO: Use real values to test
        assert(verify_sha256_pkcs1v15(
            BigUint56::from_bytes([2]),
            BigUint56::from_bytes([6]),
            BigUint56::from_bytes([65537]),
            BigUint56::from_bytes([14]),
        ));
    }

    // Background information:
    // (e, n) is the public key (e usually hardcoded to 65537)
    // (d, n) is the private key

    // To sign, we need to do sha256hash(msg)^d mod n
    // where n is part of the public key

    // To verify, we need to do signature^e mod n where e is
    // usually hardcoded to 65537 and compare sha256hash(msg) to output of
    // signature^e mod n they should be the same

    // d is part of the private key

    // In python, (pub_key, priv_key) = rsa.newkeys(512) will
    // generate a public and private key pair where the e = 65537
    // that we can use for our test cases
}
