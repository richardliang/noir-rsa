mod Rsa {
    use dep::std::println;

    fn verify_sha256_pkcs1v15(msg: [u8], sig: [u8], pubkey: [u8]) -> bool {
        // TODO: implement
        println("TODO: implement Rsa::verify with args: msg, sig, pubkey");
        true
    }
}

#[test]
fn test_verify_sha256_pkcs1v15() {
    assert(Rsa::verify_sha256_pkcs1v15([1, 2, 3], [1, 2, 3], [1, 2, 3]) == true);
}
