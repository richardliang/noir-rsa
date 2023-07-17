
mod Rsa {
    global MAX_BYTES: comptime Field = 70; // TODO: Set equal to the same as the bigint library (70 for 512 key bit)

    use dep::noir_bigint::{BigUint56};
    use dep::std::println;

    fn verify_sha256_pkcs1v15(msg_hash: BigUint56, sig: BigUint56, pubkey_e: BigUint56, pubkey_n: BigUint56) -> bool {
        // Part 1: Generate signature^e mod n to get PaddedSHA256Hash(msg)
        let padded_sha256_hash = BigUint56 { limbs: [
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
            123 as u56,
        ] };

        // Part 2: Compare signature^e mod n to PaddedSha256hash(msg)
        // PaddedSHA256Hash(msg) = 00 + 01 + PS + 00 + Prefix + Sha256(msg)
        compare_signature_hash(padded_sha256_hash.to_bytes(), msg_hash.to_bytes())
    }

    fn compare_signature_hash(padded_sha256_hash: [u8; MAX_BYTES], msg_hash: [u8; MAX_BYTES]) -> bool {
        for i in 0..32 {
            assert(padded_sha256_hash[i] == msg_hash[i]);
        }

        let hash_prefix: [u8; 19] = [48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32];

        for i in 32..51 {
            assert(hash_prefix[i - 32] == padded_sha256_hash[i]);
        }

        assert(padded_sha256_hash[51] == 0);

        for i in 52..62 {
            assert(padded_sha256_hash[i] == 255);
        }

        assert(padded_sha256_hash[62] == 1);
        assert(padded_sha256_hash[63] == 0);

        true
    }

    #[test]
    fn test_compare_signature_hash() {
        let padded_sha256_hash: [u8; MAX_BYTES] = [209, 50, 135, 178, 4, 155, 190, 229, 228, 111, 61, 174, 8, 49, 48, 116, 90, 226, 77, 7, 111, 27, 19, 113, 154, 48, 138, 136, 138, 15, 230, 132, 32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0];
        let msg_hash: [u8; MAX_BYTES] = [209, 50, 135, 178, 4, 155, 190, 229, 228, 111, 61, 174, 8, 49, 48, 116, 90, 226, 77, 7, 111, 27, 19, 113, 154, 48, 138, 136, 138, 15, 230, 132, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert(compare_signature_hash(padded_sha256_hash, msg_hash));
    }

    #[test]
    fn test_verify_sha256_pkcs1v15() {
        // TODO: Use real values to test

        assert(true);
        // assert(verify_sha256_pkcs1v15(
        //     BigUint56::from_bytes([2]),
        //     BigUint56::from_bytes([6]),
        //     BigUint56::from_bytes([65537]),
        //     BigUint56::from_bytes([14]),
        // ));
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
