use dep::biguint::{BigUint56, MAX_BYTES};
use dep::std::println;

fn verify_sha256_pkcs1v15(msg_hash: [u8; 32], sig: BigUint56, pubkey_e: BigUint56, pubkey_n: BigUint56) -> bool {
    println("Part 1: Generate signature^e mod N to get PaddedSHA256Hash(msg)");
    println("...");
    println("...");
    println("...");
    let padded_sha256_hash = sig.powmod(pubkey_e, pubkey_n);

    println("Part 2: Compare (signature ** e) mod N to msg_hash");
    println("PaddedSHA256Hash(msg) = Sha256(msg) + Prefix + 00 + PS + 01 + 00 + padding");
    println("...");
    println("...");
    println("...");
    compare_signature_sha256(padded_sha256_hash.to_bytes(), msg_hash, sig.to_bytes())
}

// Compares MAX_BYTES byte padded sha256 hash to the 32 byte message hash returned from SHA256
fn compare_signature_sha256(padded_sha256_hash: [u8; MAX_BYTES], msg_hash: [u8; 32], sig: [u8; MAX_BYTES]) -> bool {
    println("Padded SHA256 Hash: ");
    println(padded_sha256_hash);
    println("Message Hash: ");
    println(msg_hash);

    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // TODO: what if sig ends with a 0?
    // Think it should be fine because little endian means highest index is most significant byte
    let mut sig_len = 0;
    let mut sum = 0;
    for i in 0..MAX_BYTES {
        sum += sig[MAX_BYTES - 1 - i];
        if sum == 0 {
            sig_len = MAX_BYTES - 1 - i;
        }
    }

    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    let hash_prefix: [u8; 19] = [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

    for i in 32..51 {
        assert(hash_prefix[i - 32] == padded_sha256_hash[i]);
    }

    assert(padded_sha256_hash[51] == 0);

    // Sub 32 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = sig_len - 54;
    for i in 52..MAX_BYTES {
        if i as u32 < 52 + ps_len as u32 {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i as u32 == 52 + ps_len as u32  {
            // Pad 0x00
            assert(padded_sha256_hash[i] == 1);
        } else if i as u32 == 53 + ps_len as u32 {
            // 0x00
            assert(padded_sha256_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha256_hash[i] == 0);
        }
    }

    true
}

#[test]
fn test_compare_signature_sha256_512() {
    println("Verifying that the padded SHA256 hash contains the message hash as well as the appropriate padding and prefixes");
    println("...");
    println("...");
    println("...");

    // 64 bytes
    let padded_sha256_hash: [u8; 259] = [
        // Padded hash
        209, 50, 135, 178, 4, 155, 190, 229, 228, 111, 61, 174, 8, 49, 48, 116, 90, 226, 77, 7, 111, 27, 19, 113, 154, 48, 138, 136, 138, 15, 230, 132, 32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49,
        48, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0,
        // Rest is padded with 0s until max bytes
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];
    // This is be, so need to reverse in the padding check
    let msg_hash: [u8; 32] = [
        132, 230, 15, 138, 136, 138, 48, 154, 113, 19, 27, 111, 7, 77, 226, 90, 116, 48, 49, 8, 174, 61, 111, 228, 229, 190, 155, 4, 178, 135, 50, 209
    ];
    // Values arent used in computation, 64 bytes + rest padding
    let sig: [u8; 259] = [
        1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 2, 3, 4, 5, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 2, 3, 4, 5, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 2, 3, 4, 5, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 2, 3, 4, 5, 1, 1, 1, 0, 1,
        // Rest is padded with 0s until max bytes
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    assert(compare_signature_sha256(padded_sha256_hash, msg_hash, sig));
}

#[test]
fn test_verify_sha256_pkcs1v15_512() {
    println("Testing verify_sha256_pkcs1v15 with inputs:");
    println("Original Message: 'About ready south environment second finally. Work agency determine chance mean serve.'");
    println("Signature: 576745224752088557605724579075396240836094784473063860932429343679901243092360596350370941870180683657680865188551095458429546150960618883576826751753989");
    println("e: 65537");
    println("N: 7451117485959741229136504235315630995445254998446480425768448033902713699576518667817925145617353711577597420279881950650483923658530991624401513418271573");
    println("...");
    println("...");
    println("...");

    let msg_hash = BigUint56 {
        limbs: [
            60503723948323480, 54161298035806000, 27012600088414088, 24217061042254220, 3153799981, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ]
    };

    let mut sha256_hash = [0 as u8; 32];
    for i in 0..32 {
        // Reverse
        sha256_hash[i] = msg_hash.to_bytes()[31 - i];
    }

    assert(verify_sha256_pkcs1v15(
        sha256_hash,
        BigUint56 {
            limbs: [
                55229751642955525, 3387357325282344, 55293647890923184, 39104415763957832, 1619665796174313, 58538917026121421, 42799083892223376, 55799955887110396, 864672920360232, 11,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0
            ]
        },
        BigUint56 {
            limbs: [
                65537, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0
            ]
        },
        BigUint56 {
            limbs: [
                58658486617058133, 60448007089510078, 38078312823104700, 21692380715596569, 47263115411407232, 21587213462559447, 635655787029941, 3458672493564279, 19225757176393417, 142,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0
            ]
        }
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
