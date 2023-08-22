use dep::biguint::{BigUint56, MAX_BYTES, NUM_LIMBS};
use dep::rsa::{verify_sha256_pkcs1v15};
use dep::std::hash::sha256;
use dep::std::println;

global BODY_HASH_BASE64_LENGTH: comptime Field = 44;
// Specific to the email itself
global EMAIL_HEADER_LENGTH: comptime Field = 177;
global EMAIL_BODY_LENGTH: comptime Field = 37;

fn main(
    email_header: [u8; EMAIL_HEADER_LENGTH],
    email_body: [u8; EMAIL_BODY_LENGTH],
    body_hash_idx: Field,
    dkim_sig: BigUint56,
    modulus: BigUint56
) {
    dkim_verify(
        email_header,
        email_body,
        body_hash_idx,
        dkim_sig,
        modulus
    );
}

fn dkim_verify(
    email_header: [u8; EMAIL_HEADER_LENGTH],
    email_body: [u8; EMAIL_BODY_LENGTH],
    body_hash_idx: Field,
    dkim_sig: BigUint56,
    modulus: BigUint56
) -> bool {
    // Hash body and assert matches the body hash
    let mut encoded_body_hash = [0 as u8; BODY_HASH_BASE64_LENGTH];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        encoded_body_hash[i] = email_header[body_hash_idx + i];
        println(encoded_body_hash[i]);
    }

    // Convert encoded body hash to base64
    let body_hash_decoded = bodyhash_base64_decode(encoded_body_hash);
    // Check that body hash matches
    let hashed_email_body = sha256(email_body);
    println(body_hash_decoded);
    println(hashed_email_body);
    assert(hashed_email_body == body_hash_decoded);

    // Check that dkim sig matches
    let hashed_email_header = sha256(email_header);
    
    // Email public exponent is 65537
    let pubkey_e = BigUint56 {
        limbs: [
            65537, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0
        ]
    };

    // Verify DKIM signature
    verify_sha256_pkcs1v15(
        hashed_email_header,
        dkim_sig,
        pubkey_e,
        modulus
    )
}

// TODO: this function can be moved into a separate library
fn base64_lookup(input: u8) -> u8 {
    // A-Z: 65-90
    if input >= 65 & input <= 90 {
        input - 65
    } else if input >= 97 & input <= 122 {
        // a-z: 97-122
        input - 71
    } else if input >= 48 & input <= 57 {
        // 0-9: 48-57
        input + 4
    } else if input == 43 {
        // +
        62
    } else if input == 47 {
        // /
        63
    } else {
        // =
        0
    }
}

// TODO: this function can be generalized and moved into a separate base64-decode lib
fn bodyhash_base64_decode(encoded: [u8; BODY_HASH_BASE64_LENGTH]) -> [u8; 32] {
    let mut total_bits = [0 as u1; BODY_HASH_BASE64_LENGTH * 6];
    for i in 0..BODY_HASH_BASE64_LENGTH {
        let translate = base64_lookup(encoded[i] as u8);
        // Store as big endian
        let translate_bits = (translate as Field).to_be_bits(6);
        for j in 0..6 {
            total_bits[i * 6 + j] = translate_bits[j];
        }
    }

    // Since we're returning the SHA256 hash, only need first 32 bytes (=256 bits)
    let mut output = [0 as u8; 32];
    for i in 0..32 {
        for j in 0..8 {
            // Convert from big endian back to little endian
            output[i] |= (total_bits[i * 8 + j] as u8) << (7 - j) as u8;
        }
    }

    output
}

#[test]
fn test_bodyhash_base64_decode1() {
    // Raw bh: GxMlgwLiypnVrE2C0Sf4yzhcWTkAhSZ5+WERhKhXtlU=
    // Translated directly to ASCII
    let res = bodyhash_base64_decode([
        71, 120, 77, 108, 103,
        119, 76, 105, 121, 112, 
        110, 86, 114, 69, 50,
        67, 48, 83, 102, 52,
        121, 122, 104, 99, 87,
        84, 107, 65, 104, 83,
        90, 53, 43, 87, 69,
        82, 104, 75, 104, 88,
        116, 108, 85, 61
    ]);
    let expected_res = [
        27, 19, 37, 131, 2, 226, 202, 153, 213, 172,
        77, 130, 209, 39, 248, 203, 56, 92, 89, 57,
        0, 133, 38, 121, 249, 97, 17, 132, 168, 87,
        182, 85
    ];
    for i in 0..res.len() {
        assert(res[i] == expected_res[i]);
    }
}

// #[test]
// // TODO: this doesnt work yet because we assume a 2048 bit modulus. We need to generate an email with 1024 modulus instead to avoid
// // `Error: Trying to call acir_proofs_get_total_circuit_size resulted in an error`
// fn test_main() {
//     // Using the utils/test_email.eml provided. Copied from halo2-zk-email
//     // https://github.com/zkemail/halo2-zk-email/blob/main/test_data/test_email1.eml

//     // Header is 177 bytes
//     let email_header = [
//         102, 114, 111, 109, 58, 97, 108, 105, 99, 101, 64, 122, 107, 101, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 100, 107, 105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 100, 61, 122, 107, 101, 109, 97, 105, 108, 46, 99, 111, 109, 59, 32, 115, 61, 100, 101, 102, 97, 117, 108, 116, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101, 100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 104, 61, 102, 114, 111, 109, 59, 32, 116, 61, 49, 54, 57, 50, 53, 55, 55, 50, 51, 49, 59, 32, 98, 104, 61, 80, 72, 73, 114, 87, 101, 121, 90, 114, 71, 43, 68, 53, 116, 106, 56, 81, 97, 115, 83, 67, 111, 115, 116, 53, 65, 108, 104, 48, 104, 115, 48, 100, 90, 90, 103, 111, 80, 108, 99, 72, 74, 119, 61, 59, 32, 98, 61, 59
//     ];
//     // Body is 37 bytes
//     let email_body = [
//         101, 109, 97, 105, 108, 32, 119, 97, 115, 32, 109, 101, 97, 110, 116, 32, 102, 111, 114, 32, 64, 122, 107, 101, 109, 97, 105, 108, 118, 101, 114, 105, 102, 121, 46, 13, 10
//     ];
//     let body_hash_idx = 128;
//     let dkim_sig = BigUint56 {
//         limbs: [
//             1971263576699707, 70352567725838059, 40709558662682475, 11662000118852963, 48386231714581344, 72050608680104119, 47315617837820762, 36149871541685510, 68697699104177899, 22518111138906483, 25960732248206839, 68775372695140819, 108881714466252, 14317838930614204, 70237716281324022, 60742891256808427, 41106657840284820, 2786276574906080, 46527, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
//         ]
//     };
//     let modulus = BigUint56 {
//         limbs: [
//             64717530282171833, 69150871281776410, 60041593704713005, 62059607045060896, 41915361572098361, 60220677223092673, 19622150207448220, 55122224380365447, 10822631164052092, 30937858787163122, 26930722274195578, 7404292287341483, 16504591447295476, 10928064986638097, 38823521225840931, 16606398534435237, 28481438878270370, 39212269632441874, 50891, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
//         ]
//     };

//     main(
//         email_header,
//         email_body,
//         body_hash_idx,
//         dkim_sig,
//         modulus
//     );
// }