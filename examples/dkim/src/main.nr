use dep::biguint::{BigUint56, MAX_BYTES, NUM_LIMBS};
use dep::rsa::{verify_sha256_pkcs1v15};
use dep::std::hash::sha256;
use dep::std::println;

global BODY_HASH_BASE64_LENGTH: comptime Field = 44;
// Specific to the email itself
global EMAIL_HEADER_LENGTH: comptime Field = 489;
global EMAIL_BODY_LENGTH: comptime Field = 327;

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

#[test]
// TODO: this doesnt work yet because we assume a 2048 bit modulus. We need to generate an email with 1024 modulus instead to avoid
// `Error: Trying to call acir_proofs_get_total_circuit_size resulted in an error`
fn test_main() {
    // Using the utils/test_email.eml provided. Copied from halo2-zk-email
    // https://github.com/zkemail/halo2-zk-email/blob/main/test_data/test_email1.eml

    // Header is 489 bytes
    let email_header = [
        116, 111, 58, 101, 109, 97, 105, 108, 119, 97, 108, 108, 101, 116, 46, 114, 101, 108, 97, 121, 101, 114, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 115, 117, 98, 106, 101, 99, 116, 58, 69, 109, 97, 105, 108, 32, 87, 97, 108, 108, 101, 116, 32, 77, 97, 110, 105, 112, 117, 108, 97, 116, 105, 111, 110, 32, 73, 68, 32, 49, 13, 10, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 60, 67, 65, 74, 55, 89, 54, 106, 100, 119, 71, 97, 71, 80, 77, 109, 48, 87, 98, 52, 116, 116, 95, 65, 122, 107, 114, 102, 71, 114, 67, 61, 71, 50, 88, 61, 90, 52, 105, 80, 83, 116, 115, 61, 77, 80, 87, 114, 70, 85, 43, 81, 64, 109, 97, 105, 108, 46, 103, 109, 97, 105, 108, 46, 99, 111, 109, 62, 13, 10, 100, 97, 116, 101, 58, 77, 111, 110, 44, 32, 49, 55, 32, 65, 112, 114, 32, 50, 48, 50, 51, 32, 49, 56, 58, 50, 56, 58, 51, 54, 32, 43, 48, 57, 48, 48, 13, 10, 102, 114, 111, 109, 58, 115, 117, 101, 103, 97, 109, 105, 115, 111, 114, 97, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 48, 13, 10, 100, 107, 105, 109, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 58, 118, 61, 49, 59, 32, 97, 61, 114, 115, 97, 45, 115, 104, 97, 50, 53, 54, 59, 32, 99, 61, 114, 101, 108, 97, 120, 101, 100, 47, 114, 101, 108, 97, 120, 101, 100, 59, 32, 100, 61, 103, 109, 97, 105, 108, 46, 99, 111, 109, 59, 32, 115, 61, 50, 48, 50, 50, 49, 50, 48, 56, 59, 32, 116, 61, 49, 54, 56, 49, 55, 50, 51, 55, 50, 55, 59, 32, 120, 61, 49, 54, 56, 52, 51, 49, 53, 55, 50, 55, 59, 32, 104, 61, 116, 111, 58, 115, 117, 98, 106, 101, 99, 116, 58, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 100, 97, 116, 101, 58, 102, 114, 111, 109, 58, 109, 105, 109, 101, 45, 118, 101, 114, 115, 105, 111, 110, 58, 102, 114, 111, 109, 58, 116, 111, 58, 99, 99, 58, 115, 117, 98, 106, 101, 99, 116, 32, 58, 100, 97, 116, 101, 58, 109, 101, 115, 115, 97, 103, 101, 45, 105, 100, 58, 114, 101, 112, 108, 121, 45, 116, 111, 59, 32, 98, 104, 61, 71, 120, 77, 108, 103, 119, 76, 105, 121, 112, 110, 86, 114, 69, 50, 67, 48, 83, 102, 52, 121, 122, 104, 99, 87, 84, 107, 65, 104, 83, 90, 53, 43, 87, 69, 82, 104, 75, 104, 88, 116, 108, 85, 61, 59, 32, 98, 61
    ];
    // Body is 327 bytes
    let email_body = [
        45, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 53, 101, 51, 56, 98, 101, 48, 53, 102, 57, 56, 52, 100, 49, 51, 55, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 116, 101, 120, 116, 47, 112, 108, 97, 105, 110, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 85, 84, 70, 45, 56, 34, 13, 10, 13, 10, 84, 114, 97, 110, 115, 102, 101, 114, 32, 48, 46, 50, 32, 69, 84, 72, 32, 116, 111, 32, 97, 108, 105, 99, 101, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 13, 10, 13, 10, 45, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 53, 101, 51, 56, 98, 101, 48, 53, 102, 57, 56, 52, 100, 49, 51, 55, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 116, 101, 120, 116, 47, 104, 116, 109, 108, 59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 34, 85, 84, 70, 45, 56, 34, 13, 10, 13, 10, 60, 100, 105, 118, 32, 100, 105, 114, 61, 34, 108, 116, 114, 34, 62, 84, 114, 97, 110, 115, 102, 101, 114, 32, 48, 46, 50, 32, 69, 84, 72, 32, 116, 111, 32, 60, 97, 32, 104, 114, 101, 102, 61, 34, 109, 97, 105, 108, 116, 111, 58, 97, 108, 105, 99, 101, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 34, 62, 97, 108, 105, 99, 101, 64, 103, 109, 97, 105, 108, 46, 99, 111, 109, 60, 47, 97, 62, 60, 98, 114, 62, 60, 47, 100, 105, 118, 62, 13, 10, 13, 10, 45, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 53, 101, 51, 56, 98, 101, 48, 53, 102, 57, 56, 52, 100, 49, 51, 55, 45, 45, 13, 10
    ];
    let body_hash_idx = 441;
    let dkim_sig = BigUint56 {
        limbs: [
            45619522914666379, 28459669327603991, 50534380704976867, 46996177047403019, 67815720456919762, 26293997329446001, 18339544583877216, 40976263259580649, 57510083422638066, 70025063873538840,
            48896823863012624, 38244703211991706, 47703355113605671, 28943196160021994, 48436875215535704, 40427621059998127, 32916633942274277, 52275052847282258, 12388507241034663, 55146724013014824,
            25312962575007323, 68791526269676129, 24734548644426095, 7387850688688707, 59587136790746765, 70038378165885043, 1544936236188731, 47930498381796293, 54226120988751710, 66449003780718557,
            5694758949366460, 24004218205365007, 58665175680260834, 21236528083237512, 40954948274574591, 19224042090112, 373302452
        ]
    };
    let modulus = BigUint56 {
        limbs: [
            70390354775186703, 19112351779994520, 63529869756605803, 38706933194767847, 2888627299440016, 24966132775576976, 5320885126388138, 20311591186706880, 12545128305449977, 66086939926724963, 14139759123727145, 71036415068312252, 68238508491614065, 43979995608367605, 31846974603723814, 31429172160157180, 11866440102402055, 30202027004957317, 44659589484300814, 2431668247990080, 7556193521717222, 35585835362086013, 45652641078475618, 68810227625532069, 5068239286832060, 40952715462784925, 10607956749236202, 68838030775372434, 25870438081686096, 6313366753543099, 24305069360203975, 65235091882220580, 31612535141596069, 27990844099616611, 23053756024259589, 41676013670109587, 3013952480
        ]
    };

    main(
        email_header,
        email_body,
        body_hash_idx,
        dkim_sig,
        modulus
    );
}