use dep::std::println;

struct Rsa {

}

impl Rsa {
    fn verify(msg: [u8], sig: [u8], pubkey: [u8]) -> bool {
        // TODO: implement
        println("TODO: implement Rsa::verify with args: msg, sig, pubkey");
        true
    }
}

#[test]
fn test_verify() {
    assert(Rsa::verify([1, 2, 3], [1, 2, 3], [1, 2, 3]) == true);
}
