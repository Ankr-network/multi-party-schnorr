
pub use rand::prelude::*;
pub use schnorrkel::*;

#[test]
#[allow(unused_doc_comments)]
fn test_schnorrkel() {
    let rng = rand::thread_rng();

    let keypair: Keypair = Keypair::generate_with(rng);
    let context = signing_context(b"test for scnor");

    let message: &[u8] = "This is batman uni message.".as_bytes();
    let signature: Signature = keypair.sign(context.bytes(message));
    assert!(keypair.verify(context.bytes(message), &signature).is_ok());

    use schnorrkel::PublicKey;
    let public_key: PublicKey = keypair.public;
    assert!(public_key.verify(context.bytes(message), &signature).is_ok());
}
