use protocols::encryption::encryption_service::verify_cert;
use openssl::x509::X509;
use openssl::pkey::PKey;

#[test]
#[allow(unused_doc_comments)]
fn test_check_cert_tls() {
    let ca = include_bytes!("../../../agents/ca.cert");
    let agent1 = include_bytes!("../../../agents/agent1.crt");
    assert!(verify_cert(agent1, ca, b"agent=1").is_ok(), "not verified");
}

#[test]
#[allow(unused_doc_comments)]
fn test_encrypt_decrypt() {
    let senderCert = include_bytes!("../../../agents/agent1.crt");
    let senderCert = X509::from_pem(senderCert).unwrap();

    let senderPriv = include_bytes!("../../../agents/agent1.key");
    let senderPriv = PKey::private_key_from_pem(senderPriv).unwrap().ec_key().unwrap();



    let receiverCert = include_bytes!("../../../agents/agent2.crt");
    let receiverCert = X509::from_pem(receiverCert).unwrap();

    let receiverPriv = include_bytes!("../../../agents/agent2.key");
    let receiverPriv = PKey::private_key_from_pem(receiverPriv).unwrap().ec_key().unwrap();

    let message: &[u8] = &[0,1,2,3,4];



}
