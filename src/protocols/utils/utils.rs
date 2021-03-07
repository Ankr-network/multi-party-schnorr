use openssl::x509::{X509, X509StoreContext};
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::ec::EcKey;
use openssl::nid::Nid;
use std::str;
use openssl::x509::store::X509StoreBuilder;
use openssl::stack::Stack;

pub fn load_cert(binary : &[u8]) ->Result<X509,ErrorStack>{
    X509::from_pem(binary)
}

pub fn load_private_key(binary : &[u8]) ->Result<EcKey<Private>,ErrorStack>{
  PKey::private_key_from_pem(binary).unwrap().ec_key()
}
pub fn get_player_id( cert: & X509) -> usize {
    let cn = cert.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap();
    let data = cn.data().as_slice().clone();
    let data = str::from_utf8(&data[6..data.len()]).unwrap();

    usize::from_str_radix(data, 10).unwrap()
}

pub fn verify_cert_with_binary(cert: &[u8], ca: &[u8], common_name: &[u8]) -> Result<bool, String> {
    let cert = X509::from_pem(cert).unwrap();
    let key = cert.public_key();

    if key.is_err() {
        return Err("has no valid ec key".parse().unwrap());
    }
    let ca = X509::from_pem(ca).unwrap();

    verify_cert_with_commonname(&cert, &ca, common_name)
}
pub fn verify_cert_with_commonname(cert: &X509, ca: &X509, common_name: &[u8]) -> Result<bool, String> {
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();

    if common_name.ne(cn.data().as_slice()) {
        return Err("common name is not verified".parse().unwrap());
    }
    verify_cert(cert,ca)
}

pub fn verify_cert(cert: &X509, ca: &X509) -> Result<bool, String> {
    let chain = Stack::new().unwrap();
    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca.clone()).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();

    if context
        .init(&store, &cert, &chain, |c| c.verify_cert()).is_ok() {
        return Ok(true);
    } else {
        return Err("ca does not issue this cert".parse().unwrap());
    }
}
