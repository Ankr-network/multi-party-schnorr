
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use openssl::ec::EcKey;
use openssl_sys::EC_KEY;
use Error;


pub fn encrypt(pKey : &EcKey<EC_KEY>, _rec: &X509, _message : &Vec<u8>) -> Result<Vec<u8>,Error> {
     Ok(vec![0,1])
}

pub fn decrypt(pKey : &EcKey<EC_KEY>, _sender: &X509, _cipher: &Vec<u8>) -> Result<Vec<u8>,Error> {
    Ok(vec![0,1])
}

pub fn verify_cert(cert: &[u8], ca: &[u8], common_name: &[u8]) -> Result<bool, String> {
    let cert = X509::from_pem(cert).unwrap();

    let key = cert.public_key();

    if key.is_err() {
        return Err("has no valid ec key".parse().unwrap());
    }

    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();

    if common_name.ne(cn.data().as_slice()) {
        return Err("common name is not verified".parse().unwrap());
    }
    let ca = X509::from_pem(ca).unwrap();

    let chain = Stack::new().unwrap();
    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();

    let is_ok = context
        .init(&store, &cert, &chain, |c| c.verify_cert()).is_ok();
    if is_ok {
        return Ok(true);
    } else {
        return Err("ca does not issue this cert".parse().unwrap());
    }
}
