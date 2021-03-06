#![allow(non_snake_case)]

use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use openssl::ec::{EcKey, EcGroup, EcPoint, PointConversionForm};
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use rand::{thread_rng, Rng};
use openssl::pkey::Private;
use openssl::bn::{BigNumContext, BigNum};
use openssl::sha::sha256;
use std::ops::{Mul, Add};

/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 16;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];


pub fn encrypt(priv_a: &EcKey<Private>, sender_a: &X509, rec_b: &X509, message : &Vec<u8>) ->Option<EncryptedMessage> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let keyR = EcKey::generate(&group).unwrap();
    let keyS = EcKey::generate(&group).unwrap();

    let Sp = keyS.public_key();
    let S = Sp.to_bytes(&group,PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    let B = rec_b.public_key().unwrap();
    let B = B.ec_key().unwrap();
    let B = B.public_key();

    let mut Rprime = EcPoint::new(&group).unwrap();
    if Rprime.mul(&group,B,keyR.private_key(),&mut ctx).is_err() {
        return  None;
    }

    let R = Rprime.as_ref().to_bytes(&group,PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    let key = sha256(R.as_slice());
    let c = aes_encrypt(&key,message);
    if c.is_none() {
        return None
    }
    let c = c.unwrap();

    let mut temp :Vec<u8> = vec![];
    temp.extend(&S);

    let cn = sender_a.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap();
    temp.extend_from_slice(cn.data().as_slice());
    temp.extend(&c);
    let e = sha256(temp.as_slice());
    let e = BigNum::from_slice(&e[..]).unwrap();
    let e = e.as_ref();


    let z = e.mul(priv_a.private_key());
    let z = z.as_ref();
    let z = z.add(keyS.private_key());
    let z= z.as_ref();


    let point = keyR.public_key();
    let Rb = point.to_bytes(&group,PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    Some(EncryptedMessage{
        R: Rb,
        C: c,
        E:e.to_vec(),
        Z: z.to_vec(),
    })
}

#[derive( Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    R: Vec<u8>,
    C: Vec<u8>,
    E: Vec<u8>,
    Z: Vec<u8>
}

impl EncryptedMessage {
    pub fn getR(&self, group: &EcGroup) -> EcPoint{
        let mut ctx = BigNumContext::new().unwrap();
        EcPoint::from_bytes(&group, &self.R, &mut ctx).unwrap()
    }
    pub fn getE(&self) -> BigNum{
        BigNum::from_slice(self.E.as_slice()).unwrap()
    }
    pub fn getZ(&self) -> BigNum{
        BigNum::from_slice(self.Z.as_slice()).unwrap()
    }
}

pub fn decrypt(priv_b: &EcKey<Private>, sender_a: &X509, cipher: &EncryptedMessage) -> Option<Vec<u8>> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let A = sender_a.public_key().unwrap();
    let A = A.ec_key().unwrap();

    // check first e == H(zG − eA, A, C)
    let mut S = EcPoint::new(&group).unwrap();
    if S.mul_generator(&group,cipher.getZ().as_ref(),&mut ctx).is_err() {
        return None;
    }

    let mut eA = EcPoint::new(&group).unwrap();
    if eA.mul(&group, A.public_key(), cipher.getE().as_ref(), &mut ctx).is_err() {
        return None;
    }
    if eA.invert(&group,&mut ctx).is_err() {
        return None;
    }

    let mut S2 = EcPoint::new(&group).unwrap();
    if S2.add(&group,&S, eA.as_ref(), &mut ctx).is_err() {
        return None;
    }

    let str = S2.to_bytes(&group,PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    let mut temp :Vec<u8> = vec![];
    temp.extend(&str);

    let cn = sender_a.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap();
    temp.extend_from_slice(cn.data().as_slice());
    temp.extend(&cipher.C);
    if sha256(temp.as_slice()).to_vec() != cipher.E {
        return None;
    }
    //now decrypt the message
    let mut Rprime = EcPoint::new(&group).unwrap();
    if Rprime.mul(&group,cipher.getR(&group).as_ref(), priv_b.private_key(),&mut ctx) .is_err() {
        return None;
    }
    let rawKey = Rprime.as_ref().to_bytes(&group,PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    let key = sha256(rawKey.as_slice());
    aes_decrypt(&key,&cipher.C)
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

    if context
        .init(&store, &cert, &chain, |c| c.verify_cert()).is_ok() {
        return Ok(true);
    } else {
        return Err("ca does not issue this cert".parse().unwrap());
    }
}

/// AES-256-GCM encryption wrapper
pub fn aes_encrypt(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let cipher = Cipher::aes_256_gcm();

    let mut iv = [0u8; AES_IV_LENGTH];
    thread_rng().fill(&mut iv);

    let mut tag = [0u8; AES_TAG_LENGTH];

    if let Ok(encrypted) = encrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, msg, &mut tag) {
        let mut output = Vec::with_capacity(AES_IV_PLUS_TAG_LENGTH + encrypted.len());
        output.extend(&iv);
        output.extend(&tag);
        output.extend(encrypted);

        Some(output)
    } else {
        None
    }
}

/// AES-256-GCM decryption wrapper
pub fn aes_decrypt(key: &[u8], encrypted_msg: &[u8]) -> Option<Vec<u8>> {
    if encrypted_msg.len() < AES_IV_PLUS_TAG_LENGTH {
        return None;
    }

    let cipher = Cipher::aes_256_gcm();

    let iv = &encrypted_msg[..AES_IV_LENGTH];
    let tag = &encrypted_msg[AES_IV_LENGTH..AES_IV_PLUS_TAG_LENGTH];
    let encrypted = &encrypted_msg[AES_IV_PLUS_TAG_LENGTH..];

    decrypt_aead(cipher, key, Some(&iv), &EMPTY_BYTES, encrypted, tag).ok()
}
