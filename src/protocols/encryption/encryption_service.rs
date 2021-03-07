#![allow(non_snake_case)]

use std::ops::{ Mul};

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::nid::Nid;
use openssl::pkey::Private;
use openssl::sha::sha256;
use openssl::stack::Stack;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use rand::{Rng, thread_rng};

/// AES IV/nonce length
pub const AES_IV_LENGTH: usize = 16;
/// AES tag length
pub const AES_TAG_LENGTH: usize = 16;
/// AES IV + tag length
pub const AES_IV_PLUS_TAG_LENGTH: usize = AES_IV_LENGTH + AES_TAG_LENGTH;
/// Empty bytes array
pub const EMPTY_BYTES: [u8; 0] = [];


pub fn encrypt(priv_a: &EcKey<Private>, sender_a: &X509, rec_b: &X509, message: &Vec<u8>) -> Option<EncryptedMessage> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let keyR = EcKey::generate(&group).unwrap();
    let keyS = EcKey::generate(&group).unwrap();

    let Sp = keyS.public_key();
    let S = Sp.to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    let B = rec_b.public_key().unwrap();
    let B = B.ec_key().unwrap();
    let B = B.public_key();

    let mut Rprime = EcPoint::new(&group).unwrap();
    if Rprime.mul(&group, B, keyR.private_key(), &mut ctx).is_err() {
        return None;
    }

    let R = Rprime.as_ref().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    let key = sha256(R.as_slice());
    let c = aes_encrypt(&key, message);
    if c.is_none() {
        return None;
    }
    let c = c.unwrap();

    let mut temp: Vec<u8> = vec![];
    temp.extend(&S);

    let cn = sender_a.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap();
    temp.extend_from_slice(cn.data().as_slice());
    temp.extend(&c);
    let e = sha256(temp.as_slice());
    let e = BigNum::from_slice(&e[..]).unwrap();
    let e = e.as_ref();


    //z = e * a (A=aG)
    let ea = e.mul(priv_a.private_key());
    let mut z = BigNum::new().unwrap();

    let mut order = BigNum::new().unwrap();
    if group.order(&mut order, &mut ctx).is_err() {
        return None;
    }

    //z = e * a + s = ea + s mod order
    if z.mod_add(ea.as_ref(), keyS.private_key(), order.as_ref(), &mut ctx).is_err() {
        return  None;
    }
    let z = z.as_ref();
    let rG =  keyR.public_key().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    Some(EncryptedMessage {
        R: rG,
        C: c,
        E: e.to_vec(),
        Z: z.to_vec(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    R: Vec<u8>,
    C: Vec<u8>,
    E: Vec<u8>,
    Z: Vec<u8>,
}

impl EncryptedMessage {
    pub fn getR(&self, group: &EcGroup) -> EcPoint {
        let mut ctx = BigNumContext::new().unwrap();
        EcPoint::from_bytes(&group, &self.R, &mut ctx).unwrap()
    }
    pub fn getE(&self) -> BigNum {
        BigNum::from_slice(self.E.as_slice()).unwrap()
    }
    pub fn getZ(&self) -> BigNum {
        BigNum::from_slice(self.Z.as_slice()).unwrap()
    }
}

pub fn decrypt(priv_b: &EcKey<Private>, sender_a: &X509, cipher: &EncryptedMessage) -> Option<Vec<u8>> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    let A = sender_a.public_key().unwrap();
    let A = A.ec_key().unwrap();

    // check first e == H(zG − eA, A, C)
    let mut zG = EcPoint::new(&group).unwrap();
    if zG.mul_generator(&group, cipher.getZ().as_ref(), &mut ctx).is_err() {
        return None;
    }
    //eA = -e * A = -e*a*G
    let mut eA = EcPoint::new(&group).unwrap();
    if eA.mul(&group, A.public_key(), cipher.getE().as_ref(), &mut ctx).is_err() {
        return None;
    }
    if eA.invert(&group, &mut ctx).is_err() {
        return None;
    }
    // S= zG -e A = sG
    let mut S = EcPoint::new(&group).unwrap();
    if S.add(&group, &zG, eA.as_ref(), &mut ctx).is_err() {
        return None;
    }

    let str = S.to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    let mut temp: Vec<u8> = vec![];
    temp.extend(&str);

    let cn = sender_a.subject_name().entries_by_nid(Nid::COMMONNAME).next().unwrap();
    temp.extend_from_slice(cn.data().as_slice());
    temp.extend(&cipher.C);
    if sha256(temp.as_slice()).to_vec() != cipher.E {
        return None;
    }
    //now decrypt the message
    let mut Rprime = EcPoint::new(&group).unwrap();
    if Rprime.mul(&group, cipher.getR(&group).as_ref(), priv_b.private_key(), &mut ctx).is_err() {
        return None;
    }
    let rawKey = Rprime.as_ref().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx).unwrap();
    let key = sha256(rawKey.as_slice());
    aes_decrypt(&key, &cipher.C)
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
