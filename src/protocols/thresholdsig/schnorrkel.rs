#![allow(non_snake_case)]

use std::collections::HashMap;
use std::fmt::Debug;

pub use curv::arithmetic::traits::Converter;
pub use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
pub use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::*;
use openssl::x509::store::X509StoreBuilder;
use schnorrkel::{PublicKey, SIGNATURE_LENGTH};
use schnorrkel::context::{SigningContext, SigningTranscript};

#[allow(unused_doc_comments)]
use Error::{self, InvalidSig, InvalidSS};

pub(crate) type GE = curv::elliptic::curves::curve_ristretto::GE;
type FE = curv::elliptic::curves::curve_ristretto::FE;


pub fn verify_cert(cert: &[u8], ca: &[u8], commonName: &[u8]) -> Result<bool, String> {
    let cert = X509::from_pem(cert).unwrap();

    let key = cert.public_key();

    if key.is_err() {
        return Err("has no valid ec key".parse().unwrap());
    }

    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();

    if commonName.ne(cn.data().as_slice()) {
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
    }else {
        return Err("ca does not issue this cert".parse().unwrap());
    }
}


#[derive(Debug, Clone)]
pub struct DkrGen {
    pub session_id: String,
    pub player_id: usize,
    pub params: Parameters,
    pub players: HashMap<usize, Player>,
    pub poly: VerifiableSS<GE>,
    // real share
    pub shares: HashMap<usize, FE>,
    //simulated share
    pub simShares: HashMap<usize, FE>,
    pub simPoly: VerifiableSS<GE>,
    pub keyShare: FE,
    pub publicKey: GE,
}

impl Default for DkrGen {
    fn default() -> Self {
        DkrGen {
            session_id: "".to_string(),
            player_id: 0,
            params: Parameters::default(),
            players: Default::default(),
            poly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count: 0 }, commitments: vec![] },
            shares: Default::default(),
            simPoly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count: 0 }, commitments: vec![] },
            keyShare: FE::zero(),
            publicKey: GE::generator(),
            simShares: Default::default(),
        }
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Round1Message {
    sender_id: usize,
    session_id: String,
    ck: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Message {
    pub sender_id: usize,
    pub receiver_id: usize,
    pub session_id: String,
    pub vs: Vec<u8>,
    // a share on original poly = f_v(PlayerId)
    pub vs2: Vec<u8>,
    // a share on simulated poly = f_v2(PlayerId)
    pub poly: VerifiableSS<GE>,//commit on original poly = f_v * G + f_v2 * H
}

impl Default for Round2Message {
    fn default() -> Self {
        Round2Message {
            sender_id: 0,
            receiver_id: 0,
            session_id: "".to_string(),
            vs: vec![],
            vs2: vec![],
            poly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count: 0 }, commitments: vec![] },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round3Message {
    pub sender_id: usize,
    pub session_id: String,
    pub public_key: GE,
}

impl Default for Round3Message {
    fn default() -> Self {
        Round3Message {
            sender_id: 0,
            session_id: "".to_string(),
            public_key: ECPoint::generator(),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Player {
    pub round1: Round1Message,
    pub round2: Round2Message,
    pub round3: Round3Message,
}


#[derive(Clone)]
pub struct SchnorkellKey {
    pub share: FE,
    pub public_key: GE,
    pub player_id: usize,
    pub poly: VerifiableSS<GE>,

    pub r_i: FE,
    pub R: GE,
    pub sigma_i: FE,
    message: Vec<u8>,
    pub dkr: DkrGen,
    pub ctx: SigningContext,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Parameters {
    pub threshold: usize,
    //t
    pub share_count: usize, //n
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    //s=r + kx  where k = scalar(message), x is shared secret, r is random
    pub R: GE,//rP
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        bytes[..32].copy_from_slice(&self.R.get_element().as_bytes()[..]);
        bytes[32..].copy_from_slice(&self.s.get_element().as_bytes()[..]);
        bytes[63] |= 128;
        bytes
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRound1Message {
    sender_id: usize,
    session_id: String,
    R_i: GE, //r_i * P
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRound3Message {
    sender_id: usize,
    R: GE,
    // r * P
    sigma_i: FE,
}

pub fn get_scalar(ctx: &SigningContext, message: &[u8], public_key: &GE, R: &GE) -> FE {
    let mut t = ctx.bytes(message);

    t.proto_name(b"Schnorr-sig");
    let publicKey = PublicKey::from_bytes(&public_key.get_element().as_bytes()[..]).unwrap();
    t.commit_point(b"sign:pk", publicKey.as_compressed());

    let mut lower: [u8; 32] = [0u8; 32];
    lower.copy_from_slice(&R.pk_to_key_slice()[..32]);
    let R2 = CompressedRistretto(lower);
    t.commit_point(b"sign:R", &R2);

    let k1 = t.challenge_scalar(b"sign:c");
    let mut k2 = k1.to_bytes();
    k2.reverse();

    let kx = BigInt::from(&k2[..]);
    ECScalar::from(&kx)
}


impl SchnorkellKey {
    pub fn signRound1(&mut self, session_id: String, ctx: SigningContext, message: &Vec<u8>, parties: &[usize]) -> Result<Round1Message, Error> {
        self.message = message.clone();
        self.dkr = NewDrgGen(session_id, self.player_id, self.poly.parameters.threshold, parties.len());
        self.ctx = ctx;
        self.dkr.round1(parties)
    }
    pub fn signRound2(&mut self, round1s: &[Round1Message]) -> Result<Vec<Round2Message>, Error> {
        self.dkr.round2(round1s)
    }

    pub fn signRound3(&mut self, round2s: Vec<Round2Message>) -> Result<SigRound3Message, Error> {
        let result = self.dkr.round3(round2s);

        let r_i = self.dkr.keyShare;
        self.R = result.unwrap().public_key;
        //modify this for schnorkell

        let k = get_scalar(&self.ctx, &self.message, &self.public_key, &self.R);
        let sigma_i = r_i + k * self.share.clone();

        self.sigma_i = sigma_i.clone();
        Ok(SigRound3Message {
            sender_id: self.player_id.clone(),
            R: self.R,
            sigma_i: sigma_i.clone(),
        })
    }


    pub fn signRound4(&mut self, round3s: &Vec<SigRound3Message>) -> Result<Signature, Error> {
        let mut indices = vec![self.player_id - 1];
        let mut shares = vec![self.sigma_i.clone()];

        round3s.iter().map(|next| {
            indices.push(next.sender_id - 1);
            shares.push(next.sigma_i.clone());
            true
        }).all(|x| x == true);

        let reconstruct_limit = self.poly.parameters.threshold + 1;

        let sigma = self.poly.reconstruct(&indices.as_slice()[0..reconstruct_limit.clone()], &shares[0..reconstruct_limit.clone()]);

        let signature = Signature { s: sigma, R: self.R.clone() };

        if signature.verify(&self.ctx, &self.message, &self.public_key).is_ok() {
            Ok(signature)
        } else {
            Err(InvalidSig)
        }
    }
}

impl Signature {
    pub fn verify(&self, ctx: &SigningContext, message: &[u8], pubKey: &GE) -> Result<(), Error> {
        let kt1: FE = get_scalar(ctx, message, pubKey, &self.R);
        let kt2 = FE::q() - kt1.to_big_int();
        let k = ECScalar::from(&kt2);


        let P: GE = ECPoint::generator();
        let Rprime: GE = P.clone() * &self.s + pubKey * &k;

        if Rprime == self.R {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }
}

pub fn NewDrgGen(session_id: String, player_id: usize, t: usize, n: usize) -> DkrGen {
    let mut dkr = DkrGen::default();
    dkr.session_id = session_id.clone();
    dkr.player_id = player_id.clone();
    dkr.params = Parameters {
        threshold: t.clone(),
        share_count: n.clone(),
    };
    dkr
}

impl DkrGen {
    pub fn get_share(&self) -> SchnorkellKey {
        SchnorkellKey {
            share: self.keyShare.clone(),
            public_key: self.publicKey.clone(),
            player_id: self.player_id.clone(),
            poly: self.poly.clone(),
            r_i: FE::zero(),
            R: GE::generator(),
            sigma_i: FE::zero(),
            message: vec![],
            dkr: Default::default(),
            ctx: SigningContext::new(&[0]),
        }
    }
    pub fn round1(&mut self, parties: &[usize]) -> Result<Round1Message, Error> {
        let (vss, shares) = VerifiableSS::share_at_indices(
            self.params.threshold, self.params.share_count, &ECScalar::new_random(), &parties);
        self.poly = vss;

        let (vss2, shares2) = VerifiableSS::share_at_indices(self.params.threshold,
                                                             self.params.share_count, &ECScalar::new_random(), &parties);
        self.simPoly = vss2;

        (0..parties.len()).map(|i| {
            self.shares.insert(parties[i], shares[i]);
            self.simShares.insert(parties[i], shares2[i]);
            true
        }).all(|x| x == true);

        let ckVec = (0..self.poly.commitments.len()).map(|i| { self.poly.commitments[i] + self.simPoly.commitments[i] }
        ).collect::<Vec<GE>>();
        let sumPoly = VerifiableSS { parameters: self.poly.parameters.clone(), commitments: ckVec };
        let sumPolyStr = serde_json::to_string(&sumPoly).unwrap();

        Ok(Round1Message {
            sender_id: self.player_id.clone(),
            session_id: self.session_id.clone(),
            ck: sumPolyStr.as_bytes().to_vec(),
        })
    }
    pub fn round2(&mut self, round1s: &[Round1Message]) -> Result<Vec<Round2Message>, Error> {
        let sessionCheck = round1s.iter().map(|next| {
            self.session_id == next.session_id
        }).all(|x| x == true);

        assert!(sessionCheck, "not the same session");
        round1s.into_iter().map(|next| {
            let mut player = Player::default();
            player.round1 = next.clone();
            self.players.insert(next.sender_id, player);
            true
        }).all(|x| x == true);

        let result = round1s.iter().map(|next| {
            let mut r2 = Round2Message::default();
            r2.sender_id = self.player_id.clone();
            r2.receiver_id = next.sender_id.clone();
            r2.session_id = next.session_id.clone();
            r2.poly = self.poly.clone();

            r2.vs = serde_json::to_vec(&self.shares.get(&next.sender_id)).unwrap(); //should be encrypted
            r2.vs2 = serde_json::to_vec(&self.simShares.get(&next.sender_id)).unwrap(); //should be encrypted
            r2
        }).collect::<Vec<Round2Message>>();

        Ok(
            result
        )
    }
    pub fn round3(&mut self, round2s: Vec<Round2Message>) -> Result<Round3Message, Error> {
        let mut shareFinal = FE::zero();
        let mut commitment = self.poly.commitments.clone();

        let check = round2s.iter().map(|next| {
            let player = self.players.get_mut(&next.sender_id).unwrap();

            let share: FE = serde_json::from_slice(&next.vs).unwrap();
            let sim_share: FE = serde_json::from_slice(&next.vs2).unwrap();
            let sum_share = share + &sim_share;

            //let poly: VerifiableSS<GE> = serde_json::from_slice(&).unwrap();
            let sumPoly: VerifiableSS<GE> = serde_json::from_slice(&player.round1.ck).unwrap();

            let val_share = next.poly.validate_share(&share, self.player_id).is_ok();
            let val_sumshare = sumPoly.validate_share(&sum_share, self.player_id).is_ok();
            player.round2 = next.clone();
            shareFinal = shareFinal + &share;

            commitment = (0..commitment.len()).map(|i| {
                commitment[i] + &next.poly.commitments[i]
            }).collect::<Vec<GE>>();

            val_share && val_sumshare
        }).all(|x| x == true);

        if !check {
            return Err(InvalidSS);
        }

        shareFinal = shareFinal + self.shares.get(&self.player_id).unwrap();
        let polyFinal = VerifiableSS { parameters: self.poly.parameters.clone(), commitments: commitment.clone() };
        let check = polyFinal.validate_share(&shareFinal, self.player_id).is_ok();

        if !check {
            return Err(InvalidSS);
        }

        self.poly = polyFinal.clone();
        self.keyShare = shareFinal;

        self.publicKey = polyFinal.commitments[0].clone();

        Ok(Round3Message {
            sender_id: self.player_id.clone(),
            session_id: self.session_id.clone(),
            public_key: self.publicKey.clone(),
        })
    }
}

pub fn recover(poly: &VerifiableSS<GE>, indices: &[usize], shares: &Vec<FE>) -> FE {
    poly.reconstruct(indices, shares)
}


