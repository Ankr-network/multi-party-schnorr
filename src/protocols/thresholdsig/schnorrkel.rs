#![allow(non_snake_case)]

use std::collections::HashMap;
use std::fmt::Debug;

pub use curv::arithmetic::traits::Converter;
pub use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
pub use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curve25519_dalek::ristretto::CompressedRistretto;

use schnorrkel::{PublicKey, SIGNATURE_LENGTH};
use schnorrkel::context::{SigningContext, SigningTranscript};

#[allow(unused_doc_comments)]
use Error::{self, InvalidSig, InvalidSS};
use openssl::ec::EcKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use protocols::utils::utils::{get_player_id, verify_cert};
use protocols::encryption::encryption_service::{encrypt, EncryptedMessage, decrypt};
use std::path::Path;
use std::fs::File;
use std::io::Write;

pub(crate) type GE = curv::elliptic::curves::curve_ristretto::GE;
type FE = curv::elliptic::curves::curve_ristretto::FE;



#[derive(Debug, Clone)]
pub struct DkrGen {
    pub session_id: String,
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
    pub parties: Vec<usize>,
    ca : X509,
    key  :EcKey<Private>,
    cert : X509,
    agents : Vec<X509>
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
    pub secret_share: Vec<u8>,
    // a share on original poly = f_v(PlayerId)
    pub sim_secret_share: Vec<u8>,
    // a share on simulated poly = f_v2(PlayerId)
    pub poly: VerifiableSS<GE>,//commit on original poly = f_v * G + f_v2 * H
}

impl Default for Round2Message {
    fn default() -> Self {
        Round2Message {
            sender_id: 0,
            receiver_id: 0,
            session_id: "".to_string(),
            secret_share: vec![],
            sim_secret_share: vec![],
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

#[derive(Debug, Clone)]
pub struct Player {
    pub cert : X509,
    pub round1: Round1Message,
    pub round2: Round2Message,
    pub round3: Round3Message,
}


#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Parameters {
    pub threshold: usize,
    //t
    pub share_count: usize, //n
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareKey {
    pub player_id: usize,
    pub secret: FE,
    pub public_key: GE,
    pub poly: VerifiableSS<GE>,
}

impl From<&Vec<u8>> for ShareKey {
    fn from( a : &Vec<u8>) -> Self {
        serde_json::from_slice(a).unwrap()
    }
}

#[derive(Clone)]
pub struct SigningCeremony {
    pub share_key : ShareKey,
    message: Vec<u8>,
    pub r_i: FE,
    pub R: GE,
    pub sigma_i: FE,
    pub dkr: DkrGen,
    pub ctx: SigningContext,
}
pub fn NewSigningCeremony(session_id: String, ks : ShareKey, ctx : SigningContext, ca : X509, key :&EcKey<Private>, cert : &X509, agents : &[X509]) -> SigningCeremony {
    let drg = NewDrgGen(session_id,ca,key,cert,agents,ks.poly.parameters.threshold, agents.len());
    SigningCeremony{ share_key: ks, message: vec![], r_i: FE::zero(), R: GE::generator(), sigma_i: FE::zero(), dkr: drg, ctx: ctx, }
}


impl SigningCeremony {
    pub fn signRound1(&mut self, message: &Vec<u8>) -> Result<Round1Message, Error> {
        self.message = message.clone();
        self.dkr.round1()
    }
    pub fn signRound2(&mut self, round1s: &[Round1Message]) -> Result<Vec<Round2Message>, Error> {
        self.dkr.round2(round1s)
    }

    pub fn signRound3(&mut self, round2s: Vec<Round2Message>) -> Result<SigRound3Message, Error> {
        let result = self.dkr.round3(round2s);

        let r_i = self.dkr.keyShare;
        self.R = result.unwrap().public_key;
        //modify this for schnorkell

        let k = get_schnorkell_scalar(&self.ctx, &self.message, &self.share_key.public_key, &self.R);
        let sigma_i = r_i + k * self.share_key.secret.clone();

        self.sigma_i = sigma_i.clone();
        Ok(SigRound3Message {
            sender_id: self.dkr.get_player_id(),
            R: self.R,
            sigma_i: sigma_i.clone(),
        })
    }


    pub fn signRound4(&mut self, round3s: &Vec<SigRound3Message>) -> Result<Signature, Error> {
        let mut indices = vec![self.dkr.get_player_id() - 1];
        let mut shares = vec![self.sigma_i.clone()];

        round3s.iter().map(|next| {
            indices.push(next.sender_id - 1);
            shares.push(next.sigma_i.clone());
            true
        }).all(|x| x == true);

        let poly = &self.dkr.poly;

        let reconstruct_limit = poly.parameters.threshold + 1;

        let sigma = poly.reconstruct(&indices.as_slice()[0..reconstruct_limit.clone()], &shares[0..reconstruct_limit.clone()]);

        let signature = Signature { s: sigma, R: self.R.clone() };

        if signature.verify(&self.ctx, &self.message, &self.share_key.public_key).is_ok() {
            Ok(signature)
        } else {
            Err(InvalidSig)
        }
    }
}


pub fn NewDrgGen(session_id: String, ca : X509, key :&EcKey<Private>, cert : &X509, agents : &[X509], t: usize, n: usize) -> DkrGen {
    let mut dk = DkrGen {
        session_id: session_id.clone(),
        params: Parameters {
            threshold: t.clone(),
            share_count: n.clone(),
        },
        players: Default::default(),
        poly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count: 0 }, commitments: vec![] },
        shares: Default::default(),
        simPoly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count: 0 }, commitments: vec![] },
        keyShare: FE::zero(),
        publicKey: GE::generator(),
        simShares: Default::default(),
        parties: vec![],
        ca : ca.clone().to_owned(),
        key: key.to_owned(),
        cert: cert.clone().to_owned(),
        agents: agents.clone().to_owned(),
    };
    let check = agents.into_iter().map(|next| {
        dk.parties.push(get_player_id(next));
        let player = Player{cert: next.to_owned(),
            round1: Default::default(),
            round2: Default::default(),
            round3: Default::default()
        };
        let player_id =get_player_id(next);
        dk.players.insert(player_id, player);
        verify_cert(next, &ca).unwrap()
    }).all(|x| x == true);
    assert!(check, "one of the cert is not verified");

    dk

 }
pub fn get_schnorkell_scalar(ctx: &SigningContext, message: &[u8], public_key: &GE, R: &GE) -> FE {
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

/*
pub fn get_share(dkrg : &DkrGen) -> SchnorkellKey {
    SchnorkellKey {
        share: dkrg.keyShare.clone(),
        public_key: dkrg.publicKey.clone(),
        player_id: dkrg.player_id.clone(),
        poly: dkrg.poly.clone(),
        r_i: FE::zero(),
        R: GE::generator(),
        sigma_i: FE::zero(),
        message: vec![],
        dkr: Default::default(),
        ctx: SigningContext::new(&[0]),
    }
}*/
//select only receiver_id is player_id
pub fn filter(player_id: usize, cols: &Vec<Vec<Round2Message>>) -> Vec<Round2Message> {
    let mut result: Vec<Round2Message> = vec![];
    for i in 0..cols.len().clone() {
        let c1 = cols[i].clone();
        let item = c1.into_iter().find(|x| x.receiver_id == player_id);
        if item.is_some() {
            let test = item.unwrap();
            result.push(test);
        };
    }
    result
}
impl DkrGen {
    pub fn get_share_key(&self) -> ShareKey {
        ShareKey{
            player_id: self.get_player_id(),
            secret: self.keyShare,
            public_key: self.publicKey,
            poly: self.poly.clone(),
        }
    }
    pub fn write_share_to_file(&self) {
        let ks = self.get_share_key();
        let result = serde_json::to_string(&ks).unwrap();

        let pt = format!("agents/agent{}_schnorrkel_share.json", self.get_player_id());
        let path = Path::new(&pt);
        let prefix = path.parent().unwrap();

        std::fs::create_dir_all(prefix).unwrap();

        let display = path.display();

        // Open a file in write-only mode, returns `io::Result<File>`
        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create {}: {}", display, why),
            Ok(file) => file,
        };

        // Write the `LOREM_IPSUM` string to `file`, returns `io::Result<()>`
        match file.write(result.as_bytes()) {
            Err(why) => panic!("couldn't write to {}: {}", display, why),
            Ok(_) => println!("successfully wrote to {}", display),
        }

    }
    pub fn get_player_id(&self) -> usize {
        get_player_id(&self.cert)
    }
    pub fn round1(&mut self) -> Result<Round1Message, Error> {
        let (vss, shares) = VerifiableSS::share_at_indices(
            self.params.threshold, self.params.share_count, &ECScalar::new_random(), &self.parties);
        self.poly = vss;

        let (vss2, shares2) = VerifiableSS::share_at_indices(self.params.threshold,
                                                             self.params.share_count, &ECScalar::new_random(), &self.parties);
        self.simPoly = vss2;

        (0..self.parties.len()).map(|i| {
            self.shares.insert(self.parties[i], shares[i]);
            self.simShares.insert(self.parties[i], shares2[i]);
            true
        }).all(|x| x == true);

        let ckVec = (0..self.poly.commitments.len()).map(|i| { self.poly.commitments[i] + self.simPoly.commitments[i] }
        ).collect::<Vec<GE>>();
        let sumPoly = VerifiableSS { parameters: self.poly.parameters.clone(), commitments: ckVec };
        let sumPolyStr = serde_json::to_string(&sumPoly).unwrap();

        Ok(Round1Message {
            sender_id: self.get_player_id(),
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
            let player = self.players.get_mut(&next.sender_id).unwrap();
            player.round1 = next.clone();
            true
        }).all(|x| x == true);

        let result = round1s.iter().map(|next| {
            let mut r2 = Round2Message::default();
            r2.sender_id = self.get_player_id();
            r2.receiver_id = next.sender_id.clone();
            r2.session_id = next.session_id.clone();
            r2.poly = self.poly.clone();

            let player = self.players.get(&next.sender_id).unwrap();
            //encrypt share
            let enc = encrypt(&self.key,&self.cert,&player.cert,&serde_json::to_vec(&self.shares.get(&next.sender_id)).unwrap()).unwrap();
            r2.secret_share = serde_json::to_vec(&enc).unwrap();
            //encrypt simulated share
            let enc = encrypt(&self.key,&self.cert,&player.cert,&serde_json::to_vec(&self.simShares.get(&next.sender_id)).unwrap()).unwrap();
            r2.sim_secret_share = serde_json::to_vec(&enc).unwrap(); //should be encrypted
            r2
        }).collect::<Vec<Round2Message>>();

        Ok(
            result
        )
    }
    pub fn round3(&mut self, round2s: Vec<Round2Message>) -> Result<Round3Message, Error> {
        let mut shareFinal = FE::zero();
        let mut commitment = self.poly.commitments.clone();

        let player_id = self.get_player_id();

        let check = round2s.iter().map(|next| {
            let player = self.players.get_mut(&next.sender_id).unwrap();

            //decrypt share
            let share: EncryptedMessage = serde_json::from_slice(&next.secret_share).unwrap();
            let share = decrypt(&self.key,&player.cert, &share).unwrap();
            let share :FE = serde_json::from_slice(&share).unwrap();

            //decrypt simulated share
            let sim_share: EncryptedMessage = serde_json::from_slice(&next.sim_secret_share).unwrap();
            let sim_share = decrypt(&self.key,&player.cert, &sim_share).unwrap();
            let sim_share :FE = serde_json::from_slice(&sim_share).unwrap();


            let sum_share = share + &sim_share;

            //let poly: VerifiableSS<GE> = serde_json::from_slice(&).unwrap();
            let sumPoly: VerifiableSS<GE> = serde_json::from_slice(&player.round1.ck).unwrap();

            let val_share = next.poly.validate_share(&share, player_id).is_ok();
            let val_sumshare = sumPoly.validate_share(&sum_share, player_id).is_ok();
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

        shareFinal = shareFinal + self.shares.get(&player_id).unwrap();
        let polyFinal = VerifiableSS { parameters: self.poly.parameters.clone(), commitments: commitment.clone() };
        let check = polyFinal.validate_share(&shareFinal, player_id).is_ok();

        if !check {
            return Err(InvalidSS);
        }

        self.poly = polyFinal.clone();
        self.keyShare = shareFinal;

        self.publicKey = polyFinal.commitments[0].clone();

        Ok(Round3Message {
            sender_id: player_id.clone(),
            session_id: self.session_id.clone(),
            public_key: self.publicKey.clone(),
        })
    }
}

pub fn recover(poly: &VerifiableSS<GE>, indices: &[usize], shares: &Vec<FE>) -> FE {
    poly.reconstruct(indices, shares)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE,
    //s=r + kx  where k = scalar(message), x is shared secret, r is random
    pub R: GE,//rP
}

impl Signature {
    pub fn verify(&self, ctx: &SigningContext, message: &[u8], pubKey: &GE) -> Result<(), Error> {
        let kt1: FE = get_schnorkell_scalar(ctx, message, pubKey, &self.R);
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
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        let mut bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        bytes[..32].copy_from_slice(&self.R.get_element().as_bytes()[..]);
        bytes[32..].copy_from_slice(&self.s.get_element().as_bytes()[..]);
        bytes[63] |= 128;
        bytes
    }
}
