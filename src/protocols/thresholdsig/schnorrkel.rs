#![allow(non_snake_case)]

use std::collections::HashMap;

pub use curv::arithmetic::traits::Converter;
pub use curv::BigInt;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
pub use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;

#[allow(unused_doc_comments)]
use Error::{self, InvalidSig, InvalidSS};
use std::fmt::Debug;

pub(crate) type GE = curv::elliptic::curves::curve_ristretto::GE;
type FE = curv::elliptic::curves::curve_ristretto::FE;

#[derive(Debug)]
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

impl Default for DkrGen{
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

#[derive(Clone, Debug,Serialize, Deserialize)]
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
            poly: VerifiableSS { parameters: ShamirSecretSharing { threshold: 0, share_count:0 }, commitments: vec![] },
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

#[derive(Default, Debug)]
pub struct Player {
    pub round1: Round1Message,
    pub round2: Round2Message,
    pub round3: Round3Message,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorkellKey {
    pub share: FE,
    pub public_key: GE,
    pub player_id: usize,
    pub poly: VerifiableSS<GE>,

    pub r_i: FE,
    pub R: GE,
    pub sigma_i: FE,
    message: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Parameters {
    pub threshold: usize,//t
    pub share_count: usize, //n
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub s: FE, //s=r + kx  where k = scalar(message), x is shared secret, r is random
    pub R: GE,//rP
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRound1Message {
    sender_id: usize,
    session_id: String,
    R_i: GE, //r_i * P
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRound2Message {
    sender_id: usize,
    R: GE,
    // r * P
    sigma_i: FE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigRound3Message {
    pub sender_id: usize,
    pub signature: Signature,
}

impl SchnorkellKey {
    pub fn signRound1(&mut self, session_id: String, message: &Vec<u8>) -> Result<SigRound1Message, Error> {
        let G: GE = ECPoint::generator();

        self.r_i = ECScalar::new_random();
        self.R = G.clone() * &self.r_i;
        self.message = message.clone();

        Ok(SigRound1Message {
            sender_id: self.player_id.clone(),
            session_id: session_id.clone(),
            R_i: self.R.clone(),
        })
    }
    pub fn signRound2(&mut self, round1s: &[SigRound1Message]) -> Result<SigRound2Message, Error> {
        //shared random R= Sum (R_i)
        self.R = round1s.iter().fold(self.R.clone(), |acc, next| acc + next.R_i);

        //modify this for schnorkell
        let m = HSha256::create_hash_from_slice(
            &self.message[..],
        );

        let k: FE = ECScalar::from(&m);
        let sigma_i = self.r_i + k * self.share.clone();

        self.sigma_i = sigma_i.clone();

        Ok(SigRound2Message {
            sender_id: self.player_id.clone(),
            R: self.R,
            sigma_i: sigma_i.clone(),
        })
    }
    pub fn signRound3(&mut self, round2s: &[SigRound2Message]) -> Result<SigRound3Message, Error> {
        let mut indices = vec![self.player_id - 1];
        let mut shares = vec![self.sigma_i.clone()];

        round2s.iter().map(|next| {
            indices.push(next.sender_id - 1);
            shares.push(next.sigma_i.clone());
            true
        }).all(|x| x == true);

        let reconstruct_limit = self.poly.parameters.threshold + 1;

        let sigma = self.poly.reconstruct(&indices.as_slice()[0..reconstruct_limit.clone()], &shares[0..reconstruct_limit.clone()]);


        Ok(SigRound3Message {
            sender_id: self.player_id.clone(),
            signature: Signature { s: sigma, R: self.R.clone() },
        })
    }
}

impl Signature {
    pub fn verify(&self, message: &[u8], pubKey: &GE) -> Result<(), Error> {
        //modify this with scnorrkel constructions
        let m = HSha256::create_hash_from_slice(
            &message[..],
        );

        let kt1: FE = ECScalar::from(&m);
        let kt2 = FE::q() - kt1.to_big_int();
        let k = ECScalar::from(&kt2);


        let P: GE = ECPoint::generator();
        let Rprime: GE = P.clone() * &self.s + pubKey * &k;

        println!("R': {}", Rprime.bytes_compressed_to_big_int().to_hex());
        println!("R : {}", self.R.bytes_compressed_to_big_int().to_hex());

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
    pub fn get_share(&self)->SchnorkellKey{
        SchnorkellKey{
            share: self.keyShare.clone(),
            public_key: self.publicKey.clone(),
            player_id: self.player_id.clone(),
            poly:self.poly.clone(),
            r_i: FE::zero(),
            R: GE::generator(),
            sigma_i: FE::zero(),
            message: vec![]
        }
    }
    pub fn round1(&mut self, parties: &[usize]) -> Result<Round1Message, Error> {
        let (vss, shares) = VerifiableSS::share_at_indices(
            self.params.threshold,self.params.share_count, &ECScalar::new_random(),&parties);
        self.poly = vss;

        let (vss2, shares2) = VerifiableSS::share_at_indices(self.params.threshold,
                                                             self.params.share_count, &ECScalar::new_random(), &parties );
        self.simPoly = vss2;

        (0..parties.len()).map(|i| {
            self.shares.insert(parties[i], shares[i]);
            self.simShares.insert(parties[i], shares2[i]);
            true
        }).all(|x| x == true);

        let ckVec = (0..self.poly.commitments.len()).map(|i|{self.poly.commitments[i] + self.simPoly.commitments[i]}
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
        let sessionCheck = round1s.iter().map(|next| {self.session_id == next.session_id
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

    pub fn recover(&self, indices: &[usize], shares: &Vec<FE>) -> FE {
        self.poly.reconstruct(indices, shares)
    }
}


