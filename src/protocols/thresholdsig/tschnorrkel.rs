#![allow(non_snake_case)]
#[allow(unused_doc_comments)]

use Error::{self, InvalidSS, InvalidSig};
use curv::elliptic::curves::traits::*;

pub use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
pub use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use std::collections::HashMap;

pub use curv::BigInt;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;

type GE = curv::elliptic::curves::curve_ristretto::GE;
type FE = curv::elliptic::curves::curve_ristretto::FE;

#[derive(Debug)]
pub struct DkgGen{
    pub session_id: String,
    pub player_id: usize,
    pub params: Parameters,
    pub players: HashMap<usize,  Player>,
    pub vss:VerifiableSS<GE>,
    pub shares: HashMap<usize,  FE>, // real share
    pub shares2: HashMap<usize,  FE>, //simulated share
    pub vss2:VerifiableSS<GE>,
    pub key: SchnorkellKey,
}

#[derive(Default, Clone,Hash, Eq, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Round1Message {
    sender_id: usize,
    session_id: String,
    ck:  Vec<u8>,
}


#[derive(Default,Clone,Hash, Eq, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Round2Message {
    pub sender_id: usize,
    pub receiver_id: usize,
    pub session_id: String,
    pub vs:  Vec<u8>,// a share on original poly = f_v(PlayerId)
    pub vs2:  Vec<u8>,// a share on simulated poly = f_v2(PlayerId)
    pub vcf:  Vec<u8>,//commit on original poly = f_v * G + f_v2 * H
}
#[derive(Default,Clone,Hash, Eq, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
pub struct Round3Message {
    pub sender_id: usize,
    pub session_id: String,
    pub public_key:  Vec<u8>,
}

#[derive(Default, Hash, Eq, PartialEq, Debug)]
pub struct Player{
    pub round1: Round1Message,
    pub round2: Round2Message,
    pub round3: Round3Message,
}
#[derive(Debug)]
 #[derive(Serialize, Deserialize)]
pub struct SchnorkellKey {
    pub share: FE,
    pub public_key: GE,
    pub player_id: usize,
    pub poly:Vec<u8>,

    ephemeral_i: FE,
    ephemeral: GE,
    sigma_i: FE,
    message:  Vec<u8>,
}

#[derive(Debug, Default)]
#[derive(Serialize, Deserialize)]
pub struct Parameters {
    pub threshold: usize,   //t
    pub share_count: usize, //n
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: FE,
    pub v: GE,
}

#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub struct SigRound1Message {
    sender_id: usize,
    session_id: String,
    ephemeral:  GE,
}


#[derive(Default, Clone,Hash, Eq, PartialEq, Debug)]
#[derive(Serialize, Deserialize)]
pub struct SigRound2Message {
    sender_id: usize,
    r_comp:Vec<u8>,
    sigma_i:Vec<u8>,
 }
#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub struct SigRound3Message {
    sender_id: usize,
    signature: Signature,
}

impl SchnorkellKey {
    pub fn get_poly(&self) ->VerifiableSS<GE> {
        serde_json::from_slice(&self.poly).unwrap()
    }

    pub fn signRound1(&mut self, session_id : String, message : &Vec<u8>) ->Result<SigRound1Message,Error> {
        self.ephemeral_i = ECScalar::new_random();
        self.ephemeral = &ECPoint::generator() * &self.ephemeral_i;
        self.message = message.clone();

        Ok(SigRound1Message{
            sender_id: self.player_id.clone(),
            session_id: session_id.clone(),
            ephemeral: self.ephemeral.clone()
        })
    }
    pub fn signRound2(&mut self, round1s: &[SigRound1Message]) ->Result<SigRound2Message,Error> {
        //shared random R= Sum (R_i)
        self.ephemeral = round1s.iter().fold(self.ephemeral.clone(),|acc, next| acc + next.ephemeral);

        let r_comp =  self.ephemeral.bytes_compressed_to_big_int();
        //modify this for schnorkell
        let m = HSha256::create_hash_from_slice(
            &self.message[..],
        );
        let k: FE = ECScalar::from(&m);
        let sigma_i = self.ephemeral_i + k * self.share.clone();

        self.sigma_i = sigma_i.clone();

        Ok(SigRound2Message{
            sender_id: self.player_id.clone(),
            r_comp:BigInt::to_vec(&r_comp),
            sigma_i:serde_json::to_vec(&sigma_i).unwrap(),
         })
    }
    pub fn signRound3(&mut self,  round2s: &[SigRound2Message]) ->Result<SigRound3Message,Error> {
        let mut indices = vec![self.player_id];
        let mut shares = vec![self.sigma_i];

        round2s.iter().map(|next| {
            indices.push(next.sender_id);
            let sigma_i: FE= serde_json::from_slice(&next.sigma_i).unwrap();
            shares.push(sigma_i);
            true
        }).all(|x|x== true);

        let poly = self.get_poly();
        let sigma = poly.reconstruct(indices.as_slice(),shares.as_slice());

        Ok(SigRound3Message{
            sender_id: self.player_id.clone(),
            signature: Signature{ sigma: sigma, v: self.ephemeral }
        })
    }

}

pub fn NewDkgGen(session_id: String, player_id: usize, t: usize, n: usize) -> DkgGen{
    DkgGen{
        session_id: session_id.clone(),
        player_id:player_id.clone(),
        params: Parameters {
            threshold: t.clone(),
            share_count: n.clone(),
        },
        players: Default::default(),
        vss: VerifiableSS{ parameters: ShamirSecretSharing { threshold: t.clone(), share_count: n.clone()}, commitments: vec![] },
        shares: Default::default(),
        vss2: VerifiableSS{ parameters: ShamirSecretSharing { threshold: t.clone(), share_count: n.clone()}, commitments: vec![] },
        shares2: Default::default(),
        key: SchnorkellKey{
            share: FE::zero(),
            public_key: GE::generator(),
            player_id: player_id.clone(),
            poly: vec![],
            ephemeral_i: FE::zero(),
            sigma_i: FE::zero(),
            ephemeral: GE::generator(),
            message: vec![]
        }
    }
}
impl DkgGen {
    pub fn round1(&mut self, parties: &[usize]) -> Result<Round1Message, Error> {
         let (vss, share) = VerifiableSS::share_at_indices(
            self.params.threshold,
            self.params.share_count,
            &ECScalar::new_random(),
            &parties,
        );
        self.vss = vss;

        let ( vss2,  share2) = VerifiableSS::share_at_indices(
            self.params.threshold,
            self.params.share_count,
            &ECScalar::new_random(),
            &parties,
        );
        self.vss2 = vss2;

        (0..parties.len()).map(|i| {
            self.shares.insert(parties[i],share[i]);
            self.shares2.insert(parties[i],share2[i]);
            true
        }).all(|x| x == true);

        let ckVec = (0..self.vss.commitments.len()).map(
            |i|{
                self.vss.commitments[i] + self.vss2.commitments[i]
            }
        ).collect::<Vec<GE>>();
        let sumPoly = VerifiableSS { parameters: self.vss.parameters.clone(), commitments: ckVec };
        let sumPolyStr = serde_json::to_string(&sumPoly).unwrap();

        Ok(Round1Message {
            sender_id: self.player_id.clone(),
            session_id: self.session_id.clone(),
            ck: sumPolyStr.as_bytes().to_vec(),
        })
    }
     pub fn round2(&mut self, round1s: &[Round1Message]) ->Result<Vec<Round2Message>,Error>{
        let sessionCheck: bool = round1s.iter().map(|next|{
            self.session_id == next.session_id
        }) .all(|x| x == true);
        assert!(sessionCheck,"not the same session");

        round1s.into_iter().map(|next|{
            let mut player = Player::default();
            player.round1 = next.clone();
            self.players.insert(next.sender_id,player);
            true
        }).all(|x| x == true);

         let result = round1s.iter().map( |next| {
             let mut r2 = Round2Message::default();
             r2.sender_id = self.player_id.clone();
             r2.receiver_id = next.sender_id.clone();
             r2.session_id = next.session_id.clone();
             r2.vcf = serde_json::to_vec(&self.vss).unwrap();

             r2.vs = serde_json::to_vec(&self.shares.get(&next.sender_id)).unwrap(); //should be encrypted
             r2.vs2 = serde_json::to_vec(&self.shares2.get(&next.sender_id)).unwrap(); //should be encrypted
             r2
         }).collect::<Vec<Round2Message>>();

         Ok(
             result
         )
    }
    pub fn round3(&mut self, round2s: Vec<Round2Message>) -> Result<Round3Message,Error> {
        let mut shareFinal = FE::zero();
        let mut commitment = self.vss.commitments.clone();

        let check = round2s.iter().map(|next| {
            let player = self.players.get_mut(&next.sender_id).unwrap();

            let share: FE = serde_json::from_slice(&next.vs).unwrap();
            let sim_share: FE = serde_json::from_slice(&next.vs2).unwrap();
            let sum_share = share + sim_share;

            let poly:VerifiableSS<GE> = serde_json::from_slice(&next.vcf).unwrap();
            let sumPoly:VerifiableSS<GE> = serde_json::from_slice(&player.round1.ck).unwrap();

            let val_share = poly.validate_share(&share, self.player_id).is_ok();
            let val_sumshare = sumPoly.validate_share(&sum_share, self.player_id).is_ok();
            player.round2 = next.clone();
            shareFinal = shareFinal + &share;

            commitment = (0..commitment.len()).map(|i|{
                commitment[i] + poly.commitments[i]
            }).collect::<Vec<GE>>();

            val_share && val_sumshare
        }).all(|x|x == true);

        if !check {
            return Err(InvalidSS);
        }

        shareFinal = shareFinal + self.shares.get(&self.player_id).unwrap();
        let polyFinal = VerifiableSS{ parameters: self.vss.parameters.clone(), commitments: commitment.clone() };
        let check = polyFinal.validate_share(&shareFinal, self.player_id).is_ok();

        if !check {
            return Err(InvalidSS);
        }

        self.key.poly = serde_json::to_vec(&polyFinal).unwrap();
        self.key.share = shareFinal;
        self.key.public_key = polyFinal.get_point_commitment(0);

        Ok(Round3Message {
            sender_id: self.player_id.clone(),
            session_id: self.session_id.clone(),
            public_key: self.key.public_key.pk_to_key_slice()
        })
    }
}

impl Signature {
    pub fn verify(&self, message: &[u8], pubkey_y: &GE) -> Result<(), Error> {
        let e_bn = HSha256::create_hash(&[
            &self.v.bytes_compressed_to_big_int(),
            &pubkey_y.bytes_compressed_to_big_int(),
            &BigInt::from(message),
        ]);
        let e: FE = ECScalar::from(&e_bn);

        let g: GE = GE::generator();
        let sigma_g = g * &self.sigma;
        let e_y = pubkey_y * &e;
        let e_y_plus_v = e_y + &self.v;

        if e_y_plus_v == sigma_g {
            Ok(())
        } else {
            Err(InvalidSig)
        }
    }
}
