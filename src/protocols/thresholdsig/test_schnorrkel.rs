#![allow(non_snake_case)]


use protocols::thresholdsig::schnorrkel::*;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
type FE = curv::elliptic::curves::curve_ristretto::FE;


#[test]
#[allow(unused_doc_comments)]
fn test_t2_n4_with_new() {
    let t = 2;
    let n = 4;
    let mut client1 = NewDrgGen("session 1".into(), 1, t, n);
    let mut client2 = NewDrgGen("session 1".into(), 3, t, n);
    let mut client3 = NewDrgGen("session 1".into(), 5, t, n);
    let mut client4 = NewDrgGen("session 1".into(), 7, t, n);

    let parties  = [1,3,5,7];

    let round11 = client1.round1(&parties);
    let round21 = client2.round1(&parties);
    let round31 = client3.round1(&parties);
    let round41 = client4.round1(&parties);

    assert!(round11.is_ok());
    assert!(round21.is_ok());
    assert!(round31.is_ok());
    assert!(round41.is_ok());

    let round12 = client1.round2(&[round21.clone().unwrap(),round31.clone().unwrap(),round41.clone().unwrap()]);
    let round22 = client2.round2(&[round11.clone().unwrap(),round31.clone().unwrap(),round41.clone().unwrap()]);
    let round32 = client3.round2(&[round11.clone().unwrap(),round21.clone().unwrap(),round41.clone().unwrap()]);
    let round42 = client4.round2(&[round11.clone().unwrap(),round21.clone().unwrap(),round31.clone().unwrap()]);

    assert!(round12.is_ok());
    assert!(round22.is_ok());
    assert!(round32.is_ok());
    assert!(round42.is_ok());

    let round13 = client1.round3(filter(client1.player_id, round12.clone().unwrap(),round22.clone().unwrap(),round32.clone().unwrap(),round42.clone().unwrap()));
    let round23 = client2.round3(filter(client2.player_id, round12.clone().unwrap(),round22.clone().unwrap(),round32.clone().unwrap(),round42.clone().unwrap()));
    let round33 = client3.round3(filter(client3.player_id, round12.clone().unwrap(),round22.clone().unwrap(),round32.clone().unwrap(),round42.clone().unwrap()));
    let round43 = client4.round3(filter(client4.player_id, round12.clone().unwrap(),round22.clone().unwrap(),round32.clone().unwrap(),round42.clone().unwrap()));

    assert!(round13.is_ok());
    assert!(round23.is_ok());
    assert!(round33.is_ok());
    assert!(round43.is_ok());


    //let key1 = &client1.key;
    let key2 = &client2.get_share();
    let key3 = &client3.get_share();
    let key4 = &client4.get_share();
    let pubKey = round13.unwrap().public_key;

    let secret = client1.recover(&[key3.player_id-1,key2.player_id-1,key4.player_id-1].to_vec(), &vec![key3.share.clone(),key2.share.clone(),key4.share.clone()]);
    let G:GE =  ECPoint::generator();
    let pubKey2 = G.clone() * &secret;

    println!("secret: {:?}",secret);
    println!("pubKey: {:?}",pubKey);
    println!("pubKey2: {:?}",pubKey2);


    println!("Public Key: 0x{}", round23.unwrap().public_key.bytes_compressed_to_big_int().to_hex());
    println!("Public Key: 0x{}", round33.unwrap().public_key.bytes_compressed_to_big_int().to_hex());
    println!("Public Key: 0x{}", round43.unwrap().public_key.bytes_compressed_to_big_int().to_hex());


    let mut key1 = client1.get_share();
    let mut key2 = client2.get_share();
    let mut key3 = client3.get_share();

    let message :[u8;4] = [21,24,25,26];

    let signRound11 = key1.signRound1("session 1".to_string(),&message.to_vec());
    let signRound21 = key2.signRound1("session 1".to_string(),&message.to_vec());
    let signRound31 = key3.signRound1("session 1".to_string(),&message.to_vec());

    assert!(signRound11.is_ok());
    assert!(signRound21.is_ok());
    assert!(signRound31.is_ok());

    let signRound12 = key1.signRound2(&[signRound21.clone().unwrap(),signRound31.clone().unwrap()]);
    let signRound22 = key2.signRound2(&[signRound11.clone().unwrap(),signRound31.clone().unwrap()]);
    let signRound32 = key3.signRound2(&[signRound11.clone().unwrap(),signRound21.clone().unwrap()]);

    assert!(signRound12.is_ok());
    assert!(signRound22.is_ok());
    assert!(signRound32.is_ok());

    let signRound13 = key1.signRound3(&[signRound22.clone().unwrap(),signRound32.clone().unwrap()]);
    let signRound23 = key2.signRound3(&[signRound12.clone().unwrap(),signRound32.clone().unwrap()]);
    let signRound33 = key3.signRound3(&[signRound12.clone().unwrap(),signRound22.clone().unwrap()]);

    assert!(signRound13.is_ok());
    assert!(signRound23.is_ok());
    assert!(signRound33.is_ok());

    let signRound3 = signRound13.unwrap();
    let signature = signRound3.signature;

    let r = key1.r_i + key2.r_i + key3.r_i;

    let m = HSha256::create_hash_from_slice(
        &message[..],
    );

    let k:FE = ECScalar::from(&m);

    let sigma = r + secret * k;

    println!("sigma {:?}",sigma);
    println!("sigma {:?}",signature.s);

    assert!(signature.verify(&message, &pubKey2).is_ok(),"invalid signature");

}

pub fn filter(player_id: usize, c1: Vec<Round2Message>,c2: Vec<Round2Message>,c3: Vec<Round2Message>, c4: Vec<Round2Message>) -> Vec<Round2Message> {

    let mut result:Vec<Round2Message> = vec![];

    let item = c1.into_iter().find(|x|x.receiver_id == player_id);
    if item.is_some() {result.push(item.unwrap())};

    let item = c2.into_iter().find(|x|x.receiver_id == player_id);
    if item.is_some() {result.push(item.unwrap())};

    let item = c3.into_iter().find(|x|x.receiver_id == player_id);
    if item.is_some() {result.push(item.unwrap())};

    let item = c4.into_iter().find(|x|x.receiver_id == player_id);
    if item.is_some() {result.push(item.unwrap())};

    result

}
