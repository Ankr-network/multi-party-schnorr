#![allow(non_snake_case)]
use curv::elliptic::curves::traits::ECPoint;
 use protocols::thresholdsig::bitcoin_schnorr::*;
use protocols::utils::utils::{load_cert, load_private_key};
use openssl::x509::X509;
use openssl::ec::EcKey;
use openssl::pkey::Private;

pub fn load_certs_from_file() -> (X509, Vec<X509>, Vec<EcKey<Private>>){
    let ca = load_cert(include_bytes!("../../../agents/ca.cert")).unwrap();
    let agents = vec![load_cert(include_bytes!("../../../agents/agent1.crt")).unwrap(),
                      load_cert(include_bytes!("../../../agents/agent2.crt")).unwrap(),
                      load_cert(include_bytes!("../../../agents/agent3.crt")).unwrap(),
                      load_cert(include_bytes!("../../../agents/agent4.crt")).unwrap(),
                      load_cert(include_bytes!("../../../agents/agent5.crt")).unwrap()];

    let keys = vec![load_private_key(include_bytes!("../../../agents/agent1.key")).unwrap(),
                    load_private_key(include_bytes!("../../../agents/agent2.key")).unwrap(),
                    load_private_key(include_bytes!("../../../agents/agent3.key")).unwrap(),
                    load_private_key(include_bytes!("../../../agents/agent4.key")).unwrap(),
                    load_private_key(include_bytes!("../../../agents/agent5.key")).unwrap()];

    (ca,agents,keys)
}

#[test]
fn test_t2_n4_with_keygen() {

    let (ca, agents, keys) = load_certs_from_file();

    let t = 2;
    let n = 4;
    let mut client1 = NewDrgGen("session 1".into(), ca.clone(),&keys[0], &agents[0], &agents[0..4], t, n);
    let mut client2 = NewDrgGen("session 1".into(), ca.clone(),&keys[1], &agents[1], &agents[0..4], t, n);
    let mut client3 = NewDrgGen("session 1".into(), ca.clone(),&keys[2], &agents[2], &agents[0..4], t, n);
    let mut client4 = NewDrgGen("session 1".into(), ca.clone(),&keys[3], &agents[3], &agents[0..4], t, n);

    let round11 = client1.round1();
    let round21 = client2.round1();
    let round31 = client3.round1();
    let round41 = client4.round1();

    assert!(round11.is_ok());
    assert!(round21.is_ok());
    assert!(round31.is_ok());
    assert!(round41.is_ok());

    let round12 = client1.round2(&[round21.clone().unwrap(), round31.clone().unwrap(), round41.clone().unwrap()]);
    let round22 = client2.round2(&[round11.clone().unwrap(), round31.clone().unwrap(), round41.clone().unwrap()]);
    let round32 = client3.round2(&[round11.clone().unwrap(), round21.clone().unwrap(), round41.clone().unwrap()]);
    let round42 = client4.round2(&[round11.clone().unwrap(), round21.clone().unwrap(), round31.clone().unwrap()]);

    assert!(round12.is_ok());
    assert!(round22.is_ok());
    assert!(round32.is_ok());
    assert!(round42.is_ok());

    let round13 = client1.round3(filter(client1.get_player_id(), &vec![round12.clone().unwrap(), round22.clone().unwrap(), round32.clone().unwrap(), round42.clone().unwrap()]));
    let round23 = client2.round3(filter(client2.get_player_id(), &vec![round12.clone().unwrap(), round22.clone().unwrap(), round32.clone().unwrap(), round42.clone().unwrap()]));
    let round33 = client3.round3(filter(client3.get_player_id(), &vec![round12.clone().unwrap(), round22.clone().unwrap(), round32.clone().unwrap(), round42.clone().unwrap()]));
    let round43 = client4.round3(filter(client4.get_player_id(), &vec![round12.clone().unwrap(), round22.clone().unwrap(), round32.clone().unwrap(), round42.clone().unwrap()]));

    assert!(round13.is_ok());
    assert!(round23.is_ok());
    assert!(round33.is_ok());
    assert!(round43.is_ok());

    println!("Public Key Hex {}",hex::encode(round13.unwrap().public_key.pk_to_key_slice()));

    client1.write_share_to_file();
    client2.write_share_to_file();
    client3.write_share_to_file();
    client4.write_share_to_file();


}

#[test]
fn test_t2_n4_with_signing_ceremony() {

    let (ca, agents, keys) = load_certs_from_file();

    let ks1=ShareKey::from(&include_bytes!("../../../agents/agent1_bitcoin_share.json").to_vec());
    let ks2=ShareKey::from(&include_bytes!("../../../agents/agent2_bitcoin_share.json").to_vec());
    let ks3=ShareKey::from(&include_bytes!("../../../agents/agent3_bitcoin_share.json").to_vec());


    let mut key1 = NewSigningCeremony("session 1".into(), ks1,ca.clone(),&keys[0], &agents[0], &agents[0..3]);
    let mut key2 = NewSigningCeremony("session 1".into(), ks2,ca.clone(),&keys[1], &agents[1], &agents[0..3]);
    let mut key3 = NewSigningCeremony("session 1".into(), ks3,ca.clone(),&keys[2], &agents[2], &agents[0..3]);

    let message: [u8; 4] = [21, 24, 25, 26];
    let signRound11 = key1.signRound1(&message.to_vec());
    let signRound21 = key2.signRound1(&message.to_vec());
    let signRound31 = key3.signRound1(&message.to_vec());

    assert!(signRound11.is_ok());
    assert!(signRound21.is_ok());
    assert!(signRound31.is_ok());

    let signRound12 = key1.signRound2(&[signRound21.clone().unwrap(), signRound31.clone().unwrap()]);
    let signRound22 = key2.signRound2(&[signRound11.clone().unwrap(), signRound31.clone().unwrap()]);
    let signRound32 = key3.signRound2(&[signRound11.clone().unwrap(), signRound21.clone().unwrap()]);

    assert!(signRound12.is_ok());
    assert!(signRound22.is_ok());
    assert!(signRound32.is_ok());

    let signRound13 = key1.signRound3(filter(key1.dkr.get_player_id(), &vec![signRound12.clone().unwrap(), signRound22.clone().unwrap(), signRound32.clone().unwrap()]));
    let signRound23 = key2.signRound3(filter(key2.dkr.get_player_id(), &vec![signRound12.clone().unwrap(), signRound22.clone().unwrap(), signRound32.clone().unwrap()]));
    let signRound33 = key3.signRound3(filter(key3.dkr.get_player_id(), &vec![signRound12.clone().unwrap(), signRound22.clone().unwrap(), signRound32.clone().unwrap()]));


    assert!(signRound13.is_ok());
    assert!(signRound23.is_ok());
    assert!(signRound33.is_ok());

    let signRound14 = key1.signRound4(&vec![signRound23.clone().unwrap(), signRound33.clone().unwrap()]);
    let signRound24 = key2.signRound4(&vec![signRound13.clone().unwrap(), signRound33.clone().unwrap()]);
    let signRound34 = key3.signRound4(&vec![signRound13.clone().unwrap(), signRound23.clone().unwrap()]);

    assert!(signRound14.is_ok());
    assert!(signRound24.is_ok());
    assert!(signRound34.is_ok());

   /* let pubKey = key1.share_key.public_key;

    //check with polkadot lib
    let signature = signRound14.unwrap();
    let publicKey = PublicKey::from_bytes(&pubKey.get_element().as_bytes()[..]).unwrap();
    let sg = bitcoin::Signature::from_bytes(&signature.to_bytes()).unwrap();

    assert!(publicKey.verify(ctx.bytes(&message), &sg).is_ok(), "not verified by polkadot lib");
*/

}
