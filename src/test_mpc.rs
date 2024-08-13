use k256::{AffinePoint, Secp256k1};
use rand_core::OsRng;

use crate::compat::scalar_hash;
use crate::protocol::{run_protocol, Participant, Protocol};


use crate::{
    keygen, presign,
    sign,
    triples::{self, TriplePub, TripleShare},
    FullSignature, KeygenOutput, PresignArguments, PresignOutput,
};


fn run_keygen_mpc(
    participants: Vec<Participant>,
    threshold: usize,
    i : usize, //my id 
) -> impl Protocol<Output = KeygenOutput<Secp256k1>> { 
    let protocol = keygen(&participants, participants[i], threshold);
    assert!(protocol.is_ok());
    protocol.unwrap()
}



fn run_presign_mpc(
    participant_list: Vec<Participant>,
    share0: TripleShare<Secp256k1>,
    share1: TripleShare<Secp256k1>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
    keygen_out : KeygenOutput<Secp256k1>,
    p : Participant,
) -> impl Protocol<Output = PresignOutput<Secp256k1>> {
    
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                triple0: (share0, pub0.clone()),
                triple1: (share1, pub1.clone()),
                keygen_out,
                threshold,
            },
        );
        assert!(protocol.is_ok());
        protocol.unwrap()
}


#[allow(clippy::type_complexity)]
fn run_sign_mpc(
    participant_list: Vec<Participant>,
    public_key: AffinePoint,
    msg: &[u8],
    p : Participant,
    presign_out : PresignOutput<Secp256k1>,
) -> impl Protocol<Output = FullSignature<Secp256k1>> {
    
    let protocol = sign(
        &participant_list,
        p,
        public_key,
        presign_out,
        scalar_hash(msg),
    );
    assert!(protocol.is_ok());
    protocol.unwrap()
}



#[test]
fn test_e2e_mpc() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;

    //#[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());


    for p in 0..participants.len() {
        let protocol = run_keygen_mpc(participants.clone(), t, p);
        protocols.push((participants[p], Box::new(protocol)));
    }
    let mut keygen_result = run_protocol(protocols).unwrap();
    keygen_result.sort_by_key(|(p, _)| *p);

    println!("this is keygen {:?} \n", keygen_result);


    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

    assert!(keygen_result.len() == shares0.len());
    assert!(keygen_result.len() == shares1.len());
    //#[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(keygen_result.len());

    let participant_list: Vec<Participant> = keygen_result.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in keygen_result
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {

        let protocol = run_presign_mpc(participant_list.clone(), share0, share1, &pub0, &pub1, t, keygen_out, p);
        protocols.push((p, Box::new(protocol)));

    }
    let mut presign_result = run_protocol(protocols).unwrap();
    presign_result.sort_by_key(|(p, _)| *p);

    println!("this is presign {:?} \n", presign_result);


    let msg = b"hello world";

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(presign_result.len());

    let participant_list: Vec<Participant> = presign_result.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in presign_result.into_iter() {
        
        let protocol = run_sign_mpc(participant_list.clone(), public_key, msg, p, presign_out);
        protocols.push((p, Box::new(protocol)));
    
    }

    run_protocol(protocols).unwrap();

}