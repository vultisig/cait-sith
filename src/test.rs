use k256::{AffinePoint, Scalar, Secp256k1};
use rand_core::OsRng;

use crate::{
    compat::scalar_hash,
    keygen, presign,
    protocol::{run_protocol, Participant, Protocol},
    reshare, sign,
    triples::{self, TriplePub, TripleShare},
    CSCurve, FullSignature, KeygenOutput, PresignArguments, PresignOutput,
};

fn run_keygen(
    participants: Vec<Participant>,
    threshold: usize,
) -> Vec<(Participant, KeygenOutput<Secp256k1>)> {
    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = keygen(&participants, *p, threshold);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

pub fn run_reshare<C: CSCurve>(
    old_participants: Vec<(Participant, KeygenOutput<Secp256k1>)>,
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
) -> Vec<(Participant, Scalar)> {
    #[allow(clippy::type_complexity)]
    let old_participants: Vec<_> = old_participants.into_iter().collect();
    let old_participants_list: Vec<Participant> =
        old_participants.iter().map(|(p, _)| *p).collect();
    let participant_len = old_participants.len();
    let pub_key = old_participants[0].1.public_key;
    let mut setup: Vec<_> = old_participants
        .into_iter()
        .map(|(p, out)| (p, (Some(out.private_share), out.public_key)))
        .collect();
    setup.push((Participant::from(participant_len as u32), (None, pub_key)));
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Scalar>>)> =
        Vec::with_capacity(participant_len);

    for (p, out) in setup.iter() {
        let protocol = reshare::<Secp256k1>(
            &old_participants_list,
            old_threshold,
            new_participants,
            new_threshold,
            *p,
            out.0,
            out.1,
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((*p, Box::new(protocol)));
    }
    run_protocol(protocols).unwrap()
}

fn run_presign(
    participants: Vec<(Participant, KeygenOutput<Secp256k1>)>,
    shares0: Vec<TripleShare<Secp256k1>>,
    shares1: Vec<TripleShare<Secp256k1>>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
) -> Vec<(Participant, PresignOutput<Secp256k1>)> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in participants
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
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
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
        println!("protocl box");
    }

    run_protocol(protocols).unwrap()
}

#[allow(clippy::type_complexity)]
fn run_sign(
    participants: Vec<(Participant, PresignOutput<Secp256k1>)>,
    public_key: AffinePoint,
    msg: &[u8],
) -> Vec<(Participant, FullSignature<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in participants.into_iter() {
        let protocol = sign(
            &participant_list,
            p,
            public_key,
            presign_out,
            scalar_hash(msg),
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_e2e() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let t = 3;

    let mut keygen_result = run_keygen(participants.clone(), t);
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, t);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key, msg);
}

#[test]
fn test_e2e_reshare() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        //Participant::from(4u32),
    ];
    let t = 3;
    let new_t = 3;

    println!("start");

    let mut keygen_result = run_keygen(participants[..3].to_vec(), t);
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let mut reshare_result = run_reshare::<Secp256k1>(keygen_result, t, &participants, new_t);
    println!("end reshare");
    reshare_result.sort_by_key(|(p, _)| *p);

    let presign_input: Vec<(Participant, KeygenOutput<Secp256k1>)> = reshare_result
        .into_iter()
        .map(|(p, scalar)| {
            (
                p,
                KeygenOutput {
                    private_share: scalar,
                    public_key,
                },
            )
        })
        .collect();

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, t);

    println!("end triples");

    let mut presign_result = run_presign(presign_input, shares0, shares1, &pub0, &pub1, t);
    println!("end presign");

    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key, msg);
}
