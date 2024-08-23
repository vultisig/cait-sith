use k256::{AffinePoint, Scalar, Secp256k1};
use rand_core::OsRng;

use crate::compat::scalar_hash;
use crate::keyshare::reshare_keygen_output;
use crate::participants;
use k256::elliptic_curve::CurveArithmetic;

// ... existing imports ...
use crate::protocol;
use crate::protocol::Action;
use crate::protocol::{run_protocol_mpc, Participant, Protocol};
use crate::reshare;
use crate::test::{run_presign, run_reshare, run_sign};
use crate::CSCurve;

use crate::{
    keygen, presign, sign,
    triples::{self, TriplePub, TripleShare},
    FullSignature, KeygenOutput, PresignArguments, PresignOutput,
};

fn run_keygen_mpc(
    participants: Vec<Participant>,
    threshold: usize,
    i: usize, //my id
) -> impl Protocol<Output = KeygenOutput<Secp256k1>> {
    let protocol = keygen(&participants, participants[i], threshold);
    assert!(protocol.is_ok());
    protocol.unwrap()
}

fn run_reshare_mpc<C: CSCurve>(
    old_participants_list: &[protocol::Participant],
    old_threshold: usize,
    new_participants: &[Participant],
    new_threshold: usize,
    p: Participant,
    out: (Option<Scalar>, AffinePoint),
) -> impl Protocol<Output = KeygenOutput<Secp256k1>> {
    #[allow(clippy::type_complexity)]
    let protocol = reshare_keygen_output::<Secp256k1>(
        &old_participants_list,
        old_threshold,
        new_participants,
        new_threshold,
        p,
        out.0,
        out.1,
    );
    assert!(protocol.is_ok());

    protocol.unwrap()

    // Transform the protocol.unwrap() to match the expected function output
    /*let inner_protocol = protocol.unwrap();

    struct ReshareProtocolWrapper {
        inner: Box<dyn Protocol<Output = Scalar>>,
        public_key: AffinePoint,
    }

    impl Protocol for ReshareProtocolWrapper {
        type Output = KeygenOutput<Secp256k1>;

        fn poke(&mut self) -> Result<Action<Self::Output>, protocol::ProtocolError> {
            match self.inner.poke() {
                Ok(Action::Return(scalar)) => Ok(Action::Return(KeygenOutput {
                    private_share: scalar,
                    public_key: self.public_key,
                })),
                Ok(other_action) => Ok(match other_action {
                    Action::Wait => Action::Wait,
                    Action::SendMany(data) => Action::SendMany(data),
                    Action::SendPrivate(to, data) => Action::SendPrivate(to, data),
                    _ => unreachable!("All Action variants should be covered"),
                }),
                Err(e) => Err(e),
            }
        }

        fn message(&mut self, from: Participant, data: protocol::MessageData) {
            self.inner.message(from, data);
        }
    }

    ReshareProtocolWrapper {
        inner: Box::new(inner_protocol),
        public_key: out.1,
    }*/
}

fn run_presign_mpc(
    participant_list: Vec<Participant>,
    share0: TripleShare<Secp256k1>,
    share1: TripleShare<Secp256k1>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
    keygen_out: KeygenOutput<Secp256k1>,
    p: Participant,
) -> impl Protocol<Output = PresignOutput<Secp256k1>> {
    /*println!("Debug: Participant list length: {}", participant_list.len());
    println!("Debug: Current participant: {:?}", p);
    println!("Debug: Threshold: {}", threshold);
    println!("Debug: Keygen output public key: {:?}", keygen_out.public_key);*/

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

    if let Err(ref e) = protocol {
        println!("Debug: Presign error: {:?}", e);
    }

    assert!(protocol.is_ok());
    protocol.unwrap()
}

#[allow(clippy::type_complexity)]
fn run_sign_mpc(
    participant_list: Vec<Participant>,
    public_key: AffinePoint,
    msg: &[u8],
    p: Participant,
    presign_out: PresignOutput<Secp256k1>,
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
//#[ignore]
fn test_e2e_mpc() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        Participant::from(4u32),
        Participant::from(5u32),
        Participant::from(6u32),
        Participant::from(7u32),
        Participant::from(8u32),
        Participant::from(9u32),
        Participant::from(10u32),
        Participant::from(11u32),
        Participant::from(12u32),
        Participant::from(13u32),
        Participant::from(14u32),
        Participant::from(15u32),
        Participant::from(16u32),
        Participant::from(17u32),
        Participant::from(18u32),
        Participant::from(19u32),
        Participant::from(20u32),
    ];
    let t = 14;

    //#[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    for p in 0..participants.len() {
        let protocol = run_keygen_mpc(participants.clone(), t, p);
        protocols.push((participants[p], Box::new(protocol)));
    }
    //mpc protocol for dkg
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }
    let mut keygen_result = out;
    keygen_result.sort_by_key(|(p, _)| *p);

    //println!("this is keygen {:?} \n", keygen_result);

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
        let protocol = run_presign_mpc(
            participant_list.clone(),
            share0,
            share1,
            &pub0,
            &pub1,
            t,
            keygen_out,
            p,
        );
        protocols.push((p, Box::new(protocol)));
    }

    //mpc protocol for presign
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);

            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }

    let mut presign_result = out;
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

    //start run mpc protocol

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);

            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        println!("out {:?} \n ", out);
    }
}

#[test]
//#[ignore]
fn test_e2e_mpc_reshare() {
    let new_participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        Participant::from(4u32),
        Participant::from(5u32),
        Participant::from(6u32),
    ];
    let t: usize = 2;

    let participants = &new_participants[..3];
    let new_t = 6;
    //#[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    for p in 0..participants.len() {
        let protocol = keygen(&participants, participants[p], t);
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((participants[p], Box::new(protocol)));
    }
    //mpc protocol for dkg
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }
    let mut keygen_result = out;
    keygen_result.sort_by_key(|(p, _)| *p);

    //println!("this is keygen {:?} \n", keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    //let mut reshare_result = run_reshare::<Secp256k1>(keygen_result, t, &new_participants, new_t);

    //_____________________________reshare 1/2

    let old_participants: Vec<_> = keygen_result.clone().into_iter().collect();
    let old_participants_list: Vec<Participant> =
        old_participants.iter().map(|(p, _)| *p).collect();
    let participant_len = old_participants.len();
    let pub_key = old_participants[0].1.public_key;
    let mut setup: Vec<_> = old_participants
        .into_iter()
        .map(|(p, out)| (p, (Some(out.private_share), out.public_key)))
        .collect();
    for i in participant_len..new_participants.len() {
        setup.push((Participant::from(i as u32), (None, pub_key)));
    }
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = KeygenOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participant_len);

    for (p, out) in setup.iter() {
        let protocol = reshare_keygen_output::<Secp256k1>(
            &old_participants_list,
            t,
            &new_participants,
            new_t,
            *p,
            out.0,
            out.1,
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((*p, Box::new(protocol)));
    }

    //________________________________reshare 2/2_
    //mpc protocol for reshare
    println!("this is protocol len {:?} \n", protocols.len());
    println!(
        "this is new participent len {:?} \n",
        new_participants.len()
    );

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }

    let mut reshare_result = out;
    reshare_result.sort_by_key(|(p, _)| *p);

    //________________________________triples________________________________

    let (pub0, shares0) = triples::deal(&mut OsRng, &new_participants, new_t);
    let (pub1, shares1) = triples::deal(&mut OsRng, &new_participants, new_t);

    assert!(reshare_result.len() == shares0.len());
    assert!(reshare_result.len() == shares1.len());
    //#[allow(clippy::type_complexity)]

    println!("triples done");

    /*//____________
    let mut presign_result = run_presign(reshare_result, shares0, shares1, &pub0, &pub1, t);
    println!("end presign");

    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key, msg);*/

    //__________________________________presign 1/2__________________________
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(reshare_result.len());

    let participant_list: Vec<Participant> = reshare_result.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in reshare_result
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
        let protocol = run_presign_mpc(
            participant_list.clone(),
            share0,
            share1,
            &pub0,
            &pub1,
            new_t,
            keygen_out,
            p,
        );
        protocols.push((p, Box::new(protocol)));
    }

    //println!("presign 1/2 done");

    //____________________________________presign 2/2_____________________________

    //mpc protocol for presign
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);

            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }

    let mut presign_result = out;
    presign_result.sort_by_key(|(p, _)| *p);

    println!("presign done");

    let msg = b"hello world";

    //_____________________________________sign 1/2__________________________________
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(presign_result.len());

    let participant_list: Vec<Participant> = presign_result.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in presign_result.into_iter() {
        let protocol = run_sign_mpc(participant_list.clone(), public_key, msg, p, presign_out);
        protocols.push((p, Box::new(protocol)));
    }

    //____________________________________sign 2/2 ____________________________________

    //start run mpc protocol

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            //println!("loop {:?} \n ", i);

            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
        //println!("out {:?} \n ", out);
    }
}
