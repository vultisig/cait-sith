use k256::{AffinePoint, Scalar, Secp256k1};
use rand_core::OsRng;
use std::time::{Duration, Instant};

use crate::compat::scalar_hash;
use crate::triples::TripleGenerationOutput;
use crate::triples::generate_triple;
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
fn test_e2e_mpc_3_2() {
    let num_runs = 1;
    let mut total_duration = Duration::new(0, 0);

    for _ in 0..num_runs {
        let start = Instant::now();
        test_e2e_mpc(3, 2);
        total_duration += start.elapsed();
    }

    let mean_duration = total_duration / num_runs as u32;
    println!("Mean duration over {} runs: {:?}", num_runs, mean_duration);
}

#[test]
fn test_e2e_mpc_20_14() {
    let num_runs = 1;
    let mut total_duration = Duration::new(0, 0);

    for _ in 0..num_runs {
        let start = Instant::now();
        test_e2e_mpc(20, 14);
        total_duration += start.elapsed();
    }

    let mean_duration = total_duration / num_runs as u32;
    println!("Mean duration over {} runs: {:?}", num_runs, mean_duration);
}

#[test]
fn test_e2e_mpc_5_3() {
    test_e2e_mpc(5, 3);
}

fn test_e2e_mpc(num_participants: usize, t: usize) {
    let participants: Vec<Participant> = (0..num_participants)
        .map(|i| Participant::from(i as u32))
        .collect();
    // Keygen
    let keygen_start = Instant::now();
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
    
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }
    let mut keygen_result = out;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let keygen_duration = keygen_start.elapsed();
    println!("Keygen duration: {:?}", keygen_duration);


    // Triple Generation
    let triple_gen_start = Instant::now();
    let mut protocols1: Vec<(
        Participant,
        Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());
    let mut protocols0: Vec<(
        Participant,
        Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    for &p in &participants {
        let protocol1 = generate_triple(&participants, p, t);
        let protocol0 = generate_triple(&participants, p, t);

        assert!(protocol1.is_ok());
        assert!(protocol0.is_ok());

        let protocol1 = protocol1.unwrap();
        let protocol0 = protocol0.unwrap();

        protocols1.push((p, Box::new(protocol1)));
        protocols0.push((p, Box::new(protocol0)));
    }

    let size = protocols1.len();
    let mut out1 = Vec::with_capacity(size);
    let mut out0 = Vec::with_capacity(size);
    while out1.len() < size || out0.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols1, size, i, &mut out1).unwrap();
            run_protocol_mpc(&mut protocols0, size, i, &mut out0).unwrap();
        }
    }

    let pub1: TriplePub<Secp256k1> = out1[0].1.1.clone();
    let pub0: TriplePub<Secp256k1> = out0[0].1.1.clone();

    out1.sort_by_key(|(p, _)| *p);
    out0.sort_by_key(|(p, _)| *p);
    let shares1: Vec<TripleShare<Secp256k1>> = out1.into_iter().map(|(_, (share, _))| share).collect();
    let shares0: Vec<TripleShare<Secp256k1>> = out0.into_iter().map(|(_, (share, _))| share).collect();

    let triple_gen_duration = triple_gen_start.elapsed();
    println!("Triple Generation duration: {:?}", triple_gen_duration);

    // Presigning
    let presigning_start = Instant::now();
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

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }

    let mut presign_result = out;
    presign_result.sort_by_key(|(p, _)| *p);

    let presigning_duration = presigning_start.elapsed();
    println!("Presigning duration: {:?}", presigning_duration);

    let msg = b"hello world";

    // Signing
    let signing_start = Instant::now();
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(presign_result.len());

    let participant_list: Vec<Participant> = presign_result.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in presign_result.into_iter() {
        let protocol = run_sign_mpc(participant_list.clone(), public_key, msg, p, presign_out);
        protocols.push((p, Box::new(protocol)));
    }

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }

    let signing_duration = signing_start.elapsed();
    println!("Signing duration: {:?}", signing_duration);

    let total_duration = keygen_duration + triple_gen_duration + presigning_duration + signing_duration;
    println!("Total duration: {:?}", total_duration);
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

    // Keygen
    let keygen_start = Instant::now();
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
    
    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }
    let mut keygen_result = out;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let keygen_duration = keygen_start.elapsed();
    println!("Keygen duration: {:?}", keygen_duration);

    // Resharing
    let resharing_start = Instant::now();
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

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }

    let mut reshare_result = out;
    reshare_result.sort_by_key(|(p, _)| *p);

    let resharing_duration = resharing_start.elapsed();
    println!("Resharing duration: {:?}", resharing_duration);

    // Triple Generation
    let triple_gen_start = Instant::now();
    let mut protocols1: Vec<(
        Participant,
        Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
    )> = Vec::with_capacity(new_participants.len());
    let mut protocols0: Vec<(
        Participant,
        Box<dyn Protocol<Output = TripleGenerationOutput<Secp256k1>>>,
    )> = Vec::with_capacity(new_participants.len());

    for &p in &new_participants {
        let protocol1 = generate_triple(&new_participants, p, new_t);
        let protocol0 = generate_triple(&new_participants, p, new_t);

        assert!(protocol1.is_ok());
        assert!(protocol0.is_ok());

        let protocol1 = protocol1.unwrap();
        let protocol0 = protocol0.unwrap();

        protocols1.push((p, Box::new(protocol1)));
        protocols0.push((p, Box::new(protocol0)));
    }

    let size = protocols1.len();
    let mut out1 = Vec::with_capacity(size);
    let mut out0 = Vec::with_capacity(size);
    while out1.len() < size || out0.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols1, size, i, &mut out1).unwrap();
            run_protocol_mpc(&mut protocols0, size, i, &mut out0).unwrap();
        }
    }

    let pub1: TriplePub<Secp256k1> = out1[0].1.1.clone();
    let pub0: TriplePub<Secp256k1> = out0[0].1.1.clone();

    out1.sort_by_key(|(p, _)| *p);
    out0.sort_by_key(|(p, _)| *p);
    let shares1: Vec<TripleShare<Secp256k1>> = out1.into_iter().map(|(_, (share, _))| share).collect();
    let shares0: Vec<TripleShare<Secp256k1>> = out0.into_iter().map(|(_, (share, _))| share).collect();

    let triple_gen_duration = triple_gen_start.elapsed();
    println!("Triple Generation duration: {:?}", triple_gen_duration);

    // Presigning
    let presigning_start = Instant::now();
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

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }

    let mut presign_result = out;
    presign_result.sort_by_key(|(p, _)| *p);

    let presigning_duration = presigning_start.elapsed();
    println!("Presigning duration: {:?}", presigning_duration);

    let msg = b"hello world";

    // Signing
    let signing_start = Instant::now();
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(presign_result.len());

    let participant_list: Vec<Participant> = presign_result.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in presign_result.into_iter() {
        let protocol = run_sign_mpc(participant_list.clone(), public_key, msg, p, presign_out);
        protocols.push((p, Box::new(protocol)));
    }

    let size = protocols.len();
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        for i in 0..size {
            run_protocol_mpc(&mut protocols, size, i, &mut out).unwrap();
        }
    }

    let signing_duration = signing_start.elapsed();
    println!("Signing duration: {:?}", signing_duration);

    let total_duration = keygen_duration + resharing_duration + triple_gen_duration + presigning_duration + signing_duration;
    println!("Total duration: {:?}", total_duration);
}
