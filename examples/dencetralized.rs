use std::{
    collections::HashMap,
    net::{TcpListener, TcpStream},
    //io::{Read, Write},
    sync::{Arc, Mutex},
    //thread,
    time::{Duration, Instant},
};

use serde::{Serialize, Deserialize};
use structopt::StructOpt;



use cait_sith::{
    keygen, presign,
    protocol::{Action, MessageData, Participant, Protocol},
    sign, triples, PresignArguments,
};
use digest::{Digest, FixedOutput};
use easy_parallel::Parallel;
use ecdsa::hazmat::DigestPrimitive;
use elliptic_curve::{ops::Reduce, Curve};
use haisou_chan::{channel, Bandwidth};

use k256::{FieldBytes, Scalar, Secp256k1};
use rand_core::OsRng;

#[derive(Debug, StructOpt)]
struct Args {
    /// The number of parties to run the protocol with.
    parties: u32,
    /// The threshold for the protocol.
    threshold: u32,
    /// The ID of this party (0-indexed).
    party_id: u32,
    /// The base port to use for connections.
    base_port: u16,
}

#[derive(Serialize, Deserialize)]
struct Message {
    from: Participant,
    to: Participant,
    data: Vec<u8>,
}

fn main() {
    let args = Args::from_args();
    let participants: Vec<_> = (0..args.parties)
        .map(|p| Participant::from(p as u32))
        .collect();

    let this_participant = Participant::from(args.party_id);

    // Set up network connections
    let (senders, receivers) = setup_network(&participants, this_participant, args.base_port);

    // Run the protocol
    run_protocol(this_participant, &participants, args.threshold as usize, senders, receivers);
}

fn setup_network(participants: &[Participant], this_participant: Participant, base_port: u16) 
    -> (HashMap<Participant, Arc<Mutex<TcpStream>>>, HashMap<Participant, Arc<Mutex<TcpStream>>>)
{
    let mut senders = HashMap::new();
    let mut receivers = HashMap::new();

    // Start listener for incoming connections
    let listener = TcpListener::bind(format!("127.0.0.1:{}", base_port + this_participant.0 as u16)).unwrap();

    // Connect to participants with lower IDs
    for &participant in participants.iter().filter(|&&p| p < this_participant) {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", base_port + participant.0 as u16)).unwrap();
        senders.insert(participant, Arc::new(Mutex::new(stream.try_clone().unwrap())));
        receivers.insert(participant, Arc::new(Mutex::new(stream)));
    }

    // Accept connections from participants with higher IDs
    for _ in participants.iter().filter(|&&p| p > this_participant) {
        let (stream, _) = listener.accept().unwrap();
        let participant = Participant::from(stream.peer_addr().unwrap().port() - base_port);
        senders.insert(participant, Arc::new(Mutex::new(stream.try_clone().unwrap())));
        receivers.insert(participant, Arc::new(Mutex::new(stream)));
    }

    (senders, receivers)
}

fn run_protocol(
    this_participant: Participant,
    participants: &[Participant],
    threshold: usize,
    senders: HashMap<Participant, Arc<Mutex<TcpStream>>>,
    receivers: HashMap<Participant, Arc<Mutex<TcpStream>>>,
) {
    // Triple generation
    println!("Starting Triple Gen");
    let start = Instant::now();
    let triple = triples::generate_triple::<Secp256k1>(participants, this_participant, threshold).unwrap();
    println!("Triple Gen completed in {:?}", start.elapsed());

    // Key generation
    println!("Starting Keygen");
    let start = Instant::now();
    let share = keygen(participants, this_participant, threshold).unwrap();
    println!("Keygen completed in {:?}", start.elapsed());

    // Presigning
    println!("Starting Presign");
    let start = Instant::now();
    let (other_triples_pub, other_triples_share) =
        triples::deal(&mut OsRng, participants, threshold);
    let presign_out = presign(
        participants,
        this_participant,
        PresignArguments {
            triple0: triple,
            triple1: (other_triples_share, other_triples_pub),
            keygen_out: share.clone(),
            threshold,
        },
    ).unwrap();
    println!("Presign completed in {:?}", start.elapsed());

    // Signing
    println!("Starting Sign");
    let start = Instant::now();
    let signature = sign(
        participants,
        this_participant,
        share.public_key,
        presign_out,
        scalar_hash(b"hello world"),
    ).unwrap();
    println!("Sign completed in {:?}", start.elapsed());

    println!("Protocol completed successfully!");
}

// Implement network send and receive functions here
// These functions should use the senders and receivers hashmaps to communicate with other parties