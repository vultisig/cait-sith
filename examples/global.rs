use digest::{Digest, FixedOutput};
use easy_parallel::Parallel;
use ecdsa::hazmat::DigestPrimitive;
use elliptic_curve::{ops::Reduce, Curve};
use haisou_chan::{channel, Bandwidth};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use k256::{FieldBytes, Scalar, Secp256k1};
use rand_core::OsRng;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Args {
    /// The number of parties to run the benchmarks with.
    parties: u32,
    //threshold
    threshold: u32,
    /// The latency, in milliseconds.
    latency_ms: u32,
    /// The bandwidth, in bytes per second.
    bandwidth: u32,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <participant_id> <total_participants> <initial_number>",
            args[0]
        );
        eprintln!("  participant_id: 1 to n");
        eprintln!("  total_participants: total number of participants");
        eprintln!("  initial_number: starting number for the protocol");
        std::process::exit(1);
    }

    let participant_id: usize = args[1].parse().expect("Participant ID must be a number");
    let total_participants: usize = args[2]
        .parse()
        .expect("Total participants must be a number");
    let initial_number: f64 = args[3]
        .parse()
        .expect("Initial number must be a valid float");

    if participant_id < 1 || participant_id > total_participants {
        eprintln!(
            "Invalid participant ID. Must be between 1 and {}",
            total_participants
        );
        std::process::exit(1);
    }

    run_protocol(participant_id, total_participants, initial_number);
}

fn run_protocol(id: usize, total: usize, initial: f64) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", 8000 + id)).expect("Failed to bind");
    println!("Participant {} listening on port {}", id, 8000 + id);

    let mut connections = vec![];
    let mut streams = vec![];

    // Connect to participants with lower IDs
    for peer_id in 1..id {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", 8000 + peer_id))
            .expect(&format!("Failed to connect to participant {}", peer_id));
        streams.push(stream);
        println!("Connected to participant {}", peer_id);
    }

    // Accept connections from participants with higher IDs
    for _ in id + 1..=total {
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        connections.push(stream);
    }

    streams.append(&mut connections);

    println!("All connections established. Starting protocol...");

    let mut number = if id == 1 { initial } else { 0.0 };

    for round in 0..total {
        if round == id - 1 {
            // It's our turn to send
            println!("Sending number: {}", number);
            for stream in &mut streams {
                stream
                    .write_all(&number.to_le_bytes())
                    .expect("Failed to send number");
            }
        } else {
            // Receive from the current participant
            let mut buffer = [0u8; 8];
            streams[round]
                .read_exact(&mut buffer)
                .expect("Failed to receive number");
            number = f64::from_le_bytes(buffer);
            println!("Received number: {}", number);
        }

        number /= 2.0;
        println!("Divided by 2. New number: {}", number);

        // Small delay to keep things orderly
        thread::sleep(Duration::from_millis(100));
    }

    println!("Protocol completed. Final number: {}", number);
}
