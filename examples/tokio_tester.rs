use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

async fn run_sender(address: &str) -> Result<(), Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    println!("Connected to: {}", address);

    // Send initial message
    let message = "Hello from sender!";
    stream.write_all(message.as_bytes()).await?;
    println!("Sent: {}", message);

    // Wait for response
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));

    Ok(())
}

async fn run_receiver(address: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(address).await?;
    println!("Listening on: {}", address);

    let (mut socket, _) = listener.accept().await?;
    println!("Accepted connection from: {}", socket.peer_addr()?);

    // Receive message
    let mut buffer = [0; 1024];
    let n = socket.read(&mut buffer).await?;
    println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));

    // Send response
    let response = "Hello back from receiver!";
    socket.write_all(response.as_bytes()).await?;
    println!("Sent: {}", response);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <sender|receiver> <address>", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let address = &args[2];

    match mode.as_str() {
        "sender" => run_sender(address).await?,
        "receiver" => run_receiver(address).await?,
        _ => {
            eprintln!("Invalid mode. Use 'sender' or 'receiver'");
            std::process::exit(1);
        }
    }

    Ok(())
}