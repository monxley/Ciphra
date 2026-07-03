//! `ciphra-server` — the blind half of Ciphra's client/server split.
//!
//! Per ADR-0003 this process stores and serves sealed bytes. It has no
//! passphrase, derives no keys, and cannot decrypt anything it holds:
//! SQL, encryption and query planning all run in the client engine.

use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use ciphra_crypto::ServerIdentity;
use ciphra_storage::Storage;

const DEFAULT_LISTEN: &str = "127.0.0.1:5077";
const DEFAULT_DATA_DIR: &str = "./ciphra-data";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut listen = DEFAULT_LISTEN.to_string();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data" | "-d" => {
                data_dir = args.next().ok_or("--data requires a directory argument")?;
            }
            "--listen" | "-l" => {
                listen = args.next().ok_or("--listen requires an address argument")?;
            }
            "--help" | "-h" => {
                println!(
                    "ciphra-server — stores sealed bytes it cannot read

USAGE:
    ciphra-server [--data <DIR>] [--listen <ADDR>]

OPTIONS:
    -d, --data <DIR>     Data directory (default: {DEFAULT_DATA_DIR})
    -l, --listen <ADDR>  Listen address (default: {DEFAULT_LISTEN})

This process holds no keys: clients connect with `ciphra --remote <ADDR>`
and every byte that crosses the wire or touches this disk is ciphertext."
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other} (try --help)")),
        }
    }

    let storage = Storage::open(&data_dir).map_err(|e| e.to_string())?;

    // Load or create the static transport identity — the key clients
    // pin. It authenticates the server; it does NOT decrypt stored data.
    let (secret, public) = load_or_create_identity(&data_dir)?;

    let listener = TcpListener::bind(&listen).map_err(|e| e.to_string())?;
    println!("ciphra-server: serving sealed storage from {data_dir} on {listen}");
    println!("(this process has no data keys and cannot decrypt what it stores)");
    println!("transport handshake: hybrid X25519 + ML-KEM-768");
    println!(
        "server key (pin this on clients with --server-key):\n  {}",
        hex(&public)
    );
    ciphra_net::serve(listener, Arc::new(Mutex::new(storage)), secret).map_err(|e| e.to_string())
}

const IDENTITY_FILE: &str = "ciphra.serverkey";

fn load_or_create_identity(data_dir: &str) -> Result<([u8; 32], [u8; 32]), String> {
    let path = std::path::Path::new(data_dir).join(IDENTITY_FILE);
    let secret: [u8; 32] = if path.exists() {
        std::fs::read(&path)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| format!("{IDENTITY_FILE} is not a 32-byte key"))?
    } else {
        let identity = ServerIdentity::generate();
        let secret = identity.secret_bytes();
        std::fs::write(&path, secret).map_err(|e| e.to_string())?;
        secret
    };
    let public = ServerIdentity::from_secret(secret).public;
    Ok((secret, public))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
