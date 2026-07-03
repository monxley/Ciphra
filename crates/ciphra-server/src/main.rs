//! `ciphra-server` — the blind half of Ciphra's client/server split.
//!
//! Per ADR-0003 this process stores and serves sealed bytes. It has no
//! passphrase, derives no keys, and cannot decrypt anything it holds:
//! SQL, encryption and query planning all run in the client engine.

use std::net::TcpListener;
use std::process::ExitCode;

use ciphra_crypto::ServerIdentity;
use ciphra_net::{FollowEvent, SharedStorage};
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
    let mut follow: Option<String> = None;
    let mut server_key: Option<[u8; 32]> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data" | "-d" => {
                data_dir = args.next().ok_or("--data requires a directory argument")?;
            }
            "--listen" | "-l" => {
                listen = args.next().ok_or("--listen requires an address argument")?;
            }
            "--follow" | "-f" => {
                follow = Some(args.next().ok_or("--follow requires a leader address")?);
            }
            "--server-key" | "-k" => {
                let hex = args
                    .next()
                    .ok_or("--server-key requires a 64-hex-char key")?;
                server_key = Some(parse_key(&hex)?);
            }
            "--help" | "-h" => {
                println!(
                    "ciphra-server — stores sealed bytes it cannot read

USAGE:
    ciphra-server [--data <DIR>] [--listen <ADDR>]
    ciphra-server --follow <LEADER_ADDR> [--server-key <HEX>] [--data <DIR>] [--listen <ADDR>]

OPTIONS:
    -d, --data <DIR>        Data directory (default: {DEFAULT_DATA_DIR})
    -l, --listen <ADDR>     Listen address (default: {DEFAULT_LISTEN})
    -f, --follow <ADDR>     Run as a read-only replica of the leader at ADDR:
                            mirror its commit stream and serve reads locally.
    -k, --server-key <HEX>  Pin the leader's transport key (with --follow).

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

    if let Some(leader) = follow {
        return run_replica(listener, storage, secret, public, leader, server_key);
    }

    let shared = SharedStorage::new(storage);
    println!("ciphra-server: serving sealed storage from {data_dir} on {listen}");
    println!("(this process has no data keys and cannot decrypt what it stores)");
    println!("transport handshake: hybrid X25519 + ML-KEM-768");
    println!(
        "server key (pin this on clients with --server-key):\n  {}",
        hex(&public)
    );
    ciphra_net::serve(listener, shared, secret).map_err(|e| e.to_string())
}

/// Read-only replica: serve reads from a local store while a background
/// thread mirrors the leader's commit stream into it (log shipping).
fn run_replica(
    listener: TcpListener,
    storage: Storage,
    secret: [u8; 32],
    public: [u8; 32],
    leader: String,
    server_key: Option<[u8; 32]>,
) -> Result<(), String> {
    let shared = SharedStorage::read_only(storage);
    println!("ciphra-server: read-only replica of {leader}");
    println!("(writes are refused here; state is fed by the leader's commit stream)");
    if server_key.is_none() {
        println!("warning: leader key not pinned (--server-key); handshake is trust-on-first-use");
    }
    println!(
        "replica key (pin this on read clients with --server-key):\n  {}",
        hex(&public)
    );

    // Mirror the leader forever, reconnecting on error.
    let follow_handle = shared.clone();
    std::thread::spawn(move || {
        loop {
            let result =
                ciphra_net::follow(
                    &leader,
                    server_key,
                    follow_handle.clone(),
                    |event| match event {
                        FollowEvent::Connected { authenticated, .. } => {
                            let auth = if authenticated {
                                "authenticated"
                            } else {
                                "unauthenticated"
                            };
                            println!("replica: connected to leader ({auth}), subscribing");
                        }
                        FollowEvent::Snapshot { seq, rows } => {
                            println!("replica: applied snapshot at seq {seq} ({rows} rows)");
                        }
                        FollowEvent::Applied { seq, changes } => {
                            println!("replica: applied commit seq {seq} ({changes} changes)");
                        }
                    },
                );
            if let Err(e) = result {
                eprintln!("replica: stream ended ({e}); reconnecting in 2s");
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });

    ciphra_net::serve(listener, shared, secret).map_err(|e| e.to_string())
}

fn parse_key(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("server key must be 64 hex characters (32 bytes)".into());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "server key must be valid hex".to_string())?;
    }
    Ok(key)
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
