//! `ciphra-server` — the blind half of Ciphra's client/server split.
//!
//! Per ADR-0003 this process stores and serves sealed bytes. It has no
//! passphrase, derives no keys, and cannot decrypt anything it holds:
//! SQL, encryption and query planning all run in the client engine.

use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

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
    let listener = TcpListener::bind(&listen).map_err(|e| e.to_string())?;
    println!("ciphra-server: serving sealed storage from {data_dir} on {listen}");
    println!("(this process has no keys and cannot decrypt what it stores)");
    ciphra_net::serve(listener, Arc::new(Mutex::new(storage))).map_err(|e| e.to_string())
}
