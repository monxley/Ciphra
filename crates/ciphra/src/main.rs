//! The `ciphra` command-line interface and REPL.

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;

use ciphra_engine::{DataType, Engine, KdfParams, QueryResult, Value};

const DEFAULT_DATA_DIR: &str = "./ciphra-data";
const PASSPHRASE_ENV: &str = "CIPHRA_PASSPHRASE";
const NEW_PASSPHRASE_ENV: &str = "CIPHRA_NEW_PASSPHRASE";
const DEV_PASSPHRASE: &str = "ciphra-dev-only";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut execute: Vec<String> = Vec::new();
    let mut rotate = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data" | "-d" => {
                data_dir = args.next().ok_or("--data requires a directory argument")?;
            }
            "--execute" | "-e" => {
                execute.push(args.next().ok_or("-e requires a SQL argument")?);
            }
            "--rotate-passphrase" => rotate = true,
            "--help" | "-h" => {
                print_usage();
                return Ok(ExitCode::SUCCESS);
            }
            "--version" | "-V" => {
                println!("ciphra {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            other => return Err(format!("unknown argument: {other} (try --help)")),
        }
    }

    let passphrase = match std::env::var(PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!(
                "warning: {PASSPHRASE_ENV} is not set; using an INSECURE development passphrase"
            );
            DEV_PASSPHRASE.to_string()
        }
    };

    let mut engine = Engine::open(&data_dir, &passphrase).map_err(|e| e.to_string())?;

    if rotate {
        let new_passphrase = match std::env::var(NEW_PASSPHRASE_ENV) {
            Ok(p) if !p.is_empty() => p,
            _ => {
                return Err(format!(
                    "--rotate-passphrase requires {NEW_PASSPHRASE_ENV} to be set"
                ));
            }
        };
        engine
            .rotate_to(&new_passphrase, KdfParams::recommended())
            .map_err(|e| e.to_string())?;
        println!("passphrase rotated; the database is re-encrypted under the new key");
        return Ok(ExitCode::SUCCESS);
    }

    if !execute.is_empty() {
        for sql in &execute {
            run_sql(&mut engine, sql)?;
        }
        return Ok(ExitCode::SUCCESS);
    }

    repl(&mut engine, &data_dir);
    Ok(ExitCode::SUCCESS)
}

fn print_usage() {
    println!(
        "ciphra — an encrypted-by-default SQL database

USAGE:
    ciphra [OPTIONS]

OPTIONS:
    -d, --data <DIR>     Data directory (default: {DEFAULT_DATA_DIR})
    -e, --execute <SQL>  Execute statements and exit (repeatable)
    --rotate-passphrase  Re-encrypt the database under {NEW_PASSPHRASE_ENV}
    -h, --help           Show this help
    -V, --version        Show version

ENVIRONMENT:
    {PASSPHRASE_ENV}       Passphrase the master key is derived from
    {NEW_PASSPHRASE_ENV}   New passphrase for --rotate-passphrase

REPL COMMANDS:
    .tables              List tables
    .schema <table>      Show a table's schema
    .help                Show SQL help
    .exit                Quit"
    );
}

fn repl(engine: &mut Engine, data_dir: &str) {
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        println!(
            "ciphra {} — encrypted at rest, queryable at will",
            env!("CARGO_PKG_VERSION")
        );
        println!("data directory: {data_dir}");
        println!("type .help for help, .exit to quit");
    }

    let stdin = std::io::stdin();
    let mut buffer = String::new();
    loop {
        if interactive {
            let prompt = if buffer.is_empty() {
                "ciphra> "
            } else {
                "   ...> "
            };
            print!("{prompt}");
            let _ = std::io::stdout().flush();
        }
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("error reading input: {e}");
                break;
            }
        }
        let trimmed = line.trim();

        if buffer.is_empty() && trimmed.starts_with('.') {
            if !meta_command(engine, trimmed) {
                break;
            }
            continue;
        }

        buffer.push_str(&line);
        // Execute once the statement (or batch) is terminated.
        if trimmed.ends_with(';') || (interactive && trimmed.is_empty()) {
            let sql = std::mem::take(&mut buffer);
            if sql.trim().is_empty() {
                continue;
            }
            if let Err(message) = run_sql(engine, &sql) {
                eprintln!("{message}");
            }
        }
    }
}

/// Handle a `.command`. Returns `false` when the REPL should exit.
fn meta_command(engine: &mut Engine, command: &str) -> bool {
    let mut parts = command.split_whitespace();
    match parts.next().unwrap_or("") {
        ".exit" | ".quit" => return false,
        ".help" => {
            println!(
                "SQL:
    CREATE TABLE t (id INT PRIMARY KEY, name TEXT, ssn TEXT ENCRYPTED);
    INSERT INTO t (id, name) VALUES (1, 'alice'), (2, 'bob');
    SELECT * FROM t WHERE id >= 2 AND (name = 'bob' OR ssn IS NULL)
        ORDER BY id DESC LIMIT 10 OFFSET 5;
    UPDATE t SET name = 'robert' WHERE id = 2;
    DELETE FROM t WHERE name = 'bob';
    CREATE INDEX ON t (name);
    DROP INDEX ON t (name);
    DROP TABLE t;

All rows are ChaCha20-Poly1305 encrypted before they reach disk."
            );
        }
        ".tables" => match engine.tables() {
            Ok(tables) if tables.is_empty() => println!("(no tables)"),
            Ok(tables) => {
                for table in tables {
                    println!("{table}");
                }
            }
            Err(e) => eprintln!("{e}"),
        },
        ".schema" => match parts.next() {
            None => eprintln!("usage: .schema <table>"),
            Some(name) => match engine.schema(name) {
                Ok(None) => eprintln!("no such table: {name:?}"),
                Ok(Some(schema)) => {
                    for col in &schema.columns {
                        let ty = match col.ty {
                            DataType::Int => "INT",
                            DataType::Text => "TEXT",
                        };
                        let pk = if col.primary_key { " PRIMARY KEY" } else { "" };
                        let enc = if col.encrypted { " ENCRYPTED" } else { "" };
                        let idx = if col.indexed { " INDEXED" } else { "" };
                        println!("{} {ty}{pk}{enc}{idx}", col.name);
                    }
                }
                Err(e) => eprintln!("{e}"),
            },
        },
        other => eprintln!("unknown command: {other} (try .help)"),
    }
    true
}

fn run_sql(engine: &mut Engine, sql: &str) -> Result<(), String> {
    let results = engine.execute(sql).map_err(|e| e.to_string())?;
    for result in results {
        print_result(&result);
    }
    Ok(())
}

fn print_result(result: &QueryResult) {
    match result {
        QueryResult::Created(name) => println!("created table {name}"),
        QueryResult::Dropped(name) => println!("dropped table {name}"),
        QueryResult::IndexCreated { table, column } => {
            println!("created index on {table} ({column})")
        }
        QueryResult::IndexDropped { table, column } => {
            println!("dropped index on {table} ({column})")
        }
        QueryResult::Inserted(n) => println!("inserted {n} row{}", plural(*n)),
        QueryResult::Updated(n) => println!("updated {n} row{}", plural(*n)),
        QueryResult::Deleted(n) => println!("deleted {n} row{}", plural(*n)),
        QueryResult::Rows { columns, rows } => print_table(columns, rows),
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Render rows as an aligned ASCII table.
fn print_table(columns: &[String], rows: &[Vec<Value>]) {
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.iter().map(Value::to_string).collect())
        .collect();
    let mut widths: Vec<usize> = columns.iter().map(String::len).collect();
    for row in &cells {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }

    let separator: String = widths
        .iter()
        .map(|w| format!("+{}", "-".repeat(w + 2)))
        .chain(std::iter::once("+".to_string()))
        .collect();

    println!("{separator}");
    print_row(columns.iter().map(String::as_str), &widths);
    println!("{separator}");
    for row in &cells {
        print_row(row.iter().map(String::as_str), &widths);
    }
    println!("{separator}");
    println!("{} row{}", rows.len(), plural(rows.len()));
}

fn print_row<'a>(cells: impl Iterator<Item = &'a str>, widths: &[usize]) {
    let mut line = String::new();
    for (cell, width) in cells.zip(widths) {
        line.push_str(&format!("| {cell:<width$} "));
    }
    line.push('|');
    println!("{line}");
}
