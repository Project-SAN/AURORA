use authority::{serve_forever, AuthorityConfig};
use std::env;
use std::net::TcpListener;
use std::process;

fn main() {
    if let Err(err) = run() {
        eprintln!("aurora_authority: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = parse_config_path(env::args().skip(1))?;
    let config = AuthorityConfig::load(&config_path)?;
    let published = config.publish()?;
    let listener = TcpListener::bind(&config.bind_addr)?;

    eprintln!("authority: listening on {}", config.bind_addr);
    eprintln!("authority: signature_scheme={}", published.signature_scheme);
    eprintln!("authority: issued_at={}", published.issued_at);
    eprintln!(
        "authority: directory_public_key={}",
        published.public_key_hex
    );

    serve_forever(&listener, &published)?;
    Ok(())
}

fn parse_config_path(
    mut args: impl Iterator<Item = String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let Some(first) = args.next() else {
        return Ok("authority/config.json".into());
    };

    if first == "--config" {
        let Some(path) = args.next() else {
            return Err("missing path after --config".into());
        };
        if args.next().is_some() {
            return Err("unexpected extra arguments".into());
        }
        return Ok(path);
    }

    if first == "-h" || first == "--help" {
        println!("usage: cargo run -p authority -- --config authority/config.json");
        process::exit(0);
    }

    Err(format!("unknown argument: {first}").into())
}
