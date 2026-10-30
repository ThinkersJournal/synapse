// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse-agent`: drives a non-Claude model as an agent on a Synapse role.
//!
//! Usage: `synapse-agent --role <role> --model <model> [--endpoint <url/> --key-env <VAR>]
//! [--home <dir>] [--every <secs>] [--allow-send <role,role>]`. Without `--endpoint`, `genai` routes by model name and reads
//! the provider's usual key variable (`GEMINI_API_KEY`, `OPENAI_API_KEY`, ...). With it the model is
//! reached on an OpenAI-compatible endpoint (OpenRouter, NVIDIA NIM, a local server), keyed from
//! `--key-env`. `--allow-send` gives the model a `send_message` tool limited to those roles; without it
//! the model has no tools. The key is read from the environment and never printed. Logs go to stderr.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use synapse_agent::{Agent, GenaiResponder};
use synapse_mcp_server::{McpConfig, SynapseMcpServer};

const USAGE: &str = "usage: synapse-agent --role <role> --model <model> [--endpoint <url/> --key-env <VAR>] [--home <dir>] [--every <secs>] [--allow-send <role,role>]";

/// The first argument that is neither one of `known` nor the value after one.
fn unknown_arg(known: &[&str]) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if known.contains(&a.as_str()) {
            args.next();
        } else {
            return Some(a);
        }
    }
    None
}

#[tokio::main]
async fn main() -> ExitCode {
    // Before anything else: a help or version query opens no home, store or port.
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("synapse-agent {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    if let Some(bad) = unknown_arg(&["--role", "--model", "--endpoint", "--key-env", "--home", "--every", "--allow-send"]) {
        eprintln!("synapse-agent: unknown argument {bad:?}; {USAGE}");
        return ExitCode::from(2);
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let Some(role) = arg("--role").or_else(|| std::env::var("SYNAPSE_ROLE").ok()) else {
        eprintln!("synapse-agent: {USAGE}");
        return ExitCode::from(2);
    };
    let Some(model) = arg("--model") else {
        eprintln!("synapse-agent: {USAGE}");
        return ExitCode::from(2);
    };
    let home = match arg("--home") {
        Some(home) => PathBuf::from(home),
        None => match synapse::keystore::default_home() {
            Ok(home) => home,
            Err(_) => {
                eprintln!("synapse-agent: no home: pass --home or set SYNAPSE_HOME");
                return ExitCode::from(2);
            }
        },
    };
    let every = match arg("--every").map(|v| v.parse::<u64>()) {
        None => Duration::from_secs(5),
        Some(Ok(secs)) if secs > 0 => Duration::from_secs(secs),
        Some(_) => {
            eprintln!("synapse-agent: --every takes a whole number of seconds above 0");
            return ExitCode::from(2);
        }
    };
    let responder = match (arg("--endpoint"), arg("--key-env")) {
        (Some(url), Some(key_env)) => GenaiResponder::openai_compatible(&model, &url, &key_env),
        (None, None) => match GenaiResponder::new(&model) {
            Ok(responder) => responder,
            Err(e) => {
                eprintln!("synapse-agent: {e}");
                return ExitCode::FAILURE;
            }
        },
        _ => {
            eprintln!("synapse-agent: --endpoint and --key-env go together");
            return ExitCode::from(2);
        }
    };
    let server = match SynapseMcpServer::start(McpConfig { role, home }).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("synapse-agent: {e}");
            return ExitCode::FAILURE;
        }
    };
    let responder = match arg("--allow-send") {
        Some(list) => responder.with_send_tool(
            server.clone(),
            list.split(',').map(|r| r.trim().to_string()).collect(),
        ),
        None => responder,
    };
    Agent::new(server, responder).run(every).await
}

/// The value after `name` on the command line.
fn arg(name: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == name {
            return args.next();
        }
    }
    None
}
