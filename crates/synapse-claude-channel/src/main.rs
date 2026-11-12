// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse-claude-channel`: the Claude Code channel adapter over `synapsed` (M7).
//!
//! Usage: `synapse-claude-channel --role <role> [--home <dir>]`, or set `SYNAPSE_ROLE`. stdout
//! carries the MCP protocol; logs go to stderr. No output names a key path.

use std::path::PathBuf;
use std::process::ExitCode;

use rmcp::ServiceExt;
use rmcp::transport::stdio;
use synapse_claude_channel::{ChannelConfig, ChannelServer};
use synapse_mcp_server::McpConfig;

const USAGE: &str = "usage: synapse-claude-channel --role <role> [--home <dir>] (or SYNAPSE_ROLE)";

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
            println!("synapse-claude-channel {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    if let Some(bad) = unknown_arg(&["--role", "--home"]) {
        eprintln!("synapse-claude-channel: unknown argument {bad:?}; {USAGE}");
        return ExitCode::from(2);
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let Some(role) = arg("--role").or_else(|| std::env::var("SYNAPSE_ROLE").ok()) else {
        eprintln!("synapse-claude-channel: {USAGE}");
        return ExitCode::from(2);
    };
    let home = match arg("--home") {
        Some(home) => PathBuf::from(home),
        None => match synapse::keystore::default_home() {
            Ok(home) => home,
            Err(_) => {
                eprintln!("synapse-claude-channel: no home: pass --home or set SYNAPSE_HOME");
                return ExitCode::from(2);
            }
        },
    };
    let server =
        match ChannelServer::start(McpConfig { role, home }, ChannelConfig::default()).await {
            Ok(server) => server,
            Err(e) => {
                eprintln!("synapse-claude-channel: {e}");
                return ExitCode::FAILURE;
            }
        };
    let service = match server.serve(stdio()).await {
        Ok(service) => service,
        Err(e) => {
            eprintln!("synapse-claude-channel: MCP initialization failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    match service.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("synapse-claude-channel: the server task failed: {e}");
            ExitCode::FAILURE
        }
    }
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
