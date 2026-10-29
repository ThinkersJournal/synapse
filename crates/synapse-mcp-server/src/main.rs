// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse-mcp`: the generic MCP stdio adapter over `synapsed` (M6b).
//!
//! Usage: `synapse-mcp --role <role> [--home <dir>]`, or set `SYNAPSE_ROLE`. The home defaults as
//! for the `synapse` CLI (`SYNAPSE_HOME`, else the platform default). stdout carries the MCP
//! protocol; logs go to stderr. No output names a key path.

use std::path::PathBuf;
use std::process::ExitCode;

use rmcp::ServiceExt;
use rmcp::transport::stdio;
use synapse_mcp_server::{McpConfig, SynapseMcpServer};

#[tokio::main]
async fn main() -> ExitCode {
    // Before anything else: a version query opens no home and starts no server.
    if std::env::args()
        .nth(1)
        .is_some_and(|a| a == "--version" || a == "-V")
    {
        println!("synapse-mcp {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let Some(role) = arg("--role").or_else(|| std::env::var("SYNAPSE_ROLE").ok()) else {
        eprintln!("synapse-mcp: usage: synapse-mcp --role <role> [--home <dir>] (or SYNAPSE_ROLE)");
        return ExitCode::from(2);
    };
    let home = match arg("--home") {
        Some(home) => PathBuf::from(home),
        None => match synapse::keystore::default_home() {
            Ok(home) => home,
            Err(_) => {
                eprintln!("synapse-mcp: no home: pass --home or set SYNAPSE_HOME");
                return ExitCode::from(2);
            }
        },
    };
    let server = match SynapseMcpServer::start(McpConfig { role, home }).await {
        Ok(server) => server,
        Err(e) => {
            eprintln!("synapse-mcp: {e}");
            return ExitCode::FAILURE;
        }
    };
    let service = match server.serve(stdio()).await {
        Ok(service) => service,
        Err(e) => {
            eprintln!("synapse-mcp: MCP initialization failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    match service.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("synapse-mcp: the server task failed: {e}");
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
