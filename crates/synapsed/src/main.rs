// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapsed`: serve the Synapse mailbox on loopback until Ctrl-C or a termination signal, then
//! remove its announce file (#74). On Unix that is SIGTERM or SIGHUP; on Windows, Ctrl-Break and the
//! console's close, logoff and shutdown events. Those last three are best-effort: Windows ends the
//! process soon after the handler returns, which may be before the file is removed. A kill
//! (SIGKILL, `taskkill /F`) runs no handler at all. Clients never rely on the file being gone: the
//! health proof decides.
//!
//! Home: `SYNAPSE_HOME` (else the platform default, as for `synapse id`). Address: `SYNAPSE_ADDR`
//! (default `127.0.0.1:7920`), loopback only. Logs never carry tokens or key material.
//! Launch signals (`GET /v1/waiting`, lane launch on message) are OFF unless `SYNAPSE_LAUNCHER_ROLES`
//! names the role(s), comma separated, that may read them (for example `agentlife-launcher`).
//! Security alerts go as mail to the roles in `SYNAPSE_ALERT_ROLES` (comma separated), from
//! `daemon:alerts@<account>`; unset, nothing changes.
//! The mailbox store is redb unless `SYNAPSE_MAILBOX_STORE=sqlite` and the binary was built with
//! `--features sqlite-store` (PersistAnt SQLite, `<home>/mailbox.sqlite`). A different store is a
//! different file: nothing is migrated, and the other file is left untouched.
//! Security events (failed bearers and claims, over-budget requests) go to
//! `<home>/security-events.jsonl`, owner-only; they never carry a token, nonce or signature.

use std::net::SocketAddr;
use std::process::ExitCode;

use synapsed::{Daemon, DaemonConfig, StoreKind};

const DEFAULT_ADDR: &str = "127.0.0.1:7920";

#[tokio::main]
async fn main() -> ExitCode {
    let home = match synapse::keystore::default_home() {
        Ok(home) => home,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let addr: SocketAddr = match std::env::var("SYNAPSE_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.to_string())
        .parse()
    {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!("synapsed: SYNAPSE_ADDR is not an address");
            return ExitCode::from(2);
        }
    };
    let config = DaemonConfig {
        home,
        addr,
        sweep_every: std::time::Duration::from_secs(3600),
    };
    let kind = match std::env::var("SYNAPSE_MAILBOX_STORE").as_deref() {
        Err(_) | Ok("" | "redb") => StoreKind::Redb,
        #[cfg(feature = "sqlite-store")]
        Ok("sqlite") => StoreKind::Sqlite,
        Ok(other) => {
            eprintln!(
                "synapsed: SYNAPSE_MAILBOX_STORE={other:?} is not available in this build                  (redb{})",
                if cfg!(feature = "sqlite-store") {
                    ", sqlite"
                } else {
                    "; sqlite needs --features sqlite-store"
                }
            );
            return ExitCode::from(2);
        }
    };
    let daemon = match Daemon::open_with(&config, kind) {
        Ok(daemon) => daemon,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let launcher_roles: Vec<String> = std::env::var("SYNAPSE_LAUNCHER_ROLES")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(bad) = launcher_roles
        .iter()
        .find(|r| !synapse::keystore::valid_name(r))
    {
        eprintln!("synapsed: SYNAPSE_LAUNCHER_ROLES: {bad:?} is not a role name");
        return ExitCode::from(2);
    }
    let alert_roles = match role_list("SYNAPSE_ALERT_ROLES") {
        Ok(roles) => roles,
        Err(bad) => {
            eprintln!("synapsed: SYNAPSE_ALERT_ROLES: {bad:?} is not a role name");
            return ExitCode::from(2);
        }
    };
    let daemon = daemon
        .with_alert_roles(alert_roles)
        .with_launcher(synapsed::LauncherConfig {
            roles: launcher_roles,
            ..synapsed::LauncherConfig::default()
        });
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("synapsed: cannot listen on {addr}: {}", e.kind());
            return ExitCode::from(2);
        }
    };
    eprintln!("synapsed: listening on {addr}");
    match daemon.serve(listener, shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("synapsed: {}", e.kind());
            ExitCode::from(1)
        }
    }
}

/// Resolves on the first stop request. A handler that cannot be installed just never fires.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).ok();
        let mut hup = signal(SignalKind::hangup()).ok();
        tokio::select! {
            Ok(()) = tokio::signal::ctrl_c() => {}
            Some(()) = async { term.as_mut()?.recv().await } => {}
            Some(()) = async { hup.as_mut()?.recv().await } => {}
            else => std::future::pending::<()>().await,
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let mut brk = windows::ctrl_break().ok();
        let mut close = windows::ctrl_close().ok();
        let mut logoff = windows::ctrl_logoff().ok();
        let mut down = windows::ctrl_shutdown().ok();
        tokio::select! {
            Ok(()) = tokio::signal::ctrl_c() => {}
            Some(()) = async { brk.as_mut()?.recv().await } => {}
            Some(()) = async { close.as_mut()?.recv().await } => {}
            Some(()) = async { logoff.as_mut()?.recv().await } => {}
            Some(()) = async { down.as_mut()?.recv().await } => {}
            else => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// The comma-separated role names in `var` (none when unset), or the first that is not a name.
fn role_list(var: &str) -> Result<Vec<String>, String> {
    let roles: Vec<String> = std::env::var(var)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .collect();
    match roles.iter().find(|r| !synapse::keystore::valid_name(r)) {
        Some(bad) => Err(bad.clone()),
        None => Ok(roles),
    }
}
