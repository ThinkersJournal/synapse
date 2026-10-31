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
//! The address, the store pin, `SYNAPSE_LAUNCHER_ROLES` and `SYNAPSE_ALERT_ROLES` are read through
//! ConfigurAnt (`synapsed::settings`): the environment as always, and the same values from an
//! optional `<home>/synapsed.toml`, the environment winning.
//! Launch signals (`GET /v1/waiting`, lane launch on message) are OFF unless `SYNAPSE_LAUNCHER_ROLES`
//! names the role(s), comma separated, that may read them (for example `agentlife-launcher`).
//! Security alerts go as mail to the roles in `SYNAPSE_ALERT_ROLES` (comma separated), from
//! `daemon:alerts@<account>`; unset, nothing changes.
//! The mailbox store (`synapsed::select_store`), in order: `SYNAPSE_MAILBOX_STORE` (deprecated pin:
//! `redb`, or `sqlite` in a build with `--features sqlite-store`); else the PersistAnt provider recorded in
//! `<home>/mailbox-store.json` (`synapsectl storage list` shows what this build offers, `storage use`
//! records one); else, on a home with no mailbox file and in a `sqlite-store` build, the first
//! provider PersistAnt lists for the mailbox's needs, which is then recorded; else redb. A different
//! store is a different file: nothing is migrated, and the other file is left untouched.
//! Security events (failed bearers and claims, over-budget requests) go to
//! `<home>/security-events.jsonl`, owner-only; they never carry a token, nonce or signature.

use std::process::ExitCode;

use synapsed::{Daemon, DaemonConfig};

const USAGE: &str = "usage: synapsed (no arguments; configured by SYNAPSE_HOME, <home>/synapsed.toml and SYNAPSE_* in the environment)";

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
            println!("synapsed {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    if let Some(bad) = unknown_arg(&[]) {
        eprintln!("synapsed: unknown argument {bad:?}; {USAGE}");
        return ExitCode::from(2);
    }
    let home = match synapse::keystore::default_home() {
        Ok(home) => home,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let file = match std::fs::read_to_string(home.join(synapsed::settings::FILE_NAME)) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("synapsed: {}: {}", synapsed::settings::FILE_NAME, e.kind());
            return ExitCode::from(2);
        }
    };
    let settings = match synapsed::settings::load(&std::env::vars().collect(), file.as_deref()) {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let addr = settings.addr;
    let config = DaemonConfig {
        home,
        addr,
        sweep_every: std::time::Duration::from_secs(3600),
    };
    let selection = match synapsed::select_store(
        &config.home,
        settings.store_pin.as_deref(),
        settings.store_pin_from_env,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let opened = Daemon::open_selected(&config, &selection);
    let daemon = match opened {
        Ok(daemon) => daemon,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let daemon = daemon
        .with_role_ttl_days(settings.role_ttl_days)
        .with_session_ttl_hours(settings.session_ttl_hours)
        .with_redelivery_gaps(
            settings
                .redelivery_gaps_secs
                .iter()
                .map(|s| chrono::Duration::seconds(i64::try_from(*s).unwrap_or(i64::MAX)))
                .collect(),
        )
        .with_alert_roles(settings.alert_roles.clone())
        .with_launch_senders(settings.launch_senders.clone())
        .with_launcher(synapsed::LauncherConfig {
            roles: settings.launcher_roles.clone(),
            ..synapsed::LauncherConfig::default()
        });
    tokio::spawn(reload_launch_senders(
        daemon.launch_senders(),
        settings.launch_senders.clone(),
    ));
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

/// Re-read `SYNAPSE_LAUNCH_SENDERS` and `synapsed.toml` every few seconds, so a changed allowlist
/// applies on the next poll without a restart. A file that does not read or parse keeps the last
/// good list. (The environment cannot change in a running process; the file is what moves.)
async fn reload_launch_senders(handle: synapsed::LaunchSenders, mut current: Vec<String>) {
    let Ok(home) = synapse::keystore::default_home() else {
        return;
    };
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let file = match std::fs::read_to_string(home.join(synapsed::settings::FILE_NAME)) {
            Ok(text) => Some(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => continue,
        };
        let Ok(settings) = synapsed::settings::load(&std::env::vars().collect(), file.as_deref())
        else {
            continue;
        };
        if settings.launch_senders != current {
            handle.set(settings.launch_senders.clone());
            current = settings.launch_senders;
            eprintln!("synapsed: launch.senders reloaded");
        }
    }
}
