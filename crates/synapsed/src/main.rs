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
//! The mailbox store, in order: `SYNAPSE_MAILBOX_STORE` (deprecated pin: `redb`, or `sqlite` in a
//! build with `--features sqlite-store`); else the PersistAnt provider recorded in
//! `<home>/mailbox-store.json` (`synapsectl storage list` shows what this build offers, `storage use`
//! records one); else, on a home with no mailbox file and in a `sqlite-store` build, the first
//! provider PersistAnt lists for the mailbox's needs, which is then recorded; else redb. A different
//! store is a different file: nothing is migrated, and the other file is left untouched.
//! Security events (failed bearers and claims, over-budget requests) go to
//! `<home>/security-events.jsonl`, owner-only; they never carry a token, nonce or signature.

use std::process::ExitCode;

use synapsed::{Daemon, DaemonConfig, StoreKind};

#[tokio::main]
async fn main() -> ExitCode {
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
    #[cfg(feature = "sqlite-store")]
    let named = match named_choice(&config.home, &settings) {
        Ok(choice) => choice,
        Err(e) => {
            eprintln!("synapsed: {e}");
            return ExitCode::from(2);
        }
    };
    let kind = match settings.store_pin.as_deref() {
        None | Some("" | "redb") => StoreKind::Redb,
        #[cfg(feature = "sqlite-store")]
        Some("sqlite") => StoreKind::Sqlite,
        Some(other) => {
            eprintln!(
                "synapsed: the store pin (SYNAPSE_MAILBOX_STORE, or storage.id in synapsed.toml) {other:?} is not available in this build                  (redb{})",
                if cfg!(feature = "sqlite-store") {
                    ", sqlite"
                } else {
                    "; sqlite needs --features sqlite-store"
                }
            );
            return ExitCode::from(2);
        }
    };
    #[cfg(feature = "sqlite-store")]
    let opened = match &named {
        Some(choice) => Daemon::open_named(&config, choice),
        None => Daemon::open_with(&config, kind),
    };
    #[cfg(not(feature = "sqlite-store"))]
    let opened = Daemon::open_with(&config, kind);
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
        .with_alert_roles(settings.alert_roles.clone())
        .with_launcher(synapsed::LauncherConfig {
            roles: settings.launcher_roles.clone(),
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

/// The PersistAnt provider to serve the mailbox from, or `None` for the pinned/default store.
/// `SYNAPSE_MAILBOX_STORE` (deprecated) wins; then the recorded choice; then, on a home with no
/// mailbox file, the first provider PersistAnt lists for the mailbox's needs, recorded so the next
/// start opens the same one.
#[cfg(feature = "sqlite-store")]
fn named_choice(
    home: &std::path::Path,
    settings: &synapsed::settings::Settings,
) -> Result<Option<synapse_mailbox_persistant::needs::StoreChoice>, String> {
    use synapse_mailbox_persistant::needs::{StoreChoice, listing};
    if settings.store_pin.is_some() {
        if settings.store_pin_from_env {
            eprintln!(
                "synapsed: SYNAPSE_MAILBOX_STORE is deprecated; record a store with `synapse storage use`"
            );
        }
        return Ok(None);
    }
    if let Some(choice) = StoreChoice::read(home).map_err(|e| e.to_string())? {
        return Ok(Some(choice));
    }
    if home.join("mailbox.redb").exists() || home.join("mailbox.sqlite").exists() {
        return Ok(None);
    }
    let Ok(listed) = listing(&synapse::mailbox::MailboxNeeds::MAILBOX) else {
        return Ok(None);
    };
    // A server needs a URL only the operator has, so a fresh home is given the best file store.
    let Some(top) = synapse_mailbox_persistant::needs::first_file_store(&listed) else {
        return Ok(None);
    };
    let choice = StoreChoice::new(top.id, None).map_err(|e| e.to_string())?;
    choice.write(home).map_err(|e| e.to_string())?;
    eprintln!(
        "synapsed: fresh home; recorded mailbox store {:?} in {}",
        choice.id,
        synapse_mailbox_persistant::needs::CHOICE_FILE
    );
    Ok(Some(choice))
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
