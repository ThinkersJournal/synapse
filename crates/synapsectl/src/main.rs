// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapse`: the plain command line adapter (plan adapter (c)). M2 adds the identity commands:
//! `synapse id init --account <name>` and `synapse id show [--role <role>]`.
//!
//! Output carries names, key ids and validity windows only: never key material, never the
//! keystore's path (spec `docs/superpowers/specs/2026-10-01-m2-keystore-design.md` §3.3).
//!
//! M5b adds the mail commands over `synapsed`, which they start if it is not running:
//! `synapse claim|send|inbox|ack|dead|requeue|list|stats --role <role>` (or `SYNAPSE_ROLE`).
//! `inbox`, `dead`, `list` and `stats` print one JSON object per line. Session tokens are never printed.

use std::io::{IsTerminal, Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::json;
use synapse::certificate::Permission;
use synapse::keystore::{
    Keystore, KeystoreError, RolePublicKeys, account_name, default_home, valid_name,
};
use synapse::security_events::SecurityEventKind;

use synapsed_client::{Daemon, MailError, encode_body, events, inbox_line, printable};

#[derive(Parser)]
#[command(name = "synapse", about = "Synapse command line")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Identity: the account key and per-role keys kept in the keystore.
    #[command(subcommand)]
    Id(IdCommand),
    /// Which store holds the mailbox: list what this build offers, record the one to use.
    #[cfg(feature = "storage")]
    #[command(subcommand)]
    Storage(StorageCommand),
    /// Claim a role on the daemon (taking it over if another holder has it).
    ///
    /// The session is cached per role in this home, so every `synapse` command for the role here
    /// uses the new claim: one holder per (home, role).
    Claim {
        #[command(flatten)]
        role: RoleArg,
    },
    /// Send a message: the MESSAGE argument, else standard input.
    Send {
        #[command(flatten)]
        role: RoleArg,
        /// The recipient: `<role>` on this account, or `<role>@<account>`.
        #[arg(long)]
        to: String,
        /// A message id of your own, for idempotent resends (default: a fresh UUID).
        #[arg(long)]
        id: Option<String>,
        message: Option<String>,
    },
    /// Fetch waiting messages, one JSON object per line. Each stays leased until acked.
    Inbox {
        #[command(flatten)]
        role: RoleArg,
        #[arg(long)]
        max: Option<usize>,
        #[arg(long)]
        lease_secs: Option<i64>,
    },
    /// Acknowledge a fetched message, removing it from the inbox.
    Ack {
        #[command(flatten)]
        role: RoleArg,
        message_id: String,
    },
    /// List the role's dead set: messages leased the daemon's delivery cap of times and never
    /// acked, set aside (not dropped), one JSON object per line. `ack` one to discard it.
    Dead {
        #[command(flatten)]
        role: RoleArg,
    },
    /// Put a dead message back in the role's inbox with its delivery count reset.
    Requeue {
        #[command(flatten)]
        role: RoleArg,
        message_id: String,
    },
    /// Per-role message counters since this daemon started (a restart begins again from zero):
    /// `sent`, `acked`, `redelivered`, `expired`, one JSON object per line, each with the
    /// daemon's `scope` and `since`.
    Stats {
        #[command(flatten)]
        role: RoleArg,
    },
    /// List every role the daemon knows, with presence, one JSON object per line. `--cwd` and
    /// `--repo` keep only roles whose self-reported presence matches exactly (a role that reports
    /// none never matches).
    List {
        #[command(flatten)]
        role: RoleArg,
        /// Only roles whose reported working directory is exactly this.
        #[arg(long)]
        cwd: Option<String>,
        /// Only roles whose reported repo is exactly this.
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(clap::Args)]
struct RoleArg {
    /// The role to act as.
    #[arg(long, env = "SYNAPSE_ROLE")]
    role: String,
}

#[cfg(feature = "storage")]
#[derive(Subcommand)]
enum StorageCommand {
    /// The stores that meet every need of the mailbox, best first, with why each ranks where it
    /// does. Nothing is changed.
    List,
    /// Record the store the daemon opens at its next start: an id from `list`. The id is checked
    /// against the mailbox's needs before it is written.
    Use {
        id: String,
        /// The file under the home that holds it (default `mailbox.<id>`; an existing
        /// `mailbox.sqlite` must be named to keep its mail).
        #[arg(long, conflicts_with = "url_env")]
        file: Option<String>,
        /// For a server provider: the NAME of the environment variable that holds the connection
        /// URL, set in the daemon's environment. The URL itself is never recorded.
        #[arg(long, value_name = "VAR")]
        url_env: Option<String>,
    },
}

#[derive(Subcommand)]
enum IdCommand {
    /// Create the account key. Refuses if an account already exists.
    Init {
        #[arg(long)]
        account: String,
    },
    /// Make a role's keys in a home that does NOT hold the account key (a sandbox that must not be
    /// able to mint roles), and print their public halves for the account holder to `issue`.
    InitRole {
        #[arg(long)]
        account: String,
        #[arg(long)]
        role: String,
    },
    /// With the account key: certify a role's public keys (from `init-role`) and print the
    /// certificate. The certificate is public; the role's private keys never reach this home.
    Issue {
        #[arg(long)]
        role: String,
        #[arg(long, value_name = "HEX")]
        signing_pub: String,
        #[arg(long, value_name = "HEX")]
        sealing_pub: String,
        /// Validity in days (1 to 30).
        #[arg(long, default_value_t = 8)]
        days: i64,
    },
    /// In a role-only home: store the certificate read from standard input for --role, after
    /// checking that it certifies this home's keys.
    InstallCert {
        #[arg(long)]
        role: String,
    },
    /// Show the account, and with --role, that role's identity (creating its keys on first use; a
    /// role-only home creates nothing and never renews).
    Show {
        #[arg(long)]
        role: Option<String>,
    },
}

fn print_identity(identity: &synapse::keystore::RoleIdentity) {
    println!("identity: {}", identity.chain[0].subject_global_id);
    println!("signing key id: {}", identity.signing_key_id);
    println!("sealing key id: {}", identity.sealing_key_id);
    println!(
        "certificate valid: {} to {}",
        identity.not_before.to_rfc3339(),
        identity.not_after.to_rfc3339()
    );
    let permissions: Vec<String> = identity
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    println!("permissions: {}", permissions.join(", "));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str, flag: &str) -> Result<[u8; 32], MailError> {
    let bad = || MailError::Usage(format!("{flag} must be 64 hex digits"));
    if s.len() != 64 || !s.is_ascii() {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Hardening P8, rows 6 and 7: every owner-only check the CLI reaches, in the keystore
            // or in `mail`, propagates to here, so its refusal is recorded once, before exiting.
            if let MailError::Keystore(KeystoreError::PermissionsTooOpen(item)) = &e {
                events::record(
                    default_home().ok().as_deref(),
                    SecurityEventKind::PermissionsTooOpen,
                    "synapsectl/files",
                    item,
                    None,
                    "refused: accessible to more than its owner",
                );
            }
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), MailError> {
    let home = default_home()?;
    match cli.command {
        Command::Id(IdCommand::Init { account }) => {
            let summary = Keystore::init_account(&home, &account)?;
            println!("account: {}", summary.account);
            println!("account key id: {}", summary.key_id);
        }
        Command::Id(IdCommand::InitRole { account, role }) => {
            let keys = Keystore::init_role(&home, &account, &role)?;
            println!("role: {role}");
            println!("signing-pub: {}", hex(&keys.signing));
            println!("sealing-pub: {}", hex(&keys.sealing));
        }
        Command::Id(IdCommand::Issue {
            role,
            signing_pub,
            sealing_pub,
            days,
        }) => {
            let keys = RolePublicKeys {
                signing: unhex32(&signing_pub, "--signing-pub")?,
                sealing: unhex32(&sealing_pub, "--sealing-pub")?,
            };
            let pem = Keystore::open(&home)?.issue_role_certificate(
                &role,
                keys,
                chrono::Utc::now(),
                chrono::Duration::days(days),
            )?;
            std::io::stdout().write_all(pem.as_bytes())?;
        }
        Command::Id(IdCommand::InstallCert { role }) => {
            let mut pem = String::new();
            std::io::stdin().read_to_string(&mut pem)?;
            Keystore::install_role_certificate(&home, &role, &pem)?;
            println!("installed: {role}");
        }
        Command::Id(IdCommand::Show { role }) => {
            if let Some(role) = &role
                && !home.join("account").join("account.key.pem").exists()
            {
                // A role-only home: no account key to show, nothing created, nothing renewed.
                let store = Keystore::open_role_only(&home)?;
                print_identity(&store.role(role, chrono::Utc::now())?);
                return Ok(());
            }

            let store = Keystore::open(&home)?;
            let summary = store.account();
            println!("account: {}", summary.account);
            println!("account key id: {}", summary.key_id);
            if let Some(role) = role {
                let identity = store.role(&role, chrono::Utc::now())?;
                print_identity(&identity);
            }
        }
        Command::Claim { role } => {
            let daemon = connect(&home, &role)?;
            let claimed = daemon.claim(&role.role)?;
            println!("identity: {}", printable(&claimed.global_id));
            println!("epoch: {}", claimed.epoch);
        }
        Command::Send {
            role,
            to,
            id,
            message,
        } => {
            check_role(&role)?;
            let to = if to.contains('@') {
                to
            } else {
                format!("{to}@{}", account_name(&home)?)
            };
            let body = match message {
                Some(text) => text.into_bytes(),
                None if std::io::stdin().is_terminal() => {
                    return Err(MailError::Usage(
                        "give the message as an argument, or pipe it on standard input".into(),
                    ));
                }
                None => {
                    let mut bytes = Vec::new();
                    std::io::stdin().read_to_end(&mut bytes)?;
                    bytes
                }
            };
            // Chosen here, not by the daemon, so resending with `--id` is a duplicate, not a copy.
            let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/send",
                Some(&json!({"to": to, "message_id": id, "body_b64": encode_body(&body)})),
            )?;
            let field = |name: &str| printable(reply[name].as_str().unwrap_or(""));
            println!("message id: {}", field("message_id"));
            println!("outcome: {}", field("outcome"));
        }
        Command::Inbox {
            role,
            max,
            lease_secs,
        } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/fetch",
                Some(&json!({"max": max, "lease_secs": lease_secs})),
            )?;
            for message in reply["messages"].as_array().into_iter().flatten() {
                println!("{}", inbox_line(message));
            }
        }
        Command::Ack { role, message_id } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/ack",
                Some(&json!({"message_id": message_id})),
            )?;
            println!(
                "outcome: {}",
                printable(reply["outcome"].as_str().unwrap_or(""))
            );
        }
        Command::Dead { role } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(&role.role, "/v1/dead", None)?;
            for message in reply["messages"].as_array().into_iter().flatten() {
                println!("{}", inbox_line(message));
            }
        }
        Command::Requeue { role, message_id } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/requeue",
                Some(&json!({"message_id": message_id})),
            )?;
            println!(
                "outcome: {}",
                printable(reply["outcome"].as_str().unwrap_or(""))
            );
        }
        Command::Stats { role } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(&role.role, "/v1/stats", None)?;
            for entry in reply["roles"].as_array().into_iter().flatten() {
                let mut entry = entry.clone();
                entry["scope"] = reply["scope"].clone();
                entry["since"] = reply["since"].clone();
                println!("{entry}");
            }
        }
        #[cfg(feature = "storage")]
        Command::Storage(command) => storage(&home, command)?,
        Command::List { role, cwd, repo } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                &list_path(cwd.as_deref(), repo.as_deref()),
                None,
            )?;
            for entry in reply["roles"].as_array().into_iter().flatten() {
                println!("{entry}");
            }
        }
    }
    Ok(())
}

#[cfg(feature = "storage")]
fn storage(home: &std::path::Path, command: StorageCommand) -> Result<(), MailError> {
    use synapse::mailbox::MailboxNeeds;
    use synapse_mailbox_persistant::needs::{StoreChoice, listing};
    let usage = |e: &dyn std::fmt::Display| MailError::Usage(e.to_string());
    let listed = listing(&MailboxNeeds::MAILBOX).map_err(|e| usage(&e))?;
    match command {
        StorageCommand::List => {
            let recorded = StoreChoice::read(home).map_err(|e| usage(&e))?;
            for l in &listed {
                let mark = recorded.as_ref().is_some_and(|c| c.id == l.id);
                println!(
                    "{}{}  {}",
                    l.id,
                    if mark { "  (recorded)" } else { "" },
                    l.title
                );
                for line in l.why() {
                    println!("    {line}");
                }
            }
            if recorded.is_none() {
                println!("no store recorded in this home; `synapse storage use <id>` records one");
            }
        }
        StorageCommand::Use { id, file, url_env } => {
            if !listed.iter().any(|l| l.id == id) {
                let ids: Vec<_> = listed.iter().map(|l| l.id).collect();
                return Err(MailError::Usage(format!(
                    "`{id}` does not meet the mailbox's needs in this build; choose one of {ids:?}"
                )));
            }
            let wants_url = listed
                .iter()
                .find(|l| l.id == id)
                .is_some_and(synapse_mailbox_persistant::needs::wants_url);
            if wants_url != url_env.is_some() {
                return Err(MailError::Usage(if wants_url {
                    format!(
                        "`{id}` is a server: give --url-env <VAR> naming the variable that holds its URL"
                    )
                } else {
                    format!("`{id}` is a file: use --file (or neither), not --url-env")
                }));
            }
            let choice = match url_env.as_deref() {
                Some(var) => StoreChoice::server(&id, var),
                None => StoreChoice::new(&id, file.as_deref()),
            }
            .map_err(|e| usage(&e))?;
            choice.write(home).map_err(|e| usage(&e))?;
            println!(
                "recorded {} in {}; the daemon uses it at its next start",
                choice.id,
                choice.describe()
            );
        }
    }
    Ok(())
}

/// `/v1/list` with the filters as percent-encoded query parameters (paths hold `\`, `:` and `&`).
fn list_path(cwd: Option<&str>, repo: Option<&str>) -> String {
    let mut pairs = Vec::new();
    for (key, value) in [("cwd", cwd), ("repo", repo)] {
        if let Some(value) = value {
            pairs.push(format!("{key}={}", percent_encode(value)));
        }
    }
    if pairs.is_empty() {
        "/v1/list".to_string()
    } else {
        format!("/v1/list?{}", pairs.join("&"))
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Validate the role before it names a file or starts a daemon, then connect.
fn connect(home: &std::path::Path, role: &RoleArg) -> Result<Daemon, MailError> {
    check_role(role)?;
    Daemon::connect(home)
}

fn check_role(role: &RoleArg) -> Result<(), MailError> {
    if valid_name(&role.role) {
        Ok(())
    } else {
        Err(MailError::Usage(format!(
            "`{}` is not a role name: use [A-Za-z0-9_-], at most 64 characters",
            role.role
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_path_encodes_filters() {
        assert_eq!(list_path(None, None), "/v1/list");
        assert_eq!(
            list_path(Some(r"C:\Projects\a b&c"), Some("r")),
            "/v1/list?cwd=C%3A%5CProjects%5Ca%20b%26c&repo=r"
        );
        assert_eq!(list_path(None, Some("é")), "/v1/list?repo=%C3%A9");
    }
}
