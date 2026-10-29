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

mod checker;

use clap::{Parser, Subcommand};
use serde_json::json;
use synapse::certificate::Permission;
use synapse::keystore::{
    Keystore, KeystoreError, RolePublicKeys, account_name, default_home, valid_name,
};
use synapse::security_events::SecurityEventKind;

use synapsed_client::{Daemon, MailError, encode_body, events, inbox_line, printable};

#[derive(Parser)]
#[command(name = "synapse", about = "Synapse command line", version)]
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
    /// Shared state between lanes: one record per cross-lane thread, written by compare-and-set.
    #[command(subcommand)]
    State(StateCommand),
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
    /// Retire a role now: it leaves `list` unless `--include-retired`, and keeps its epoch and its
    /// queued mail. Needs the `role-admin` grant. A claim by the role itself brings it back.
    Retire {
        #[command(flatten)]
        role: RoleArg,
        /// The role to retire (a name, not `name@account`).
        target: String,
    },
    /// Bring a retired role back and restart its idle clock. Needs the `role-admin` grant.
    Revive {
        #[command(flatten)]
        role: RoleArg,
        /// The role to revive (a name, not `name@account`).
        target: String,
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
        /// Also list roles retired for being idle past the ttl (each carries `retired_at`).
        #[arg(long)]
        include_retired: bool,
    },
}

/// A condition is `FACT,OP,VALUE` (`crate_version:synapse,ge,6.0.0`; `exists` and `absent` take no
/// value). A blocker is a record id (`T-12`) or a condition.
#[derive(Subcommand)]
enum StateCommand {
    /// Create a record; prints it as one JSON object.
    New {
        #[command(flatten)]
        role: RoleArg,
        #[arg(long)]
        title: String,
        /// A party (repeatable). The creator must be one.
        #[arg(long = "party", required = true)]
        parties: Vec<String>,
        #[arg(long)]
        owner: String,
        /// open (default), blocked, waiting, done or cancelled.
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// A fact that makes the record true or done (repeatable).
        #[arg(long = "verify")]
        verify: Vec<String>,
        /// What a blocked record waits on (repeatable).
        #[arg(long = "blocked-on")]
        blocked_on: Vec<String>,
    },
    /// Print one record as JSON.
    Show {
        #[command(flatten)]
        role: RoleArg,
        id: String,
    },
    /// Print the records you may see, one JSON object per line.
    List {
        #[command(flatten)]
        role: RoleArg,
        /// Comma-separated states.
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        party: Option<String>,
    },
    /// Change a record, if it is still at --rev. A stale --rev changes nothing and says so.
    Set {
        #[command(flatten)]
        role: RoleArg,
        id: String,
        /// The revision you read.
        #[arg(long)]
        rev: u64,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        owner: Option<String>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Replace the parties (repeatable).
        #[arg(long = "party")]
        parties: Vec<String>,
        /// Replace the verify list (repeatable).
        #[arg(long = "verify")]
        verify: Vec<String>,
        #[arg(long)]
        clear_verify: bool,
        /// Replace what the record is blocked on (repeatable).
        #[arg(long = "blocked-on")]
        blocked_on: Vec<String>,
        #[arg(long)]
        clear_blocked_on: bool,
    },
    /// Print a record's history, one JSON entry per line.
    History {
        #[command(flatten)]
        role: RoleArg,
        id: String,
    },
    /// Run the checker: look up the facts open records name (crates.io, GitHub) and report them.
    /// Needs the `state-derive` grant (`synapse id grant --role <role> state-derive`); run it as
    /// the checker role. Nothing else may write a fact.
    Check {
        #[command(flatten)]
        role: RoleArg,
        /// One pass, then exit (default: repeat).
        #[arg(long)]
        once: bool,
        /// Seconds between passes.
        #[arg(long, default_value_t = 300)]
        interval: u64,
        /// The environment variable holding a GitHub token (none: GitHub's unauthenticated limits).
        #[arg(long, default_value = "SYNAPSE_CHECKER_GITHUB_TOKEN")]
        github_token_env: String,
        #[arg(long, default_value = "https://crates.io")]
        crates_url: String,
        #[arg(long, default_value = "https://api.github.com")]
        github_url: String,
    },
}

fn condition_json(text: &str) -> Result<serde_json::Value, MailError> {
    let bad = || {
        MailError::Usage(format!(
            "`{}` is not FACT,OP,VALUE (OP: eq, ge, exists, absent)",
            printable(text)
        ))
    };
    let mut parts = text.splitn(3, ',');
    let fact = parts.next().filter(|f| !f.is_empty()).ok_or_else(bad)?;
    let op = parts.next().ok_or_else(bad)?;
    let value = parts.next().unwrap_or("");
    Ok(json!({ "fact": fact, "op": op, "value": value }))
}

fn blocker_json(text: &str) -> Result<serde_json::Value, MailError> {
    if text.starts_with("T-") {
        Ok(json!({ "record": text }))
    } else {
        Ok(json!({ "condition": condition_json(text)? }))
    }
}

fn state_command(home: &std::path::Path, command: StateCommand) -> Result<(), MailError> {
    let conditions = |v: &[String]| {
        v.iter()
            .map(|c| condition_json(c))
            .collect::<Result<Vec<_>, _>>()
    };
    let blockers = |v: &[String]| {
        v.iter()
            .map(|c| blocker_json(c))
            .collect::<Result<Vec<_>, _>>()
    };
    let query = |id: &str| id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    // The record is the command's output, written as data rather than formatted into a log line.
    let print_record = |reply: &serde_json::Value| -> Result<(), MailError> {
        let mut out = std::io::stdout().lock();
        out.write_all(reply["record"].to_string().as_bytes())?;
        out.write_all(b"\n")?;
        Ok(())
    };
    match command {
        StateCommand::New {
            role,
            title,
            parties,
            owner,
            state,
            notes,
            verify,
            blocked_on,
        } => {
            let mut body = json!({
                "title": title,
                "parties": parties,
                "owner": owner,
                "verify": conditions(&verify)?,
                "blocked_on": blockers(&blocked_on)?,
            });
            if let Some(state) = state {
                body["state"] = json!(state);
            }
            if let Some(notes) = notes {
                body["notes"] = json!(notes);
            }
            let daemon = connect(home, &role)?;
            print_record(&daemon.call(&role.role, "/v1/state/create", Some(&body))?)?;
        }
        StateCommand::Show { role, id } => {
            if !query(&id) {
                return Err(MailError::Usage("not a record id".into()));
            }
            let daemon = connect(home, &role)?;
            print_record(&daemon.call(&role.role, &format!("/v1/state/get?id={id}"), None)?)?;
        }
        StateCommand::List { role, state, party } => {
            let mut path = String::from("/v1/state/list?");
            if let Some(state) = state {
                if !state.bytes().all(|b| b.is_ascii_lowercase() || b == b',') {
                    return Err(MailError::Usage(
                        "--state is comma-separated state names".into(),
                    ));
                }
                path.push_str(&format!("state={state}&"));
            }
            if let Some(party) = party {
                if !valid_name(&party) {
                    return Err(MailError::Usage("--party is a role name".into()));
                }
                path.push_str(&format!("party={party}&"));
            }
            let daemon = connect(home, &role)?;
            let reply = daemon.call(&role.role, path.trim_end_matches(['?', '&']), None)?;
            for record in reply["records"].as_array().into_iter().flatten() {
                println!("{record}");
            }
        }
        StateCommand::Set {
            role,
            id,
            rev,
            title,
            owner,
            state,
            notes,
            parties,
            verify,
            clear_verify,
            blocked_on,
            clear_blocked_on,
        } => {
            let mut patch = serde_json::Map::new();
            let mut put = |k: &str, v: serde_json::Value| {
                patch.insert(k.to_string(), v);
            };
            if let Some(v) = title {
                put("title", json!(v));
            }
            if let Some(v) = owner {
                put("owner", json!(v));
            }
            if let Some(v) = state {
                put("state", json!(v));
            }
            if let Some(v) = notes {
                put("notes", json!(v));
            }
            if !parties.is_empty() {
                put("parties", json!(parties));
            }
            if !verify.is_empty() || clear_verify {
                put("verify", json!(conditions(&verify)?));
            }
            if !blocked_on.is_empty() || clear_blocked_on {
                put("blocked_on", json!(blockers(&blocked_on)?));
            }
            let body = json!({ "id": id, "expected_revision": rev, "patch": patch });
            let daemon = connect(home, &role)?;
            print_record(&daemon.call(&role.role, "/v1/state/patch", Some(&body))?)?;
        }
        StateCommand::Check {
            role,
            once,
            interval,
            github_token_env,
            crates_url,
            github_url,
        } => {
            let forge = checker::Forge::new(
                &crates_url,
                &github_url,
                Box::new(checker::EnvToken(github_token_env)),
            )?;
            loop {
                // Connect afresh each pass: a daemon that restarted is a new instance.
                let pass = connect(home, &role)
                    .and_then(|daemon| checker::check_once(&daemon, &role.role, &forge));
                match pass {
                    Ok(p) => println!(
                        "checked {} facts: {} found, {} absent, {} failed",
                        p.found + p.absent + p.failed,
                        p.found,
                        p.absent,
                        p.failed
                    ),
                    Err(e) if once => return Err(e),
                    Err(e) => eprintln!("error: {e}"),
                }
                if once {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(interval.max(1)));
            }
        }
        StateCommand::History { role, id } => {
            if !query(&id) {
                return Err(MailError::Usage("not a record id".into()));
            }
            let daemon = connect(home, &role)?;
            let reply = daemon.call(&role.role, &format!("/v1/state/history?id={id}"), None)?;
            for entry in reply["entries"].as_array().into_iter().flatten() {
                println!("{entry}");
            }
        }
    }
    Ok(())
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
    /// With the account key: give every role in --roles-file its own home under --lane-home-root
    /// (`<root>/<role>`), holding that role's keys and a current certificate and NOT the account key.
    /// A dry run unless --apply. Idempotent: a role whose certificate is current is `ok` and
    /// untouched. Prints one line per role, `<role> <status>`, and never a key, certificate or path.
    /// Exit 2 if any role was refused. Certificates last --days; a role within --renew-below-days of
    /// expiry is reissued, so run this on a schedule shorter than that. Roles in one lane's home are
    /// not hidden from other lanes of the same OS user.
    Provision {
        /// One role name per line; blank lines and `#` comments are skipped.
        #[arg(long, value_name = "FILE")]
        roles_file: std::path::PathBuf,
        /// The directory that holds the per-role homes.
        #[arg(long, value_name = "DIR")]
        lane_home_root: std::path::PathBuf,
        /// Write. Without it nothing on disk changes.
        #[arg(long)]
        apply: bool,
        /// Certificate validity in days (1 to 30).
        #[arg(long, default_value_t = 30)]
        days: i64,
        /// Reissue when this many days or fewer remain.
        #[arg(long, default_value_t = 14)]
        renew_below_days: i64,
    },
    /// In a role-only home: store the certificate read from standard input for --role, after
    /// checking that it certifies this home's keys.
    InstallCert {
        #[arg(long)]
        role: String,
    },
    /// With the account key: give --role an extra grant (state-read-all, state-admin or
    /// state-derive). It takes effect when the role's certificate is next made.
    Grant {
        #[arg(long)]
        role: String,
        permission: String,
    },
    /// With the account key: take an extra grant back.
    Ungrant {
        #[arg(long)]
        role: String,
        permission: String,
    },
    /// Show the account, and with --role, that role's identity (creating its keys on first use; a
    /// role-only home creates nothing and never renews).
    Show {
        #[arg(long)]
        role: Option<String>,
    },
}

/// The role names in a `--roles-file`: one per line, blank lines and `#` comments skipped. Refuses
/// the whole file, before anything is written, on an invalid or repeated name.
fn parse_roles_file(text: &str) -> Result<Vec<String>, String> {
    let mut roles: Vec<String> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let name = line.split('#').next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        if !synapse::keystore::valid_name(name) {
            return Err(format!("roles file line {}: not a role name", n + 1));
        }
        if roles.iter().any(|r| r == name) {
            return Err(format!("roles file line {}: role repeated", n + 1));
        }
        roles.push(name.to_string());
    }
    if roles.is_empty() {
        return Err("roles file names no role".to_string());
    }
    Ok(roles)
}

fn provision_word(p: synapse::keystore::Provision, apply: bool) -> &'static str {
    use synapse::keystore::Provision::{Created, Ok, Renewed};
    match (p, apply) {
        (Ok, _) => "ok",
        (Created, true) => "created",
        (Created, false) => "would-create",
        (Renewed, true) => "renewed",
        (Renewed, false) => "would-renew",
    }
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

fn parse_grant(text: &str) -> Result<Permission, MailError> {
    match Permission::parse(text) {
        Some(
            p @ (Permission::StateReadAll
            | Permission::StateAdmin
            | Permission::StateDerive
            | Permission::RoleAdmin),
        ) => Ok(p),
        _ => Err(MailError::Usage(
            "a grant is state-read-all, state-admin, state-derive or role-admin".to_string(),
        )),
    }
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
        Command::Id(IdCommand::Provision {
            roles_file,
            lane_home_root,
            apply,
            days,
            renew_below_days,
        }) => {
            let text = std::fs::read_to_string(&roles_file)?;
            let roles = parse_roles_file(&text).map_err(MailError::Usage)?;
            let store = Keystore::open(&home)?;
            let now = chrono::Utc::now();
            let mut refused = 0usize;
            for role in &roles {
                let status = store.provision_role(
                    &lane_home_root.join(role),
                    role,
                    now,
                    chrono::Duration::days(days),
                    chrono::Duration::days(renew_below_days),
                    apply,
                );
                match status {
                    Ok(p) => println!("{role} {}", provision_word(p, apply)),
                    Err(e) => {
                        refused += 1;
                        println!("{role} refused: {e}");
                    }
                }
            }
            println!(
                "{} role(s), {} refused{}",
                roles.len(),
                refused,
                if apply {
                    ""
                } else {
                    " (dry run: nothing written)"
                }
            );
            if refused > 0 {
                std::io::stdout().flush()?;
                std::process::exit(2);
            }
        }
        Command::Id(IdCommand::InstallCert { role }) => {
            let mut pem = String::new();
            std::io::stdin().read_to_string(&mut pem)?;
            Keystore::install_role_certificate(&home, &role, &pem)?;
            println!("installed: {role}");
        }
        Command::Id(IdCommand::Grant { role, permission }) => {
            let permission = parse_grant(&permission)?;
            Keystore::open(&home)?.grant(&role, &permission)?;
            println!("granted: {} to {role}", permission.as_str());
        }
        Command::Id(IdCommand::Ungrant { role, permission }) => {
            let permission = parse_grant(&permission)?;
            Keystore::open(&home)?.ungrant(&role, &permission)?;
            println!("ungranted: {} from {role}", permission.as_str());
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
                // `store.role` makes or renews the role's keys and certificate; what is printed is
                // then read back through the public view, so no value that passed through the
                // account-key-holding store reaches the print.
                store.role(&role, chrono::Utc::now())?;
                let view = Keystore::open_public_view(&home)?;
                print_identity(&view.role(&role, chrono::Utc::now())?);
            }
        }
        Command::State(command) => state_command(&home, command)?,
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
        Command::Retire { role, target } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/roles/retire",
                Some(&json!({"role": target})),
            )?;
            println!(
                "retired: {}",
                printable(reply["role"].as_str().unwrap_or(""))
            );
        }
        Command::Revive { role, target } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                "/v1/roles/revive",
                Some(&json!({"role": target})),
            )?;
            println!(
                "revived: {}",
                printable(reply["role"].as_str().unwrap_or(""))
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
        Command::List {
            role,
            cwd,
            repo,
            include_retired,
        } => {
            let daemon = connect(&home, &role)?;
            let reply = daemon.call(
                &role.role,
                &list_path(cwd.as_deref(), repo.as_deref(), include_retired),
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
fn list_path(cwd: Option<&str>, repo: Option<&str>, include_retired: bool) -> String {
    let mut pairs = Vec::new();
    for (key, value) in [("cwd", cwd), ("repo", repo)] {
        if let Some(value) = value {
            pairs.push(format!("{key}={}", percent_encode(value)));
        }
    }
    if include_retired {
        pairs.push("include_retired=true".to_string());
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
        assert_eq!(list_path(None, None, false), "/v1/list");
        assert_eq!(
            list_path(Some(r"C:\Projects\a b&c"), Some("r"), false),
            "/v1/list?cwd=C%3A%5CProjects%5Ca%20b%26c&repo=r"
        );
        assert_eq!(list_path(None, Some("é"), false), "/v1/list?repo=%C3%A9");
        assert_eq!(list_path(None, None, true), "/v1/list?include_retired=true");
        assert_eq!(
            list_path(None, Some("r"), true),
            "/v1/list?repo=r&include_retired=true"
        );
    }
}
