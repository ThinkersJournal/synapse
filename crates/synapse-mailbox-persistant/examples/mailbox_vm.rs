// SPDX-License-Identifier: MIT OR Apache-2.0
//! The guest side of Synapse's own power-loss test for the mailbox (board 229, the stop-line for
//! removing redb): run **inside** a Linux VM that the host then powers off with `Stop-VM -TurnOff`.
//!
//! ```text
//! mailbox_vm write  <backend> <db-file>           enqueue numbered messages, print "acked N" after each returns
//! mailbox_vm check  <backend> <db-file> <count>   messages 0..count must all be queued, with their bodies
//! mailbox_vm enospc <backend> <db-file>           enqueue until one fails; it must fail, never ack silently
//! ```
//!
//! The command line, output and exit codes are those of PersistAnt's `machine_vm`
//! (`crates/persistant-sqlx/examples/machine_vm.rs`), so its `scripts/machine-durability/run.ps1`
//! drives this binary unchanged with `-Binary <this> -Backends sqlite,sqlite-off`: it copies the
//! binary into the guest as `machine_vm` and runs the cycles, the known-bad control and the
//! disk-full check. What differs is the layer under test: here an acknowledgement is
//! `Mailbox::enqueue` returning `Ok`, through the whole mailbox and `SqliteMailStore`, not a key put.
//!
//! `<backend>` is `sqlite` (`SqliteMailStore::open`, opened through `Mailbox::open`, so it must
//! declare `Machine`) or `sqlite-off` (`synchronous=OFF`: **the known-bad control**, which
//! acknowledges before the data is on stable storage and is opened with `Mailbox::open_volatile`
//! because it declares less than `Machine`).
//!
//! Exit codes: 0 done; 1 an acknowledged message is missing or holds another body; 2 usage or cannot
//! open; 3 `enospc` saw an enqueue fail (the expected, loud outcome); 4 `enospc` enqueued its whole
//! budget without a failure (the disk was not full, so the run proves nothing); 6 `check` could not
//! read (errors, not losses).

use chrono::{Duration, TimeZone, Utc};
use persistant_kv::KvOnRelational;
use persistant_sqlx::{Bounded, SqliteBackend};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::io::Write;
use std::process::ExitCode;
use synapse::mailbox::conformance::env;
use synapse::mailbox::{MailConfig, MailStore, Mailbox};
use synapse_mailbox_persistant::{PersistantMailStore, SqliteMailStore};

const ROLE: &str = "lane@acct";
const BUDGET: u32 = 1_000_000;

fn body(n: u32) -> Vec<u8> {
    format!("message body {n}").into_bytes()
}

fn id(n: u32) -> String {
    format!("m{n}")
}

fn config() -> MailConfig {
    MailConfig {
        max_messages: BUDGET as usize,
        max_bytes: u64::MAX,
        ..MailConfig::default()
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 20, 12, 0, 0).unwrap()
}

/// The control: the same store and key layout, with `synchronous=OFF`.
fn sqlite_off(
    path: &str,
) -> Result<PersistantMailStore<KvOnRelational<Bounded<SqliteBackend>>>, String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let kv = rt.block_on(async {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Off)
            .busy_timeout(std::time::Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .map_err(|e| e.to_string())?;
        let db = SqliteBackend::from_pool(pool)
            .await
            .map_err(|e| format!("{e:?}"))?;
        KvOnRelational::open(Bounded::new(db, std::time::Duration::from_secs(30)))
            .await
            .map_err(|e| format!("{e:?}"))
    })?;
    rt.shutdown_background();
    PersistantMailStore::new(kv, "mail.v2").map_err(|e| e.to_string())
}

fn write_loop<S: MailStore>(mb: &mut Mailbox<S>, announce: bool) -> ExitCode {
    let mut acked = 0_u32;
    for n in 0..BUDGET {
        match mb.enqueue(env(&id(n), ROLE, &body(n)), now()) {
            Ok(_) => {
                acked = n + 1;
                if announce {
                    // The host reads this over SSH and cuts power right after seeing it.
                    println!("acked {n}");
                    let _ = std::io::stdout().flush();
                } else if acked.is_multiple_of(500) {
                    println!("progress {acked}");
                    let _ = std::io::stdout().flush();
                }
            }
            Err(e) => {
                println!("failed {n} after acked {acked}: {e}");
                return ExitCode::from(3);
            }
        }
    }
    if announce {
        ExitCode::SUCCESS
    } else {
        println!("never failed; acked {acked}");
        ExitCode::from(4)
    }
}

fn check<S: MailStore>(mb: &Mailbox<S>, count: u32) -> ExitCode {
    let mut lost = Vec::new();
    let mut unreadable: Vec<(u32, String)> = Vec::new();
    let mut held = 0_u32;
    for n in 0..count {
        let mut found = None;
        let read = mb.store().write(&mut |txn| {
            found = txn
                .queued(ROLE, &id(n))
                .map_err(synapse::mailbox::MailError::Store)?;
            Ok(())
        });
        match read {
            Ok(()) => match &found {
                Some(s) if s.envelope.body == body(n) => held += 1,
                _ => lost.push(n),
            },
            Err(e) => unreadable.push((n, e.to_string())),
        }
        if unreadable.len() >= 5 {
            break;
        }
    }
    if !lost.is_empty() {
        println!(
            "lost {} of {count} (held {held}, unreadable {}); first missing messages {:?}",
            lost.len(),
            unreadable.len(),
            &lost[..lost.len().min(8)]
        );
        ExitCode::from(1)
    } else if !unreadable.is_empty() {
        println!(
            "unreadable: {} errors at messages {:?}, stopped there (held {held} of {count}, none proven lost); first error: {}",
            unreadable.len(),
            unreadable.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            unreadable[0].1
        );
        ExitCode::from(6)
    } else {
        println!("held {count}");
        ExitCode::SUCCESS
    }
}

fn run<S: MailStore>(cmd: &str, mb: &mut Mailbox<S>, count: u32) -> ExitCode {
    match cmd {
        "write" => write_loop(mb, true),
        "check" => check(mb, count),
        _ => write_loop(mb, false),
    }
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (Some(cmd), Some(backend), Some(spec)) = (a.first(), a.get(1), a.get(2)) else {
        eprintln!("usage: mailbox_vm <write|check|enospc> <backend> <db-file> [count]");
        return ExitCode::from(2);
    };
    let count = a.get(3).and_then(|c| c.parse().ok()).unwrap_or(0);
    if !matches!(cmd.as_str(), "write" | "enospc") && !(cmd == "check" && count > 0) {
        eprintln!("usage: mailbox_vm <write|check|enospc> <backend> <db-file> [count]");
        return ExitCode::from(2);
    }
    let opened = now() - Duration::seconds(1);
    match backend.as_str() {
        "sqlite" => {
            let store = match SqliteMailStore::open(spec) {
                Ok(s) => s,
                Err(e) => {
                    println!("cannot open {spec}: {e}");
                    return ExitCode::from(2);
                }
            };
            // Through `Mailbox::open`: the durable store must be accepted as Machine.
            match Mailbox::open(store, config(), opened) {
                Ok(mut mb) => run(cmd, &mut mb, count),
                Err(e) => {
                    println!("cannot open the mailbox: {e}");
                    ExitCode::from(2)
                }
            }
        }
        "sqlite-off" => {
            let store = match sqlite_off(spec) {
                Ok(s) => s,
                Err(e) => {
                    println!("cannot open {spec}: {e}");
                    return ExitCode::from(2);
                }
            };
            match Mailbox::open_volatile(store, config(), opened) {
                Ok(mut mb) => run(cmd, &mut mb, count),
                Err(e) => {
                    println!("cannot open the mailbox: {e}");
                    ExitCode::from(2)
                }
            }
        }
        other => {
            eprintln!("unknown backend {other}");
            ExitCode::from(2)
        }
    }
}
