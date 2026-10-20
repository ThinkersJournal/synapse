// SPDX-License-Identifier: MIT OR Apache-2.0
//! First start on the SQLite store with a redb mailbox already in the home (`sqlite-store`): copy
//! the mailbox across, prove the copy, and leave a marker. Design:
//! `docs/MAILBOX_MIGRATION_REDB_TO_SQLITE.md`.
//!
//! The decision is made from three files and never guessed:
//!
//! | `mailbox.redb` | `mailbox.sqlite` | `mailbox.sqlite.migrated` | does |
//! |---|---|---|---|
//! | absent | any | any | nothing (a fresh home, or already on SQLite) |
//! | present | absent | any | copy, verify, write the marker |
//! | present | present | present | nothing (already migrated; the redb file is kept, now stale) |
//! | present | present | absent | refuse to start: either the SQLite store was made without a copy, or a copy was cut short, and only the operator knows which |
//!
//! Nothing is ever deleted. The redb file is only read, and is kept, so going back to redb is
//! possible but loses every message accepted since the move.

use std::io::Write;
use std::path::Path;

use synapse::mailbox::RedbStore;
use synapse::mailbox::migrate::copy_verified;
use synapse_mailbox_persistant::SqliteMailStore;

use crate::DaemonError;

pub(crate) const REDB_FILE: &str = "mailbox.redb";
pub(crate) const SQLITE_FILE: &str = "mailbox.sqlite";
pub(crate) const MARKER_FILE: &str = "mailbox.sqlite.migrated";

/// Bring `home` to a state where the SQLite store can be opened as the mailbox.
pub(crate) fn prepare(home: &Path) -> Result<(), DaemonError> {
    let (redb, sqlite, marker) = (
        home.join(REDB_FILE),
        home.join(SQLITE_FILE),
        home.join(MARKER_FILE),
    );
    if !redb.exists() {
        return Ok(());
    }
    match (sqlite.exists(), marker.exists()) {
        (true, true) => Ok(()),
        (true, false) => Err(DaemonError::Migration(format!(
            "both {REDB_FILE} and {SQLITE_FILE} exist in {} and {MARKER_FILE} does not, so it is not known \
             which holds the mail. Nothing was changed. If {SQLITE_FILE} is a leftover of a copy that was cut \
             short, remove it (and {SQLITE_FILE}-wal, {SQLITE_FILE}-shm, {SQLITE_FILE}.lock) and start again to \
             copy from {REDB_FILE}; if it holds mail you want, remove {REDB_FILE} instead.",
            home.display()
        ))),
        (false, _) => copy(&redb, &sqlite, &marker),
    }
}

fn copy(redb: &Path, sqlite: &Path, marker: &Path) -> Result<(), DaemonError> {
    let fail = |what: &str, e: &dyn std::fmt::Display| {
        DaemonError::Migration(format!(
            "copying the mailbox from {} to {}: {what}: {e}. {} is untouched; remove {} (and its -wal, -shm \
             and .lock files) before trying again",
            redb.display(),
            sqlite.display(),
            redb.display(),
            sqlite.display()
        ))
    };
    let summary = {
        // Opening redb takes its file lock, so a daemon still serving it makes this fail instead
        // of copying a moving target.
        let from = RedbStore::open(redb).map_err(|e| fail("open the redb store", &e))?;
        let to = SqliteMailStore::open(sqlite).map_err(|e| fail("create the SQLite store", &e))?;
        let copied = copy_verified(&from, &to).map_err(|e| fail("copy", &e))?;
        format!(
            "{} queued messages in {} queues, {} acked entries, {} role epochs, sequence {}",
            copied.messages(),
            copied.queues.len(),
            copied.acked.len(),
            copied.roles.roles.len(),
            copied.seq
        )
    };
    let mut file = std::fs::File::create(marker).map_err(|e| fail("write the marker", &e))?;
    writeln!(
        file,
        "copied from {REDB_FILE} and verified read-back equal: {summary}"
    )
    .and_then(|()| file.sync_all())
    .map_err(|e| fail("write the marker", &e))?;
    eprintln!("synapsed: mailbox copied from {REDB_FILE} to {SQLITE_FILE}: {summary}");
    Ok(())
}
