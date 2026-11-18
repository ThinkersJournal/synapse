// SPDX-License-Identifier: MIT OR Apache-2.0
//! Which store serves the mailbox: one decision, made in one place (ROADMAP row 42, slice B).
//!
//! In order: a pin (`SYNAPSE_MAILBOX_STORE`, deprecated, or `storage.id` in `synapsed.toml`) of
//! `redb` or, in a `sqlite-store` build, `sqlite`; else the PersistAnt provider recorded in
//! `<home>/mailbox-store.json`; else a home that already holds a mailbox file stays on the store it
//! has; else, in a `sqlite-store` build, the first file provider PersistAnt lists for the mailbox's
//! needs, which is then recorded; else redb. A different store is a different file: nothing is
//! migrated here (`migration::prepare` moves a redb mailbox when the SQLite store first opens).

use std::path::Path;

use crate::StoreKind;

/// The outcome of [`select_store`]: what [`crate::Daemon::open_selected`] opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// One of the daemon's own stores, named by a pin or by the file already in the home.
    Kind(StoreKind),
    /// A PersistAnt provider the operator recorded, or the one a fresh home was given.
    #[cfg(feature = "sqlite-store")]
    Named(synapse_mailbox_persistant::needs::StoreChoice),
}

/// Resolve the store for `home`. `pin` is `settings.store_pin`; `pin_from_env` is whether it came
/// from the deprecated environment variable (which prints its deprecation line). An error is the
/// message to print before exiting 2.
pub fn select_store(
    home: &Path,
    pin: Option<&str>,
    pin_from_env: bool,
) -> Result<Selection, String> {
    if let Some(pin) = pin {
        if pin_from_env {
            eprintln!(
                "synapsed: SYNAPSE_MAILBOX_STORE is deprecated; record a store with `synapse storage use`"
            );
        }
        return match pin {
            "" | "redb" => Ok(Selection::Kind(StoreKind::Redb)),
            #[cfg(feature = "sqlite-store")]
            "sqlite" => Ok(Selection::Kind(StoreKind::Sqlite)),
            other => Err(format!(
                "the store pin (SYNAPSE_MAILBOX_STORE, or storage.id in synapsed.toml) {other:?} is not available in this build (redb{})",
                if cfg!(feature = "sqlite-store") {
                    ", sqlite"
                } else {
                    "; sqlite needs --features sqlite-store"
                }
            )),
        };
    }
    #[cfg(feature = "sqlite-store")]
    {
        use synapse_mailbox_persistant::needs::{
            CHOICE_FILE, StoreChoice, first_file_store, listing,
        };
        if let Some(choice) = StoreChoice::read(home).map_err(|e| e.to_string())? {
            return Ok(Selection::Named(choice));
        }
        refuse_ambiguous_files(home)?;
        if home.join(StoreKind::Redb.file_name()).exists() {
            return Ok(Selection::Kind(StoreKind::Redb));
        }
        let Ok(listed) = listing(&synapse::mailbox::MailboxNeeds::MAILBOX) else {
            return Ok(Selection::Kind(StoreKind::Redb));
        };
        // A server needs a URL only the operator has, so a fresh home is given the best file store.
        let Some(top) = first_file_store(&listed) else {
            return Ok(Selection::Kind(StoreKind::Redb));
        };
        let choice = StoreChoice::new(top.id, None).map_err(|e| e.to_string())?;
        choice.write(home).map_err(|e| e.to_string())?;
        eprintln!(
            "synapsed: fresh home; recorded mailbox store {:?} in {CHOICE_FILE}",
            choice.id
        );
        Ok(Selection::Named(choice))
    }
    #[cfg(not(feature = "sqlite-store"))]
    {
        refuse_ambiguous_files(home)?;
        Ok(Selection::Kind(StoreKind::Redb))
    }
}

/// With no pin and no recorded choice, a home holding a `mailbox.sqlite` that the redb file does not
/// account for is not decided here. Opening redb beside it would create a second, empty store and
/// leave two stores in one home (the 2026-11-16 auto-start that chose redb next to the task's
/// SQLite store). Only the operator knows which file holds the mail, so say what to run.
fn refuse_ambiguous_files(home: &Path) -> Result<(), String> {
    let sqlite = home.join(StoreKind::Sqlite.file_name());
    if !sqlite.exists() {
        return Ok(());
    }
    let redb = home.join(StoreKind::Redb.file_name());
    // `mailbox.sqlite.migrated` is the marker `migration::prepare` leaves after a verified copy: the
    // home is on SQLite by design, and the daemon's own migration check owns that case.
    if redb.exists() && home.join(crate::migration::MARKER_FILE).exists() {
        return Ok(());
    }
    let have = if redb.exists() {
        "both mailbox.redb and mailbox.sqlite"
    } else {
        "mailbox.sqlite but no mailbox.redb"
    };
    Err(format!(
        "{} holds {have} and records no store choice (mailbox-store.json): refusing to pick one silently. Run `synapse storage use <id>` to record the store that holds the mail (`synapse storage inspect` compares the files), or pin it with storage.id in synapsed.toml",
        home.display()
    ))
}
