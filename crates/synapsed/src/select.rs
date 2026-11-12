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
        if home.join(StoreKind::Redb.file_name()).exists()
            || home.join(StoreKind::Sqlite.file_name()).exists()
        {
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
        let _ = home;
        Ok(Selection::Kind(StoreKind::Redb))
    }
}
