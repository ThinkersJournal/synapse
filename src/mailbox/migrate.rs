// SPDX-License-Identifier: MIT OR Apache-2.0
//! Copying a mailbox from one [`MailStore`] to another (redb to SQLite, board 229), and proving the
//! copy: the whole state is read out of the source, written to the destination in one transaction,
//! read back out of the destination, and the two must be equal. Run it offline, with no daemon
//! serving either store. Design: `docs/MAILBOX_MIGRATION_REDB_TO_SQLITE.md`.
//!
//! What is copied is everything the mailbox keeps: every role's queue in order (leases, attempt
//! counts and the dead sets included, which are queues of the pseudo-role `dead:<role>`), the acked
//! history that backs resend detection, the role epochs, and the sequence counter. Nothing is
//! translated: a lease taken before the copy is still held after it.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};

use super::{MailError, MailStore, StoreError, Stored};
use crate::roles::RolesState;

/// A mailbox's whole state, in a form two stores can be compared by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dump {
    /// Each role with queued mail (dead sets as `dead:<role>`), in ascending `seq`.
    pub queues: BTreeMap<String, Vec<Stored>>,
    /// Acked history: `(role, message id)` to when.
    pub acked: BTreeMap<(String, String), DateTime<Utc>>,
    pub roles: RolesState,
    /// The last sequence number handed out.
    pub seq: u64,
}

impl Dump {
    /// How many queued messages the dump holds, dead sets included.
    #[must_use]
    pub fn messages(&self) -> usize {
        self.queues.values().map(Vec::len).sum()
    }
}

/// Why a copy was refused.
#[derive(Debug)]
pub enum MigrateError {
    /// Reading or writing a store failed.
    Store(MailError),
    /// The destination, read back, differs from what was read out of the source.
    Mismatch(String),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Store(e) => write!(f, "{e}"),
            MigrateError::Mismatch(what) => write!(f, "the copy does not match the source: {what}"),
        }
    }
}

impl std::error::Error for MigrateError {}

impl From<MailError> for MigrateError {
    fn from(e: MailError) -> Self {
        MigrateError::Store(e)
    }
}

/// Read the whole state of `store`.
///
/// # Errors
/// When the store cannot be read, or does not support export (`MailTxn::queue_roles`).
pub fn dump<S: MailStore>(store: &S) -> Result<Dump, MailError> {
    let mut out = None;
    store.write(&mut |txn| {
        let mut queues = BTreeMap::new();
        for role in txn.queue_roles().map_err(MailError::Store)? {
            let mut rows = Vec::new();
            txn.scan(&role, &mut |stored| {
                rows.push(stored.clone());
                true
            })
            .map_err(MailError::Store)?;
            if !rows.is_empty() {
                queues.insert(role, rows);
            }
        }
        let acked = txn
            .all_acked()
            .map_err(MailError::Store)?
            .into_iter()
            .map(|(role, id, at)| ((role, id), at))
            .collect();
        out = Some(Dump {
            queues,
            acked,
            roles: txn.roles().map_err(MailError::Store)?,
            seq: txn.seq_counter().map_err(MailError::Store)?,
        });
        Ok(())
    })?;
    out.ok_or_else(|| MailError::Store(StoreError("dump produced nothing".into())))
}

/// Write `dump` into `store` in one transaction: all of it, or none.
///
/// # Errors
/// When the store cannot be written.
pub fn restore<S: MailStore>(store: &S, dump: &Dump) -> Result<(), MailError> {
    store.write(&mut |txn| {
        for (role, rows) in &dump.queues {
            for stored in rows {
                txn.put(role, stored.clone()).map_err(MailError::Store)?;
            }
        }
        for ((role, id), at) in &dump.acked {
            txn.record_ack(role, id, *at).map_err(MailError::Store)?;
        }
        txn.set_roles(&dump.roles).map_err(MailError::Store)?;
        txn.set_seq_counter(dump.seq).map_err(MailError::Store)?;
        Ok(())
    })
}

/// Copy `from` into `to` (which must be empty) and prove it: read `from`, write `to`, read `to`
/// back, and require the two reads to be equal. Returns what was copied.
///
/// # Errors
/// [`MigrateError::Mismatch`] naming the first difference; a store error otherwise. On either,
/// `to` may hold a partial or wrong copy and must be discarded; `from` is only read.
pub fn copy_verified<A: MailStore, B: MailStore>(from: &A, to: &B) -> Result<Dump, MigrateError> {
    let source = dump(from)?;
    restore(to, &source)?;
    let copy = dump(to)?;
    if let Some(difference) = first_difference(&source, &copy) {
        return Err(MigrateError::Mismatch(difference));
    }
    Ok(source)
}

fn first_difference(a: &Dump, b: &Dump) -> Option<String> {
    if a == b {
        return None;
    }
    if a.seq != b.seq {
        return Some(format!("sequence counter {} against {}", a.seq, b.seq));
    }
    if a.roles != b.roles {
        return Some("role epochs".into());
    }
    if a.acked != b.acked {
        return Some(format!(
            "acked history ({} entries against {})",
            a.acked.len(),
            b.acked.len()
        ));
    }
    for role in a.queues.keys().chain(b.queues.keys()) {
        if a.queues.get(role) != b.queues.get(role) {
            let (x, y) = (a.queues.get(role), b.queues.get(role));
            return Some(format!(
                "queue {role:?} ({} messages against {})",
                x.map_or(0, Vec::len),
                y.map_or(0, Vec::len)
            ));
        }
    }
    Some("state".into())
}
