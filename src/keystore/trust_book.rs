// SPDX-License-Identifier: MIT OR Apache-2.0
//! The trust book: who knocked, and which account keys the holder chose to believe (ROADMAP row 33,
//! slice 1; PM ruling 2026-11-07, "promote a knock").
//!
//! Trust is a local allow-list and adding an account is the holder's act, never a message's
//! (`docs/FEDERATION_TRUST.md` section 5). So a first contact from an account nobody pinned is only
//! a **knock**: a record that grants nothing. The holder lists the knocks and pins one of them by
//! typing its key id back, and only then does [`TrustBook::load_into`] hand that account key to a
//! [`TrustStore`], whose chain rules then apply as they always did. Nothing here relaxes them: an
//! unpinned root still costs no signature work (spec 2026-09-17 decision 8), and no name is
//! resolved and no key is fetched.
//!
//! Two files under `<home>/trust/`, both owner-only and replaced atomically like the keystore's own:
//! `knocks.json` (bounded: [`MAX_KNOCKS`], strings cut to [`MAX_FIELD`]) and `trusted_accounts.json`
//! (the pins). A knock carries the **account key id** the sender's chain names (a hash, not the
//! key), so the holder gets the account's public key from that account's holder out of band and
//! [`TrustBook::pin`] checks that it hashes to both the knocked id and the id the holder retyped.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{KeystoreError, Result, ensure_dir, exists, read_checked, replace, valid_name};
use crate::sender_auth::{TrustStore, key_id, to_hex};

/// Knocks kept; the one least recently seen goes first.
pub const MAX_KNOCKS: usize = 256;
/// Characters kept of any string that came off the wire (a claimed id, a key id, a reason).
pub const MAX_FIELD: usize = 128;

const DIR: &str = "trust";
const KNOCKS: &str = "knocks.json";
const PINNED: &str = "trusted_accounts.json";
const ITEM_KNOCKS: &str = "trust book knocks";
const ITEM_PINNED: &str = "trust book pins";

/// Someone who tried to reach this node and was kept out. Grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookKnock {
    /// The id the sender claimed (`pm@alice`). Unverified.
    pub claimed_global_id: String,
    /// The key id on the sender's proof. Unverified.
    pub sender_key_id: String,
    /// The account key id the sender's chain named as its root: what the holder would pin. `None`
    /// when the knock had no chain.
    pub account_key_id: Option<String>,
    /// Why it was kept out (the verdict's name).
    pub reason: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
}

/// An account key the holder chose to believe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedAccount {
    /// The holder's own name for it; reporting only.
    pub label: String,
    pub key_id: String,
    /// The public key, lowercase hex (32 bytes).
    pub public_key_hex: String,
    pub pinned_at: DateTime<Utc>,
}

/// Why a pin was refused. Nothing is written for any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The label is not a [`valid_name`].
    BadLabel,
    /// The key id typed back is not the key id of the public key given: a typo, or the wrong key.
    ConfirmationMismatch,
    /// No knock names this account key id. A pin is made only from a knock.
    NoSuchKnock,
    /// This account key is already pinned.
    AlreadyPinned,
    /// The book could not be read or written.
    Store(KeystoreError),
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::BadLabel => write!(
                f,
                "the label may contain only letters, digits, '-' and '_' (1 to 64)"
            ),
            PinError::ConfirmationMismatch => write!(
                f,
                "the key id typed does not match the public key given: nothing was pinned"
            ),
            PinError::NoSuchKnock => write!(
                f,
                "no knock names that account key id: a pin is made only from a knock (see `synapse trust knocks`)"
            ),
            PinError::AlreadyPinned => write!(f, "that account key is already pinned"),
            PinError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PinError {}

impl From<KeystoreError> for PinError {
    fn from(e: KeystoreError) -> Self {
        PinError::Store(e)
    }
}

/// The book in one keystore home. Opening does no I/O.
#[derive(Debug, Clone)]
pub struct TrustBook {
    dir: PathBuf,
}

/// At most [`MAX_FIELD`] characters, cut on a character boundary.
fn cut(text: &str) -> String {
    text.chars().take(MAX_FIELD).collect()
}

impl TrustBook {
    #[must_use]
    pub fn open(home: &Path) -> TrustBook {
        TrustBook {
            dir: home.join(DIR),
        }
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str, item: &'static str) -> Result<Vec<T>> {
        let path = self.dir.join(name);
        if !exists(&path, item)? {
            return Ok(Vec::new());
        }
        let bytes = read_checked(&path, item)?;
        serde_json::from_slice(&bytes).map_err(|_| KeystoreError::Corrupt(item))
    }

    fn write<T: Serialize>(&self, name: &str, item: &'static str, rows: &[T]) -> Result<()> {
        ensure_dir(&self.dir, item)?;
        let bytes = serde_json::to_vec_pretty(rows).map_err(|_| KeystoreError::Corrupt(item))?;
        replace(&self.dir.join(name), &bytes, item)
    }

    /// Note that `claimed_global_id` knocked with `sender_key_id` (and, when its chain named one,
    /// `account_key_id`). All three are unverified text off the wire, so they are cut to
    /// [`MAX_FIELD`] characters and the book keeps at most [`MAX_KNOCKS`], dropping the one least
    /// recently seen. A repeat of the same (claimed id, sender key, account key) only counts.
    pub fn record_knock(
        &self,
        claimed_global_id: &str,
        sender_key_id: &str,
        account_key_id: Option<&str>,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut knocks: Vec<BookKnock> = self.read(KNOCKS, ITEM_KNOCKS)?;
        let claimed = cut(claimed_global_id);
        let sender = cut(sender_key_id);
        let account = account_key_id.map(cut);
        if let Some(known) = knocks.iter_mut().find(|k| {
            k.claimed_global_id == claimed
                && k.sender_key_id == sender
                && k.account_key_id == account
        }) {
            known.last_seen = now;
            known.count += 1;
            known.reason = cut(reason);
        } else {
            knocks.push(BookKnock {
                claimed_global_id: claimed,
                sender_key_id: sender,
                account_key_id: account,
                reason: cut(reason),
                first_seen: now,
                last_seen: now,
                count: 1,
            });
        }
        while knocks.len() > MAX_KNOCKS {
            if let Some(oldest) = knocks
                .iter()
                .enumerate()
                .min_by_key(|(_, k)| k.last_seen)
                .map(|(i, _)| i)
            {
                knocks.remove(oldest);
            }
        }
        self.write(KNOCKS, ITEM_KNOCKS, &knocks)
    }

    /// The knocks, most recently seen first.
    pub fn knocks(&self) -> Result<Vec<BookKnock>> {
        let mut knocks: Vec<BookKnock> = self.read(KNOCKS, ITEM_KNOCKS)?;
        knocks.sort_by_key(|k| std::cmp::Reverse(k.last_seen));
        Ok(knocks)
    }

    /// The account keys the holder pinned, oldest first.
    pub fn pinned(&self) -> Result<Vec<PinnedAccount>> {
        let mut pins: Vec<PinnedAccount> = self.read(PINNED, ITEM_PINNED)?;
        pins.sort_by_key(|p| p.pinned_at);
        Ok(pins)
    }

    /// Pin `public_key` as the account key `label`. The holder must have obtained the key from the
    /// account's holder, and must type its key id back as `confirm_key_id`: there is no default and
    /// no "yes" (PM ruling). Refused, with nothing written, unless the label is a name, the key
    /// hashes to exactly the id typed, and some knock names that id as its account key. The knocks
    /// for that key are removed on success: they are answered.
    pub fn pin(
        &self,
        label: &str,
        public_key: [u8; 32],
        confirm_key_id: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<PinnedAccount, PinError> {
        if !valid_name(label) {
            return Err(PinError::BadLabel);
        }
        let id = key_id(&public_key);
        if confirm_key_id.trim().to_ascii_lowercase() != id {
            return Err(PinError::ConfirmationMismatch);
        }
        let mut knocks: Vec<BookKnock> = self.read(KNOCKS, ITEM_KNOCKS)?;
        if !knocks
            .iter()
            .any(|k| k.account_key_id.as_deref() == Some(id.as_str()))
        {
            return Err(PinError::NoSuchKnock);
        }
        let mut pins: Vec<PinnedAccount> = self.read(PINNED, ITEM_PINNED)?;
        if pins.iter().any(|p| p.key_id == id) {
            return Err(PinError::AlreadyPinned);
        }
        let pinned = PinnedAccount {
            label: label.to_string(),
            key_id: id.clone(),
            public_key_hex: to_hex(&public_key),
            pinned_at: now,
        };
        pins.push(pinned.clone());
        self.write(PINNED, ITEM_PINNED, &pins)?;
        knocks.retain(|k| k.account_key_id.as_deref() != Some(id.as_str()));
        self.write(KNOCKS, ITEM_KNOCKS, &knocks)?;
        Ok(pinned)
    }

    /// Give `store` every pinned account key and nothing else: a knock is never loaded. Returns how
    /// many keys were given. A pin whose key does not hash to its own id (a hand-edited file) is
    /// `Corrupt`, not skipped.
    pub fn load_into(&self, store: &mut TrustStore) -> Result<usize> {
        let pins = self.pinned()?;
        for pin in &pins {
            let key = unhex32(&pin.public_key_hex).ok_or(KeystoreError::Corrupt(ITEM_PINNED))?;
            if key_id(&key) != pin.key_id {
                return Err(KeystoreError::Corrupt(ITEM_PINNED));
            }
            store.pin_account_key(pin.label.clone(), key);
        }
        Ok(pins.len())
    }
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}
