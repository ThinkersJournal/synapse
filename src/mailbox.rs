// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox (M4): mail for a role waits for that role, across session restarts, daemon
//! restarts and crashes.
//!
//! Delivery is at-least-once. [`Mailbox::fetch`] **leases** messages; [`Mailbox::ack`] removes
//! one; a lease that expires makes its message deliverable again; consumers dedupe by
//! `message_id`. A role's newest claim (M3) voids every lease an older epoch held. Retention
//! ([`Mailbox::sweep`]) deletes **acked** history only, never undelivered mail.
//!
//! The mailbox never parses what it carries: an [`Envelope`]'s body is opaque bytes (the daemon
//! stores a signed message there). Every operation is one atomic write transaction on a
//! [`MailStore`], and a claim's new role state is written in the same call that grants it.
//! No clock: `now` is passed in. Design: `docs/superpowers/specs/2026-10-02-m4-mailbox-design.md`.

#[cfg(feature = "mailbox-conformance")]
pub mod conformance;
pub mod migrate;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::certificate::RevocationLookup;
use crate::roles::{ClaimError, ClaimRequest, Grant, InvalidState, Roles, RolesState, Superseded};

/// Bounds and timings (PM-approved defaults, spec §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    pub default_lease: Duration,
    pub min_lease: Duration,
    pub max_lease: Duration,
    /// How long acked history (and with it, dedupe of resends) is kept.
    pub retention: Duration,
    /// Per role, counting queued (unacked) messages.
    pub max_messages: usize,
    /// Per role, counting queued envelope body bytes.
    pub max_bytes: u64,
    /// How many times one message may be leased before it moves to the role's **dead set**
    /// (`0`: no cap). A message that is leased and never acked (a poison message, a receiver that
    /// fails every time) is otherwise redelivered for as long as it is queued. The dead set is
    /// bounded and visible, never silently dropped: see [`Mailbox::dead_letters`].
    pub max_deliveries: u32,
}

impl Default for MailConfig {
    fn default() -> Self {
        MailConfig {
            default_lease: Duration::seconds(60),
            min_lease: Duration::seconds(5),
            max_lease: Duration::minutes(15),
            retention: Duration::days(7),
            max_messages: 10_000,
            max_bytes: 64 * 1024 * 1024,
            max_deliveries: 10,
        }
    }
}

/// One message, as the mailbox carries it. `body` is opaque, and `Debug` shows only its length:
/// bodies are signed message content and can be large (final review M1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub message_id: String,
    /// The recipient role, `role@account`.
    pub to: String,
    pub from: String,
    pub body: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("message_id", &self.message_id)
            .field("to", &self.to)
            .field("from", &self.from)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The longest `message_id` or `from` the mailbox accepts, in bytes.
pub const MAX_ADDRESS_LEN: usize = 256;

/// Structural checks only (final review I3): the mailbox keys storage on these strings, so it
/// refuses ones that cannot be sane keys. Whether a sender may write to a role, and whether the
/// role exists, is the caller's (M5's) decision.
fn well_formed(env: &Envelope) -> bool {
    let printable =
        |s: &str| !s.is_empty() && s.len() <= MAX_ADDRESS_LEN && !s.chars().any(char::is_control);
    let role_id = env.to.split_once('@').is_some_and(|(role, account)| {
        crate::keystore::valid_name(role) && crate::keystore::valid_name(account)
    });
    role_id && printable(&env.message_id) && printable(&env.from)
}

/// The pseudo-role under which a role's dead set is stored: the ordinary queue tables, so no store
/// and no on-disk format changes. A real role name never contains `:` (see
/// `keystore::valid_name`), so no sender can address it and it cannot collide with one.
fn dead_role(role: &str) -> String {
    format!("dead:{role}")
}

/// Who holds a message, and until when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub epoch: u64,
    pub until: DateTime<Utc>,
}

/// A queued message as a store keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub envelope: Envelope,
    /// Enqueue order across the whole store; fetch returns ascending `seq`.
    pub seq: u64,
    pub enqueued_at: DateTime<Utc>,
    pub lease: Option<Lease>,
    /// How many times it has been leased.
    pub attempts: u32,
}

/// A leased message, as `fetch` hands it out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub envelope: Envelope,
    pub enqueued_at: DateTime<Utc>,
    pub lease_until: DateTime<Utc>,
    pub attempts: u32,
    /// An earlier lease on this message had run out by its deadline (as opposed to being voided by
    /// a takeover, or there being none). Lets a caller count expiries apart from takeovers.
    pub prior_lease_lapsed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enqueued {
    Queued,
    /// `(to, message_id)` is already queued, or was acked within retention. Nothing changed.
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acked {
    Removed,
    /// It was acked before; acking is idempotent.
    AlreadyAcked,
}

/// One role's mailbox depth at a moment (S-1): what `fetch` would hand out next, what the role's
/// current epoch holds, and when the oldest of either arrived. Acked mail is in neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Depth {
    pub queued: usize,
    pub leased: usize,
    /// Messages that reached `max_deliveries` and were set aside (see [`Mailbox::dead_letters`]).
    /// Not in `queued` or `leased`, and not in `oldest_enqueued_at`.
    pub dead: usize,
    pub oldest_enqueued_at: Option<DateTime<Utc>>,
}

/// What [`Mailbox::depths`] reads for one role: queued and leased counts and the oldest arrival.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueDepth {
    pub queued: usize,
    pub leased: usize,
    pub oldest_enqueued_at: Option<DateTime<Utc>>,
}

/// A store failure, described without message contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mail store: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MailError {
    /// The caller's epoch is not the role's current one.
    Superseded(Superseded),
    /// The recipient's queue is at its message or byte bound; the sender is told, nothing dropped.
    MailboxFull,
    /// No queued message with that id.
    NotFound,
    /// The message is not leased to the caller's epoch.
    NotYourLease,
    /// A requested lease is outside `[min_lease, max_lease]`.
    LeaseOutOfRange,
    /// The envelope's `to`, `message_id` or `from` is not well formed or is too long.
    Malformed,
    Claim(ClaimError),
    InvalidState(InvalidState),
    Store(StoreError),
    /// The store declares a [`DurabilityClass`] below [`REQUIRED_DURABILITY`]; [`Mailbox::open`]
    /// refuses it, because mail acknowledged to a sender must survive a power loss.
    DurabilityTooWeak {
        declared: DurabilityClass,
        required: DurabilityClass,
    },
    /// A store write failed after a claim was granted in memory. Reopen the mailbox.
    Poisoned,
}

/// How much failure an acknowledged write survives. Ordered: a class includes every weaker one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurabilityClass {
    /// Survives the process dying (a crash or kill), not the machine losing power.
    Process,
    /// Survives power loss: an acknowledged write is on stable storage.
    Machine,
}

impl fmt::Display for DurabilityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DurabilityClass::Process => "Process",
            DurabilityClass::Machine => "Machine",
        })
    }
}

/// The least durability a [`MailStore`] may declare for [`Mailbox::open`] to accept it.
/// CireSnave, 2026-10-18 (board 229): option A, `Machine` required. The full list of needs the
/// conformance suite enforces is `docs/MAILBOX_STORE_NEEDS.md`.
pub const REQUIRED_DURABILITY: DurabilityClass = DurabilityClass::Machine;

/// What the mailbox needs from whatever store holds it, stated without naming a store
/// (`docs/MAILBOX_STORE_NEEDS.md`). A selector (`synapse-mailbox-persistant::select`) maps these to a
/// storage kind's own checks and picks among the stores that meet every one; a need no store meets
/// is an error that lists why each was left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxNeeds {
    /// The least durability an acknowledged write must have (need 1).
    pub durability: DurabilityClass,
    /// A write applies every change or none, and concurrent writers cannot both win (needs 2, 6, 8).
    pub atomic_batch: bool,
    /// Entries come back in key order, so a queue scans in enqueue order (need 3).
    pub ordered_scan: bool,
    /// Entries can expire and be swept, which lease redelivery and retention rest on (needs 4, 5).
    pub lease_ttl: bool,
    /// A call that cannot finish returns an error within a bound (need 9).
    pub bounded_calls: bool,
}

impl MailboxNeeds {
    /// What [`Mailbox`] relies on today.
    pub const MAILBOX: MailboxNeeds = MailboxNeeds {
        durability: REQUIRED_DURABILITY,
        atomic_batch: true,
        ordered_scan: true,
        lease_ttl: true,
        bounded_calls: true,
    };
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::Superseded(s) => write!(f, "{s}"),
            MailError::MailboxFull => write!(f, "the recipient's mailbox is full"),
            MailError::NotFound => write!(f, "no such queued message"),
            MailError::NotYourLease => write!(f, "the message is not leased to this epoch"),
            MailError::LeaseOutOfRange => write!(f, "the requested lease is out of range"),
            MailError::Malformed => write!(f, "the envelope's addressing is malformed"),
            MailError::Claim(e) => write!(f, "{e}"),
            MailError::InvalidState(e) => write!(f, "{e}"),
            MailError::Store(e) => write!(f, "{e}"),
            MailError::DurabilityTooWeak { declared, required } => write!(
                f,
                "the store declares durability {declared}, the mailbox requires {required}"
            ),
            MailError::Poisoned => write!(f, "the mailbox must be reopened after a store failure"),
        }
    }
}

impl std::error::Error for MailError {}

/// Whether `epoch` may lease a message holding `lease` at `now`: it has none, it expired, or it
/// belongs to an older epoch (a takeover voids it).
pub fn is_free(lease: Option<&Lease>, epoch: u64, now: DateTime<Utc>) -> bool {
    match lease {
        None => true,
        Some(held) => held.until <= now || held.epoch != epoch,
    }
}

/// One write transaction's view of the store.
pub trait MailTxn {
    /// How many messages the role has queued, and their total body bytes.
    fn stats(&self, role: &str) -> Result<(usize, u64), StoreError>;
    /// Visit the role's queue in ascending `seq`, stopping when `visit` returns `false`. Lets a
    /// store stop early instead of loading a whole queue (final review I2).
    fn scan(&self, role: &str, visit: &mut dyn FnMut(&Stored) -> bool) -> Result<(), StoreError>;
    /// Visit each of the role's messages' `enqueued_at` and lease, never its body (S-1). The default
    /// goes through [`MailTxn::scan`]; a store that keeps bodies apart should override it.
    fn scan_leases(
        &self,
        role: &str,
        visit: &mut dyn FnMut(DateTime<Utc>, Option<&Lease>),
    ) -> Result<(), StoreError> {
        self.scan(role, &mut |stored| {
            visit(stored.enqueued_at, stored.lease.as_ref());
            true
        })
    }
    /// Visit the role's messages that `epoch` may lease at `now` (see [`is_free`]), in ascending
    /// `seq`, stopping when `visit` returns `false`. The default filters [`MailTxn::scan`]; a store
    /// that keeps bodies apart should override it so a skipped message's body is never loaded.
    fn scan_free(
        &self,
        role: &str,
        epoch: u64,
        now: DateTime<Utc>,
        visit: &mut dyn FnMut(&Stored) -> bool,
    ) -> Result<(), StoreError> {
        self.scan(role, &mut |stored| {
            if is_free(stored.lease.as_ref(), epoch, now) {
                visit(stored)
            } else {
                true
            }
        })
    }
    /// The role's [`QueueDepth`] for a holder of `epoch` at `now`: a lease counts as leased only
    /// while `fetch` would withhold it (unexpired, and held by `epoch`). The default goes through
    /// [`MailTxn::scan_leases`], reading every message; a store that indexes leases should override it.
    fn queue_depth(
        &self,
        role: &str,
        epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<QueueDepth, StoreError> {
        let mut depth = QueueDepth::default();
        self.scan_leases(role, &mut |enqueued_at, lease| {
            if lease.is_some_and(|held| held.epoch == epoch && held.until > now) {
                depth.leased += 1;
            } else {
                depth.queued += 1;
            }
            depth.oldest_enqueued_at = Some(
                depth
                    .oldest_enqueued_at
                    .map_or(enqueued_at, |oldest| oldest.min(enqueued_at)),
            );
        })?;
        Ok(depth)
    }
    fn queued(&self, role: &str, id: &str) -> Result<Option<Stored>, StoreError>;
    /// Insert, or replace by `envelope.message_id`.
    fn put(&mut self, role: &str, stored: Stored) -> Result<(), StoreError>;
    fn remove(&mut self, role: &str, id: &str) -> Result<(), StoreError>;
    fn acked_at(&self, role: &str, id: &str) -> Result<Option<DateTime<Utc>>, StoreError>;
    fn record_ack(&mut self, role: &str, id: &str, at: DateTime<Utc>) -> Result<(), StoreError>;
    /// Delete acked history recorded before `before`; returns how many.
    fn sweep_acked(&mut self, before: DateTime<Utc>) -> Result<usize, StoreError>;
    fn next_seq(&mut self) -> Result<u64, StoreError>;
    fn roles(&self) -> Result<RolesState, StoreError>;
    fn set_roles(&mut self, state: &RolesState) -> Result<(), StoreError>;

    // The four methods below exist for [`migrate`] (copying a mailbox between stores). They have
    // defaults that refuse, so a store that does not support export still compiles.

    /// Every role that has queued mail, dead sets (`dead:<role>`) included.
    fn queue_roles(&self) -> Result<Vec<String>, StoreError> {
        Err(StoreError("this store cannot export its roles".into()))
    }
    /// Every acked-history entry: role, message id, when.
    fn all_acked(&self) -> Result<Vec<(String, String, DateTime<Utc>)>, StoreError> {
        Err(StoreError(
            "this store cannot export its acked history".into(),
        ))
    }
    /// The last sequence number [`MailTxn::next_seq`] handed out.
    fn seq_counter(&self) -> Result<u64, StoreError> {
        Err(StoreError(
            "this store cannot export its sequence counter".into(),
        ))
    }
    /// Set the sequence counter, so the next [`MailTxn::next_seq`] returns `value + 1`.
    fn set_seq_counter(&mut self, value: u64) -> Result<(), StoreError> {
        let _ = value;
        Err(StoreError(
            "this store cannot import a sequence counter".into(),
        ))
    }
}

/// A transactional store.
pub trait MailStore {
    /// The strongest failure this store's acknowledged writes survive. No default: a store must
    /// state its class, so a new backend cannot be accepted by omission. Declare only what has
    /// been verified for the configuration in use (`Machine` means a commit has reached stable
    /// storage before `write` returns `Ok`).
    fn durability(&self) -> DurabilityClass;

    /// One atomic write transaction: every change `f` makes commits together, or none does.
    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError>;

    /// A transaction that only reads: `f` must not change anything, and anything it does change
    /// is discarded. The default is `write`; a store that can read without writing overrides it,
    /// so that reading what an earlier run acknowledged does not need room to write (a full disk
    /// must not hide the mail already on it).
    fn read(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        self.write(f)
    }
}

/// An in-memory store. `write` applies the closure to a copy and keeps it only on `Ok`.
#[derive(Default)]
pub struct MemoryStore {
    state: Mutex<MemState>,
}

#[derive(Clone, Default)]
struct MemState {
    queues: BTreeMap<String, BTreeMap<String, Stored>>,
    acked: BTreeMap<(String, String), DateTime<Utc>>,
    seq: u64,
    roles: RolesState,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        MemoryStore::default()
    }
}

impl MailStore for MemoryStore {
    fn durability(&self) -> DurabilityClass {
        DurabilityClass::Process
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| MailError::Store(StoreError("memory store lock poisoned".into())))?;
        let mut copy = guard.clone();
        f(&mut copy)?;
        *guard = copy;
        Ok(())
    }
}

impl MailTxn for MemState {
    fn stats(&self, role: &str) -> Result<(usize, u64), StoreError> {
        Ok(self.queues.get(role).map_or((0, 0), |q| {
            (
                q.len(),
                q.values().map(|s| s.envelope.body.len() as u64).sum(),
            )
        }))
    }

    fn scan(&self, role: &str, visit: &mut dyn FnMut(&Stored) -> bool) -> Result<(), StoreError> {
        let Some(queue) = self.queues.get(role) else {
            return Ok(());
        };
        let mut ordered: Vec<&Stored> = queue.values().collect();
        ordered.sort_by_key(|s| s.seq);
        for stored in ordered {
            if !visit(stored) {
                break;
            }
        }
        Ok(())
    }

    fn queued(&self, role: &str, id: &str) -> Result<Option<Stored>, StoreError> {
        Ok(self.queues.get(role).and_then(|q| q.get(id)).cloned())
    }

    fn put(&mut self, role: &str, stored: Stored) -> Result<(), StoreError> {
        self.queues
            .entry(role.to_string())
            .or_default()
            .insert(stored.envelope.message_id.clone(), stored);
        Ok(())
    }

    fn remove(&mut self, role: &str, id: &str) -> Result<(), StoreError> {
        if let Some(queue) = self.queues.get_mut(role) {
            queue.remove(id);
        }
        Ok(())
    }

    fn acked_at(&self, role: &str, id: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
        Ok(self.acked.get(&(role.to_string(), id.to_string())).copied())
    }

    fn record_ack(&mut self, role: &str, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        self.acked.insert((role.to_string(), id.to_string()), at);
        Ok(())
    }

    fn sweep_acked(&mut self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let len = self.acked.len();
        self.acked.retain(|_, at| *at >= before);
        Ok(len - self.acked.len())
    }

    fn next_seq(&mut self) -> Result<u64, StoreError> {
        self.seq += 1;
        Ok(self.seq)
    }

    fn queue_roles(&self) -> Result<Vec<String>, StoreError> {
        Ok(self.queues.keys().cloned().collect())
    }

    fn all_acked(&self) -> Result<Vec<(String, String, DateTime<Utc>)>, StoreError> {
        Ok(self
            .acked
            .iter()
            .map(|((role, id), at)| (role.clone(), id.clone(), *at))
            .collect())
    }

    fn seq_counter(&self) -> Result<u64, StoreError> {
        Ok(self.seq)
    }

    fn set_seq_counter(&mut self, value: u64) -> Result<(), StoreError> {
        self.seq = value;
        Ok(())
    }

    fn roles(&self) -> Result<RolesState, StoreError> {
        Ok(self.roles.clone())
    }

    fn set_roles(&mut self, state: &RolesState) -> Result<(), StoreError> {
        self.roles = state.clone();
        Ok(())
    }
}

/// The mailbox: role epochs (M3) in memory, everything else in the store.
pub struct Mailbox<S: MailStore> {
    store: S,
    config: MailConfig,
    roles: Roles,
    poisoned: bool,
}

impl<S: MailStore> Mailbox<S> {
    /// Open over `store`, restoring the role epochs it holds. Claims signed at or before `now`
    /// are refused after this (M3: a captured claim cannot be replayed across a restart).
    ///
    /// # Errors
    /// [`MailError::DurabilityTooWeak`] when the store declares less than [`REQUIRED_DURABILITY`].
    pub fn open(store: S, config: MailConfig, now: DateTime<Utc>) -> Result<Self, MailError> {
        let declared = store.durability();
        if declared < REQUIRED_DURABILITY {
            return Err(MailError::DurabilityTooWeak {
                declared,
                required: REQUIRED_DURABILITY,
            });
        }
        Self::open_volatile(store, config, now)
    }

    /// [`Mailbox::open`] without the durability check: for tests and throwaway in-memory use,
    /// never for a daemon's persistent mailbox.
    pub fn open_volatile(
        store: S,
        config: MailConfig,
        now: DateTime<Utc>,
    ) -> Result<Self, MailError> {
        let mut state = None;
        store.read(&mut |txn| {
            state = Some(txn.roles().map_err(MailError::Store)?);
            Ok(())
        })?;
        let roles =
            Roles::restore(state.unwrap_or_default(), now).map_err(MailError::InvalidState)?;
        Ok(Mailbox {
            store,
            config,
            roles,
            poisoned: false,
        })
    }

    /// `Ok` only for the role's current epoch; the daemon checks every session with this (M5).
    pub fn check(&self, role: &str, epoch: u64) -> Result<(), MailError> {
        self.live()?;
        self.roles.check(role, epoch).map_err(MailError::Superseded)
    }

    /// Every claimed role and its current epoch (the daemon's `list`, M5).
    #[must_use]
    pub fn roles_snapshot(&self) -> RolesState {
        self.roles.snapshot()
    }

    /// Every claimed role's [`Depth`] at `now` (S-1, the daemon's `list`). Changes nothing. A lease
    /// counts as leased only while `fetch` would withhold it: unexpired, and held by the role's
    /// current epoch.
    pub fn depths(&self, now: DateTime<Utc>) -> Result<BTreeMap<String, Depth>, MailError> {
        self.live()?;
        let roles = self.roles.snapshot();
        let mut out = BTreeMap::new();
        self.store.read(&mut |txn| {
            out.clear();
            for (role, record) in &roles.roles {
                let found = txn
                    .queue_depth(role, record.epoch, now)
                    .map_err(MailError::Store)?;
                let mut depth = Depth {
                    queued: found.queued,
                    leased: found.leased,
                    oldest_enqueued_at: found.oldest_enqueued_at,
                    ..Depth::default()
                };
                depth.dead = txn.stats(&dead_role(role)).map_err(MailError::Store)?.0;
                out.insert(role.clone(), depth);
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// The underlying store (tests and the daemon's diagnostics).
    pub fn store(&self) -> &S {
        &self.store
    }

    fn live(&self) -> Result<(), MailError> {
        if self.poisoned {
            Err(MailError::Poisoned)
        } else {
            Ok(())
        }
    }

    /// Queue `env` for its recipient. Mail may wait for a role that has never claimed.
    ///
    /// **Caller's contract (M5):** the sender is authenticated and allowed to write to `env.to`.
    /// The mailbox checks only that the addressing is well formed ([`MailError::Malformed`]) and
    /// bounds each role's queue; it cannot know which roles exist, so the number of roles is the
    /// caller's to bound. A resend of an acked message is a [`Enqueued::Duplicate`] for as long as
    /// acked history is retained, and is delivered again after [`Mailbox::sweep`] removes it.
    pub fn enqueue(&mut self, env: Envelope, now: DateTime<Utc>) -> Result<Enqueued, MailError> {
        self.live()?;
        if !well_formed(&env) {
            return Err(MailError::Malformed);
        }
        let config = self.config.clone();
        let mut outcome = Enqueued::Queued;
        self.store.write(&mut |txn| {
            let role = env.to.as_str();
            let id = env.message_id.as_str();
            if txn.queued(role, id).map_err(MailError::Store)?.is_some()
                || txn.acked_at(role, id).map_err(MailError::Store)?.is_some()
                || txn
                    .queued(&dead_role(role), id)
                    .map_err(MailError::Store)?
                    .is_some()
            {
                outcome = Enqueued::Duplicate;
                return Ok(());
            }
            let (count, bytes) = txn.stats(role).map_err(MailError::Store)?;
            if count + 1 > config.max_messages
                || bytes.saturating_add(env.body.len() as u64) > config.max_bytes
            {
                return Err(MailError::MailboxFull);
            }
            let seq = txn.next_seq().map_err(MailError::Store)?;
            txn.put(
                role,
                Stored {
                    envelope: env.clone(),
                    seq,
                    enqueued_at: now,
                    lease: None,
                    attempts: 0,
                },
            )
            .map_err(MailError::Store)?;
            outcome = Enqueued::Queued;
            Ok(())
        })?;
        Ok(outcome)
    }

    /// Take a role (M3) and persist the new epoch in the same call. If the store write fails the
    /// mailbox is poisoned: the epoch was granted in memory but not recorded.
    pub fn claim(
        &mut self,
        req: &ClaimRequest,
        account_keys: &dyn Fn(&str) -> Option<[u8; 32]>,
        revoked: &dyn RevocationLookup,
        now: DateTime<Utc>,
    ) -> Result<Grant, MailError> {
        self.live()?;
        let grant = self
            .roles
            .claim(req, account_keys, revoked, now)
            .map_err(MailError::Claim)?;
        let snapshot = self.roles.snapshot();
        let written = self
            .store
            .write(&mut |txn| txn.set_roles(&snapshot).map_err(MailError::Store));
        if let Err(e) = written {
            self.poisoned = true;
            return Err(e);
        }
        Ok(grant)
    }

    /// Lease up to `max` deliverable messages, oldest first. A message is deliverable when it has
    /// no lease, its lease expired, or its lease belongs to an older epoch (a takeover voids it).
    pub fn fetch(
        &mut self,
        role: &str,
        epoch: u64,
        max: usize,
        lease: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<Vec<Delivery>, MailError> {
        self.fetch_excluding(role, epoch, max, lease, now, &[])
    }

    /// [`Self::fetch`], passing over the messages named in `exclude`: they are not leased, their
    /// attempt count does not move, and they do not count toward `max`. For a consumer that has
    /// already delivered a message as often as it intends to and wants the rest, without removing
    /// it (removal is the receiver's `ack`).
    pub fn fetch_excluding(
        &mut self,
        role: &str,
        epoch: u64,
        max: usize,
        lease: Option<Duration>,
        now: DateTime<Utc>,
        exclude: &[String],
    ) -> Result<Vec<Delivery>, MailError> {
        self.live()?;
        self.roles
            .check(role, epoch)
            .map_err(MailError::Superseded)?;
        let lease = lease.unwrap_or(self.config.default_lease);
        if lease < self.config.min_lease || lease > self.config.max_lease {
            return Err(MailError::LeaseOutOfRange);
        }
        let config = self.config.clone();
        let until = now + lease;
        let mut out = Vec::new();
        if max == 0 {
            return Ok(out);
        }
        self.store.write(&mut |txn| {
            out.clear();
            // Collect up to `max` free messages in order, stopping the scan early, then lease them.
            let mut picked: Vec<Stored> = Vec::new();
            txn.scan_free(role, epoch, now, &mut |stored| {
                if exclude.contains(&stored.envelope.message_id) {
                    return true;
                }
                picked.push(stored.clone());
                picked.len() < max
            })
            .map_err(MailError::Store)?;
            let dead_set = dead_role(role);
            for mut stored in picked {
                // Leased `max_deliveries` times already and still here: set it aside, body and all,
                // instead of leasing it again. If the dead set is itself full it stays queued: a
                // message is never dropped to make room.
                if config.max_deliveries > 0 && stored.attempts >= config.max_deliveries {
                    let (count, bytes) = txn.stats(&dead_set).map_err(MailError::Store)?;
                    if count < config.max_messages
                        && bytes.saturating_add(stored.envelope.body.len() as u64)
                            <= config.max_bytes
                    {
                        let id = stored.envelope.message_id.clone();
                        txn.remove(role, &id).map_err(MailError::Store)?;
                        stored.lease = None;
                        txn.put(&dead_set, stored).map_err(MailError::Store)?;
                        continue;
                    }
                }
                let prior_lease_lapsed = stored.lease.is_some_and(|held| held.until <= now);
                stored.lease = Some(Lease { epoch, until });
                stored.attempts = stored.attempts.saturating_add(1);
                out.push(Delivery {
                    envelope: stored.envelope.clone(),
                    enqueued_at: stored.enqueued_at,
                    lease_until: until,
                    attempts: stored.attempts,
                    prior_lease_lapsed,
                });
                txn.put(role, stored).map_err(MailError::Store)?;
            }
            Ok(())
        })?;
        Ok(out)
    }

    /// Acknowledge a message this epoch holds the lease on (expired or not: the holder processed
    /// it). Idempotent.
    pub fn ack(
        &mut self,
        role: &str,
        epoch: u64,
        message_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Acked, MailError> {
        self.live()?;
        self.roles
            .check(role, epoch)
            .map_err(MailError::Superseded)?;
        let mut outcome = Acked::Removed;
        self.store.write(&mut |txn| {
            if txn
                .acked_at(role, message_id)
                .map_err(MailError::Store)?
                .is_some()
            {
                outcome = Acked::AlreadyAcked;
                return Ok(());
            }
            // Acking a dead message is the receiver discarding it.
            let dead = dead_role(role);
            if txn
                .queued(&dead, message_id)
                .map_err(MailError::Store)?
                .is_some()
            {
                txn.remove(&dead, message_id).map_err(MailError::Store)?;
                txn.record_ack(role, message_id, now)
                    .map_err(MailError::Store)?;
                outcome = Acked::Removed;
                return Ok(());
            }
            let stored = txn
                .queued(role, message_id)
                .map_err(MailError::Store)?
                .ok_or(MailError::NotFound)?;
            match stored.lease {
                Some(held) if held.epoch == epoch => {}
                _ => return Err(MailError::NotYourLease),
            }
            txn.remove(role, message_id).map_err(MailError::Store)?;
            txn.record_ack(role, message_id, now)
                .map_err(MailError::Store)?;
            outcome = Acked::Removed;
            Ok(())
        })?;
        Ok(outcome)
    }

    /// Delete acked history older than the retention period. Queued mail is never touched.
    ///
    /// Acked history is outside the per-role queue bound and grows until swept, so the daemon
    /// (M5) must call this periodically (final review I4).
    pub fn sweep(&mut self, now: DateTime<Utc>) -> Result<usize, MailError> {
        self.live()?;
        let before = now - self.config.retention;
        let roles = self.roles.snapshot();
        let mut swept = 0;
        self.store.write(&mut |txn| {
            swept = txn.sweep_acked(before).map_err(MailError::Store)?;
            // The dead set is kept for the same retention, counted from when the message was
            // enqueued, then removed: bounded, and visible until then.
            for role in roles.roles.keys() {
                let dead = dead_role(role);
                let mut expired = Vec::new();
                txn.scan(&dead, &mut |stored| {
                    if stored.enqueued_at < before {
                        expired.push(stored.envelope.message_id.clone());
                    }
                    true
                })
                .map_err(MailError::Store)?;
                for id in expired {
                    txn.remove(&dead, &id).map_err(MailError::Store)?;
                    swept += 1;
                }
            }
            Ok(())
        })?;
        Ok(swept)
    }

    /// The role's dead set, oldest first, bodies included: what was set aside after
    /// `max_deliveries` leases and never acked. Changes nothing. Bounded by `max_messages` and
    /// `max_bytes` like the queue, and kept for `retention`; never silently dropped.
    pub fn dead_letters(&self, role: &str, epoch: u64) -> Result<Vec<Stored>, MailError> {
        self.live()?;
        self.roles
            .check(role, epoch)
            .map_err(MailError::Superseded)?;
        let mut out = Vec::new();
        self.store.write(&mut |txn| {
            out.clear();
            txn.scan(&dead_role(role), &mut |stored| {
                out.push(stored.clone());
                true
            })
            .map_err(MailError::Store)
        })?;
        Ok(out)
    }

    /// Put a dead message back in the role's queue with its delivery count reset. The queue bound
    /// applies: a full queue refuses with [`MailError::MailboxFull`] and the message stays dead.
    pub fn requeue_dead(
        &mut self,
        role: &str,
        epoch: u64,
        message_id: &str,
    ) -> Result<(), MailError> {
        self.live()?;
        self.roles
            .check(role, epoch)
            .map_err(MailError::Superseded)?;
        let config = self.config.clone();
        self.store.write(&mut |txn| {
            let dead = dead_role(role);
            let mut stored = txn
                .queued(&dead, message_id)
                .map_err(MailError::Store)?
                .ok_or(MailError::NotFound)?;
            let (count, bytes) = txn.stats(role).map_err(MailError::Store)?;
            if count + 1 > config.max_messages
                || bytes.saturating_add(stored.envelope.body.len() as u64) > config.max_bytes
            {
                return Err(MailError::MailboxFull);
            }
            txn.remove(&dead, message_id).map_err(MailError::Store)?;
            stored.attempts = 0;
            stored.lease = None;
            txn.put(role, stored).map_err(MailError::Store)
        })
    }
}

/// A durable [`MailStore`] on redb (M4 PR 2; D1, CireSnave: *"Redb is fine for now."*).
///
/// Every [`MailStore::write`] is exactly one redb write transaction, committed only when the
/// closure returns `Ok` and aborted otherwise; a process that dies inside it leaves the previous
/// committed state. Bodies live apart from lease metadata, so leasing a message never rewrites
/// its body. The file is created owner-only and checked on every open (M2's permission check).
#[cfg(feature = "mailbox-redb")]
pub struct RedbStore {
    db: redb::Database,
    body_writes: std::sync::atomic::AtomicU64,
    body_reads: std::sync::atomic::AtomicU64,
    meta_decodes: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "mailbox-redb")]
use redb::ReadableTable;

#[cfg(feature = "mailbox-redb")]
mod redb_tables {
    use redb::TableDefinition;
    /// `(role, seq)` -> serde_json `Meta`.
    pub const META: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("meta");
    /// `(role, seq)` -> raw body bytes, written once.
    pub const BODIES: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("bodies");
    /// `(role, message_id)` -> `seq`.
    pub const BY_ID: TableDefinition<(&str, &str), u64> = TableDefinition::new("by_id");
    /// `(role, message_id)` -> acked-at, unix micros.
    pub const ACKED: TableDefinition<(&str, &str), i64> = TableDefinition::new("acked");
    /// `(acked-at micros, role, message_id)` -> nothing: the sweep's time index.
    pub const ACKED_BY_TIME: TableDefinition<(i64, &str, &str), ()> =
        TableDefinition::new("acked_by_time");
    /// `role` -> `(queued count, queued body bytes)`.
    pub const STATS: TableDefinition<&str, (u64, u64)> = TableDefinition::new("stats");
    /// `"seq"` -> the last sequence number issued.
    pub const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");
    /// `"state"` -> serde_json `RolesState`.
    pub const ROLES: TableDefinition<&str, &[u8]> = TableDefinition::new("roles");
    /// `(role, seq)` -> `(epoch, until micros)` for each message that holds a lease: a fixed-width
    /// copy of `Meta::lease`, so `fetch` can tell a held message from a free one without decoding
    /// its JSON (the fetch-scan slice). `RedbTxn::put` and `remove` keep it equal to `META`.
    pub const LEASES: TableDefinition<(&str, u64), (u64, i64)> = TableDefinition::new("leases");
    /// The `COUNTERS` key that stamps the store's format.
    pub const FORMAT_KEY: &str = "format";
    /// The format this binary writes. Absent = 1 (rc.26 and earlier: no `LEASES`). 2 = `LEASES`.
    pub const FORMAT: u64 = 2;
}

#[cfg(feature = "mailbox-redb")]
#[derive(Serialize, Deserialize)]
struct Meta {
    message_id: String,
    from: String,
    enqueued_at: DateTime<Utc>,
    lease: Option<Lease>,
    attempts: u32,
    body_len: u64,
}

#[cfg(feature = "mailbox-redb")]
fn store_err(what: &str) -> impl Fn(&dyn fmt::Display) -> StoreError + '_ {
    move |e| StoreError(format!("{what}: {e}"))
}

#[cfg(feature = "mailbox-redb")]
fn micros(at: DateTime<Utc>) -> i64 {
    at.timestamp_micros()
}

#[cfg(feature = "mailbox-redb")]
impl RedbStore {
    /// Create or open the store at `path`. A new file is created owner-only (Unix `0600`; on
    /// Windows it inherits the user profile's ACL); every open refuses a file broader than its owner.
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        #[cfg(unix)]
        create_owner_only(path).map_err(|e| store_err("create")(&e))?;
        let db = redb::Database::create(path).map_err(|e| store_err("open")(&e))?;
        crate::keystore::check_owner_only(path, "mail store")
            .map_err(|e| store_err("permissions")(&e))?;
        // Create every table once, so later read paths can assume they exist.
        let txn = db.begin_write().map_err(|e| store_err("begin")(&e))?;
        {
            use redb_tables::*;
            txn.open_table(META).map_err(|e| store_err("table")(&e))?;
            txn.open_table(BODIES).map_err(|e| store_err("table")(&e))?;
            txn.open_table(BY_ID).map_err(|e| store_err("table")(&e))?;
            txn.open_table(ACKED).map_err(|e| store_err("table")(&e))?;
            txn.open_table(ACKED_BY_TIME)
                .map_err(|e| store_err("table")(&e))?;
            txn.open_table(STATS).map_err(|e| store_err("table")(&e))?;
            txn.open_table(COUNTERS)
                .map_err(|e| store_err("table")(&e))?;
            txn.open_table(ROLES).map_err(|e| store_err("table")(&e))?;
            txn.open_table(LEASES).map_err(|e| store_err("table")(&e))?;
        }
        // The migration shares this transaction with the table creation, so a crash anywhere in it
        // leaves the file exactly as the old binary wrote it, and the next open starts again.
        migrate(&txn)?;
        txn.commit().map_err(|e| store_err("commit")(&e))?;
        Ok(RedbStore {
            db,
            body_writes: std::sync::atomic::AtomicU64::new(0),
            body_reads: std::sync::atomic::AtomicU64::new(0),
            meta_decodes: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// How many body rows this handle has written (a diagnostic: lease updates must not add to it).
    #[must_use]
    pub fn body_writes(&self) -> u64 {
        self.body_writes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many body rows this handle has read (a diagnostic: counting a queue must not add to it).
    #[must_use]
    pub fn body_reads(&self) -> u64 {
        self.body_reads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many `META` rows `fetch`'s scan has JSON-decoded on this handle (a diagnostic: a held message
    /// must be skipped from its `leases` row without being decoded).
    #[must_use]
    pub fn meta_decodes(&self) -> u64 {
        self.meta_decodes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Bring the store to [`redb_tables::FORMAT`] inside `txn`, which the caller commits: a store with no
/// stamp (rc.26 and earlier, or a new one) has its `LEASES` rebuilt from `META`; a stamp newer than
/// this binary knows is refused. Idempotent: at the current format it reads one counter and changes
/// nothing. Dropping `txn` without committing undoes all of it.
#[cfg(feature = "mailbox-redb")]
fn migrate(txn: &redb::WriteTransaction) -> Result<(), StoreError> {
    use redb_tables::{COUNTERS, FORMAT, FORMAT_KEY, LEASES, META};
    let stamped = txn
        .open_table(COUNTERS)
        .map_err(|e| store_err("counters")(&e))?
        .get(FORMAT_KEY)
        .map_err(|e| store_err("counters")(&e))?
        .map(|g| g.value());
    match stamped {
        Some(v) if v > FORMAT => {
            return Err(StoreError(format!(
                "mail store is format {v}, newer than this binary understands (format {FORMAT}); \
                 upgrade synapse, a downgrade is not supported"
            )));
        }
        Some(_) => return Ok(()),
        None => {}
    }
    let mut rows: Vec<((String, u64), (u64, i64))> = Vec::new();
    {
        let meta = txn.open_table(META).map_err(|e| store_err("meta")(&e))?;
        for entry in meta.iter().map_err(|e| store_err("meta")(&e))? {
            let (k, v) = entry.map_err(|e| store_err("meta")(&e))?;
            let m: Meta =
                serde_json::from_slice(v.value()).map_err(|e| store_err("meta decode")(&e))?;
            if let Some(lease) = m.lease {
                let (role, seq) = k.value();
                rows.push(((role.to_string(), seq), (lease.epoch, micros(lease.until))));
            }
        }
    }
    let mut leases = txn
        .open_table(LEASES)
        .map_err(|e| store_err("leases")(&e))?;
    leases
        .retain(|_, _| false)
        .map_err(|e| store_err("leases")(&e))?;
    for ((role, seq), held) in &rows {
        leases
            .insert((role.as_str(), *seq), *held)
            .map_err(|e| store_err("leases")(&e))?;
    }
    drop(leases);
    let mut counters = txn
        .open_table(COUNTERS)
        .map_err(|e| store_err("counters")(&e))?;
    counters
        .insert(FORMAT_KEY, FORMAT)
        .map_err(|e| store_err("counters")(&e))?;
    #[cfg(test)]
    if FAIL_AFTER_REBUILD.with(std::cell::Cell::get) {
        return Err(StoreError("injected failure after the rebuild".into()));
    }
    Ok(())
}

// Test hook: make `migrate` fail on this thread once everything is written but before the commit.
#[cfg(all(test, feature = "mailbox-redb"))]
thread_local! {
    static FAIL_AFTER_REBUILD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(feature = "mailbox-redb")]
impl RedbStore {
    /// How many `leases` rows the store holds (a diagnostic: it must equal the messages with a lease).
    pub fn held_rows(&self) -> Result<usize, StoreError> {
        use redb::ReadableDatabase;
        let txn = self.db.begin_read().map_err(|e| store_err("begin")(&e))?;
        let t = txn
            .open_table(redb_tables::LEASES)
            .map_err(|e| store_err("leases")(&e))?;
        let mut n = 0usize;
        for entry in t.iter().map_err(|e| store_err("leases")(&e))? {
            entry.map_err(|e| store_err("leases")(&e))?;
            n += 1;
        }
        Ok(n)
    }

    /// The store's format stamp, if any.
    pub fn format(&self) -> Result<Option<u64>, StoreError> {
        use redb::ReadableDatabase;
        let txn = self.db.begin_read().map_err(|e| store_err("begin")(&e))?;
        let t = txn
            .open_table(redb_tables::COUNTERS)
            .map_err(|e| store_err("counters")(&e))?;
        let got = t
            .get(redb_tables::FORMAT_KEY)
            .map_err(|e| store_err("counters")(&e))?
            .map(|g| g.value());
        Ok(got)
    }
}

/// Create `path` empty and `0600` if it is absent, before redb opens it (redb initialises an empty
/// file). A file redb creates gets the umask's mode, often `0644`, and the creator may then lose
/// redb's lock to a racing daemon: the winner, finding a file it did not create, refused it as too
/// open, and both daemons exited. An M5a bug, found by M5b's concurrent-start test on Linux. An
/// existing file is opened without truncation and left as it is.
#[cfg(all(feature = "mailbox-redb", unix))]
fn create_owner_only(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map(drop)
}

#[cfg(all(test, feature = "mailbox-redb", unix))]
mod redb_create_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// Two daemons racing to open one new store: the one that creates the file loses redb's lock,
    /// and the winner must still accept the file. The creator's part is simulated by the step it
    /// takes before locking (and then dropping the handle, as a lock loser exits).
    #[test]
    fn a_store_file_created_by_a_racing_opener_is_owner_only_and_accepted() {
        let dir = tempfile::tempdir().unwrap();

        // Positive control, the M5a path: redb creates the file with the umask's mode (0644 under
        // the usual 022), and the winner refuses it.
        let old = dir.path().join("old.redb");
        drop(redb::Database::create(&old).unwrap());
        assert_ne!(
            mode(&old) & 0o077,
            0,
            "control: expected a umask-mode file, got {:o}",
            mode(&old)
        );
        assert!(
            RedbStore::open(&old).is_err(),
            "control: the winner refuses a file it found too open"
        );

        // The fix: the loser's first step creates the file 0600, so the winner opens it.
        let new = dir.path().join("new.redb");
        create_owner_only(&new).unwrap();
        assert_eq!(mode(&new), 0o600);
        RedbStore::open(&new).expect("the winner opens the file the loser created");
        assert_eq!(mode(&new), 0o600);
    }

    #[test]
    fn a_fresh_store_file_is_never_created_looser_than_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.redb");
        drop(RedbStore::open(&path).unwrap());
        assert_eq!(mode(&path), 0o600);
    }
}

/// The migration is one write transaction: a process that dies after rebuilding `leases` but before
/// the commit (simulated by dropping the transaction, which is what `mailbox_crash.rs` shows a real
/// abort amounts to) leaves the file as rc.26 wrote it, and the next open migrates it in full.
#[cfg(all(test, feature = "mailbox-redb"))]
mod redb_migration_tests {
    use super::*;
    use redb::ReadableDatabase;

    fn counts(path: &std::path::Path) -> (usize, Option<u64>) {
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_read().unwrap();
        let held = txn
            .open_table(redb_tables::LEASES)
            .unwrap()
            .iter()
            .unwrap()
            .count();
        let format = txn
            .open_table(redb_tables::COUNTERS)
            .unwrap()
            .get(redb_tables::FORMAT_KEY)
            .unwrap()
            .map(|g| g.value());
        (held, format)
    }

    fn rc26_with_one_lease(path: &std::path::Path) {
        let store = RedbStore::open(path).unwrap();
        let at = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        store
            .write(&mut |txn| {
                txn.put(
                    "lane@acct",
                    Stored {
                        envelope: Envelope {
                            message_id: "m0".into(),
                            to: "lane@acct".into(),
                            from: "peer@acct".into(),
                            body: b"x".to_vec(),
                        },
                        seq: 1,
                        enqueued_at: at,
                        lease: Some(Lease {
                            epoch: 1,
                            until: at,
                        }),
                        attempts: 1,
                    },
                )
                .map_err(MailError::Store)
            })
            .unwrap();
        drop(store);
        let db = redb::Database::open(path).unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(redb_tables::LEASES)
            .unwrap()
            .retain(|_, _| false)
            .unwrap();
        txn.open_table(redb_tables::COUNTERS)
            .unwrap()
            .remove(redb_tables::FORMAT_KEY)
            .unwrap();
        txn.commit().unwrap();
    }

    #[test]
    fn a_migration_that_dies_before_commit_changes_nothing_and_reruns_in_full() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.redb");
        rc26_with_one_lease(&path);
        assert_eq!(counts(&path), (0, None), "setup: an rc.26-shaped file");

        {
            let db = redb::Database::open(&path).unwrap();
            let txn = db.begin_write().unwrap();
            migrate(&txn).unwrap();
            // The process dies here: no commit.
            drop(txn);
        }
        assert_eq!(
            counts(&path),
            (0, None),
            "an uncommitted migration left a trace"
        );

        let store = RedbStore::open(&path).expect("reopen migrates");
        assert_eq!(store.held_rows().unwrap(), 1);
        assert_eq!(store.format().unwrap(), Some(redb_tables::FORMAT));
        drop(store);

        // Control: the harness can tell a committed migration from an aborted one.
        assert_eq!(counts(&path), (1, Some(redb_tables::FORMAT)));
    }

    /// The same, through `RedbStore::open`: a migration that fails after writing everything must
    /// leave the file untouched (open must not commit what it could not finish), and a later open
    /// must succeed.
    #[test]
    fn a_failed_migration_in_open_commits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.redb");
        rc26_with_one_lease(&path);

        FAIL_AFTER_REBUILD.with(|f| f.set(true));
        let failed = RedbStore::open(&path);
        FAIL_AFTER_REBUILD.with(|f| f.set(false));
        assert!(
            failed.is_err(),
            "the injected failure must reach the caller"
        );
        drop(failed);
        assert_eq!(counts(&path), (0, None), "a failed migration left a trace");

        let store = RedbStore::open(&path).expect("the next open migrates");
        assert_eq!(store.held_rows().unwrap(), 1);
    }
}

#[cfg(feature = "mailbox-redb")]
impl MailStore for RedbStore {
    /// redb commits at its default `Durability::Immediate` (fsync before return); this store never
    /// lowers it.
    fn durability(&self) -> DurabilityClass {
        DurabilityClass::Machine
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| MailError::Store(store_err("begin")(&e)))?;
        let outcome = {
            let mut view = RedbTxn {
                txn: &txn,
                body_writes: &self.body_writes,
                body_reads: &self.body_reads,
                meta_decodes: &self.meta_decodes,
            };
            f(&mut view)
        };
        match outcome {
            Ok(()) => txn
                .commit()
                .map_err(|e| MailError::Store(store_err("commit")(&e))),
            Err(e) => {
                txn.abort()
                    .map_err(|ae| MailError::Store(store_err("abort")(&ae)))?;
                Err(e)
            }
        }
    }
}

#[cfg(feature = "mailbox-redb")]
struct RedbTxn<'a> {
    txn: &'a redb::WriteTransaction,
    body_writes: &'a std::sync::atomic::AtomicU64,
    body_reads: &'a std::sync::atomic::AtomicU64,
    meta_decodes: &'a std::sync::atomic::AtomicU64,
}

#[cfg(feature = "mailbox-redb")]
impl RedbTxn<'_> {
    fn seq_of(&self, role: &str, id: &str) -> Result<Option<u64>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::BY_ID)
            .map_err(|e| store_err("by_id")(&e))?;
        Ok(t.get((role, id))
            .map_err(|e| store_err("by_id")(&e))?
            .map(|g| g.value()))
    }

    fn meta(&self, role: &str, seq: u64) -> Result<Option<Meta>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::META)
            .map_err(|e| store_err("meta")(&e))?;
        let Some(raw) = t.get((role, seq)).map_err(|e| store_err("meta")(&e))? else {
            return Ok(None);
        };
        serde_json::from_slice(raw.value())
            .map(Some)
            .map_err(|e| store_err("meta decode")(&e))
    }

    fn body(&self, role: &str, seq: u64) -> Result<Vec<u8>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::BODIES)
            .map_err(|e| store_err("bodies")(&e))?;
        self.body_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // A META row without its body is corruption: serving an empty body would deliver (and let
        // a consumer ack) a message whose signed content is gone (final review I4).
        t.get((role, seq))
            .map_err(|e| store_err("bodies")(&e))?
            .map(|g| g.value().to_vec())
            .ok_or_else(|| StoreError("a queued message's body is missing".into()))
    }

    /// The META row for an id the BY_ID index names; a missing one is corruption (review I4).
    fn indexed_meta(&self, role: &str, seq: u64) -> Result<Meta, StoreError> {
        self.meta(role, seq)?
            .ok_or_else(|| StoreError("a queued message's metadata is missing".into()))
    }

    fn assemble(&self, role: &str, seq: u64, meta: Meta) -> Result<Stored, StoreError> {
        Ok(Stored {
            envelope: Envelope {
                message_id: meta.message_id,
                to: role.to_string(),
                from: meta.from,
                body: self.body(role, seq)?,
            },
            seq,
            enqueued_at: meta.enqueued_at,
            lease: meta.lease,
            attempts: meta.attempts,
        })
    }

    fn adjust_stats(&self, role: &str, count: i64, bytes: i64) -> Result<(), StoreError> {
        let mut t = self
            .txn
            .open_table(redb_tables::STATS)
            .map_err(|e| store_err("stats")(&e))?;
        let (c, b) = t
            .get(role)
            .map_err(|e| store_err("stats")(&e))?
            .map(|g| g.value())
            .unwrap_or((0, 0));
        // Underflow means the accounting is wrong; fail the transaction instead of clamping, which
        // would let a queue silently exceed its bound (final review I3).
        let underflow = || StoreError("queue statistics underflow".into());
        let next = (
            c.checked_add_signed(count).ok_or_else(underflow)?,
            b.checked_add_signed(bytes).ok_or_else(underflow)?,
        );
        if next == (0, 0) {
            t.remove(role).map_err(|e| store_err("stats")(&e))?;
        } else {
            t.insert(role, next).map_err(|e| store_err("stats")(&e))?;
        }
        Ok(())
    }
}

#[cfg(feature = "mailbox-redb")]
impl MailTxn for RedbTxn<'_> {
    fn stats(&self, role: &str) -> Result<(usize, u64), StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::STATS)
            .map_err(|e| store_err("stats")(&e))?;
        let (c, b) = t
            .get(role)
            .map_err(|e| store_err("stats")(&e))?
            .map(|g| g.value())
            .unwrap_or((0, 0));
        Ok((usize::try_from(c).unwrap_or(usize::MAX), b))
    }

    fn scan(&self, role: &str, visit: &mut dyn FnMut(&Stored) -> bool) -> Result<(), StoreError> {
        let rows: Vec<(u64, Vec<u8>)> = {
            let t = self
                .txn
                .open_table(redb_tables::META)
                .map_err(|e| store_err("meta")(&e))?;
            let range = t
                .range((role, 0u64)..=(role, u64::MAX))
                .map_err(|e| store_err("meta")(&e))?;
            let mut rows = Vec::new();
            for entry in range {
                let (k, v) = entry.map_err(|e| store_err("meta")(&e))?;
                rows.push((k.value().1, v.value().to_vec()));
            }
            rows
        };
        for (seq, raw) in rows {
            let meta: Meta =
                serde_json::from_slice(&raw).map_err(|e| store_err("meta decode")(&e))?;
            let stored = self.assemble(role, seq, meta)?;
            if !visit(&stored) {
                break;
            }
        }
        Ok(())
    }

    /// Decides from META alone, so only the bodies of messages that are visited are loaded. Rows
    /// are decoded as they are reached, so scanning stops at the first `false` from `visit` and a
    /// row after it is never read.
    fn scan_free(
        &self,
        role: &str,
        epoch: u64,
        now: DateTime<Utc>,
        visit: &mut dyn FnMut(&Stored) -> bool,
    ) -> Result<(), StoreError> {
        // Which messages `fetch` must withhold, from the fixed-width LEASES rows alone: held by this
        // epoch and not yet expired. Anything else is a candidate, and only candidates are decoded.
        let withheld: std::collections::HashSet<u64> = {
            let leases = self
                .txn
                .open_table(redb_tables::LEASES)
                .map_err(|e| store_err("leases")(&e))?;
            let range = leases
                .range((role, 0u64)..=(role, u64::MAX))
                .map_err(|e| store_err("leases")(&e))?;
            let now = micros(now);
            let mut held = std::collections::HashSet::new();
            for entry in range {
                let (k, v) = entry.map_err(|e| store_err("leases")(&e))?;
                let (held_epoch, until) = v.value();
                if held_epoch == epoch && until > now {
                    held.insert(k.value().1);
                }
            }
            held
        };
        let t = self
            .txn
            .open_table(redb_tables::META)
            .map_err(|e| store_err("meta")(&e))?;
        let range = t
            .range((role, 0u64)..=(role, u64::MAX))
            .map_err(|e| store_err("meta")(&e))?;
        for entry in range {
            let (k, v) = entry.map_err(|e| store_err("meta")(&e))?;
            if withheld.contains(&k.value().1) {
                continue;
            }
            self.meta_decodes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let meta: Meta =
                serde_json::from_slice(v.value()).map_err(|e| store_err("meta decode")(&e))?;
            // The authority is still the decoded lease: a LEASES row can only be missing or
            // stale if some other binary wrote this file, and this keeps that from handing out
            // a held message.
            if !is_free(meta.lease.as_ref(), epoch, now) {
                continue;
            }
            let stored = self.assemble(role, k.value().1, meta)?;
            if !visit(&stored) {
                break;
            }
        }
        Ok(())
    }

    /// META only: a queue is counted without loading a body (S-1).
    fn scan_leases(
        &self,
        role: &str,
        visit: &mut dyn FnMut(DateTime<Utc>, Option<&Lease>),
    ) -> Result<(), StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::META)
            .map_err(|e| store_err("meta")(&e))?;
        let range = t
            .range((role, 0u64)..=(role, u64::MAX))
            .map_err(|e| store_err("meta")(&e))?;
        for entry in range {
            let (_, v) = entry.map_err(|e| store_err("meta")(&e))?;
            let meta: Meta =
                serde_json::from_slice(v.value()).map_err(|e| store_err("meta decode")(&e))?;
            visit(meta.enqueued_at, meta.lease.as_ref());
        }
        Ok(())
    }

    fn queued(&self, role: &str, id: &str) -> Result<Option<Stored>, StoreError> {
        let Some(seq) = self.seq_of(role, id)? else {
            return Ok(None);
        };
        let meta = self.indexed_meta(role, seq)?;
        self.assemble(role, seq, meta).map(Some)
    }

    fn put(&mut self, role: &str, stored: Stored) -> Result<(), StoreError> {
        let id = stored.envelope.message_id.clone();
        let existing = self.seq_of(role, &id)?;
        let seq = existing.unwrap_or(stored.seq);
        // A body is written once. An update (fetch re-leasing a message) keeps the stored body, so
        // it must keep the stored length too, or STATS and the byte bound drift (final review I2).
        let body_len = match existing {
            Some(seq) => self.indexed_meta(role, seq)?.body_len,
            None => stored.envelope.body.len() as u64,
        };
        let meta = Meta {
            message_id: id.clone(),
            from: stored.envelope.from.clone(),
            enqueued_at: stored.enqueued_at,
            lease: stored.lease.clone(),
            attempts: stored.attempts,
            body_len,
        };
        let raw = serde_json::to_vec(&meta).map_err(|e| store_err("meta encode")(&e))?;
        {
            let mut t = self
                .txn
                .open_table(redb_tables::META)
                .map_err(|e| store_err("meta")(&e))?;
            t.insert((role, seq), raw.as_slice())
                .map_err(|e| store_err("meta")(&e))?;
        }
        {
            let mut t = self
                .txn
                .open_table(redb_tables::LEASES)
                .map_err(|e| store_err("leases")(&e))?;
            match &stored.lease {
                Some(lease) => {
                    t.insert((role, seq), (lease.epoch, micros(lease.until)))
                        .map_err(|e| store_err("leases")(&e))?;
                }
                None => {
                    t.remove((role, seq)).map_err(|e| store_err("leases")(&e))?;
                }
            }
        }
        if existing.is_none() {
            {
                let mut t = self
                    .txn
                    .open_table(redb_tables::BODIES)
                    .map_err(|e| store_err("bodies")(&e))?;
                t.insert((role, seq), stored.envelope.body.as_slice())
                    .map_err(|e| store_err("bodies")(&e))?;
            }
            self.body_writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            {
                let mut t = self
                    .txn
                    .open_table(redb_tables::BY_ID)
                    .map_err(|e| store_err("by_id")(&e))?;
                t.insert((role, id.as_str()), seq)
                    .map_err(|e| store_err("by_id")(&e))?;
            }
            self.adjust_stats(role, 1, i64::try_from(body_len).unwrap_or(i64::MAX))?;
        }
        Ok(())
    }

    fn remove(&mut self, role: &str, id: &str) -> Result<(), StoreError> {
        let Some(seq) = self.seq_of(role, id)? else {
            return Ok(());
        };
        let body_len = self.indexed_meta(role, seq)?.body_len;
        {
            let mut t = self
                .txn
                .open_table(redb_tables::META)
                .map_err(|e| store_err("meta")(&e))?;
            t.remove((role, seq)).map_err(|e| store_err("meta")(&e))?;
        }
        {
            let mut t = self
                .txn
                .open_table(redb_tables::LEASES)
                .map_err(|e| store_err("leases")(&e))?;
            t.remove((role, seq)).map_err(|e| store_err("leases")(&e))?;
        }
        {
            let mut t = self
                .txn
                .open_table(redb_tables::BODIES)
                .map_err(|e| store_err("bodies")(&e))?;
            t.remove((role, seq)).map_err(|e| store_err("bodies")(&e))?;
        }
        {
            let mut t = self
                .txn
                .open_table(redb_tables::BY_ID)
                .map_err(|e| store_err("by_id")(&e))?;
            t.remove((role, id)).map_err(|e| store_err("by_id")(&e))?;
        }
        self.adjust_stats(role, -1, -i64::try_from(body_len).unwrap_or(i64::MAX))
    }

    fn acked_at(&self, role: &str, id: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::ACKED)
            .map_err(|e| store_err("acked")(&e))?;
        Ok(t.get((role, id))
            .map_err(|e| store_err("acked")(&e))?
            .and_then(|g| DateTime::from_timestamp_micros(g.value())))
    }

    fn record_ack(&mut self, role: &str, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        {
            let mut t = self
                .txn
                .open_table(redb_tables::ACKED)
                .map_err(|e| store_err("acked")(&e))?;
            t.insert((role, id), micros(at))
                .map_err(|e| store_err("acked")(&e))?;
        }
        let mut t = self
            .txn
            .open_table(redb_tables::ACKED_BY_TIME)
            .map_err(|e| store_err("acked_by_time")(&e))?;
        t.insert((micros(at), role, id), ())
            .map_err(|e| store_err("acked_by_time")(&e))?;
        Ok(())
    }

    fn sweep_acked(&mut self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let doomed: Vec<(i64, String, String)> = {
            let t = self
                .txn
                .open_table(redb_tables::ACKED_BY_TIME)
                .map_err(|e| store_err("acked_by_time")(&e))?;
            let range = t
                .range(..(micros(before), "", ""))
                .map_err(|e| store_err("acked_by_time")(&e))?;
            let mut out = Vec::new();
            for entry in range {
                let (k, _) = entry.map_err(|e| store_err("acked_by_time")(&e))?;
                let (at, role, id) = k.value();
                out.push((at, role.to_string(), id.to_string()));
            }
            out
        };
        {
            let mut by_time = self
                .txn
                .open_table(redb_tables::ACKED_BY_TIME)
                .map_err(|e| store_err("acked_by_time")(&e))?;
            let mut acked = self
                .txn
                .open_table(redb_tables::ACKED)
                .map_err(|e| store_err("acked")(&e))?;
            for (at, role, id) in &doomed {
                by_time
                    .remove((*at, role.as_str(), id.as_str()))
                    .map_err(|e| store_err("acked_by_time")(&e))?;
                acked
                    .remove((role.as_str(), id.as_str()))
                    .map_err(|e| store_err("acked")(&e))?;
            }
        }
        Ok(doomed.len())
    }

    fn queue_roles(&self) -> Result<Vec<String>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::META)
            .map_err(|e| store_err("meta")(&e))?;
        let mut roles: Vec<String> = Vec::new();
        for entry in t.iter().map_err(|e| store_err("meta")(&e))? {
            let (k, _) = entry.map_err(|e| store_err("meta")(&e))?;
            let role = k.value().0;
            if roles.last().map(String::as_str) != Some(role) {
                roles.push(role.to_string());
            }
        }
        Ok(roles)
    }

    fn all_acked(&self) -> Result<Vec<(String, String, DateTime<Utc>)>, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::ACKED)
            .map_err(|e| store_err("acked")(&e))?;
        let mut out = Vec::new();
        for entry in t.iter().map_err(|e| store_err("acked")(&e))? {
            let (k, v) = entry.map_err(|e| store_err("acked")(&e))?;
            let (role, id) = k.value();
            let at = DateTime::from_timestamp_micros(v.value())
                .ok_or_else(|| StoreError("acked time out of range".into()))?;
            out.push((role.to_string(), id.to_string(), at));
        }
        Ok(out)
    }

    fn seq_counter(&self) -> Result<u64, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::COUNTERS)
            .map_err(|e| store_err("counters")(&e))?;
        Ok(t.get("seq")
            .map_err(|e| store_err("counters")(&e))?
            .map_or(0, |g| g.value()))
    }

    fn set_seq_counter(&mut self, value: u64) -> Result<(), StoreError> {
        let mut t = self
            .txn
            .open_table(redb_tables::COUNTERS)
            .map_err(|e| store_err("counters")(&e))?;
        t.insert("seq", value)
            .map_err(|e| store_err("counters")(&e))?;
        Ok(())
    }

    fn next_seq(&mut self) -> Result<u64, StoreError> {
        let mut t = self
            .txn
            .open_table(redb_tables::COUNTERS)
            .map_err(|e| store_err("counters")(&e))?;
        let next = t
            .get("seq")
            .map_err(|e| store_err("counters")(&e))?
            .map_or(0, |g| g.value())
            + 1;
        t.insert("seq", next)
            .map_err(|e| store_err("counters")(&e))?;
        Ok(next)
    }

    fn roles(&self) -> Result<RolesState, StoreError> {
        let t = self
            .txn
            .open_table(redb_tables::ROLES)
            .map_err(|e| store_err("roles")(&e))?;
        match t.get("state").map_err(|e| store_err("roles")(&e))? {
            Some(raw) => {
                serde_json::from_slice(raw.value()).map_err(|e| store_err("roles decode")(&e))
            }
            None => Ok(RolesState::default()),
        }
    }

    fn set_roles(&mut self, state: &RolesState) -> Result<(), StoreError> {
        let raw = serde_json::to_vec(state).map_err(|e| store_err("roles encode")(&e))?;
        let mut t = self
            .txn
            .open_table(redb_tables::ROLES)
            .map_err(|e| store_err("roles")(&e))?;
        t.insert("state", raw.as_slice())
            .map_err(|e| store_err("roles")(&e))?;
        Ok(())
    }
}

#[cfg(test)]
mod needs_tests {
    use super::*;

    /// The declared needs are what `Mailbox::open` enforces, and every one is asked for.
    #[test]
    fn the_mailbox_needs_ask_for_everything_open_enforces() {
        let n = MailboxNeeds::MAILBOX;
        assert_eq!(n.durability, REQUIRED_DURABILITY);
        assert!(n.atomic_batch && n.ordered_scan && n.lease_ttl && n.bounded_calls);
        // Control: the class really is ordered, so a Process store is below the need.
        assert!(DurabilityClass::Process < n.durability);
    }
}
