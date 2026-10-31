// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox conformance suite: the semantics a [`MailStore`] must have, as cases generic over
//! the store, so every implementation (`MemoryStore`, `RedbStore`, and a store from another crate)
//! is held to the same contract. Design: `docs/superpowers/specs/2026-10-02-m4-mailbox-design.md`.
//!
//! **A stable store contract.** Behind the off-by-default `mailbox-conformance` feature. A case is
//! added only when the mailbox gains a guarantee, never to track an implementation detail, and a
//! case is never loosened to let a store pass.
//!
//! Each case takes `make: impl Fn() -> S`, which must return a **fresh, empty** store on every
//! call, and that store must stay valid after the closure returns (a durable store should keep
//! its files until the process ends). A failing case panics; [`run_all`] runs every case and names
//! the one that failed.
//!
//! ```
//! // A store of your own goes where `MemoryStore` does; `MemoryStore::new()` is a fresh store.
//! synapse::mailbox::conformance::run_all(|| synapse::mailbox::MemoryStore::new());
//! ```

use super::{
    Acked, Depth, DurabilityClass, Enqueued, Envelope, MailConfig, MailError, MailStore, Mailbox,
    REQUIRED_DURABILITY, Stored,
};
use crate::certificate::RevocationLookup;
use crate::keystore::Keystore;
use crate::roles::{ClaimRequest, Superseded, sign_claim};
use chrono::{DateTime, Duration, TimeZone, Utc};

pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 12, 0, 0).unwrap()
}

struct NoRevocations;
impl RevocationLookup for NoRevocations {
    fn is_revoked(&self, _issuer_key_id: &str, _serial: &[u8; 16]) -> bool {
        false
    }
}

/// A keystore with account `acct`, and helpers to claim its roles.
pub struct Ids {
    _dir: Option<tempfile::TempDir>,
    path: std::path::PathBuf,
    store: Keystore,
    nonce: std::cell::Cell<u8>,
}

impl Default for Ids {
    fn default() -> Self {
        Self::new()
    }
}

impl Ids {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Keystore::init_account(dir.path(), "acct").expect("init");
        let store = Keystore::open(dir.path()).expect("open");
        Ids {
            path: dir.path().to_path_buf(),
            _dir: Some(dir),
            store,
            nonce: std::cell::Cell::new(0),
        }
    }

    /// The same account, reopened from `path` (a crash test's child process). `nonce_base` keeps
    /// the child's claim nonces apart from the parent's.
    pub fn open_existing(path: &std::path::Path, nonce_base: u8) -> Self {
        Ids {
            _dir: None,
            path: path.to_path_buf(),
            store: Keystore::open(path).expect("reopen keystore"),
            nonce: std::cell::Cell::new(nonce_base),
        }
    }

    /// Where the keystore lives, for handing to a child process.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn request(&self, role: &str, now: DateTime<Utc>) -> ClaimRequest {
        let n = self.nonce.get().wrapping_add(1);
        self.nonce.set(n);
        let identity = self.store.role(role, t0()).expect("role");
        sign_claim(&identity, [n; 16], now).expect("sign")
    }

    /// Claim `role` and return the mailbox's result unchanged (for failure-path tests).
    pub fn try_claim<S: MailStore>(
        &self,
        mailbox: &mut Mailbox<S>,
        role: &str,
        now: DateTime<Utc>,
    ) -> Result<crate::roles::Grant, MailError> {
        let req = self.request(role, now);
        let key_id = self.store.account().key_id;
        let key = self.store.account_public_key();
        mailbox.claim(
            &req,
            &move |kid: &str| (kid == key_id).then_some(key),
            &NoRevocations,
            now,
        )
    }

    /// Claim `role` (e.g. "lane") on `mailbox`; returns the granted epoch.
    pub fn claim<S: MailStore>(
        &self,
        mailbox: &mut Mailbox<S>,
        role: &str,
        now: DateTime<Utc>,
    ) -> u64 {
        let req = self.request(role, now);
        let key_id = self.store.account().key_id;
        let key = self.store.account_public_key();
        mailbox
            .claim(
                &req,
                &move |kid: &str| (kid == key_id).then_some(key),
                &NoRevocations,
                now,
            )
            .expect("claim")
            .epoch
    }
}

pub fn open<S: MailStore>(store: S) -> Mailbox<S> {
    Mailbox::open_volatile(store, MailConfig::default(), t0() - Duration::seconds(1)).expect("open")
}

pub fn env(id: &str, to: &str, body: &[u8]) -> Envelope {
    Envelope {
        message_id: id.to_string(),
        to: to.to_string(),
        from: "peer@acct".to_string(),
        body: body.to_vec(),
    }
}

fn ids_of(deliveries: &[super::Delivery]) -> Vec<String> {
    deliveries
        .iter()
        .map(|d| d.envelope.message_id.clone())
        .collect()
}

const LANE: &str = "lane@acct";

pub fn enqueue_then_fetch_leases_and_hides<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    assert_eq!(
        mb.enqueue(env("m1", LANE, b"hi"), t0()).unwrap(),
        Enqueued::Queued
    );
    let got = mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    assert_eq!(ids_of(&got), ["m1"]);
    assert_eq!(got[0].envelope.body, b"hi");
    assert_eq!(got[0].attempts, 1);
    assert_eq!(
        got[0].lease_until,
        t0() + Duration::seconds(60),
        "default lease is 60s"
    );
    let again = mb
        .fetch(LANE, epoch, 10, None, t0() + Duration::seconds(59))
        .unwrap();
    assert!(
        again.is_empty(),
        "a leased message is hidden until its lease expires"
    );
}

pub fn an_expired_lease_redelivers_in_order<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    for id in ["m1", "m2", "m3"] {
        mb.enqueue(env(id, LANE, b"x"), t0()).unwrap();
    }
    assert_eq!(
        ids_of(&mb.fetch(LANE, epoch, 2, None, t0()).unwrap()),
        ["m1", "m2"]
    );
    let later = t0() + Duration::seconds(61);
    let redelivered = mb.fetch(LANE, epoch, 10, None, later).unwrap();
    assert_eq!(
        ids_of(&redelivered),
        ["m1", "m2", "m3"],
        "oldest first, redelivery keeps order"
    );
    assert_eq!(redelivered[0].attempts, 2);
    assert_eq!(redelivered[2].attempts, 1);
}

pub fn ack_removes_for_good_and_a_resend_is_a_duplicate<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    assert_eq!(mb.ack(LANE, epoch, "m1", t0()).unwrap(), Acked::Removed);
    let much_later = t0() + Duration::hours(1);
    assert!(
        mb.fetch(LANE, epoch, 10, None, much_later)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        mb.enqueue(env("m1", LANE, b"x"), much_later).unwrap(),
        Enqueued::Duplicate,
        "a resend of an acked message is recognised"
    );
    assert!(
        mb.fetch(LANE, epoch, 10, None, much_later)
            .unwrap()
            .is_empty()
    );
}

pub fn a_duplicate_while_queued_is_not_queued_twice<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    assert_eq!(
        mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap(),
        Enqueued::Queued
    );
    assert_eq!(
        mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap(),
        Enqueued::Duplicate
    );
    assert_eq!(
        ids_of(&mb.fetch(LANE, epoch, 10, None, t0()).unwrap()),
        ["m1"]
    );
}

pub fn a_superseded_epoch_cannot_fetch_or_ack<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let old = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, old, 10, None, t0()).unwrap();
    let new = ids.claim(&mut mb, "lane", t0() + Duration::seconds(1));
    assert_eq!(new, old + 1);
    let current = Superseded { current: new };
    assert_eq!(
        mb.fetch(LANE, old, 10, None, t0() + Duration::seconds(2))
            .unwrap_err(),
        MailError::Superseded(current)
    );
    assert_eq!(
        mb.ack(LANE, old, "m1", t0() + Duration::seconds(2))
            .unwrap_err(),
        MailError::Superseded(current)
    );
}

pub fn a_takeover_frees_the_old_leases_at_once<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let old = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, old, 10, None, t0()).unwrap();
    let soon = t0() + Duration::seconds(2); // well inside the old 60s lease
    let new = ids.claim(&mut mb, "lane", soon);
    let got = mb.fetch(LANE, new, 10, None, soon).unwrap();
    assert_eq!(
        ids_of(&got),
        ["m1"],
        "the new holder gets in-flight mail without waiting"
    );
    assert_eq!(mb.ack(LANE, new, "m1", soon).unwrap(), Acked::Removed);
}

pub fn only_the_lease_holder_acks<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    assert_eq!(
        mb.ack(LANE, epoch, "m1", t0()).unwrap_err(),
        MailError::NotYourLease,
        "never fetched"
    );
    assert_eq!(
        mb.ack(LANE, epoch, "nope", t0()).unwrap_err(),
        MailError::NotFound
    );
    mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    let after_expiry = t0() + Duration::seconds(90);
    assert_eq!(
        mb.ack(LANE, epoch, "m1", after_expiry).unwrap(),
        Acked::Removed,
        "the holder may ack after its lease ran out: it processed the message"
    );
}

pub fn ack_is_idempotent<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    assert_eq!(mb.ack(LANE, epoch, "m1", t0()).unwrap(), Acked::Removed);
    assert_eq!(
        mb.ack(LANE, epoch, "m1", t0()).unwrap(),
        Acked::AlreadyAcked
    );
}

pub fn the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let config = MailConfig {
        max_messages: 2,
        max_bytes: 10,
        ..MailConfig::default()
    };
    let mut mb = Mailbox::open_volatile(make(), config, t0() - Duration::seconds(1)).expect("open");
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"abcd"), t0()).unwrap();
    assert_eq!(
        mb.enqueue(env("big", LANE, b"1234567"), t0()).unwrap_err(),
        MailError::MailboxFull,
        "4 + 7 bytes crosses the 10-byte bound"
    );
    mb.enqueue(env("m2", LANE, b"ef"), t0()).unwrap();
    assert_eq!(
        mb.enqueue(env("m3", LANE, b"g"), t0()).unwrap_err(),
        MailError::MailboxFull,
        "a third message crosses the 2-message bound"
    );
    assert_eq!(
        ids_of(&mb.fetch(LANE, epoch, 10, None, t0()).unwrap()),
        ["m1", "m2"]
    );
    // Acked mail no longer counts against the bound.
    mb.ack(LANE, epoch, "m1", t0()).unwrap();
    assert_eq!(
        mb.enqueue(env("m3", LANE, b"g"), t0()).unwrap(),
        Enqueued::Queued
    );
}

pub fn sweep_deletes_old_acked_history_never_queued_mail<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("acked", LANE, b"x"), t0()).unwrap();
    mb.enqueue(env("waiting", LANE, b"y"), t0()).unwrap();
    mb.fetch(LANE, epoch, 1, None, t0()).unwrap();
    mb.ack(LANE, epoch, "acked", t0()).unwrap();

    let eight_days = t0() + Duration::days(8);
    assert_eq!(
        mb.sweep(eight_days).unwrap(),
        1,
        "the 8-day-old acked record goes"
    );
    // Its dedupe record went with it, so a resend now queues again (by design, after retention).
    assert_eq!(
        mb.enqueue(env("acked", LANE, b"x"), eight_days).unwrap(),
        Enqueued::Queued
    );
    // The never-fetched message, older than retention, is still there.
    let got = mb.fetch(LANE, epoch, 10, None, eight_days).unwrap();
    assert_eq!(ids_of(&got), ["waiting", "acked"]);
}

pub fn a_lease_outside_the_range_is_refused<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    for lease in [Duration::seconds(4), Duration::minutes(16)] {
        assert_eq!(
            mb.fetch(LANE, epoch, 1, Some(lease), t0()).unwrap_err(),
            MailError::LeaseOutOfRange
        );
    }
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    let got = mb
        .fetch(LANE, epoch, 1, Some(Duration::minutes(15)), t0())
        .unwrap();
    assert_eq!(got[0].lease_until, t0() + Duration::minutes(15));
}

pub fn mail_waits_for_a_role_that_has_not_claimed_yet<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    mb.enqueue(env("early", LANE, b"x"), t0()).unwrap();
    let later = t0() + Duration::minutes(10);
    let epoch = ids.claim(&mut mb, "lane", later);
    assert_eq!(
        ids_of(&mb.fetch(LANE, epoch, 10, None, later).unwrap()),
        ["early"]
    );
}

pub fn claims_are_written_through_the_store<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    let mut seen = None;
    mb.store()
        .write(&mut |txn| {
            seen = txn
                .roles()
                .map_err(MailError::Store)?
                .roles
                .get(LANE)
                .map(|r| r.epoch);
            Ok(())
        })
        .unwrap();
    assert_eq!(seen, Some(epoch));
}

/// Liveness (docs/ROLE_LIVENESS_DESIGN.md, L1): sightings and retirement are written through the
/// store, so a restarted daemon still knows when a role was last seen and that it was retired.
pub fn role_liveness_is_written_through_the_store<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    ids.claim(&mut mb, "lane", t0());
    let seen = t0() + Duration::hours(2);
    let ttl = Duration::days(30);
    let retired = mb
        .maintain_roles(&[(LANE.to_string(), seen)], t0() + Duration::days(10), ttl)
        .unwrap();
    assert!(retired.is_empty(), "seen and young: nothing retired");
    let persisted = |mb: &Mailbox<S>| {
        let mut record = None;
        mb.store()
            .write(&mut |txn| {
                record = txn
                    .roles()
                    .map_err(MailError::Store)?
                    .roles
                    .get(LANE)
                    .cloned();
                Ok(())
            })
            .unwrap();
        record.expect("the role is stored")
    };
    assert_eq!(
        persisted(&mb).last_seen,
        Some(seen),
        "the sighting was written"
    );
    let late = seen + ttl + Duration::days(1);
    assert_eq!(
        mb.maintain_roles(&[], late, ttl).unwrap(),
        [LANE.to_string()]
    );
    assert_eq!(
        persisted(&mb).retired_at,
        Some(late),
        "the retirement was written"
    );
    assert!(mb.maintain_roles(&[], late, ttl).unwrap().is_empty());
}

fn depth_of<S: MailStore>(mb: &Mailbox<S>, global_id: &str, now: DateTime<Utc>) -> Depth {
    *mb.depths(now)
        .expect("depths")
        .get(global_id)
        .expect("a claimed role has a depth")
}

fn depth(queued: usize, leased: usize, oldest: Option<DateTime<Utc>>) -> Depth {
    Depth {
        queued,
        leased,
        dead: 0,
        oldest_enqueued_at: oldest,
    }
}

/// S-1: `queued` is what a fetch would hand out next, `leased` what the current epoch holds, and
/// `oldest_enqueued_at` spans both. Acked mail is in neither.
pub fn depths_count_queued_and_leased_per_role<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    assert_eq!(depth_of(&mb, LANE, t0()), depth(0, 0, None), "no mail yet");
    let t1 = t0() + Duration::seconds(1);
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.enqueue(env("m2", LANE, b"yy"), t1).unwrap();
    assert_eq!(depth_of(&mb, LANE, t1), depth(2, 0, Some(t0())));
    assert_eq!(ids_of(&mb.fetch(LANE, epoch, 1, None, t1).unwrap()), ["m1"]);
    assert_eq!(
        depth_of(&mb, LANE, t1),
        depth(1, 1, Some(t0())),
        "the oldest is leased, and still the oldest"
    );
    mb.ack(LANE, epoch, "m1", t1).unwrap();
    assert_eq!(
        depth_of(&mb, LANE, t1),
        depth(1, 0, Some(t1)),
        "acked mail is gone"
    );
    // Only roles in the role table are reported, as `list` reports only those.
    mb.enqueue(env("w1", "waiting@acct", b"x"), t1).unwrap();
    let all = mb.depths(t1).unwrap();
    assert_eq!(all.keys().collect::<Vec<_>>(), [LANE]);
}

/// S-1: a lease that expired, or that an older epoch holds, is deliverable, so it counts as queued.
pub fn an_expired_or_superseded_lease_counts_as_queued<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = open(make());
    let old = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m1", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, old, 1, Some(Duration::seconds(5)), t0())
        .unwrap();
    assert_eq!(depth_of(&mb, LANE, t0()), depth(0, 1, Some(t0())));
    let expired = t0() + Duration::seconds(5);
    assert_eq!(
        depth_of(&mb, LANE, expired),
        depth(1, 0, Some(t0())),
        "a lease ends at its `until`, as fetch reads it"
    );
    mb.fetch(LANE, old, 1, None, expired).unwrap();
    assert_eq!(depth_of(&mb, LANE, expired), depth(0, 1, Some(t0())));
    let soon = expired + Duration::seconds(1);
    ids.claim(&mut mb, "lane", soon);
    assert_eq!(
        depth_of(&mb, LANE, soon),
        depth(1, 0, Some(t0())),
        "a takeover voids the old epoch's lease"
    );
}

pub fn fetch_excluding_skips_the_named_messages_and_leaves_them_unleased<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    for id in ["a", "b", "c"] {
        mb.enqueue(env(id, LANE, b"x"), t0()).unwrap();
    }
    let skip = vec!["b".to_string()];
    let got = mb
        .fetch_excluding(LANE, epoch, 10, None, t0(), &skip)
        .unwrap();
    assert_eq!(ids_of(&got), ["a", "c"]);

    // "b" was never leased: an ordinary fetch at the same instant returns it as a first attempt.
    let rest = mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    assert_eq!(ids_of(&rest), ["b"]);
    assert_eq!(rest[0].attempts, 1);
}

pub fn fetch_excluding_counts_delivered_messages_not_skipped_ones<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let mut mb = open(make());
    let epoch = ids.claim(&mut mb, "lane", t0());
    for id in ["a", "b", "c"] {
        mb.enqueue(env(id, LANE, b"x"), t0()).unwrap();
    }
    let skip = vec!["a".to_string()];
    let got = mb
        .fetch_excluding(LANE, epoch, 1, None, t0(), &skip)
        .unwrap();
    assert_eq!(ids_of(&got), ["b"]);
    // An empty exclusion is exactly `fetch`.
    let next = mb
        .fetch_excluding(LANE, epoch, 10, None, t0(), &[])
        .unwrap();
    assert_eq!(ids_of(&next), ["a", "c"]);
}

/// A write that returns `Err` leaves nothing behind: not the queued entry, not the sequence
/// number it took, not a claimed role. This is the atomic multi-key transaction a store must give
/// (a store that applies writes as they come and never undoes them passes every other case).
pub fn a_failed_write_changes_nothing<S: MailStore>(make: impl Fn() -> S) {
    let fresh_seq = {
        let mut seq = 0;
        make()
            .write(&mut |txn| {
                seq = txn.next_seq().map_err(MailError::Store)?;
                Ok(())
            })
            .expect("a fresh store hands out a sequence number");
        seq
    };
    let store = make();
    let queued_at = t0();
    let err = store
        .write(&mut |txn| {
            let seq = txn.next_seq().map_err(MailError::Store)?;
            txn.put(
                LANE,
                Stored {
                    envelope: env("half", LANE, b"body"),
                    seq,
                    enqueued_at: queued_at,
                    lease: None,
                    attempts: 0,
                },
            )
            .map_err(MailError::Store)?;
            txn.record_ack(LANE, "acked", queued_at)
                .map_err(MailError::Store)?;
            Err(MailError::NotFound)
        })
        .unwrap_err();
    assert_eq!(err, MailError::NotFound, "the closure's error comes back");
    store
        .write(&mut |txn| {
            assert_eq!(
                txn.stats(LANE).unwrap(),
                (0, 0),
                "the entry was rolled back"
            );
            assert!(txn.queued(LANE, "half").unwrap().is_none());
            assert!(txn.acked_at(LANE, "acked").unwrap().is_none());
            assert_eq!(
                txn.next_seq().unwrap(),
                fresh_seq,
                "the sequence number was not consumed"
            );
            Ok(())
        })
        .unwrap();
}

/// A message leased `max_deliveries` times and never acked is set aside in the role's dead set, body
/// and all: not redelivered again, not dropped, counted in `Depth::dead`, a resend of its id is a
/// duplicate, and the receiver's ack discards it.
pub fn a_message_leased_max_deliveries_times_goes_dead_and_is_kept<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let config = MailConfig {
        max_deliveries: 3,
        ..MailConfig::default()
    };
    let mut mb = Mailbox::open_volatile(make(), config, t0() - Duration::seconds(1)).expect("open");
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("poison", LANE, b"payload"), t0()).unwrap();
    for round in 0..3 {
        let at = t0() + Duration::seconds(61 * round);
        let got = mb.fetch(LANE, epoch, 10, None, at).unwrap();
        assert_eq!(ids_of(&got), ["poison"], "lease {}", round + 1);
        assert_eq!(got[0].attempts, round as u32 + 1);
    }
    let at = t0() + Duration::seconds(61 * 3);
    assert!(
        mb.fetch(LANE, epoch, 10, None, at).unwrap().is_empty(),
        "past the cap it is not leased again"
    );
    let depth = depth_of(&mb, LANE, at);
    assert_eq!((depth.queued, depth.leased, depth.dead), (0, 0, 1));
    let dead = mb.dead_letters(LANE, epoch).unwrap();
    assert_eq!(dead.len(), 1);
    assert_eq!(dead[0].envelope.message_id, "poison");
    assert_eq!(dead[0].envelope.body, b"payload", "the body is kept");
    assert_eq!(dead[0].attempts, 3);
    assert_eq!(
        mb.enqueue(env("poison", LANE, b"payload"), at).unwrap(),
        Enqueued::Duplicate,
        "a resend of a dead message is not queued again"
    );
    assert_eq!(mb.ack(LANE, epoch, "poison", at).unwrap(), Acked::Removed);
    assert!(mb.dead_letters(LANE, epoch).unwrap().is_empty());
    assert_eq!(depth_of(&mb, LANE, at).dead, 0);
}

fn backoff_config() -> MailConfig {
    MailConfig {
        redelivery_gaps: [2, 4, 8, 16].map(Duration::minutes).to_vec(),
        ..MailConfig::default()
    }
}

fn backoff_mailbox<S: MailStore>(make: &impl Fn() -> S) -> Mailbox<S> {
    Mailbox::open_volatile(make(), backoff_config(), t0() - Duration::seconds(1)).expect("open")
}

/// Deliver `m` at 0, 2, 6 and 14 minutes (gaps 2, 4, 8, 16) and check each lease, so the tests
/// below can start from a known point.
fn deliver_on_schedule<S: MailStore>(mb: &mut Mailbox<S>, epoch: u64, upto: usize) {
    let gaps = [2i64, 4, 8, 16];
    for (n, minute) in [0i64, 2, 6, 14].into_iter().take(upto).enumerate() {
        let at = t0() + Duration::minutes(minute);
        if minute > 0 {
            assert!(
                mb.fetch(LANE, epoch, 10, None, at - Duration::seconds(1))
                    .unwrap()
                    .is_empty(),
                "still hidden a second before minute {minute}"
            );
        }
        let got = mb.fetch(LANE, epoch, 10, None, at).unwrap();
        assert_eq!(ids_of(&got), ["m"], "delivery {} at minute {minute}", n + 1);
        assert_eq!(got[0].attempts, n as u32 + 1);
        assert_eq!(got[0].lease_until, at + Duration::minutes(gaps[n]));
    }
}

/// An unacked message is redelivered after 2, 4, 8 and 16 minutes (30 in all); when the last lease
/// runs out it goes to the dead set (kept, counted) and is reported once, with its sender, so the
/// sender can be told.
pub fn redelivery_backs_off_then_goes_dead_and_names_the_sender<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let mut mb = backoff_mailbox(&make);
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    deliver_on_schedule(&mut mb, epoch, 4);
    let end = t0() + Duration::minutes(30);
    assert!(
        mb.dead_exhausted(end - Duration::seconds(1))
            .unwrap()
            .is_empty(),
        "the last lease has not run out"
    );
    let gone = mb.dead_exhausted(end).unwrap();
    assert_eq!(gone.len(), 1, "{gone:?}");
    assert_eq!(
        (
            gone[0].to.as_str(),
            gone[0].from.as_str(),
            gone[0].message_id.as_str()
        ),
        (LANE, "peer@acct", "m")
    );
    assert_eq!((gone[0].attempts, gone[0].enqueued_at), (4, t0()));
    let depth = depth_of(&mb, LANE, end);
    assert_eq!((depth.queued, depth.leased, depth.dead), (0, 0, 1));
    assert_eq!(
        mb.dead_letters(LANE, epoch).unwrap().len(),
        1,
        "kept, body and all"
    );
    let later = end + Duration::minutes(1);
    assert!(mb.fetch(LANE, epoch, 10, None, later).unwrap().is_empty());
    assert!(
        mb.dead_exhausted(later).unwrap().is_empty(),
        "reported once"
    );
}

/// A reader that keeps polling finds the message exhausted on its own fetch; the report still
/// comes out of `dead_exhausted`, once.
pub fn a_polling_reader_also_reports_the_exhausted_message<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = backoff_mailbox(&make);
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    deliver_on_schedule(&mut mb, epoch, 4);
    let end = t0() + Duration::minutes(30);
    assert!(mb.fetch(LANE, epoch, 10, None, end).unwrap().is_empty());
    assert_eq!(depth_of(&mb, LANE, end).dead, 1);
    let gone = mb.dead_exhausted(end).unwrap();
    assert_eq!(gone.len(), 1, "{gone:?}");
    assert_eq!(gone[0].message_id, "m");
    assert!(mb.dead_exhausted(end).unwrap().is_empty());
}

/// An ack at the second attempt ends it: no third delivery, nothing dead, nothing to report.
pub fn an_ack_at_the_second_attempt_ends_the_schedule_with_no_notice<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let mut mb = backoff_mailbox(&make);
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    deliver_on_schedule(&mut mb, epoch, 2);
    let at = t0() + Duration::minutes(2);
    assert_eq!(mb.ack(LANE, epoch, "m", at).unwrap(), Acked::Removed);
    for minute in [3, 6, 14, 30, 45] {
        let at = t0() + Duration::minutes(minute);
        assert!(
            mb.fetch(LANE, epoch, 10, None, at).unwrap().is_empty(),
            "minute {minute}"
        );
        assert!(mb.dead_exhausted(at).unwrap().is_empty(), "minute {minute}");
    }
    let depth = depth_of(&mb, LANE, t0() + Duration::minutes(45));
    assert_eq!((depth.queued, depth.leased, depth.dead), (0, 0, 0));
}

/// A lane that restarts mid-schedule (a new epoch) is given the message again at once, not at the
/// end of the old lease, and the schedule carries on from its attempt count.
pub fn a_restart_mid_schedule_gets_the_message_again<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let mut mb = backoff_mailbox(&make);
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    deliver_on_schedule(&mut mb, epoch, 2);
    let restart = t0() + Duration::minutes(3);
    let epoch2 = ids.claim(&mut mb, "lane", restart);
    assert!(epoch2 > epoch);
    let got = mb.fetch(LANE, epoch2, 10, None, restart).unwrap();
    assert_eq!(ids_of(&got), ["m"]);
    assert_eq!(got[0].attempts, 3, "the count survives the restart");
    assert_eq!(got[0].lease_until, restart + Duration::minutes(8));
}

/// A message set aside for lack of an ack is not lost to a restart: the role's next claim puts it
/// back in the queue with a fresh count, and it is delivered again.
pub fn a_dead_message_is_delivered_again_when_the_role_next_claims<S: MailStore>(
    make: impl Fn() -> S,
) {
    let ids = Ids::new();
    let mut mb = backoff_mailbox(&make);
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    deliver_on_schedule(&mut mb, epoch, 4);
    let end = t0() + Duration::minutes(30);
    assert_eq!(mb.dead_exhausted(end).unwrap().len(), 1);
    let back = end + Duration::minutes(1);
    let epoch2 = ids.claim(&mut mb, "lane", back);
    assert!(mb.dead_letters(LANE, epoch2).unwrap().is_empty());
    let got = mb.fetch(LANE, epoch2, 10, None, back).unwrap();
    assert_eq!(ids_of(&got), ["m"]);
    assert_eq!(got[0].attempts, 1, "a fresh count");
    assert_eq!(got[0].lease_until, back + Duration::minutes(2));
}

/// A full dead set never costs a message: the one past the cap stays queued and is leased again.
pub fn a_full_dead_set_keeps_the_message_queued<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let config = MailConfig {
        max_deliveries: 1,
        max_messages: 1,
        ..MailConfig::default()
    };
    let mut mb = Mailbox::open_volatile(make(), config, t0() - Duration::seconds(1)).expect("open");
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("first", LANE, b"a"), t0()).unwrap();
    mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    let t1 = t0() + Duration::seconds(61);
    assert!(mb.fetch(LANE, epoch, 10, None, t1).unwrap().is_empty());
    assert_eq!(
        depth_of(&mb, LANE, t1).dead,
        1,
        "the bound of 1 is now full"
    );
    mb.enqueue(env("second", LANE, b"b"), t1).unwrap();
    mb.fetch(LANE, epoch, 10, None, t1).unwrap();
    let t2 = t1 + Duration::seconds(61);
    let got = mb.fetch(LANE, epoch, 10, None, t2).unwrap();
    assert_eq!(
        ids_of(&got),
        ["second"],
        "kept and leased again, not dropped"
    );
    assert_eq!(got[0].attempts, 2);
    assert_eq!(depth_of(&mb, LANE, t2).dead, 1);
}

/// A dead message can be put back: queued again with its count reset.
pub fn a_dead_message_can_be_requeued<S: MailStore>(make: impl Fn() -> S) {
    let ids = Ids::new();
    let config = MailConfig {
        max_deliveries: 1,
        ..MailConfig::default()
    };
    let mut mb = Mailbox::open_volatile(make(), config, t0() - Duration::seconds(1)).expect("open");
    let epoch = ids.claim(&mut mb, "lane", t0());
    mb.enqueue(env("m", LANE, b"x"), t0()).unwrap();
    mb.fetch(LANE, epoch, 10, None, t0()).unwrap();
    let t1 = t0() + Duration::seconds(61);
    assert!(mb.fetch(LANE, epoch, 10, None, t1).unwrap().is_empty());
    assert_eq!(
        mb.requeue_dead(LANE, epoch, "nope").unwrap_err(),
        MailError::NotFound
    );
    mb.requeue_dead(LANE, epoch, "m").unwrap();
    assert!(mb.dead_letters(LANE, epoch).unwrap().is_empty());
    let got = mb.fetch(LANE, epoch, 10, None, t1).unwrap();
    assert_eq!(ids_of(&got), ["m"]);
    assert_eq!(got[0].attempts, 1, "the count was reset");
}

/// Run every case against stores from `make`, naming the case that failed.
///
/// The need the semantic cases cannot check: the store declares at least [`REQUIRED_DURABILITY`]
/// and [`Mailbox::open`] accepts it. A store that will hold real mail must pass this beside
/// [`run_all`] (which runs over [`Mailbox::open_volatile`], so a `Process` store can still be
/// held to the semantics).
///
/// # Panics
/// When the store declares less, or `Mailbox::open` refuses it.
pub fn declares_the_needed_durability<S: MailStore>(make: impl Fn() -> S) {
    let store = make();
    let declared = store.durability();
    assert!(
        declared >= REQUIRED_DURABILITY,
        "store declares {declared}, the mailbox requires {REQUIRED_DURABILITY}"
    );
    Mailbox::open(store, MailConfig::default(), t0() - Duration::seconds(1))
        .expect("Mailbox::open accepts a store declaring the required class");
}

/// The refusal side: a store declaring below the requirement is refused with the declared and
/// required classes named, and nothing is read from it.
///
/// # Panics
/// When `Mailbox::open` accepts the store.
pub fn a_store_declaring_less_is_refused<S: MailStore>(make: impl Fn() -> S) {
    let store = make();
    if store.durability() >= REQUIRED_DURABILITY {
        return;
    }
    let declared = store.durability();
    let err = Mailbox::open(store, MailConfig::default(), t0() - Duration::seconds(1))
        .err()
        .expect("a weaker store is refused");
    assert_eq!(
        err,
        MailError::DurabilityTooWeak {
            declared,
            required: REQUIRED_DURABILITY
        }
    );
    let _: DurabilityClass = declared;
}

/// A switch for a stallable store (need 9 of `docs/MAILBOX_STORE_NEEDS.md`): while it is set, the
/// store's backend must never answer, as MySQL did on a full disk. Clone it into the backend.
#[derive(Clone, Default)]
pub struct Stall(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Stall {
    #[must_use]
    pub fn new() -> Self {
        Stall::default()
    }

    pub fn set(&self, on: bool) {
        self.0.store(on, std::sync::atomic::Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_set(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Need 9: a store whose backend stops answering returns `Err` from `write` within `within` instead
/// of hanging, and nothing is lost or doubled. `make` must build a store whose backend consults
/// the [`Stall`] and whose own call bound is well under `within`. Not part of [`run_all`], which
/// takes no stall switch; a store that can stall must run this beside it.
///
/// A timed-out write has an unknown outcome (it may have been applied), so the sender retries
/// under the same message id; the case checks that the retry leaves exactly one copy.
///
/// # Panics
/// When the stalled write returns `Ok` or takes longer than `within`, or the queue afterwards is
/// not exactly the two messages once each.
pub fn a_stalled_backend_returns_an_error_not_a_hang<S: MailStore>(
    make: impl Fn(Stall) -> S,
    within: std::time::Duration,
) {
    let stall = Stall::new();
    let mut mb = Mailbox::open_volatile(
        make(stall.clone()),
        MailConfig::default(),
        t0() - Duration::seconds(1),
    )
    .expect("open");
    mb.enqueue(env("one", "lane@acct", b"1"), t0())
        .expect("a healthy write");
    stall.set(true);
    let started = std::time::Instant::now();
    let stalled = mb.enqueue(env("two", "lane@acct", b"2"), t0());
    let took = started.elapsed();
    assert!(
        stalled.is_err(),
        "a write against a stalled backend returned Ok"
    );
    assert!(
        took < within,
        "the stalled write took {took:?}, bound {within:?}"
    );
    stall.set(false);
    mb.enqueue(env("two", "lane@acct", b"2"), t0())
        .expect("the retry once the backend answers");
    let ids = Ids::new();
    let epoch = ids.claim(&mut mb, "lane", t0() + Duration::seconds(1));
    let got = mb
        .fetch("lane@acct", epoch, 10, None, t0() + Duration::seconds(2))
        .expect("fetch");
    let mut seen: Vec<&str> = got.iter().map(|d| d.envelope.message_id.as_str()).collect();
    seen.sort_unstable();
    assert_eq!(seen, ["one", "two"], "each message exactly once");
}

/// # Panics
/// With the case name prefixed, on the first failing case.
pub fn run_all<S: MailStore>(make: impl Fn() -> S) {
    case("enqueue_then_fetch_leases_and_hides", || {
        enqueue_then_fetch_leases_and_hides(&make)
    });
    case("an_expired_lease_redelivers_in_order", || {
        an_expired_lease_redelivers_in_order(&make)
    });
    case("ack_removes_for_good_and_a_resend_is_a_duplicate", || {
        ack_removes_for_good_and_a_resend_is_a_duplicate(&make)
    });
    case("a_duplicate_while_queued_is_not_queued_twice", || {
        a_duplicate_while_queued_is_not_queued_twice(&make)
    });
    case("a_superseded_epoch_cannot_fetch_or_ack", || {
        a_superseded_epoch_cannot_fetch_or_ack(&make)
    });
    case("a_takeover_frees_the_old_leases_at_once", || {
        a_takeover_frees_the_old_leases_at_once(&make)
    });
    case("only_the_lease_holder_acks", || {
        only_the_lease_holder_acks(&make)
    });
    case("ack_is_idempotent", || ack_is_idempotent(&make));
    case(
        "the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue",
        || the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue(&make),
    );
    case("sweep_deletes_old_acked_history_never_queued_mail", || {
        sweep_deletes_old_acked_history_never_queued_mail(&make)
    });
    case("a_lease_outside_the_range_is_refused", || {
        a_lease_outside_the_range_is_refused(&make)
    });
    case("mail_waits_for_a_role_that_has_not_claimed_yet", || {
        mail_waits_for_a_role_that_has_not_claimed_yet(&make)
    });
    case("claims_are_written_through_the_store", || {
        claims_are_written_through_the_store(&make)
    });
    case("depths_count_queued_and_leased_per_role", || {
        depths_count_queued_and_leased_per_role(&make)
    });
    case("an_expired_or_superseded_lease_counts_as_queued", || {
        an_expired_or_superseded_lease_counts_as_queued(&make)
    });
    case(
        "fetch_excluding_skips_the_named_messages_and_leaves_them_unleased",
        || fetch_excluding_skips_the_named_messages_and_leaves_them_unleased(&make),
    );
    case(
        "fetch_excluding_counts_delivered_messages_not_skipped_ones",
        || fetch_excluding_counts_delivered_messages_not_skipped_ones(&make),
    );
    case("a_failed_write_changes_nothing", || {
        a_failed_write_changes_nothing(&make)
    });
    case(
        "a_message_leased_max_deliveries_times_goes_dead_and_is_kept",
        || a_message_leased_max_deliveries_times_goes_dead_and_is_kept(&make),
    );
    case("a_full_dead_set_keeps_the_message_queued", || {
        a_full_dead_set_keeps_the_message_queued(&make)
    });
    case("role_liveness_is_written_through_the_store", || {
        role_liveness_is_written_through_the_store(&make)
    });
    case("a_dead_message_can_be_requeued", || {
        a_dead_message_can_be_requeued(&make)
    });
    case(
        "redelivery_backs_off_then_goes_dead_and_names_the_sender",
        || redelivery_backs_off_then_goes_dead_and_names_the_sender(&make),
    );
    case(
        "a_polling_reader_also_reports_the_exhausted_message",
        || a_polling_reader_also_reports_the_exhausted_message(&make),
    );
    case(
        "an_ack_at_the_second_attempt_ends_the_schedule_with_no_notice",
        || an_ack_at_the_second_attempt_ends_the_schedule_with_no_notice(&make),
    );
    case("a_restart_mid_schedule_gets_the_message_again", || {
        a_restart_mid_schedule_gets_the_message_again(&make)
    });
    case(
        "a_dead_message_is_delivered_again_when_the_role_next_claims",
        || a_dead_message_is_delivered_again_when_the_role_next_claims(&make),
    );
}

fn case(name: &str, f: impl FnOnce()) {
    if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        eprintln!("mailbox conformance case failed: {name}");
        std::panic::resume_unwind(e);
    }
}
