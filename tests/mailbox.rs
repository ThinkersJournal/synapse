// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox suite (M4) run against `MemoryStore`, one named test per case.

use synapse::mailbox::conformance as suite;
use synapse::mailbox::{MailError, MailStore, MemoryStore, Stored};

macro_rules! cases {
    ($($name:ident),* $(,)?) => {
        $( #[test] fn $name() { suite::$name(MemoryStore::new); } )*
    };
}

cases!(
    enqueue_then_fetch_leases_and_hides,
    an_expired_lease_redelivers_in_order,
    ack_removes_for_good_and_a_resend_is_a_duplicate,
    a_duplicate_while_queued_is_not_queued_twice,
    a_superseded_epoch_cannot_fetch_or_ack,
    a_takeover_frees_the_old_leases_at_once,
    only_the_lease_holder_acks,
    ack_is_idempotent,
    the_bound_refuses_by_count_and_by_bytes_and_keeps_the_queue,
    sweep_deletes_old_acked_history_never_queued_mail,
    a_lease_outside_the_range_is_refused,
    mail_waits_for_a_role_that_has_not_claimed_yet,
    claims_are_written_through_the_store,
    role_liveness_is_written_through_the_store,
    depths_count_queued_and_leased_per_role,
    an_expired_or_superseded_lease_counts_as_queued,
    fetch_excluding_skips_the_named_messages_and_leaves_them_unleased,
    fetch_excluding_counts_delivered_messages_not_skipped_ones,
    a_failed_write_changes_nothing,
    a_message_leased_max_deliveries_times_goes_dead_and_is_kept,
    a_full_dead_set_keeps_the_message_queued,
    a_dead_message_can_be_requeued,
);

/// MemoryStore's transaction contract: a closure that changes state and then fails leaves the
/// prior state (review focus 1).
#[test]
fn a_failed_write_leaves_the_prior_state() {
    let store = MemoryStore::new();
    let stored = Stored {
        envelope: suite::env("m1", "lane@acct", b"x"),
        seq: 1,
        enqueued_at: suite::t0(),
        lease: None,
        attempts: 0,
    };
    let failed = store.write(&mut |txn| {
        txn.put("lane@acct", stored.clone())
            .map_err(MailError::Store)?;
        Err(MailError::MailboxFull)
    });
    assert_eq!(failed, Err(MailError::MailboxFull));
    let mut queue_len = None;
    store
        .write(&mut |txn| {
            queue_len = Some(txn.stats("lane@acct").map_err(MailError::Store)?.0);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        queue_len,
        Some(0),
        "the failed transaction's put must not survive"
    );
}

// ---- Final-review fixes (M4 PR1) ----

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use synapse::mailbox::{Envelope, MailConfig, MailTxn, Mailbox};

/// A store that fails the next write when told to, over a shared MemoryStore (review I1).
#[derive(Clone)]
struct FailingStore {
    inner: Arc<MemoryStore>,
    fail_next: Arc<AtomicBool>,
}

impl MailStore for FailingStore {
    fn durability(&self) -> synapse::mailbox::DurabilityClass {
        self.inner.durability()
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(MailError::Store(synapse::mailbox::StoreError(
                "injected".into(),
            )));
        }
        self.inner.write(f)
    }
}

/// Review I1: a claim whose epoch the store did not record poisons the mailbox, every later call
/// refuses, and a reopen continues from the last persisted epoch.
#[test]
fn a_failed_claim_write_poisons_and_a_reopen_continues_from_the_store() {
    let ids = suite::Ids::new();
    let store = FailingStore {
        inner: Arc::new(MemoryStore::new()),
        fail_next: Arc::new(AtomicBool::new(false)),
    };
    let mut mb = suite::open(store.clone());
    let first = ids.claim(&mut mb, "lane", suite::t0());
    let later = suite::t0() + chrono::Duration::seconds(5);
    assert_eq!(
        ids.claim(&mut mb, "lane", later),
        first + 1,
        "persisted normally"
    );

    // Control: before the failure, depths are readable and the mailbox says it is healthy.
    assert!(mb.depths(later).unwrap().contains_key("lane@acct"));
    assert!(!mb.is_poisoned());

    // The next store write fails: the claim is granted in memory but not recorded.
    store.fail_next.store(true, Ordering::SeqCst);
    let at = later + chrono::Duration::seconds(5);
    assert!(
        matches!(ids.try_claim(&mut mb, "lane", at), Err(MailError::Store(_))),
        "the store write failed"
    );
    assert!(
        mb.is_poisoned(),
        "a failed write poisons, and the mailbox can say so"
    );
    for result in [
        mb.enqueue(suite::env("m", "lane@acct", b"x"), at)
            .map(|_| ()),
        mb.fetch("lane@acct", first + 2, 1, None, at).map(|_| ()),
        mb.ack("lane@acct", first + 2, "m", at).map(|_| ()),
        mb.sweep(at).map(|_| ()),
        mb.depths(at).map(|_| ()),
    ] {
        assert_eq!(result, Err(MailError::Poisoned));
    }
    assert!(matches!(
        ids.try_claim(&mut mb, "lane", at),
        Err(MailError::Poisoned)
    ));

    // Reopen over the same store: the unrecorded epoch was never handed out, so it is reissued.
    let reopened_at = at + chrono::Duration::seconds(1);
    let mut reopened =
        Mailbox::open_volatile(store.clone(), MailConfig::default(), reopened_at).expect("reopen");
    let next = ids.claim(
        &mut reopened,
        "lane",
        reopened_at + chrono::Duration::seconds(1),
    );
    assert_eq!(next, first + 2, "the store's last epoch was first + 1");
}

/// Review I3: the mailbox keys storage on `to` and `message_id`, so it refuses malformed or
/// oversized ones. Whether a role may receive is M5's decision; whether a key is sane is ours.
#[test]
fn malformed_envelopes_are_refused() {
    let mut mb = suite::open(MemoryStore::new());
    let long = "x".repeat(257);
    let cases = [
        ("", "m1", "peer@acct"),
        ("nobody", "m1", "peer@acct"),
        ("a@b@c", "m1", "peer@acct"),
        ("bad.label@acct", "m1", "peer@acct"),
        ("lane@acct", "", "peer@acct"),
        ("lane@acct", long.as_str(), "peer@acct"),
        ("lane@acct", "m1", long.as_str()),
    ];
    for (to, id, from) in cases {
        let env = Envelope {
            message_id: id.into(),
            to: to.into(),
            from: from.into(),
            body: vec![],
        };
        assert_eq!(
            mb.enqueue(env, suite::t0()),
            Err(MailError::Malformed),
            "to={to:?} id_len={} from_len={}",
            id.len(),
            from.len()
        );
    }
}

/// Review M1 (re-graded Important): bodies are signed message content and may be large; Debug
/// must show their length, never their bytes.
#[test]
fn debug_never_prints_a_body() {
    let env = suite::env("m1", "lane@acct", b"top-secret-body");
    let shown = format!("{env:?}");
    assert!(
        shown.contains("m1") && shown.contains("15"),
        "ids and body length shown: {shown}"
    );
    let bytes_as_debug = format!("{:?}", b"top-secret-body".to_vec());
    assert!(
        !shown.contains("top-secret-body") && !shown.contains(&bytes_as_debug[1..20]),
        "{shown}"
    );
}

// `run_all` is the entry point other crates use, so it is tested here against a store that is
// known-good and against one that is known-bad: a runner that always passed would pass both.
#[test]
fn run_all_passes_a_conforming_store() {
    synapse::mailbox::conformance::run_all(MemoryStore::new);
}

/// A store that forgets every write: its transactions run against a fresh empty state each time.
struct Amnesiac;
impl MailStore for Amnesiac {
    fn durability(&self) -> synapse::mailbox::DurabilityClass {
        synapse::mailbox::DurabilityClass::Process
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn synapse::mailbox::MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        MemoryStore::new().write(f)
    }
}

#[test]
fn run_all_rejects_a_store_that_forgets_its_writes() {
    let outcome = std::panic::catch_unwind(|| {
        synapse::mailbox::conformance::run_all(|| Amnesiac);
    });
    assert!(
        outcome.is_err(),
        "a store that persists nothing passed the conformance suite"
    );
}

/// Board 229 (CireSnave, 2026-10-18): mail needs `Machine` durability. A store declaring `Process`
/// is refused at open, and the refusal names both classes.
#[test]
fn a_store_declaring_less_than_machine_is_refused_at_open() {
    use synapse::mailbox::{DurabilityClass, REQUIRED_DURABILITY};
    assert_eq!(REQUIRED_DURABILITY, DurabilityClass::Machine);
    assert_eq!(MemoryStore::new().durability(), DurabilityClass::Process);
    let err = Mailbox::open(
        MemoryStore::new(),
        MailConfig::default(),
        suite::t0() - chrono::Duration::seconds(1),
    )
    .err()
    .expect("refused");
    assert_eq!(
        err,
        MailError::DurabilityTooWeak {
            declared: DurabilityClass::Process,
            required: DurabilityClass::Machine
        }
    );
    suite::a_store_declaring_less_is_refused(MemoryStore::new);
    // the escape hatch is explicit, and still works for throwaway stores
    Mailbox::open_volatile(
        MemoryStore::new(),
        MailConfig::default(),
        suite::t0() - chrono::Duration::seconds(1),
    )
    .expect("open_volatile");
}

/// A store whose writes all fail, as a full volume's do: reads go through the inner store.
struct NoRoomStore(MemoryStore);

impl MailStore for NoRoomStore {
    fn durability(&self) -> synapse::mailbox::DurabilityClass {
        self.0.durability()
    }

    fn write(
        &self,
        _f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        Err(MailError::Store(synapse::mailbox::StoreError(
            "database or disk is full".into(),
        )))
    }

    fn read(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        self.0.write(f)
    }
}

/// Opening a mailbox, and asking its depths, only read: a store with no room to write (a full
/// disk) must still open, so the mail it acknowledged earlier can be read back.
#[test]
fn opening_and_depths_need_no_room_to_write() {
    let mb = Mailbox::open_volatile(
        NoRoomStore(MemoryStore::new()),
        MailConfig::default(),
        suite::t0() - chrono::Duration::seconds(1),
    )
    .expect("open reads, it does not write");
    mb.depths(suite::t0())
        .expect("depths reads, it does not write");
}
