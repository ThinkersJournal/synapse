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
use crate::rooms::RoomsState;

/// A mailbox's whole state, in a form two stores can be compared by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dump {
    /// Each role with queued mail (dead sets as `dead:<role>`), in ascending `seq`.
    pub queues: BTreeMap<String, Vec<Stored>>,
    /// Acked history: `(role, message id)` to when.
    pub acked: BTreeMap<(String, String), DateTime<Utc>>,
    pub roles: RolesState,
    pub rooms: RoomsState,
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
            rooms: txn.rooms().map_err(MailError::Store)?,
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
        txn.set_rooms(&dump.rooms).map_err(MailError::Store)?;
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
    if a.rooms != b.rooms {
        return Some("rooms".into());
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

/// What an import would change in the target, and the counts of it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportReport {
    /// Roles only the source knew.
    pub roles_added: usize,
    /// Roles both knew where the source's epoch was higher, so its record was kept.
    pub roles_raised: usize,
    /// Queued messages added (dead letters included in `dead_added`).
    pub messages_added: usize,
    /// Of those, how many sit in a `dead:<role>` queue.
    pub dead_added: usize,
    /// Source messages left out because the target already queues them.
    pub skipped_present: usize,
    /// Source messages left out because the target already acked them (a stale copy).
    pub skipped_acked: usize,
    /// Target messages removed because the source acked them (handled there since the split).
    pub messages_dropped: usize,
    /// Acked-history entries added to the target.
    pub acks_added: usize,
    /// Rooms only the source knew.
    pub rooms_added: usize,
    /// The target's sequence counter before and after.
    pub seq_before: u64,
    pub seq_after: u64,
}

/// The exact writes an import makes, worked out from two dumps and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    /// Messages to put: `(queue, stored)`, re-sequenced above the target's counter, leases cleared.
    pub add: Vec<(String, Stored)>,
    /// Target messages to remove: `(queue, message id)`.
    pub drop: Vec<(String, String)>,
    /// Acked-history entries to record.
    pub acks: Vec<(String, String, DateTime<Utc>)>,
    /// The role table after the import.
    pub roles: RolesState,
    /// The rooms after the import.
    pub rooms: RoomsState,
    /// The counter after the import.
    pub seq: u64,
    pub report: ImportReport,
}

/// The role a queue belongs to: a dead set `dead:<role>` is acked under `<role>`.
fn queue_role(queue: &str) -> &str {
    queue.strip_prefix("dead:").unwrap_or(queue)
}

/// Work out how to fold `source` (an older store, here the redb file) into `target` (the store that
/// stays). Nothing is read or written: the rules are these, each tested on its own.
///
/// 1. Roles: every role of the source joins; where both have one, the HIGHER epoch's record is kept
///    (an epoch is never reissued), the target's on a tie.
/// 2. Messages: a source message the target neither queues nor already acked is added, in a fresh
///    sequence above the target's counter (the source's order kept), its lease cleared (a lease
///    from another daemon's clock means nothing here) and its attempt count kept. Dead letters
///    follow the same rule in their `dead:<role>` queue.
/// 3. Acked history: the union; where both have an entry the target's time stays.
/// 4. A target message the source acked (handled there after the stores split) is dropped, or the
///    lane would be handed it a second time.
/// 5. Rooms: rooms only the source has are added; a room both have stays as the target has it.
/// 6. The counter becomes the larger of the target's and the last number handed out.
#[must_use]
pub fn plan_import(target: &Dump, source: &Dump) -> ImportPlan {
    let mut report = ImportReport {
        seq_before: target.seq,
        ..ImportReport::default()
    };

    // 1. roles
    let mut roles = target.roles.clone();
    for (role, theirs) in &source.roles.roles {
        match roles.roles.get(role) {
            None => {
                roles.roles.insert(role.clone(), theirs.clone());
                report.roles_added += 1;
            }
            Some(ours) if theirs.epoch > ours.epoch => {
                roles.roles.insert(role.clone(), theirs.clone());
                report.roles_raised += 1;
            }
            Some(_) => {}
        }
    }

    // 3. acked history (the union, as writes)
    let acks: Vec<(String, String, DateTime<Utc>)> = source
        .acked
        .iter()
        .filter(|(key, _)| !target.acked.contains_key(*key))
        .map(|((role, id), at)| (role.clone(), id.clone(), *at))
        .collect();
    report.acks_added = acks.len();

    // 4. target messages the source acked
    let mut drop = Vec::new();
    for (queue, rows) in &target.queues {
        for stored in rows {
            let key = (
                queue_role(queue).to_string(),
                stored.envelope.message_id.clone(),
            );
            if source.acked.contains_key(&key) && !target.acked.contains_key(&key) {
                drop.push((queue.clone(), stored.envelope.message_id.clone()));
            }
        }
    }
    report.messages_dropped = drop.len();

    // 2. messages, in the source's own order
    let mut candidates: Vec<(u64, &String, &Stored)> = source
        .queues
        .iter()
        .flat_map(|(queue, rows)| rows.iter().map(move |stored| (stored.seq, queue, stored)))
        .collect();
    candidates.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let mut next = target.seq;
    let mut add = Vec::new();
    for (_, queue, stored) in candidates {
        let id = &stored.envelope.message_id;
        let present = target
            .queues
            .get(queue)
            .is_some_and(|rows| rows.iter().any(|r| &r.envelope.message_id == id));
        if present {
            report.skipped_present += 1;
            continue;
        }
        if target
            .acked
            .contains_key(&(queue_role(queue).to_string(), id.clone()))
        {
            report.skipped_acked += 1;
            continue;
        }
        next += 1;
        let mut moved = stored.clone();
        moved.seq = next;
        moved.lease = None;
        if queue.starts_with("dead:") {
            report.dead_added += 1;
        }
        report.messages_added += 1;
        add.push((queue.clone(), moved));
    }

    // 5. rooms
    let mut rooms = target.rooms.clone();
    for (id, room) in &source.rooms.rooms {
        if !rooms.rooms.contains_key(id) {
            rooms.rooms.insert(id.clone(), room.clone());
            report.rooms_added += 1;
        }
    }

    // 6. the counter
    let seq = target.seq.max(next);
    report.seq_after = seq;
    ImportPlan {
        add,
        drop,
        acks,
        roles,
        rooms,
        seq,
        report,
    }
}

/// What `target` must dump as once `plan` has been applied, so the write can be proved afterwards.
#[must_use]
pub fn dump_after(target: &Dump, plan: &ImportPlan) -> Dump {
    let mut out = target.clone();
    for (queue, id) in &plan.drop {
        if let Some(rows) = out.queues.get_mut(queue) {
            rows.retain(|r| &r.envelope.message_id != id);
            if rows.is_empty() {
                out.queues.remove(queue);
            }
        }
    }
    for (queue, stored) in &plan.add {
        out.queues
            .entry(queue.clone())
            .or_default()
            .push(stored.clone());
    }
    for rows in out.queues.values_mut() {
        rows.sort_by_key(|r| r.seq);
    }
    for (role, id, at) in &plan.acks {
        out.acked.insert((role.clone(), id.clone()), *at);
    }
    out.roles = plan.roles.clone();
    out.rooms = plan.rooms.clone();
    out.seq = plan.seq;
    out
}

/// Apply `plan` to `store` in one transaction (all of it, or none), then read the store back and
/// require it to equal [`dump_after`]. Returns what was read back.
///
/// # Errors
/// [`MigrateError::Mismatch`] naming the first difference; a store error otherwise.
pub fn apply_import<S: MailStore>(store: &S, plan: &ImportPlan) -> Result<Dump, MigrateError> {
    let before = dump(store)?;
    let expected = dump_after(&before, plan);
    store.write(&mut |txn| {
        for (queue, id) in &plan.drop {
            txn.remove(queue, id).map_err(MailError::Store)?;
        }
        for (queue, stored) in &plan.add {
            txn.put(queue, stored.clone()).map_err(MailError::Store)?;
        }
        for (role, id, at) in &plan.acks {
            txn.record_ack(role, id, *at).map_err(MailError::Store)?;
        }
        txn.set_roles(&plan.roles).map_err(MailError::Store)?;
        txn.set_rooms(&plan.rooms).map_err(MailError::Store)?;
        txn.set_seq_counter(plan.seq).map_err(MailError::Store)?;
        Ok(())
    })?;
    let after = dump(store)?;
    if let Some(difference) = first_difference(&expected, &after) {
        return Err(MigrateError::Mismatch(difference));
    }
    Ok(after)
}

#[cfg(test)]
mod import_tests {
    use super::*;
    use crate::mailbox::{Envelope, Lease, MemoryStore};
    use crate::roles::RoleRecord;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).expect("a time")
    }

    fn stored(id: &str, seq: u64, leased: bool) -> Stored {
        Stored {
            envelope: Envelope {
                message_id: id.into(),
                to: "q".into(),
                from: "f".into(),
                body: id.as_bytes().to_vec(),
                mode: None,
            },
            seq,
            enqueued_at: at(1_000 + seq as i64),
            lease: leased.then(|| Lease {
                epoch: 1,
                until: at(2_000),
            }),
            attempts: 3,
        }
    }

    fn role(epoch: u64) -> RoleRecord {
        RoleRecord {
            epoch,
            claimed_at: at(500 + epoch as i64),
            last_seen: None,
            retired_at: None,
        }
    }

    fn dump_of(
        seq: u64,
        roles: &[(&str, u64)],
        queues: &[(&str, Vec<Stored>)],
        acked: &[(&str, &str, i64)],
    ) -> Dump {
        Dump {
            queues: queues
                .iter()
                .map(|(q, rows)| ((*q).to_string(), rows.clone()))
                .collect(),
            acked: acked
                .iter()
                .map(|(r, id, t)| (((*r).to_string(), (*id).to_string()), at(*t)))
                .collect(),
            roles: RolesState {
                roles: roles
                    .iter()
                    .map(|(r, e)| ((*r).to_string(), role(*e)))
                    .collect(),
            },
            rooms: RoomsState::default(),
            seq,
        }
    }

    fn room() -> crate::rooms::Room {
        serde_json::from_value(
            serde_json::json!({"created_at": "2026-11-16T00:00:00Z", "creator": "account"}),
        )
        .expect("a room")
    }

    #[test]
    fn rule_1_roles_join_and_the_higher_epoch_wins() {
        let target = dump_of(0, &[("pm", 2), ("x", 5)], &[], &[]);
        let source = dump_of(0, &[("pm", 3), ("y", 1), ("x", 4)], &[], &[]);
        let plan = plan_import(&target, &source);
        assert_eq!(
            plan.roles.roles["pm"].epoch, 3,
            "the source's higher epoch is kept"
        );
        assert_eq!(
            plan.roles.roles["x"].epoch, 5,
            "the target's higher epoch is kept"
        );
        assert!(
            plan.roles.roles.contains_key("y"),
            "a source-only role joins"
        );
        assert_eq!((plan.report.roles_added, plan.report.roles_raised), (1, 1));
    }

    #[test]
    fn rule_2_messages_are_added_in_source_order_above_the_counter_with_leases_cleared() {
        let target = dump_of(10, &[], &[("q", vec![stored("m0", 10, false)])], &[]);
        let source = dump_of(
            0,
            &[],
            &[
                ("q", vec![stored("m0", 1, false), stored("m1", 7, true)]),
                ("dead:q", vec![stored("d1", 3, false)]),
            ],
            &[],
        );
        let plan = plan_import(&target, &source);
        let added: Vec<(&str, &str, u64)> = plan
            .add
            .iter()
            .map(|(q, s)| (q.as_str(), s.envelope.message_id.as_str(), s.seq))
            .collect();
        assert_eq!(
            added,
            vec![("dead:q", "d1", 11), ("q", "m1", 12)],
            "source order, fresh seqs"
        );
        assert!(
            plan.add.iter().all(|(_, s)| s.lease.is_none()),
            "leases cleared"
        );
        assert!(
            plan.add.iter().all(|(_, s)| s.attempts == 3),
            "attempts kept"
        );
        assert_eq!(plan.report.skipped_present, 1, "m0 is already there");
        assert_eq!((plan.report.messages_added, plan.report.dead_added), (2, 1));
    }

    #[test]
    fn rule_2_a_message_the_target_already_acked_is_not_brought_back() {
        let target = dump_of(5, &[], &[], &[("q", "old", 100), ("q", "olddead", 100)]);
        let source = dump_of(
            0,
            &[],
            &[
                ("q", vec![stored("old", 1, false)]),
                ("dead:q", vec![stored("olddead", 2, false)]),
            ],
            &[],
        );
        let plan = plan_import(&target, &source);
        assert!(plan.add.is_empty(), "{:?}", plan.add);
        assert_eq!(
            plan.report.skipped_acked, 2,
            "a dead set is acked under its role"
        );
    }

    #[test]
    fn rule_3_acked_history_is_the_union_and_the_targets_time_stays() {
        let target = dump_of(0, &[], &[], &[("q", "a", 100)]);
        let source = dump_of(0, &[], &[], &[("q", "a", 999), ("q", "b", 200)]);
        let plan = plan_import(&target, &source);
        assert_eq!(plan.acks, vec![("q".into(), "b".into(), at(200))]);
        let after = dump_after(&target, &plan);
        assert_eq!(after.acked[&("q".to_string(), "a".to_string())], at(100));
        assert!(
            after
                .acked
                .contains_key(&("q".to_string(), "b".to_string()))
        );
    }

    #[test]
    fn rule_4_a_target_message_the_source_acked_is_dropped() {
        let target = dump_of(
            9,
            &[],
            &[
                (
                    "q",
                    vec![stored("done", 1, false), stored("keep", 2, false)],
                ),
                ("dead:q", vec![stored("deaddone", 3, false)]),
            ],
            &[],
        );
        let source = dump_of(0, &[], &[], &[("q", "done", 5), ("q", "deaddone", 6)]);
        let plan = plan_import(&target, &source);
        assert_eq!(
            plan.drop,
            vec![
                ("dead:q".to_string(), "deaddone".to_string()),
                ("q".to_string(), "done".to_string())
            ]
        );
        let after = dump_after(&target, &plan);
        assert_eq!(after.queues["q"].len(), 1, "keep stays");
        assert!(
            !after.queues.contains_key("dead:q"),
            "an emptied queue goes"
        );
    }

    #[test]
    fn rule_5_rooms_only_the_source_has_are_added() {
        let mut target = dump_of(0, &[], &[], &[]);
        let mut source = dump_of(0, &[], &[], &[]);
        let mut changed = room();
        changed.creator = "other".into();
        target.rooms.rooms.insert("both".into(), room());
        source.rooms.rooms.insert("both".into(), changed);
        source.rooms.rooms.insert("new".into(), room());
        let plan = plan_import(&target, &source);
        assert_eq!(plan.report.rooms_added, 1);
        assert!(plan.rooms.rooms.contains_key("new"));
        assert_eq!(
            plan.rooms.rooms["both"].creator, "account",
            "the target's room stays"
        );
    }

    #[test]
    fn rule_6_the_counter_is_the_larger_of_the_two() {
        let source = dump_of(0, &[], &[("q", vec![stored("m", 1, false)])], &[]);
        let high = plan_import(&dump_of(50, &[], &[], &[]), &source);
        assert_eq!(
            high.seq, 51,
            "above the target's counter by the messages added"
        );
        let none = plan_import(&dump_of(50, &[], &[], &[]), &dump_of(0, &[], &[], &[]));
        assert_eq!(none.seq, 50, "nothing added leaves it alone");
    }

    #[test]
    fn the_plan_applies_to_a_store_reads_back_equal_and_a_second_import_changes_nothing() {
        let target = dump_of(
            4,
            &[("pm", 2)],
            &[(
                "q",
                vec![stored("done", 3, false), stored("keep", 4, false)],
            )],
            &[],
        );
        let source = dump_of(
            0,
            &[("pm", 3), ("lane", 1)],
            &[("q", vec![stored("new", 1, true)])],
            &[("q", "done", 7)],
        );
        let store = MemoryStore::new();
        restore(&store, &target).expect("restore");
        let plan = plan_import(&dump(&store).expect("dump"), &source);
        let after = apply_import(&store, &plan).expect("apply");
        assert_eq!(after, dump_after(&target, &plan));
        assert_eq!(after.seq, 5);
        let ids: Vec<&str> = after.queues["q"]
            .iter()
            .map(|s| s.envelope.message_id.as_str())
            .collect();
        assert_eq!(ids, vec!["keep", "new"], "done dropped, new added after it");
        let again = plan_import(&after, &source);
        assert_eq!(
            (
                again.add.len(),
                again.drop.len(),
                again.acks.len(),
                again.report.roles_added,
                again.report.roles_raised
            ),
            (0, 0, 0, 0, 0),
            "importing twice is a no-op: {again:?}"
        );
    }
}
