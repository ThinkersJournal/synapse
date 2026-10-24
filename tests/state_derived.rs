// SPDX-License-Identifier: MIT OR Apache-2.0
//! Derived facts (design: docs/superpowers/specs/2026-10-23-shared-state-design.md, slice S4a):
//! a checker reports, readers see `satisfied` / `stale` / `last_verified` / `unblocked` computed
//! from those reports, and nobody can type a fact.

use chrono::{DateTime, Duration, TimeZone, Utc};
use synapse::state::{
    Blocker, Caller, Condition, FactReport, FactSpec, Filter, Look, MemoryState, NewRecord, Op,
    Patch, Staleness, State, StateError, StateStore,
};

fn t(n: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 24, 12, 0, 0).unwrap() + Duration::minutes(n)
}

fn caller(role: &str) -> Caller {
    Caller {
        role: role.into(),
        write: true,
        admin: false,
        read_all: false,
        derive: false,
    }
}

fn checker() -> Caller {
    Caller {
        write: false,
        derive: true,
        ..caller("checker")
    }
}

fn fact(text: &str) -> FactSpec {
    FactSpec::parse(text).unwrap()
}

fn cond(f: &str, op: Op, value: &str) -> Condition {
    Condition {
        fact: fact(f),
        op,
        value: value.into(),
    }
}

fn record_with(verify: Vec<Condition>) -> NewRecord {
    NewRecord {
        title: "thread".into(),
        parties: vec!["alpha".into(), "beta".into()],
        owner: "alpha".into(),
        state: State::Open,
        blocked_on: vec![],
        verify,
        notes: String::new(),
    }
}

fn found(f: &str, v: &str) -> FactReport {
    FactReport {
        fact: fact(f),
        look: Look::Found(v.into()),
    }
}

fn failed(f: &str) -> FactReport {
    FactReport {
        fact: fact(f),
        look: Look::Failed("503 from the forge".into()),
    }
}

fn absent(f: &str) -> FactReport {
    FactReport {
        fact: fact(f),
        look: Look::Absent,
    }
}

fn view<S: StateStore>(s: &S, id: &str, now: DateTime<Utc>) -> synapse::state::Derived {
    s.get_view(&caller("alpha"), id, now).unwrap().unwrap().1
}

fn a_condition_nobody_has_checked_is_stale_unknown_and_never_verified<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![cond("crate_version:synapse", Op::Ge, "6.0.0")]),
            t(0),
        )
        .unwrap();
    let d = view(&s, &r.id, t(1));
    assert_eq!(
        (d.stale, d.last_verified, d.verify[0].satisfied),
        (true, None, None)
    );
    // A record with nothing to verify is not stale.
    let plain = s.create(&a, record_with(vec![]), t(2)).unwrap();
    let d = view(&s, &plain.id, t(3));
    assert_eq!((d.stale, d.last_verified), (false, None));
}

fn only_the_checker_reports_facts_and_learns_which_are_wanted<S: StateStore>(s: S) {
    let a = caller("alpha");
    s.create(
        &a,
        record_with(vec![
            cond("crate_version:synapse", Op::Ge, "6.0.0"),
            cond("pr_state:ThinkersJournal/synapse#245", Op::Eq, "merged"),
        ]),
        t(0),
    )
    .unwrap();
    // A second record names one of the same facts, and a done record's facts are not wanted.
    s.create(
        &a,
        record_with(vec![cond("crate_version:synapse", Op::Exists, "")]),
        t(1),
    )
    .unwrap();
    let done = s
        .create(
            &a,
            record_with(vec![cond("ref_sha:o/r@main", Op::Exists, "")]),
            t(2),
        )
        .unwrap();
    s.patch(
        &a,
        &done.id,
        1,
        Patch {
            state: Some(State::Done),
            ..Patch::default()
        },
        t(3),
    )
    .unwrap();

    let wanted = s.wanted_facts(&checker()).unwrap();
    assert_eq!(
        wanted.iter().map(FactSpec::as_str).collect::<Vec<_>>(),
        [
            "crate_version:synapse",
            "pr_state:ThinkersJournal/synapse#245"
        ],
        "distinct, and no done record's facts"
    );
    for who in [
        caller("alpha"),
        Caller {
            admin: true,
            ..caller("root")
        },
    ] {
        assert_eq!(s.wanted_facts(&who), Err(StateError::Forbidden));
        assert_eq!(
            s.report_facts(&who, vec![found("crate_version:synapse", "9.9.9")], t(4)),
            Err(StateError::Forbidden),
            "not even an admin may type a fact"
        );
    }
}

fn a_reported_fact_satisfies_a_condition_and_is_attributed<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![
                cond("crate_version:synapse", Op::Ge, "6.0.0-rc.144"),
                cond("pr_state:o/r#1", Op::Eq, "merged"),
            ]),
            t(0),
        )
        .unwrap();
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "6.0.0-rc.145")],
        t(10),
    )
    .unwrap();
    s.report_facts(&checker(), vec![found("pr_state:o/r#1", "open")], t(20))
        .unwrap();
    let d = view(&s, &r.id, t(30));
    assert_eq!(
        d.verify.iter().map(|c| c.satisfied).collect::<Vec<_>>(),
        [Some(true), Some(false)]
    );
    assert_eq!(d.verify[0].observed_by.as_deref(), Some("checker"));
    assert_eq!(
        d.last_verified,
        Some(t(10)),
        "the oldest observation is the record's"
    );
    assert_eq!(d.last_verified_by.as_deref(), Some("checker"));
    assert!(!d.stale);
    // The record itself did not change: derived facts are not writes.
    assert_eq!(s.get(&a, &r.id).unwrap().unwrap().revision, 1);
}

fn versions_compare_as_semver_not_as_text<S: StateStore>(s: S) {
    let a = caller("alpha");
    let ge = |value: &str| record_with(vec![cond("crate_version:synapse", Op::Ge, value)]);
    let r1 = s.create(&a, ge("6.0.0-rc.10"), t(0)).unwrap();
    let r2 = s.create(&a, ge("6.0.0"), t(1)).unwrap();
    let r3 = s.create(&a, ge("6.0.0-rc.144"), t(2)).unwrap();
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "6.0.0-rc.9")],
        t(3),
    )
    .unwrap();
    assert_eq!(
        view(&s, &r1.id, t(4)).verify[0].satisfied,
        Some(false),
        "rc.9 < rc.10, though '9' > '1' as text"
    );
    assert_eq!(
        view(&s, &r2.id, t(4)).verify[0].satisfied,
        Some(false),
        "a pre-release is below its release"
    );
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "6.0.0")],
        t(5),
    )
    .unwrap();
    assert_eq!(view(&s, &r2.id, t(6)).verify[0].satisfied, Some(true));
    assert_eq!(
        view(&s, &r3.id, t(6)).verify[0].satisfied,
        Some(true),
        "the release is above a pre-release"
    );
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "v6.0.1")],
        t(7),
    )
    .unwrap();
    assert_eq!(
        view(&s, &r2.id, t(8)).verify[0].satisfied,
        Some(true),
        "a leading v is tolerated"
    );
}

fn a_failed_look_answers_nothing_and_absent_is_not_a_failure<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![
                cond("file_at_ref:o/r@main:docs/X.md", Op::Absent, ""),
                cond("crate_version:synapse", Op::Exists, ""),
            ]),
            t(0),
        )
        .unwrap();
    // Never looked: unknown, so "absent" is not satisfied by silence.
    assert_eq!(view(&s, &r.id, t(1)).verify[0].satisfied, None);
    // A failure is not "absent".
    s.report_facts(
        &checker(),
        vec![failed("file_at_ref:o/r@main:docs/X.md")],
        t(2),
    )
    .unwrap();
    let d = view(&s, &r.id, t(3));
    assert_eq!(d.verify[0].satisfied, None);
    assert_eq!(d.verify[0].error.as_deref(), Some("503 from the forge"));
    // A successful look that found nothing is.
    s.report_facts(
        &checker(),
        vec![absent("file_at_ref:o/r@main:docs/X.md")],
        t(4),
    )
    .unwrap();
    assert_eq!(view(&s, &r.id, t(5)).verify[0].satisfied, Some(true));
    // A later failure does not erase the good look, but the fact answers nothing while it is newest.
    s.report_facts(
        &checker(),
        vec![failed("file_at_ref:o/r@main:docs/X.md")],
        t(6),
    )
    .unwrap();
    let d = view(&s, &r.id, t(7));
    assert_eq!(d.verify[0].satisfied, None);
    assert_eq!(
        d.verify[0].observed_at,
        Some(t(4)),
        "the last good look is kept"
    );
    s.report_facts(
        &checker(),
        vec![found("file_at_ref:o/r@main:docs/X.md", "abc123")],
        t(8),
    )
    .unwrap();
    let d = view(&s, &r.id, t(9));
    assert_eq!(
        (d.verify[0].satisfied, d.verify[0].error.clone()),
        (Some(false), None)
    );
}

fn blockers_clear_when_their_facts_hold_and_their_records_finish<S: StateStore>(s: S) {
    let a = caller("alpha");
    let dep = s.create(&a, record_with(vec![]), t(0)).unwrap();
    let mut n = record_with(vec![]);
    n.state = State::Blocked;
    n.blocked_on = vec![
        Blocker::Record(dep.id.clone()),
        Blocker::Condition(cond("pr_state:o/r#7", Op::Eq, "merged")),
    ];
    let b = s.create(&a, n, t(1)).unwrap();
    assert!(!view(&s, &b.id, t(2)).unblocked);
    s.report_facts(&checker(), vec![found("pr_state:o/r#7", "merged")], t(3))
        .unwrap();
    assert!(
        !view(&s, &b.id, t(4)).unblocked,
        "the record blocker is still open"
    );
    s.patch(
        &a,
        &dep.id,
        1,
        Patch {
            state: Some(State::Done),
            ..Patch::default()
        },
        t(5),
    )
    .unwrap();
    let d = view(&s, &b.id, t(6));
    assert!(d.unblocked);
    assert_eq!(
        d.blocked_on.iter().map(|x| x.satisfied).collect::<Vec<_>>(),
        [Some(true), Some(true)]
    );
    // It is a flag, not a state change: only a party moves the record.
    assert_eq!(s.get(&a, &b.id).unwrap().unwrap().state, State::Blocked);
    // Not blocked, not "unblocked".
    s.patch(
        &a,
        &b.id,
        1,
        Patch {
            state: Some(State::Open),
            blocked_on: Some(vec![]),
            ..Patch::default()
        },
        t(7),
    )
    .unwrap();
    assert!(!view(&s, &b.id, t(8)).unblocked);
}

fn staleness_follows_the_age_of_the_oldest_observation<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![
                cond("crate_version:synapse", Op::Exists, ""),
                cond("ref_sha:o/r@main", Op::Exists, ""),
            ]),
            t(0),
        )
        .unwrap();
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "1.0.0")],
        t(0),
    )
    .unwrap();
    s.report_facts(&checker(), vec![found("ref_sha:o/r@main", "abc")], t(300))
        .unwrap();
    let d = view(&s, &r.id, t(330));
    assert_eq!((d.stale, d.last_verified), (false, Some(t(0))));
    let d = view(&s, &r.id, t(361)); // 6 h 1 min after the older observation
    assert!(
        d.stale,
        "one condition past its limit makes the record stale"
    );
    assert!(d.verify[0].stale && !d.verify[1].stale);
}

fn refresh_notifies_each_change_once<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![cond("crate_version:synapse", Op::Ge, "6.0.0")]),
            t(0),
        )
        .unwrap();
    let before = s.pending_notices(100).unwrap().len();
    assert_eq!(
        s.refresh_derived(t(1)).unwrap(),
        0,
        "the first look is a baseline"
    );
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "6.0.1")],
        t(2),
    )
    .unwrap();
    assert_eq!(
        s.refresh_derived(t(3)).unwrap(),
        2,
        "both parties hear that a fact flipped and it is fresh"
    );
    let notices = s.pending_notices(100).unwrap();
    let derived: Vec<_> = notices.iter().filter(|n| n.derived).collect();
    assert_eq!(derived.len(), 2);
    assert_eq!(derived[0].fields, ["facts", "stale"]);
    assert!(
        derived
            .iter()
            .all(|n| n.id == r.id && !n.body().contains("6.0.1")),
        "ids and field names only"
    );
    assert_ne!(derived[0].message_id(), derived[1].message_id());
    assert_eq!(s.pending_notices(100).unwrap().len(), before + 2);
    assert_eq!(
        s.refresh_derived(t(4)).unwrap(),
        0,
        "nothing changed, nothing sent"
    );
    // Time passes: it goes stale, once.
    assert_eq!(s.refresh_derived(t(2 + 361)).unwrap(), 2);
    let last: Vec<_> = s
        .pending_notices(100)
        .unwrap()
        .into_iter()
        .filter(|n| n.derived)
        .collect();
    assert_eq!(last.last().unwrap().fields, ["stale"]);
    assert_eq!(
        s.refresh_derived(t(2 + 400)).unwrap(),
        0,
        "once per transition"
    );
    // Two derived notices to one party for one record are two messages, not a duplicate.
    let ids: std::collections::BTreeSet<_> = last.iter().map(|n| n.message_id()).collect();
    assert_eq!(ids.len(), last.len());
}

fn a_report_before_the_first_refresh_still_notifies<S: StateStore>(s: S) {
    let a = caller("alpha");
    s.create(
        &a,
        record_with(vec![cond("crate_version:synapse", Op::Ge, "6.0.0")]),
        t(0),
    )
    .unwrap();
    // No refresh has run yet: the baseline was taken when the record was written.
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "6.0.1")],
        t(1),
    )
    .unwrap();
    assert_eq!(s.refresh_derived(t(2)).unwrap(), 2);
}

fn refresh_ignores_finished_records_and_reshaped_ones<S: StateStore>(s: S) {
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![cond("crate_version:synapse", Op::Exists, "")]),
            t(0),
        )
        .unwrap();
    assert_eq!(s.refresh_derived(t(1)).unwrap(), 0);
    // Editing the conditions changes the record's shape: a new baseline, not a flip.
    s.patch(
        &a,
        &r.id,
        1,
        Patch {
            verify: Some(vec![
                cond("crate_version:synapse", Op::Exists, ""),
                cond("ref_sha:o/r@main", Op::Exists, ""),
            ]),
            ..Patch::default()
        },
        t(2),
    )
    .unwrap();
    assert_eq!(s.refresh_derived(t(3)).unwrap(), 0);
    s.patch(
        &a,
        &r.id,
        2,
        Patch {
            state: Some(State::Done),
            ..Patch::default()
        },
        t(4),
    )
    .unwrap();
    s.report_facts(
        &checker(),
        vec![found("crate_version:synapse", "1.0.0")],
        t(5),
    )
    .unwrap();
    assert_eq!(
        s.refresh_derived(t(6)).unwrap(),
        0,
        "a done record is left alone"
    );
}

fn bad_reports_are_refused<S: StateStore>(s: S) {
    let long = "x".repeat(300);
    for look in [
        Look::Found(long.clone()),
        Look::Failed(long),
        Look::Found("a\u{1b}b".into()),
    ] {
        let r = FactReport {
            fact: fact("crate_version:synapse"),
            look,
        };
        assert!(matches!(
            s.report_facts(&checker(), vec![r], t(0)),
            Err(StateError::Malformed(_))
        ));
    }
    assert!(
        s.list_views(&caller("alpha"), &Filter::default(), t(1))
            .unwrap()
            .is_empty()
    );
}

fn run_all<S: StateStore>(make: impl Fn() -> S) {
    a_condition_nobody_has_checked_is_stale_unknown_and_never_verified(make());
    only_the_checker_reports_facts_and_learns_which_are_wanted(make());
    a_reported_fact_satisfies_a_condition_and_is_attributed(make());
    versions_compare_as_semver_not_as_text(make());
    a_failed_look_answers_nothing_and_absent_is_not_a_failure(make());
    blockers_clear_when_their_facts_hold_and_their_records_finish(make());
    staleness_follows_the_age_of_the_oldest_observation(make());
    refresh_notifies_each_change_once(make());
    a_report_before_the_first_refresh_still_notifies(make());
    refresh_ignores_finished_records_and_reshaped_ones(make());
    bad_reports_are_refused(make());
}

#[test]
fn the_memory_store_derives_facts() {
    run_all(MemoryState::in_memory);
}

#[test]
fn a_kind_can_have_its_own_staleness_limit() {
    let mut staleness = Staleness::default();
    staleness
        .per_kind
        .insert("pr_state".to_string(), Duration::minutes(10));
    let s = MemoryState::in_memory().with_staleness(staleness);
    let a = caller("alpha");
    let r = s
        .create(
            &a,
            record_with(vec![
                cond("pr_state:o/r#1", Op::Eq, "merged"),
                cond("crate_version:synapse", Op::Exists, ""),
            ]),
            t(0),
        )
        .unwrap();
    s.report_facts(
        &checker(),
        vec![
            found("pr_state:o/r#1", "open"),
            found("crate_version:synapse", "1.0.0"),
        ],
        t(0),
    )
    .unwrap();
    let d = view(&s, &r.id, t(11));
    assert!(
        d.verify[0].stale && !d.verify[1].stale,
        "pr_state is stale after 10 min, crates after 6 h"
    );
}

#[cfg(feature = "mailbox-redb")]
mod redb {
    use super::*;
    use synapse::state::{RedbBackend, StateEngine};

    #[test]
    fn the_redb_store_derives_facts() {
        let dir = tempfile::tempdir().unwrap();
        let n = std::cell::Cell::new(0);
        let path = dir.path().to_path_buf();
        run_all(|| {
            n.set(n.get() + 1);
            StateEngine::new(RedbBackend::open(&path.join(format!("s{}.redb", n.get()))).unwrap())
        });
    }

    #[test]
    fn facts_and_the_notified_baseline_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let a = caller("alpha");
        let id = {
            let s = StateEngine::new(RedbBackend::open(&path).unwrap());
            let r = s
                .create(
                    &a,
                    record_with(vec![cond("crate_version:synapse", Op::Ge, "6.0.0")]),
                    t(0),
                )
                .unwrap();
            assert_eq!(s.refresh_derived(t(1)).unwrap(), 0);
            s.report_facts(
                &checker(),
                vec![found("crate_version:synapse", "6.0.1")],
                t(2),
            )
            .unwrap();
            r.id
        };
        let s = StateEngine::new(RedbBackend::open(&path).unwrap());
        assert_eq!(view(&s, &id, t(3)).verify[0].satisfied, Some(true));
        assert_eq!(
            s.refresh_derived(t(4)).unwrap(),
            2,
            "the baseline from before the reopen is remembered"
        );
        assert_eq!(s.refresh_derived(t(5)).unwrap(), 0);
    }
}
