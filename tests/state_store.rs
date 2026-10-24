// SPDX-License-Identifier: MIT OR Apache-2.0
//! The shared-state store's contract (design: docs/superpowers/specs/2026-10-23-shared-state-design.md,
//! slice S1), as cases generic over the store, run against memory and redb.

use chrono::{DateTime, TimeZone, Utc};
use synapse::state::{
    Blocker, Caller, Change, Condition, FactSpec, Filter, MemoryState, NewRecord, Op, Patch, State,
    StateError, StateStore, fold, verify_chain,
};

fn t(n: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 23, 12, 0, 0).unwrap() + chrono::Duration::seconds(n)
}

fn caller(role: &str) -> Caller {
    Caller {
        role: role.into(),
        write: true,
        admin: false,
        read_all: false,
    }
}

fn admin(role: &str) -> Caller {
    Caller {
        admin: true,
        ..caller(role)
    }
}

fn reader(role: &str) -> Caller {
    Caller {
        write: false,
        read_all: true,
        ..caller(role)
    }
}

fn new(title: &str, parties: &[&str], owner: &str) -> NewRecord {
    NewRecord {
        title: title.into(),
        parties: parties.iter().map(|p| (*p).into()).collect(),
        owner: owner.into(),
        state: State::Open,
        blocked_on: vec![],
        verify: vec![],
        notes: String::new(),
    }
}

fn set_state(state: State) -> Patch {
    Patch {
        state: Some(state),
        ..Patch::default()
    }
}

fn cond(fact: &str, op: Op, value: &str) -> Condition {
    Condition {
        fact: FactSpec::parse(fact).unwrap(),
        op,
        value: value.into(),
    }
}

fn create_and_get<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("wire the thing", &["alpha", "beta"], "alpha"),
            t(0),
        )
        .unwrap();
    assert_eq!(
        (r.id.as_str(), r.revision, r.uid.as_ref()),
        ("T-1", 1, None)
    );
    let r2 = s
        .create(&caller("beta"), new("second", &["beta"], "beta"), t(1))
        .unwrap();
    assert_eq!(r2.id, "T-2", "ids are sequential and never reused");
    assert_eq!(s.get(&caller("beta"), "T-1").unwrap().unwrap(), r);
    assert!(s.get(&caller("beta"), "T-9").unwrap().is_none());
}

fn a_lost_race_changes_nothing_and_returns_the_current_record<S: StateStore>(
    make: &impl Fn() -> S,
) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("race", &["alpha", "beta"], "alpha"),
            t(0),
        )
        .unwrap();
    // Both writers read revision 1; alpha writes first.
    let won = s
        .patch(&caller("alpha"), &r.id, 1, set_state(State::Waiting), t(1))
        .unwrap();
    assert_eq!(won.revision, 2);
    let lost = s.patch(&caller("beta"), &r.id, 1, set_state(State::Done), t(2));
    match lost {
        Err(StateError::StaleRevision(current)) => assert_eq!(*current, won),
        other => panic!("expected stale_revision, got ok={}", other.is_ok()),
    }
    let now = s.get(&caller("alpha"), &r.id).unwrap().unwrap();
    assert_eq!(
        (now.revision, now.state),
        (2, State::Waiting),
        "the loser changed nothing"
    );
    assert_eq!(s.history(&caller("alpha"), &r.id).unwrap().len(), 2);
    // Re-reading and writing against the current revision succeeds.
    assert_eq!(
        s.patch(&caller("beta"), &r.id, 2, set_state(State::Done), t(3))
            .unwrap()
            .revision,
        3
    );
}

fn history_is_a_verifiable_chain_and_the_whole_story<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("chain", &["alpha", "beta"], "alpha"),
            t(0),
        )
        .unwrap();
    s.patch(
        &caller("beta"),
        &r.id,
        1,
        Patch {
            notes: Some("n".into()),
            ..Patch::default()
        },
        t(1),
    )
    .unwrap();
    let last = s
        .patch(&caller("alpha"), &r.id, 2, set_state(State::Waiting), t(2))
        .unwrap();
    let h = s.history(&caller("alpha"), &r.id).unwrap();
    assert_eq!(verify_chain(&h), Ok(()));
    assert_eq!(
        h.iter().map(|e| e.writer.as_str()).collect::<Vec<_>>(),
        ["alpha", "beta", "alpha"]
    );
    assert_eq!(fold(&h).unwrap(), last, "the record is exactly its history");
    assert!(matches!(h[0].change, Change::Create(_)));

    let mut altered = h.clone();
    altered[1].writer = "alpha".into();
    assert_eq!(
        verify_chain(&altered),
        Err(2),
        "an altered entry is detected"
    );
    let mut removed = h.clone();
    removed.remove(1);
    assert_eq!(
        verify_chain(&removed),
        Err(3),
        "a removed entry is detected"
    );
    assert_eq!(
        verify_chain(&h[..2]),
        Ok(()),
        "a prefix is still a valid chain"
    );
}

fn access_is_by_party<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("private", &["alpha", "beta"], "alpha"),
            t(0),
        )
        .unwrap();
    let gamma = caller("gamma");
    assert!(
        s.get(&gamma, &r.id).unwrap().is_none(),
        "a non-party does not see it"
    );
    assert!(s.list(&gamma, &Filter::default()).unwrap().is_empty());
    assert_eq!(s.history(&gamma, &r.id), Err(StateError::Forbidden));
    assert_eq!(
        s.patch(&gamma, &r.id, 1, set_state(State::Done), t(1)),
        Err(StateError::Forbidden)
    );
    // create needs the write grant, and the creator must be a party unless admin.
    let no_write = Caller {
        write: false,
        ..caller("alpha")
    };
    assert_eq!(
        s.create(&no_write, new("x", &["alpha"], "alpha"), t(1)),
        Err(StateError::Forbidden)
    );
    assert_eq!(
        s.create(&gamma, new("x", &["alpha"], "alpha"), t(1)),
        Err(StateError::Forbidden)
    );
    assert!(
        s.create(&admin("gamma"), new("x", &["alpha"], "alpha"), t(1))
            .is_ok()
    );
    // read_all reads everything and writes nothing.
    let pm = reader("pm");
    assert_eq!(s.list(&pm, &Filter::default()).unwrap().len(), 2);
    assert!(s.history(&pm, &r.id).is_ok());
    assert_eq!(
        s.patch(&pm, &r.id, 1, set_state(State::Done), t(2)),
        Err(StateError::Forbidden)
    );
    // admin reads and patches anything.
    assert!(
        s.patch(&admin("root"), &r.id, 1, set_state(State::Waiting), t(2))
            .is_ok()
    );
    // a party without the write grant cannot patch.
    let read_only = Caller {
        write: false,
        ..caller("beta")
    };
    assert_eq!(
        s.patch(&read_only, &r.id, 2, set_state(State::Open), t(3)),
        Err(StateError::Forbidden)
    );
}

fn only_the_owner_or_an_admin_reshapes_the_record<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("owned", &["alpha", "beta"], "alpha"),
            t(0),
        )
        .unwrap();
    let take = Patch {
        owner: Some("beta".into()),
        ..Patch::default()
    };
    assert_eq!(
        s.patch(&caller("beta"), &r.id, 1, take.clone(), t(1)),
        Err(StateError::Forbidden)
    );
    assert_eq!(
        s.patch(&caller("alpha"), &r.id, 1, take, t(2))
            .unwrap()
            .owner,
        "beta"
    );
    let add = Patch {
        parties: Some(vec!["alpha".into(), "beta".into(), "gamma".into()]),
        ..Patch::default()
    };
    assert_eq!(
        s.patch(&caller("alpha"), &r.id, 2, add.clone(), t(3)),
        Err(StateError::Forbidden),
        "no longer the owner"
    );
    assert!(s.patch(&caller("beta"), &r.id, 2, add, t(4)).is_ok());
    assert!(
        s.get(&caller("gamma"), &r.id).unwrap().is_some(),
        "a new party sees it"
    );
}

fn terminal_records_are_patched_only_by_an_admin<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(&caller("alpha"), new("done", &["alpha"], "alpha"), t(0))
        .unwrap();
    s.patch(
        &caller("alpha"),
        &r.id,
        1,
        set_state(State::Cancelled),
        t(1),
    )
    .unwrap();
    assert_eq!(
        s.patch(&caller("alpha"), &r.id, 2, set_state(State::Open), t(2)),
        Err(StateError::Terminal)
    );
    assert_eq!(
        s.patch(&admin("root"), &r.id, 2, set_state(State::Open), t(3))
            .unwrap()
            .state,
        State::Open
    );
}

fn writes_are_validated<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let a = caller("alpha");
    // An admin creates, so a refusal below is the validation, not the party rule.
    let root = admin("root");
    let bad = |n: NewRecord| matches!(s.create(&root, n, t(0)), Err(StateError::Malformed(_)));
    assert!(bad(new("", &["alpha"], "alpha")), "empty title");
    assert!(
        bad(new(&"x".repeat(201), &["alpha"], "alpha")),
        "long title"
    );
    assert!(
        bad(new("a\u{1b}[31m", &["alpha"], "alpha")),
        "control character in title"
    );
    assert!(bad(new("t", &[], "alpha")), "no parties");
    assert!(bad(new("t", &["alpha"], "beta")), "owner not a party");
    assert!(bad(new("t", &["alpha", "alpha"], "alpha")), "party twice");
    assert!(
        bad(new("t", &["al pha"], "al pha")),
        "party not a role name"
    );
    let mut n = new("t", &["alpha"], "alpha");
    n.notes = "x".repeat(9000);
    assert!(bad(n), "long notes");
    let mut n = new("t", &["alpha"], "alpha");
    n.blocked_on = vec![Blocker::Condition(cond("pr_state:o/r#1", Op::Eq, "merged"))];
    assert!(bad(n), "blocked_on while not blocked");
    let mut n = new("t", &["alpha"], "alpha");
    n.state = State::Blocked;
    n.blocked_on = vec![Blocker::Record("T-77".into())];
    assert!(matches!(
        s.create(&a, n, t(0)),
        Err(StateError::UnknownBlocker(_))
    ));
    let mut n = new("t", &["alpha"], "alpha");
    n.verify = vec![cond("pr_state:o/r#1", Op::Ge, "1")];
    assert!(bad(n), "ge applies only to crate_version");
    let mut n = new("t", &["alpha"], "alpha");
    n.verify = vec![cond("crate_version:serde", Op::Exists, "1")];
    assert!(bad(n), "exists takes no value");
    let ok = s
        .create(&a, new("fine", &["alpha"], "alpha"), t(0))
        .unwrap();
    assert_eq!(
        s.patch(&a, &ok.id, 1, Patch::default(), t(1)),
        Err(StateError::Malformed(
            "an empty patch changes nothing".into()
        ))
    );
    assert_eq!(
        s.list(&a, &Filter::default()).unwrap().len(),
        1,
        "a refused create left nothing behind"
    );
    assert_eq!(
        s.create(&a, new("next", &["alpha"], "alpha"), t(2))
            .unwrap()
            .id,
        "T-2",
        "a refused create does not burn an id"
    );
}

fn blocking_on_a_record_and_filters<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let a = caller("alpha");
    let dep = s
        .create(&a, new("dependency", &["alpha"], "alpha"), t(0))
        .unwrap();
    let mut n = new("waits", &["alpha", "beta"], "alpha");
    n.state = State::Blocked;
    n.blocked_on = vec![
        Blocker::Record(dep.id.clone()),
        Blocker::Condition(cond("crate_version:synapse", Op::Ge, "6.0.0")),
    ];
    n.verify = vec![cond("ref_sha:ThinkersJournal/synapse@main", Op::Exists, "")];
    let b = s.create(&a, n, t(1)).unwrap();
    assert_eq!(
        s.patch(
            &a,
            &b.id,
            1,
            Patch {
                blocked_on: Some(vec![Blocker::Record(b.id.clone())]),
                ..Patch::default()
            },
            t(2)
        ),
        Err(StateError::Malformed(
            "a record cannot block on that id".into()
        ))
    );
    let blocked = s
        .list(
            &a,
            &Filter {
                states: vec![State::Blocked],
                party: None,
            },
        )
        .unwrap();
    assert_eq!(
        blocked.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        [b.id.as_str()]
    );
    let beta = s
        .list(
            &caller("beta"),
            &Filter {
                states: vec![],
                party: Some("beta".into()),
            },
        )
        .unwrap();
    assert_eq!(beta.len(), 1);
    let ids: Vec<_> = s
        .list(&a, &Filter::default())
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, ["T-1", "T-2"], "listed in id order");
}

fn a_write_leaves_an_id_only_notice_for_each_other_party<S: StateStore>(make: &impl Fn() -> S) {
    let s = make();
    let r = s
        .create(
            &caller("alpha"),
            new("secret title", &["alpha", "beta", "gamma"], "alpha"),
            t(0),
        )
        .unwrap();
    let n = s.pending_notices(10).unwrap();
    assert_eq!(
        n.iter()
            .map(|n| (n.to.as_str(), n.fields.clone()))
            .collect::<Vec<_>>(),
        [
            ("beta", vec!["created".to_string()]),
            ("gamma", vec!["created".to_string()])
        ],
        "everyone but the writer, in party order"
    );
    assert!(
        n.iter()
            .all(|n| n.id == r.id && n.revision == 1 && n.changed_by == "alpha")
    );
    assert!(
        n.iter().all(|n| !n.body().contains("secret")),
        "no free text in a notice"
    );
    assert_eq!(n[0].message_id(), "state:T-1:1:beta");

    s.patch(&caller("beta"), &r.id, 1, set_state(State::Waiting), t(1))
        .unwrap();
    let all = s.pending_notices(10).unwrap();
    let from_patch: Vec<_> = all.iter().filter(|n| n.revision == 2).collect();
    assert_eq!(
        from_patch.iter().map(|n| n.to.as_str()).collect::<Vec<_>>(),
        ["alpha", "gamma"],
        "the patcher is not told about its own write"
    );
    assert_eq!(from_patch[0].fields, ["state"]);

    // Delivered ones go; the rest stay; marking twice is harmless.
    for n in n.iter() {
        s.notice_delivered(n.seq).unwrap();
        s.notice_delivered(n.seq).unwrap();
    }
    assert_eq!(s.pending_notices(10).unwrap().len(), 2);
    assert_eq!(s.pending_notices(1).unwrap().len(), 1, "max is honoured");

    // A refused or stale write leaves no notice behind.
    let before = s.pending_notices(100).unwrap().len();
    let _ = s.patch(&caller("alpha"), &r.id, 1, set_state(State::Done), t(2));
    let _ = s.patch(&caller("zed"), &r.id, 2, set_state(State::Done), t(2));
    assert_eq!(s.pending_notices(100).unwrap().len(), before);
}

fn run_all<S: StateStore>(make: impl Fn() -> S) {
    a_write_leaves_an_id_only_notice_for_each_other_party(&make);
    create_and_get(&make);
    a_lost_race_changes_nothing_and_returns_the_current_record(&make);
    history_is_a_verifiable_chain_and_the_whole_story(&make);
    access_is_by_party(&make);
    only_the_owner_or_an_admin_reshapes_the_record(&make);
    terminal_records_are_patched_only_by_an_admin(&make);
    writes_are_validated(&make);
    blocking_on_a_record_and_filters(&make);
}

#[test]
fn the_memory_store_meets_the_contract() {
    run_all(MemoryState::in_memory);
}

#[test]
fn fact_specs_come_from_a_closed_registry() {
    for good in [
        "crate_version:synapse-security",
        "pr_state:ThinkersJournal/synapse#238",
        "ref_sha:ThinkersJournal/synapse@main",
        "check_state:ThinkersJournal/synapse@85d5c92",
        "file_at_ref:ThinkersJournal/synapse@main:docs/CHANGELOG.md",
    ] {
        assert!(FactSpec::parse(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "crate_version:",
        "crate_version:a b",
        "pr_state:o/r#x",
        "pr_state:o/r",
        "ref_sha:o/r@a..b",
        "check_state:o/r@zz",
        "file_at_ref:o/r@main",
        "rm_rf:/",
        "crate_version:x;ls",
        "pr_state:o/r#1\n",
    ] {
        assert!(FactSpec::parse(bad).is_err(), "{bad:?}");
    }
    let json = r#"{"fact":"pr_state:o/r#1","op":"eq","value":"merged","extra":1}"#;
    assert!(
        serde_json::from_str::<Condition>(json).is_err(),
        "unknown fields are refused"
    );
    assert!(
        serde_json::from_str::<Patch>(r#"{"revision":9}"#).is_err(),
        "derived fields are not patchable"
    );
}

#[cfg(feature = "mailbox-redb")]
mod redb {
    use super::*;
    use synapse::state::{RedbBackend, StateEngine};

    #[test]
    fn the_redb_store_meets_the_contract() {
        let dir = tempfile::tempdir().unwrap();
        let n = std::cell::Cell::new(0);
        let path = dir.path().to_path_buf();
        run_all(|| {
            n.set(n.get() + 1);
            StateEngine::new(
                RedbBackend::open(&path.join(format!("state{}.redb", n.get()))).unwrap(),
            )
        });
    }

    #[test]
    fn records_and_history_survive_a_reopen_and_the_counter_does_not_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let a = caller("alpha");
        let first = {
            let s = StateEngine::new(RedbBackend::open(&path).unwrap());
            let r = s
                .create(&a, new("durable", &["alpha"], "alpha"), t(0))
                .unwrap();
            s.patch(&a, &r.id, 1, set_state(State::Waiting), t(1))
                .unwrap()
        };
        let s = StateEngine::new(RedbBackend::open(&path).unwrap());
        assert_eq!(s.get(&a, "T-1").unwrap().unwrap(), first);
        let h = s.history(&a, "T-1").unwrap();
        assert_eq!(verify_chain(&h), Ok(()));
        assert_eq!(fold(&h).unwrap(), first);
        assert_eq!(
            s.create(&a, new("after", &["alpha"], "alpha"), t(2))
                .unwrap()
                .id,
            "T-2"
        );
    }

    #[test]
    fn undelivered_notices_survive_a_reopen_and_keep_their_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let a = caller("alpha");
        {
            let s = StateEngine::new(RedbBackend::open(&path).unwrap());
            s.create(&a, new("one", &["alpha", "beta"], "alpha"), t(0))
                .unwrap();
            s.create(&a, new("two", &["alpha", "beta"], "alpha"), t(1))
                .unwrap();
        }
        let s = StateEngine::new(RedbBackend::open(&path).unwrap());
        let n = s.pending_notices(10).unwrap();
        assert_eq!(
            n.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
            ["T-1", "T-2"]
        );
        s.notice_delivered(n[0].seq).unwrap();
        s.create(&a, new("three", &["alpha", "beta"], "alpha"), t(2))
            .unwrap();
        let n = s.pending_notices(10).unwrap();
        assert_eq!(
            n.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
            ["T-2", "T-3"]
        );
        assert!(n[0].seq < n[1].seq, "seq never repeats after a reopen");
    }

    #[test]
    fn a_refused_write_leaves_the_file_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let s = StateEngine::new(RedbBackend::open(&dir.path().join("state.redb")).unwrap());
        let a = caller("alpha");
        assert!(s.create(&a, new("", &["alpha"], "alpha"), t(0)).is_err());
        assert_eq!(
            s.create(&a, new("first", &["alpha"], "alpha"), t(1))
                .unwrap()
                .id,
            "T-1"
        );
    }
}
