// SPDX-License-Identifier: MIT OR Apache-2.0
//! Lane launch on message: the pure state machine behind `GET /v1/waiting`, `POST
//! /v1/launch-result` and `POST /v1/launch-clear`. Design:
//! `docs/superpowers/specs/2026-10-15-cutover-and-lane-launch.md` section C.
//!
//! The daemon launches nothing. It says which roles have mail waiting and no live session, keeps a
//! little in-memory state about the answers, and re-signals with a bounded backoff. The signal is
//! LEVEL-triggered: [`Table::evaluate`] is recomputed from the mailbox and presence on every read,
//! so a lost response or a restarted poller loses nothing. Launch state is in memory; a daemon
//! restart starts a new `epoch` and attempt 1 again.
//!
//! No clock here: every function takes `now`. Nothing in a signal is mail content, a sender, a
//! token or a model.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

/// Tuning, and the roles allowed to read the signal. `roles` is empty by default, which turns the
/// feature off: every launch route answers 403.
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    /// Role names (not global ids) that may read `/v1/waiting` and answer it.
    pub roles: Vec<String>,
    /// How long the oldest mail must have waited before its role is launchable.
    pub grace: Duration,
    /// How long a signal or a started launch may stay unanswered before it counts as failed.
    pub wait: Duration,
    /// Delay before re-signalling after attempt `n` failed (`backoff[n - 1]`). The attempt count is
    /// `backoff.len() + 1`: one signal and one retry per entry.
    pub backoff: Vec<Duration>,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        LauncherConfig {
            roles: Vec::new(),
            grace: Duration::seconds(5),
            wait: Duration::seconds(120),
            backoff: vec![
                Duration::seconds(30),
                Duration::seconds(120),
                Duration::seconds(600),
            ],
        }
    }
}

/// The authenticated senders whose pending mail may raise a launch signal. Shared, so a change
/// applies on the next poll. Empty allows nobody: it is never "anyone".
#[derive(Debug, Clone, Default)]
pub struct LaunchSenders(Arc<RwLock<Vec<String>>>);

impl LaunchSenders {
    /// Replace the list. Each entry is `role` (this daemon's account) or `role@account`.
    pub fn set(&self, senders: Vec<String>) {
        if let Ok(mut held) = self.0.write() {
            *held = senders;
        }
    }

    /// Whether no sender is allowed. A poisoned lock reads as empty (fail closed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.read().map_or(true, |held| held.is_empty())
    }

    /// Whether `from`, a sender's global id `role@account`, is listed. A bare listed role means
    /// `account`, this daemon's own. Compared exactly, as role@account.
    #[must_use]
    pub fn allows(&self, from: &str, account: &str) -> bool {
        self.0.read().is_ok_and(|held| {
            held.iter().any(|entry| {
                if entry.contains('@') {
                    entry == from
                } else {
                    from.split_once('@')
                        .is_some_and(|(role, acct)| role == entry && acct == account)
                }
            })
        })
    }
}

impl LauncherConfig {
    fn max_attempts(&self) -> u32 {
        u32::try_from(self.backoff.len()).unwrap_or(u32::MAX - 1) + 1
    }
}

/// What the launcher said about one signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Started,
    AlreadyRunning,
    Refused,
    Failed,
}

impl Outcome {
    #[must_use]
    pub fn parse(s: &str) -> Option<Outcome> {
        match s {
            "started" => Some(Outcome::Started),
            "already-running" => Some(Outcome::AlreadyRunning),
            "refused" => Some(Outcome::Refused),
            "failed" => Some(Outcome::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Handed out, no answer yet.
    Signalled,
    /// Started (or already running); waiting for the role to claim.
    Launching,
    /// Failed; the next attempt is due at `next_at`.
    Failed,
    /// Policy said no. Terminal for this signal id until cleared.
    Refused,
    /// Every attempt failed. Terminal for this signal id until cleared.
    Unreachable,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Signalled => "signalled",
            State::Launching => "launching",
            State::Failed => "failed",
            State::Refused => "refused",
            State::Unreachable => "unreachable",
        }
    }
}

/// One role with mail waiting and no live session, as the daemon read it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// `<role>@<account>`.
    pub global_id: String,
    pub queued: usize,
    pub oldest_enqueued_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct Launch {
    signal_id: String,
    epoch: String,
    attempt: u32,
    state: State,
    reason: Option<String>,
    since: DateTime<Utc>,
    /// When the current wait ends (a signal or a started launch) or the next attempt is due.
    next_at: DateTime<Utc>,
}

/// The launcher's answer to one signal.
#[derive(Debug, Clone)]
pub struct Answer {
    pub signal_id: String,
    pub epoch: String,
    pub attempt: u32,
    pub outcome: Outcome,
    pub reason: Option<String>,
}

/// Why a launch answer was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultError {
    /// No such signal is open: the id, epoch or attempt is not the current one, or it was already
    /// answered.
    Stale,
}

/// Per-role launch state, in memory.
#[derive(Debug)]
pub struct Table {
    boot: String,
    counter: u64,
    by_role: HashMap<String, Launch>,
}

/// The role name of a global id.
#[must_use]
pub fn role_name(global_id: &str) -> &str {
    global_id
        .split_once('@')
        .map_or(global_id, |(role, _)| role)
}

/// The signal id of a role's current wait: the role and when its oldest pending mail arrived.
/// Stable while that mail stays pending; no mail id or content.
#[must_use]
pub fn signal_id(global_id: &str, oldest: DateTime<Utc>) -> String {
    format!(
        "{}:{}",
        role_name(global_id),
        oldest.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    )
}

impl Table {
    #[must_use]
    pub fn new(started_at: DateTime<Utc>) -> Table {
        Table {
            boot: started_at.timestamp_millis().to_string(),
            counter: 0,
            by_role: HashMap::new(),
        }
    }

    fn epoch(&self) -> String {
        format!("{}.{}", self.boot, self.counter)
    }

    /// The signals due now, given every role that is waiting and offline (`candidates`). A role
    /// that is not a candidate (online, or nothing queued) has nothing to launch, so its state is
    /// dropped.
    pub fn evaluate(
        &mut self,
        cfg: &LauncherConfig,
        candidates: &[Candidate],
        now: DateTime<Utc>,
    ) -> Vec<Value> {
        self.by_role
            .retain(|role, _| candidates.iter().any(|c| &c.global_id == role));
        let mut out = Vec::new();
        for c in candidates {
            let id = signal_id(&c.global_id, c.oldest_enqueued_at);
            let epoch = self.epoch();
            let due = match self.by_role.get_mut(&c.global_id) {
                Some(l) if l.signal_id == id => match l.state {
                    State::Refused | State::Unreachable => false,
                    State::Signalled if now < l.next_at => true,
                    State::Signalled => {
                        fail(l, cfg, now, "no-answer");
                        advance(l, cfg, now)
                    }
                    State::Launching if now < l.next_at => false,
                    State::Launching => {
                        fail(l, cfg, now, "no-claim");
                        // The launch was believed: re-signal at once, count the attempt.
                        if l.state == State::Failed {
                            l.next_at = now;
                        }
                        advance(l, cfg, now)
                    }
                    State::Failed => advance(l, cfg, now),
                },
                _ => {
                    self.by_role.insert(
                        c.global_id.clone(),
                        Launch {
                            signal_id: id.clone(),
                            epoch: epoch.clone(),
                            attempt: 1,
                            state: State::Signalled,
                            reason: None,
                            since: now,
                            next_at: now + cfg.wait,
                        },
                    );
                    true
                }
            };
            if due && let Some(l) = self.by_role.get(&c.global_id) {
                out.push(json!({
                    "role": role_name(&c.global_id),
                    "global_id": c.global_id,
                    "signal_id": l.signal_id,
                    "epoch": l.epoch,
                    "attempt": l.attempt,
                    "count": c.queued,
                    "oldest_enqueued_at": c.oldest_enqueued_at.to_rfc3339(),
                }));
            }
        }
        out
    }

    /// Apply the launcher's answer to the signal `(signal_id, epoch, attempt)` for `global_id`.
    pub fn result(
        &mut self,
        cfg: &LauncherConfig,
        global_id: &str,
        answer: Answer,
        now: DateTime<Utc>,
    ) -> Result<(), ResultError> {
        let Answer {
            signal_id,
            epoch,
            attempt,
            outcome,
            reason,
        } = answer;
        let l = self
            .by_role
            .get_mut(global_id)
            .filter(|l| {
                l.signal_id == signal_id
                    && l.epoch == epoch
                    && l.attempt == attempt
                    && l.state == State::Signalled
            })
            .ok_or(ResultError::Stale)?;
        match outcome {
            Outcome::Started | Outcome::AlreadyRunning => {
                l.state = State::Launching;
                l.reason = reason;
                l.since = now;
                l.next_at = now + cfg.wait;
            }
            Outcome::Refused => {
                l.state = State::Refused;
                l.reason = reason;
                l.since = now;
            }
            Outcome::Failed => {
                fail(l, cfg, now, reason.as_deref().unwrap_or("failed"));
            }
        }
        Ok(())
    }

    /// Forget a role's launch state (an operator's or the launcher's clear). Starts a new epoch, so
    /// a replayed `(signal_id, attempt)` from before is told apart. Returns the new epoch.
    pub fn clear(&mut self, global_id: &str) -> String {
        self.by_role.remove(global_id);
        self.counter += 1;
        self.epoch()
    }

    /// A role claimed: whatever was pending about it is stale.
    pub fn claimed(&mut self, global_id: &str) {
        self.by_role.remove(global_id);
    }

    /// `launch` as `/v1/list` shows it, or `null` when the role has no launch state.
    #[must_use]
    pub fn view(&self, global_id: &str) -> Value {
        self.by_role.get(global_id).map_or(Value::Null, |l| {
            json!({
                "state": l.state.name(),
                "reason": l.reason,
                "since": l.since.to_rfc3339(),
                "attempts": l.attempt,
            })
        })
    }
}

/// Record a failed attempt: schedule the retry, or give up.
fn fail(l: &mut Launch, cfg: &LauncherConfig, now: DateTime<Utc>, reason: &str) {
    l.reason = Some(reason.to_string());
    l.since = now;
    if l.attempt >= cfg.max_attempts() {
        l.state = State::Unreachable;
    } else {
        l.state = State::Failed;
        let idx = usize::try_from(l.attempt - 1).unwrap_or(usize::MAX);
        l.next_at = now + cfg.backoff.get(idx).copied().unwrap_or(cfg.wait);
    }
}

/// If a failed launch's next attempt is due, start it and report that it should be signalled.
fn advance(l: &mut Launch, cfg: &LauncherConfig, now: DateTime<Utc>) -> bool {
    match l.state {
        State::Failed if now >= l.next_at => {
            l.attempt += 1;
            l.state = State::Signalled;
            l.since = now;
            l.next_at = now + cfg.wait;
            true
        }
        State::Signalled => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn cand(oldest: i64) -> Candidate {
        Candidate {
            global_id: "alpha@acct".into(),
            queued: 2,
            oldest_enqueued_at: t(oldest),
        }
    }

    fn cfg() -> LauncherConfig {
        LauncherConfig {
            roles: vec!["overmind".into()],
            grace: Duration::seconds(5),
            wait: Duration::seconds(100),
            backoff: vec![Duration::seconds(30), Duration::seconds(60)],
        }
    }

    fn ans(s: &Value, attempt: u32, outcome: Outcome, reason: Option<&str>) -> Answer {
        Answer {
            signal_id: s["signal_id"].as_str().unwrap().to_string(),
            epoch: s["epoch"].as_str().unwrap().to_string(),
            attempt,
            outcome,
            reason: reason.map(str::to_string),
        }
    }

    fn only(sigs: &[Value]) -> &Value {
        assert_eq!(sigs.len(), 1, "{sigs:?}");
        &sigs[0]
    }

    #[test]
    fn a_waiting_role_is_signalled_at_attempt_one_with_a_stable_id_and_no_content() {
        let mut table = Table::new(t(0));
        let sigs = table.evaluate(&cfg(), &[cand(1)], t(10));
        let s = only(&sigs);
        assert_eq!(s["role"], "alpha");
        assert_eq!(s["attempt"], 1);
        assert_eq!(s["count"], 2);
        assert_eq!(s["signal_id"], signal_id("alpha@acct", t(1)));
        // Level-triggered: the same read again shows the same signal.
        let again = table.evaluate(&cfg(), &[cand(1)], t(11));
        assert_eq!(only(&again)["signal_id"], s["signal_id"]);
        assert_eq!(only(&again)["epoch"], s["epoch"]);
        // Contents: role, ids, count, timestamps; nothing else.
        let mut keys: Vec<_> = s.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "attempt",
                "count",
                "epoch",
                "global_id",
                "oldest_enqueued_at",
                "role",
                "signal_id"
            ]
        );
    }

    #[test]
    fn started_waits_then_resignals_with_the_next_attempt() {
        let mut table = Table::new(t(0));
        let c = cfg();
        let sigs = table.evaluate(&c, &[cand(1)], t(10));
        let s = only(&sigs).clone();
        table
            .result(&c, "alpha@acct", ans(&s, 1, Outcome::Started, None), t(11))
            .unwrap();
        assert_eq!(table.view("alpha@acct")["state"], "launching");
        assert!(table.evaluate(&c, &[cand(1)], t(50)).is_empty());
        let later = table.evaluate(&c, &[cand(1)], t(112));
        assert_eq!(only(&later)["attempt"], 2, "{later:?}");
    }

    /// The outcome vocabulary is exactly four wire strings (spec C4). `launching` and `unreachable`
    /// are launch *states*, and a dry run answers nothing: none of them is an outcome.
    #[test]
    fn only_the_four_spec_outcomes_parse() {
        for (s, want) in [
            ("started", Outcome::Started),
            ("already-running", Outcome::AlreadyRunning),
            ("refused", Outcome::Refused),
            ("failed", Outcome::Failed),
        ] {
            assert_eq!(Outcome::parse(s), Some(want), "{s}");
        }
        for s in ["launching", "unreachable", "dry-run", "Started", ""] {
            assert_eq!(Outcome::parse(s), None, "{s:?}");
        }
    }

    #[test]
    fn failed_backs_off_then_the_last_failure_is_unreachable() {
        let mut table = Table::new(t(0));
        let c = cfg();
        let mut now = 10;
        for attempt in 1..=3u32 {
            let sigs = table.evaluate(&c, &[cand(1)], t(now));
            let s = only(&sigs).clone();
            assert_eq!(s["attempt"], attempt);
            table
                .result(
                    &c,
                    "alpha@acct",
                    ans(&s, attempt, Outcome::Failed, Some("spawn-failed")),
                    t(now),
                )
                .unwrap();
            if attempt < 3 {
                let back = i64::from(attempt) * 30;
                assert!(
                    table.evaluate(&c, &[cand(1)], t(now + back - 1)).is_empty(),
                    "signalled before its backoff"
                );
                now += back;
            }
        }
        let view = table.view("alpha@acct");
        assert_eq!(view["state"], "unreachable");
        assert_eq!(view["reason"], "spawn-failed");
        assert!(table.evaluate(&c, &[cand(1)], t(now + 5000)).is_empty());
    }

    #[test]
    fn refused_is_terminal_until_the_oldest_mail_changes_or_it_is_cleared() {
        let mut table = Table::new(t(0));
        let c = cfg();
        let sigs = table.evaluate(&c, &[cand(1)], t(10));
        let s = only(&sigs).clone();
        table
            .result(
                &c,
                "alpha@acct",
                ans(&s, 1, Outcome::Refused, Some("policy")),
                t(10),
            )
            .unwrap();
        assert!(table.evaluate(&c, &[cand(1)], t(9000)).is_empty());
        // New oldest mail: a new signal id, so a new decision.
        assert_eq!(
            only(&table.evaluate(&c, &[cand(500)], t(9001)))["attempt"],
            1
        );
        // Clearing: same signal id again, attempt 1 of a NEW epoch.
        let first_epoch = s["epoch"].as_str().unwrap().to_string();
        let new_epoch = table.clear("alpha@acct");
        assert_ne!(new_epoch, first_epoch);
        let again = table.evaluate(&c, &[cand(1)], t(9002));
        assert_eq!(only(&again)["signal_id"], s["signal_id"]);
        assert_eq!(only(&again)["attempt"], 1);
        assert_eq!(only(&again)["epoch"], new_epoch.as_str());
    }

    #[test]
    fn an_answer_for_another_epoch_attempt_or_id_is_stale() {
        let mut table = Table::new(t(0));
        let c = cfg();
        let sigs = table.evaluate(&c, &[cand(1)], t(10));
        let s = only(&sigs).clone();
        let id = s["signal_id"].as_str().unwrap();
        let ep = s["epoch"].as_str().unwrap();
        let go = |table: &mut Table, id: &str, ep: &str, attempt: u32| {
            let answer = Answer {
                signal_id: id.to_string(),
                epoch: ep.to_string(),
                attempt,
                outcome: Outcome::Started,
                reason: None,
            };
            table.result(&c, "alpha@acct", answer, t(11))
        };
        assert_eq!(go(&mut table, id, "other.0", 1), Err(ResultError::Stale));
        assert_eq!(go(&mut table, id, ep, 2), Err(ResultError::Stale));
        assert_eq!(go(&mut table, "alpha:nope", ep, 1), Err(ResultError::Stale));
        assert_eq!(go(&mut table, id, ep, 1), Ok(()));
        // Answered once: the same answer again is stale (it is no longer an open signal).
        assert_eq!(go(&mut table, id, ep, 1), Err(ResultError::Stale));
    }

    #[test]
    fn no_answer_counts_as_failed_after_the_wait() {
        let mut table = Table::new(t(0));
        let c = cfg();
        assert_eq!(table.evaluate(&c, &[cand(1)], t(10)).len(), 1);
        // Still inside the wait: still shown, attempt 1.
        assert_eq!(only(&table.evaluate(&c, &[cand(1)], t(100)))["attempt"], 1);
        // Past the wait, inside the backoff: nothing.
        assert!(table.evaluate(&c, &[cand(1)], t(111)).is_empty());
        assert_eq!(table.view("alpha@acct")["reason"], "no-answer");
        // After the backoff: attempt 2.
        assert_eq!(only(&table.evaluate(&c, &[cand(1)], t(141)))["attempt"], 2);
    }

    #[test]
    fn a_role_with_nothing_waiting_loses_its_state() {
        let mut table = Table::new(t(0));
        let c = cfg();
        table.evaluate(&c, &[cand(1)], t(10));
        assert_ne!(table.view("alpha@acct"), Value::Null);
        table.evaluate(&c, &[], t(20));
        assert_eq!(table.view("alpha@acct"), Value::Null);
    }
}
