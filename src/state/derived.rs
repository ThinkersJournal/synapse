// SPDX-License-Identifier: MIT OR Apache-2.0
//! Derived facts (design: docs/superpowers/specs/2026-10-23-shared-state-design.md, sections 3 and
//! 7, slice S4a). A fact the forge can answer is never typed by a lane: a checker role reports what
//! it looked up, and everything a reader sees about a record's conditions (`satisfied`, `stale`,
//! `last_verified`, `unblocked`) is computed here, at read time, from those reports.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::{Blocker, Condition, FactSpec, Op, Record, State};

/// What a checker saw when it looked a fact up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Look {
    /// The lookup succeeded and found this value.
    Found(String),
    /// The lookup succeeded and found nothing (no such file, no such crate version).
    Absent,
    /// The lookup failed. This is NOT "absent": it satisfies no condition.
    Failed(String),
}

/// One fact reported by the checker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactReport {
    pub fact: FactSpec,
    pub look: Look,
}

/// The store's memory of one fact. A failed look does not erase the last good one; it is recorded
/// beside it, and while it is the newer of the two the fact answers nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactObservation {
    pub fact: FactSpec,
    /// The last successful look: `Some(value)`, or `None` for "looked, found nothing".
    pub observed: Option<String>,
    /// When `observed` was taken; `None` if no look has ever succeeded.
    pub observed_at: Option<DateTime<Utc>>,
    pub observed_by: Option<String>,
    /// The latest failed look.
    pub error: Option<String>,
    pub error_at: Option<DateTime<Utc>>,
}

impl FactObservation {
    /// Fold one report into what was known.
    pub(super) fn fold(
        previous: Option<FactObservation>,
        report: &FactReport,
        by: &str,
        now: DateTime<Utc>,
    ) -> FactObservation {
        let mut fact = previous.unwrap_or(FactObservation {
            fact: report.fact.clone(),
            observed: None,
            observed_at: None,
            observed_by: None,
            error: None,
            error_at: None,
        });
        match &report.look {
            Look::Found(value) => {
                fact.observed = Some(value.clone());
                fact.observed_at = Some(now);
                fact.observed_by = Some(by.to_string());
                fact.error = None;
                fact.error_at = None;
            }
            Look::Absent => {
                fact.observed = None;
                fact.observed_at = Some(now);
                fact.observed_by = Some(by.to_string());
                fact.error = None;
                fact.error_at = None;
            }
            Look::Failed(text) => {
                fact.error = Some(text.clone());
                fact.error_at = Some(now);
            }
        }
        fact
    }

    /// True while the newest look is a failure: nothing is known from this fact right now.
    fn failing(&self) -> bool {
        match (self.error_at, self.observed_at) {
            (Some(error), Some(good)) => error > good,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// How old a fact may be before a condition on it is called stale: a default, and per kind.
#[derive(Clone, Debug)]
pub struct Staleness {
    pub default: Duration,
    pub per_kind: BTreeMap<String, Duration>,
}

impl Default for Staleness {
    fn default() -> Self {
        Staleness {
            default: Duration::hours(6),
            per_kind: BTreeMap::new(),
        }
    }
}

impl Staleness {
    fn limit(&self, kind: &str) -> Duration {
        self.per_kind.get(kind).copied().unwrap_or(self.default)
    }
}

/// One condition, with what is known about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConditionView {
    pub fact: FactSpec,
    pub op: Op,
    pub value: String,
    pub observed: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub observed_by: Option<String>,
    pub error: Option<String>,
    /// `None`: unknown (never observed, or the newest look failed).
    pub satisfied: Option<bool>,
    /// Never observed, or older than its kind's limit.
    pub stale: bool,
}

/// One blocker, with whether it is cleared.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerView {
    pub blocker: Blocker,
    /// For a condition: its view. For a record: `None`.
    pub condition: Option<ConditionView>,
    /// A record blocker is cleared when that record is done or cancelled.
    pub satisfied: Option<bool>,
}

/// Everything derived about a record, never stored as typed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Derived {
    pub verify: Vec<ConditionView>,
    pub blocked_on: Vec<BlockerView>,
    /// The OLDEST observation among all its conditions, and who made it. `None`: nothing to verify,
    /// or some condition has never been observed.
    pub last_verified: Option<DateTime<Utc>>,
    pub last_verified_by: Option<String>,
    /// Some condition is unobserved or past its limit. A record with no conditions is not stale.
    pub stale: bool,
    /// The record is `blocked` and every blocker is cleared. A flag, not a state change.
    pub unblocked: bool,
}

/// What `refresh_derived` remembers per record, to notify once per change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedFlags {
    pub stale: bool,
    pub unblocked: bool,
    /// `satisfied` of each verify condition, then each blocker, in order.
    pub satisfied: Vec<Option<bool>>,
}

impl Derived {
    #[must_use]
    pub fn flags(&self) -> DerivedFlags {
        DerivedFlags {
            stale: self.stale,
            unblocked: self.unblocked,
            satisfied: self
                .verify
                .iter()
                .map(|c| c.satisfied)
                .chain(self.blocked_on.iter().map(|b| b.satisfied))
                .collect(),
        }
    }
}

fn semver_of(text: &str) -> Option<semver::Version> {
    semver::Version::parse(text.trim().trim_start_matches('v')).ok()
}

/// Does `observation` meet `condition`? `None` when it cannot be said.
fn satisfied(condition: &Condition, observation: Option<&FactObservation>) -> Option<bool> {
    let seen = observation?;
    seen.observed_at?;
    if seen.failing() {
        return None;
    }
    match condition.op {
        Op::Exists => Some(seen.observed.is_some()),
        Op::Absent => Some(seen.observed.is_none()),
        Op::Eq => Some(seen.observed.as_deref() == Some(condition.value.as_str())),
        Op::Ge => {
            let want = semver_of(&condition.value)?;
            match seen.observed.as_deref() {
                None => Some(false),
                Some(text) => Some(semver_of(text)? >= want),
            }
        }
    }
}

fn condition_view(
    condition: &Condition,
    observation: Option<&FactObservation>,
    now: DateTime<Utc>,
    staleness: &Staleness,
) -> ConditionView {
    let stale = match observation.and_then(|o| o.observed_at) {
        None => true,
        Some(at) => now - at > staleness.limit(condition.fact.kind()),
    };
    ConditionView {
        fact: condition.fact.clone(),
        op: condition.op,
        value: condition.value.clone(),
        observed: observation.and_then(|o| o.observed.clone()),
        observed_at: observation.and_then(|o| o.observed_at),
        observed_by: observation.and_then(|o| o.observed_by.clone()),
        error: observation.and_then(|o| o.error.clone()),
        satisfied: satisfied(condition, observation),
        stale,
    }
}

/// Derive what can be said about `record` at `now`. `fact` and `state_of` look up the checker's
/// observations and other records' states.
pub fn derive(
    record: &Record,
    fact: &dyn Fn(&FactSpec) -> Option<FactObservation>,
    state_of: &dyn Fn(&str) -> Option<State>,
    now: DateTime<Utc>,
    staleness: &Staleness,
) -> Derived {
    let verify: Vec<ConditionView> = record
        .verify
        .iter()
        .map(|c| condition_view(c, fact(&c.fact).as_ref(), now, staleness))
        .collect();
    let blocked_on: Vec<BlockerView> = record
        .blocked_on
        .iter()
        .map(|b| match b {
            Blocker::Condition(c) => {
                let view = condition_view(c, fact(&c.fact).as_ref(), now, staleness);
                BlockerView {
                    blocker: b.clone(),
                    satisfied: view.satisfied,
                    condition: Some(view),
                }
            }
            Blocker::Record(id) => BlockerView {
                blocker: b.clone(),
                condition: None,
                satisfied: state_of(id).map(State::is_terminal),
            },
        })
        .collect();

    let mut observed: Vec<(DateTime<Utc>, Option<String>)> = Vec::new();
    let mut unobserved = false;
    for c in verify
        .iter()
        .chain(blocked_on.iter().filter_map(|b| b.condition.as_ref()))
    {
        match c.observed_at {
            Some(at) => observed.push((at, c.observed_by.clone())),
            None => unobserved = true,
        }
    }
    let (last_verified, last_verified_by) = if unobserved {
        (None, None)
    } else {
        observed
            .into_iter()
            .min_by_key(|(at, _)| *at)
            .map_or((None, None), |(at, by)| (Some(at), by))
    };
    let stale = verify
        .iter()
        .chain(blocked_on.iter().filter_map(|b| b.condition.as_ref()))
        .any(|c| c.stale);
    let unblocked =
        record.state == State::Blocked && blocked_on.iter().all(|b| b.satisfied == Some(true));
    Derived {
        verify,
        blocked_on,
        last_verified,
        last_verified_by,
        stale,
        unblocked,
    }
}
