// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security events, the failure limiter and the alert policy (brute-force hardening P4).
//!
//! Core types and logic only, with no I/O: sinks live in the `synapse-security` crate. Alert delivery
//! is a seam there and awaits board 131. Time is always injected, so nothing here reads a clock.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// The longest text field an event carries, in characters.
const MAX_TEXT_CHARS: usize = 256;

/// What was attempted or observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventKind {
    /// A bad bearer, claim, password or API key.
    AuthFailure,
    /// A listener failed the daemon's health proof (a squatted port).
    ProofFailure,
    /// A signature or chain did not verify.
    UnverifiedSender,
    /// A replayed message was refused.
    ReplayRefused,
    /// A limiter tripped.
    RateLimited,
    /// A key crossed the lockout threshold.
    Lockout,
    /// A secret file that others can reach was refused.
    PermissionsTooOpen,
    /// A client identity's first successful use.
    NewClient,
    /// A switch was toggled, or a key created or revoked.
    Config,
    /// An alert could not be delivered.
    AlertFailed,
    /// A shared-state call was refused: the role is not a party to the record or lacks the grant.
    StateDenied,
}

/// One security-relevant occurrence. Text fields are sanitized and must never hold a secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// When it happened.
    pub at: DateTime<Utc>,
    /// What kind of occurrence.
    pub kind: SecurityEventKind,
    /// Where, for example `synapsed/bearer`.
    pub surface: String,
    /// What was attempted: a key id, role or username, never a secret.
    pub subject: String,
    /// Peer address or identity, where known.
    pub source: Option<String>,
    /// Bounded, printable context.
    pub detail: String,
}

impl SecurityEvent {
    /// Builds an event; every text field passes through [`sanitize`].
    pub fn new(
        at: DateTime<Utc>,
        kind: SecurityEventKind,
        surface: &str,
        subject: &str,
        source: Option<&str>,
        detail: &str,
    ) -> Self {
        Self {
            at,
            kind,
            surface: sanitize(surface),
            subject: sanitize(subject),
            source: source.map(sanitize),
            detail: sanitize(detail),
        }
    }
}

/// Escapes control characters (as the command line's `printable` does), then truncates to 256
/// characters on a char boundary.
pub fn sanitize(s: &str) -> String {
    let mut out = String::new();
    let mut chars = 0;
    for c in s.chars() {
        if c.is_control() {
            for escaped in c.escape_default() {
                if chars >= MAX_TEXT_CHARS {
                    return out;
                }
                out.push(escaped);
                chars += 1;
            }
        } else {
            if chars >= MAX_TEXT_CHARS {
                return out;
            }
            out.push(c);
            chars += 1;
        }
    }
    out
}

/// Where events go. Implementations must never panic or block the caller for long.
pub trait SecuritySink: Send + Sync {
    /// Records one event.
    fn record(&self, event: &SecurityEvent);
}

/// Tuning for a [`FailureLimiter`].
#[derive(Debug, Clone)]
pub struct LimiterConfig {
    /// Failures allowed in `window` before any delay.
    pub free_failures: u32,
    /// Failures older than this stop counting.
    pub window: Duration,
    /// The first delay once over `free_failures`.
    pub base_delay: Duration,
    /// The delay doubles per extra failure, capped here.
    pub max_delay: Duration,
    /// Failures in `window` that lock the key. Attempts reserved with `try_reserve` count toward it
    /// while in flight, so zero refuses every reserved attempt.
    pub lockout_after: u32,
    /// How long a lockout lasts.
    pub lockout: Duration,
    /// Bound on tracked keys. When full, the least recently failed eighth is evicted at once. A key
    /// with an attempt in flight is never evicted, so the map can exceed this by the number of
    /// such keys, which the callers' concurrency bounds.
    pub max_keys: usize,
}

impl Default for LimiterConfig {
    fn default() -> Self {
        Self {
            free_failures: 5,
            window: Duration::minutes(5),
            base_delay: Duration::seconds(1),
            max_delay: Duration::seconds(60),
            lockout_after: 20,
            lockout: Duration::minutes(15),
            max_keys: 10_000,
        }
    }
}

/// What a caller should do with the next attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed.
    Allow,
    /// Wait this long first.
    Delay(Duration),
    /// Refuse until the given time.
    Refuse {
        /// When the lockout ends.
        until: DateTime<Utc>,
    },
}

#[derive(Debug, Default)]
struct Entry {
    failures: VecDeque<DateTime<Utc>>,
    locked_until: Option<DateTime<Utc>>,
    /// Attempts reserved by `try_reserve` and not yet released.
    in_flight: u32,
}

impl Entry {
    fn last_failure(&self) -> Option<DateTime<Utc>> {
        self.failures.back().copied()
    }
}

/// Counts failures only, keyed by caller-chosen strings, with time injected.
pub struct FailureLimiter {
    config: LimiterConfig,
    entries: Mutex<HashMap<String, Entry>>,
}

impl FailureLimiter {
    /// A limiter with the given tuning.
    pub fn new(config: LimiterConfig) -> Self {
        Self {
            config,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The delay owed after `count` failures in the window (zero while within the free budget).
    fn delay_for(&self, count: u32) -> Duration {
        if count <= self.config.free_failures {
            return Duration::zero();
        }
        let doublings = (count - self.config.free_failures - 1).min(30);
        let scaled = self.config.base_delay * (1i32 << doublings);
        scaled.min(self.config.max_delay)
    }

    fn prune(&self, entry: &mut Entry, now: DateTime<Utc>) {
        if entry.locked_until.is_some_and(|until| now >= until) {
            entry.locked_until = None;
            entry.failures.clear();
        }
        while entry
            .failures
            .front()
            .is_some_and(|at| now - *at >= self.config.window)
        {
            entry.failures.pop_front();
        }
    }

    fn verdict(&self, entry: &Entry, now: DateTime<Utc>) -> Verdict {
        if let Some(until) = entry.locked_until {
            return Verdict::Refuse { until };
        }
        let (Some(last), Ok(count)) = (entry.last_failure(), u32::try_from(entry.failures.len()))
        else {
            return Verdict::Allow;
        };
        let remaining = last + self.delay_for(count) - now;
        if remaining > Duration::zero() {
            Verdict::Delay(remaining)
        } else {
            Verdict::Allow
        }
    }

    /// Makes room for new keys by evicting the least recently failed eighth of the tracked keys (at
    /// least enough to fit one more) in a single pass. Evicting one key per new key scanned every key
    /// each time, so a spray of fresh keys cost O(`max_keys`) per key; a batch makes it O(1)
    /// amortised.
    ///
    /// A key still locked out is evicted only if every tracked key is: otherwise an attacker could
    /// clear its own lockout by spraying fresh keys until it was evicted. A key with an attempt in
    /// flight is never evicted: its release would land on a later attempt's slot.
    fn evict(&self, entries: &mut HashMap<String, Entry>, now: DateTime<Utc>) {
        let locked = |e: &Entry| e.locked_until.is_some_and(|until| now < until);
        let mut order: Vec<_> = entries
            .iter()
            .filter(|(_, e)| e.in_flight == 0)
            .map(|(k, e)| (locked(e), e.last_failure(), k))
            .collect();
        let unlocked = order.iter().filter(|(is_locked, ..)| !is_locked).count();
        let excess = (entries.len() + 1).saturating_sub(self.config.max_keys);
        let n = if unlocked > 0 {
            (self.config.max_keys / 8).max(excess).min(unlocked)
        } else {
            excess.min(order.len())
        };
        if n < order.len() {
            order.select_nth_unstable(n);
        }
        let victims: Vec<String> = order.iter().take(n).map(|(.., k)| (*k).clone()).collect();
        for k in victims {
            entries.remove(&k);
        }
    }

    /// Before an attempt: `Allow`, or `Delay`/`Refuse` if the key is over its budget or locked.
    pub fn check(&self, key: &str, now: DateTime<Utc>) -> Verdict {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(key) else {
            return Verdict::Allow;
        };
        self.prune(entry, now);
        self.verdict(entry, now)
    }

    /// After a failed attempt: records it and returns the verdict for the next attempt. The second
    /// value is true only on the failure that first locks the key.
    pub fn record_failure(&self, key: &str, now: DateTime<Utc>) -> (Verdict, bool) {
        let mut entries = self.lock();
        if !entries.contains_key(key)
            && self.config.max_keys > 0
            && entries.len() >= self.config.max_keys
        {
            self.evict(&mut entries, now);
        }
        let entry = entries.entry(key.to_string()).or_default();
        self.prune(entry, now);
        if let Some(until) = entry.locked_until {
            return (Verdict::Refuse { until }, false);
        }
        entry.failures.push_back(now);
        let count = u32::try_from(entry.failures.len()).unwrap_or(u32::MAX);
        if count >= self.config.lockout_after {
            let until = now + self.config.lockout;
            entry.locked_until = Some(until);
            return (Verdict::Refuse { until }, true);
        }
        (self.verdict(entry, now), false)
    }

    /// Before an attempt whose outcome is not known yet: true if it may proceed, in which case it
    /// counts as a failure in flight until [`release`](Self::release). A caller that verifies
    /// between checking and recording must reserve rather than `check`: otherwise every attempt
    /// already past `check` is invisible to the others, and each can land past the lockout. False if
    /// the key is locked, or if its failures plus the attempts in flight reach `lockout_after`.
    pub fn try_reserve(&self, key: &str, now: DateTime<Utc>) -> bool {
        let mut entries = self.lock();
        if !entries.contains_key(key)
            && self.config.max_keys > 0
            && entries.len() >= self.config.max_keys
        {
            self.evict(&mut entries, now);
        }
        let entry = entries.entry(key.to_string()).or_default();
        self.prune(entry, now);
        let failures = u32::try_from(entry.failures.len()).unwrap_or(u32::MAX);
        if entry.locked_until.is_some()
            || failures.saturating_add(entry.in_flight) >= self.config.lockout_after
        {
            if failures == 0 && entry.locked_until.is_none() && entry.in_flight == 0 {
                entries.remove(key);
            }
            return false;
        }
        entry.in_flight += 1;
        true
    }

    /// Ends an attempt reserved by [`try_reserve`](Self::try_reserve). Record a failure before
    /// releasing it, so the key is never briefly under-counted. A key left with no failures, no
    /// lockout and nothing in flight is forgotten, so attempts that never fail leave no key.
    pub fn release(&self, key: &str) {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(key) else {
            return;
        };
        entry.in_flight = entry.in_flight.saturating_sub(1);
        if entry.in_flight == 0 && entry.failures.is_empty() && entry.locked_until.is_none() {
            entries.remove(key);
        }
    }

    /// After a success: forgets the key, so legitimate callers never accumulate. It forgets any
    /// reservations on the key too, so a caller that reserves never calls it.
    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// How many keys are tracked (never more than `max_keys`, plus keys with attempts in flight).
    pub fn tracked_keys(&self) -> usize {
        self.lock().len()
    }
}

/// Tuning for an [`AlertPolicy`].
#[derive(Debug, Clone)]
pub struct AlertConfig {
    /// Events for one `(kind, surface, subject)` that trigger a threshold alert.
    pub threshold: u32,
    /// The window those events must fall in.
    pub threshold_window: Duration,
    /// At most one alert per `(kind, surface)` in this period; the rest are held for a digest.
    pub coalesce: Duration,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            threshold: 10,
            threshold_window: Duration::minutes(5),
            coalesce: Duration::minutes(15),
        }
    }
}

/// Why an alert was raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertReason {
    /// The kind always alerts.
    Immediate,
    /// A `(kind, surface, subject)` crossed the threshold.
    Threshold,
    /// A summary of alerts held during coalescing.
    Digest,
}

/// Something a person should be told about.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    /// The kind of event.
    pub kind: SecurityEventKind,
    /// The surface it happened on.
    pub surface: String,
    /// The first event that this alert covers.
    pub first: SecurityEvent,
    /// How many events it covers.
    pub count: u32,
    /// Why it was raised.
    pub reason: AlertReason,
}

#[derive(Debug, Default)]
struct Pair {
    last_alert: Option<DateTime<Utc>>,
    held: u32,
    held_first: Option<SecurityEvent>,
}

#[derive(Default)]
struct PolicyState {
    recent: HashMap<(SecurityEventKind, String, String), VecDeque<DateTime<Utc>>>,
    pairs: HashMap<(SecurityEventKind, String), Pair>,
}

/// Bound on distinct `(kind, surface, subject)` threshold counters, so a flood of subjects cannot
/// exhaust memory.
const MAX_THRESHOLD_KEYS: usize = 10_000;

/// Decides which events reach a person. Pure logic, with time taken from the events themselves.
pub struct AlertPolicy {
    config: AlertConfig,
    state: Mutex<PolicyState>,
}

impl AlertPolicy {
    /// A policy with the given tuning.
    pub fn new(config: AlertConfig) -> Self {
        Self {
            config,
            state: Mutex::new(PolicyState::default()),
        }
    }

    fn immediate(kind: SecurityEventKind) -> bool {
        use SecurityEventKind::{
            AlertFailed, Config, Lockout, NewClient, PermissionsTooOpen, ProofFailure,
        };
        matches!(
            kind,
            NewClient | Config | PermissionsTooOpen | ProofFailure | Lockout | AlertFailed
        )
    }

    /// Feed every event; returns an alert to send now, if any.
    pub fn observe(&self, event: &SecurityEvent) -> Option<Alert> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = &mut *guard;

        let (reason, count) = if Self::immediate(event.kind) {
            (AlertReason::Immediate, 1)
        } else {
            let key = (event.kind, event.surface.clone(), event.subject.clone());
            if !state.recent.contains_key(&key) && state.recent.len() >= MAX_THRESHOLD_KEYS {
                let oldest = state
                    .recent
                    .iter()
                    .min_by_key(|(_, times)| times.back().copied())
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    state.recent.remove(&k);
                }
            }
            let times = state.recent.entry(key).or_default();
            times.push_back(event.at);
            while times
                .front()
                .is_some_and(|at| event.at - *at >= self.config.threshold_window)
            {
                times.pop_front();
            }
            let count = u32::try_from(times.len()).unwrap_or(u32::MAX);
            if count < self.config.threshold {
                return None;
            }
            (AlertReason::Threshold, count)
        };

        let pair = state
            .pairs
            .entry((event.kind, event.surface.clone()))
            .or_default();
        let due = pair
            .last_alert
            .is_none_or(|last| event.at - last >= self.config.coalesce);
        if due {
            pair.last_alert = Some(event.at);
            Some(Alert {
                kind: event.kind,
                surface: event.surface.clone(),
                first: event.clone(),
                count,
                reason,
            })
        } else {
            pair.held += 1;
            pair.held_first.get_or_insert_with(|| event.clone());
            None
        }
    }

    /// Called periodically; returns a digest for each `(kind, surface)` pair whose held events are due.
    pub fn flush(&self, now: DateTime<Utc>) -> Vec<Alert> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut digests = Vec::new();
        for ((kind, surface), pair) in &mut state.pairs {
            let due = pair
                .last_alert
                .is_none_or(|last| now - last >= self.config.coalesce);
            if pair.held == 0 || !due {
                continue;
            }
            if let Some(first) = pair.held_first.take() {
                digests.push(Alert {
                    kind: *kind,
                    surface: surface.clone(),
                    first,
                    count: pair.held,
                    reason: AlertReason::Digest,
                });
            }
            pair.held = 0;
            pair.last_alert = Some(now);
        }
        digests
    }
}

/// Bound on distinct `(kind, surface)` pairs an [`EventGate`] tracks. Surfaces are fixed strings in
/// code, so this is never reached in practice; it only keeps the map bounded.
const MAX_GATE_PAIRS: usize = 1_024;

#[derive(Default)]
struct GateEntry {
    last_written: Option<DateTime<Utc>>,
    held_back: u32,
}

/// Writes at most one event line per `(kind, surface)` per interval; later ones are counted, and the
/// count rides on the next line that passes. Keyed on the surface, never the subject, because a
/// subject can be attacker-chosen. This keeps a flood on one surface from rotating every other
/// surface's evidence out of a size-capped sink.
pub struct EventGate {
    interval: Duration,
    state: Mutex<HashMap<(SecurityEventKind, String), GateEntry>>,
}

impl EventGate {
    /// A gate with the given interval; zero passes everything.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// `Some(detail)` to write now, with `"; N similar events held back"` appended when N > 0, or
    /// `None` to hold this one back.
    pub fn pass(
        &self,
        kind: SecurityEventKind,
        surface: &str,
        detail: &str,
        now: DateTime<Utc>,
    ) -> Option<String> {
        if self.interval <= Duration::zero() {
            return Some(detail.to_string());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (kind, surface.to_string());
        if !state.contains_key(&key) && state.len() >= MAX_GATE_PAIRS {
            state.clear();
        }
        let entry = state.entry(key).or_default();
        if entry
            .last_written
            .is_some_and(|at| now - at < self.interval)
        {
            entry.held_back = entry.held_back.saturating_add(1);
            return None;
        }
        let detail = if entry.held_back > 0 {
            format!("{detail}; {} similar events held back", entry.held_back)
        } else {
            detail.to_string()
        };
        entry.held_back = 0;
        entry.last_written = Some(now);
        Some(detail)
    }
}
