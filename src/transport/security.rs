// SPDX-License-Identifier: MIT OR Apache-2.0
//! Security events on the receive path (brute-force hardening P6, audit rows 8–11).
//!
//! A rejected sender is sent nothing back, so there is no answer to delay. The knock limiters
//! therefore budget the RECORD, never the message (PM ruling, option A): every message is still
//! verified, and the limiters decide only whether a knock is written as its own event or folded into
//! one `RateLimited` event when a key trips. Dropping before verifying was rejected because a source
//! address is spoofable, so a spoofer could silence a real peer.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};

use crate::replay::Bounded;
use crate::security_events::{
    EventGate, FailureLimiter, LimiterConfig, SecurityEvent, SecurityEventKind, SecuritySink,
    Verdict,
};

/// The longest attacker-supplied key id carried into an event's detail.
const MAX_KEY_ID_CHARS: usize = 64;

/// The longest claimed global id used in a budget key, as the knock record bounds it: one datagram
/// can carry ~64 KB, and every tracked key would otherwise hold that much.
const MAX_CLAIMED_ID_CHARS: usize = 256;

/// Budgets for the knock record. Keys use the source's IP, never its port: a port is free to change.
#[derive(Debug, Clone)]
pub struct KnockLimits {
    /// Keyed `<claimed global id>|<source ip>`.
    pub per_sender: LimiterConfig,
    /// Keyed `<source ip>`: the backstop against one source spraying claimed ids.
    pub per_source: LimiterConfig,
    /// At most one event line per (kind, surface) per interval; zero writes every event.
    pub event_interval: Duration,
}

impl Default for KnockLimits {
    fn default() -> Self {
        let limiter = |free_failures| LimiterConfig {
            free_failures,
            window: Duration::minutes(5),
            base_delay: Duration::seconds(1),
            max_delay: Duration::seconds(60),
            lockout_after: u32::MAX,
            lockout: Duration::zero(),
            max_keys: 10_000,
        };
        Self {
            per_sender: limiter(10),
            per_source: limiter(50),
            event_interval: Duration::seconds(1),
        }
    }
}

/// The receive path's event writer. With no sink it does nothing and keeps no state.
pub(crate) struct TransportEvents {
    sink: Option<Arc<dyn SecuritySink>>,
    per_sender: FailureLimiter,
    per_source: FailureLimiter,
    gate: EventGate,
    /// Sources that knocked within the per-source window, for the `new_source` marker.
    seen_sources: Mutex<Bounded<()>>,
}

fn over_budget(verdict: Verdict) -> bool {
    !matches!(verdict, Verdict::Allow)
}

/// The IP part of a `host:port` source, or the whole string when it is not a socket address.
pub(super) fn source_ip(source: &str) -> String {
    source
        .parse::<std::net::SocketAddr>()
        .map_or_else(|_| source.to_string(), |addr| addr.ip().to_string())
}

impl TransportEvents {
    /// Every limiter's `lockout_after` is forced to `u32::MAX`: nothing here ever refuses.
    pub(crate) fn new(mut limits: KnockLimits, sink: Option<Arc<dyn SecuritySink>>) -> Self {
        limits.per_sender.lockout_after = u32::MAX;
        limits.per_source.lockout_after = u32::MAX;
        let seen_sources = Bounded::new(limits.per_source.window, limits.per_source.max_keys);
        Self {
            sink,
            per_sender: FailureLimiter::new(limits.per_sender),
            per_source: FailureLimiter::new(limits.per_source),
            gate: EventGate::new(limits.event_interval),
            seen_sources: Mutex::new(seen_sources),
        }
    }

    /// The sink, for transports that record events of their own.
    pub(crate) fn sink(&self) -> Option<&Arc<dyn SecuritySink>> {
        self.sink.as_ref()
    }

    fn emit(
        &self,
        kind: SecurityEventKind,
        surface: &str,
        subject: &str,
        source: Option<&str>,
        detail: &str,
        now: DateTime<Utc>,
    ) {
        let Some(sink) = &self.sink else { return };
        if let Some(detail) = self.gate.pass(kind, surface, detail, now) {
            sink.record(&SecurityEvent::new(
                now, kind, surface, subject, source, &detail,
            ));
        }
    }

    /// Row 9 (and row 8's chain failures, which arrive as knocks): a message the gate rejected.
    pub(crate) fn knock(
        &self,
        claimed_global_id: &str,
        source: &str,
        reason: &str,
        proof_key_id: &str,
        now: DateTime<Utc>,
    ) {
        if self.sink.is_none() {
            return;
        }
        let claimed: String = claimed_global_id
            .chars()
            .take(MAX_CLAIMED_ID_CHARS)
            .collect();
        let claimed_global_id = claimed.as_str();
        let ip = source_ip(source);
        let new_source = self
            .seen_sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ip.clone(), (), now)
            .is_none();
        let sender_key = format!("{claimed_global_id}|{ip}");
        let sender_was = over_budget(self.per_sender.check(&sender_key, now));
        let source_was = over_budget(self.per_source.check(&ip, now));
        let sender_is = over_budget(self.per_sender.record_failure(&sender_key, now).0);
        let source_is = over_budget(self.per_source.record_failure(&ip, now).0);

        let surface = "transport/knock";
        let kind = SecurityEventKind::RateLimited;
        if source_is && !source_was {
            self.emit(
                kind,
                surface,
                &ip,
                Some(source),
                "per_source over budget",
                now,
            );
        } else if sender_is && !sender_was {
            let detail = format!("per_sender over budget; {reason}");
            self.emit(kind, surface, claimed_global_id, Some(source), &detail, now);
        } else if !sender_is && !source_is {
            let key_id: String = if proof_key_id.is_empty() {
                "unsigned".to_string()
            } else {
                proof_key_id.chars().take(MAX_KEY_ID_CHARS).collect()
            };
            let marker = if new_source { "new_source; " } else { "" };
            let detail = format!("{marker}{reason}; key_id {key_id}");
            let kind = SecurityEventKind::UnverifiedSender;
            self.emit(kind, surface, claimed_global_id, Some(source), &detail, now);
        }
    }

    /// Row 10: a verified sender's message was refused as a replay.
    pub(crate) fn replay(&self, key_id: &str, source: &str, now: DateTime<Utc>) {
        let kind = SecurityEventKind::ReplayRefused;
        self.emit(
            kind,
            "transport/replay",
            key_id,
            Some(source),
            "replayed",
            now,
        );
    }

    /// Row 11: a body that could not be opened.
    pub(crate) fn unopenable(
        &self,
        from_global_id: &str,
        source: &str,
        error: crate::sealing::OpenError,
        now: DateTime<Utc>,
    ) {
        let kind = SecurityEventKind::UnverifiedSender;
        let detail = error.to_string();
        self.emit(
            kind,
            "transport/sealing",
            from_global_id,
            Some(source),
            &detail,
            now,
        );
    }

    /// Row 8: a revocation refused as foreign or forged.
    pub(crate) fn revocation_refused(&self, issuer_key_id: &str, reason: &str, now: DateTime<Utc>) {
        let kind = SecurityEventKind::UnverifiedSender;
        self.emit(
            kind,
            "transport/revocation",
            issuer_key_id,
            None,
            reason,
            now,
        );
    }
}
