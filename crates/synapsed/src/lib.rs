// SPDX-License-Identifier: MIT OR Apache-2.0
//! `synapsed`: one daemon per user per machine, on loopback, serving the durable role mailbox
//! (M5a of the claude-peers replacement plan). Design:
//! `docs/superpowers/specs/2026-10-02-m5-synapsed-design.md`.
//!
//! **Security (PM conditions, 2026-10-02):**
//! - A session token is issued only by `/v1/claim`, and only after M3's claim verifies: an Ed25519
//!   signature by the role key over a domain-separated text with a fresh nonce, inside the
//!   freshness window, not replayed, on a certificate the account key signed.
//! - Every request's `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (421 otherwise). No
//!   CORS headers are ever sent. POST bodies must be `application/json` (415), which forces a
//!   browser preflight that this daemon never answers. Every route except `/v1/health` and
//!   `/v1/claim` needs `Authorization: Bearer <token>` (401).
//! - `/v1/health?challenge=<hex>` proves this daemon holds the instance id from the owner-only
//!   announce file (#74): clients send no claim or token to a listener that cannot prove it, so a
//!   process that squats a stale announced port learns nothing.
//! - Tokens are kept only as SHA-256 hashes and looked up by hash: the secret is never compared
//!   byte-wise, stored, or logged.
//! - A message's sender is always the session's verified role; a client-supplied `from` is refused.
//! - Brute-force hardening (P5): every failed bearer or claim, and every over-budget challenged
//!   health, unknown recipient or bad ack, is written as one JSON line to the owner-only
//!   `<home>/security-events.jsonl` (never a token, nonce or signature), and the failure is
//!   answered *later*, never differently. Only the failed answer is delayed, never the attempt, so
//!   a legitimate caller is not slowed by anyone else's failures; there is no lockout anywhere.

#[cfg(feature = "sqlite-store")]
mod migration;

pub mod settings;
mod state_api;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use synapse::certificate::{RevocationLookup, chain_from_pem};
use synapse::keystore::{Keystore, KeystoreError};
use synapse::mailbox::{
    Acked, Depth, DurabilityClass, Enqueued, Envelope, MailConfig, MailError, MailStore, MailTxn,
    Mailbox, RedbStore, StoreError,
};
use synapse::roles::{ClaimRequest, RolesState};
use synapse::security_events::{
    Alert, AlertConfig, AlertPolicy, FailureLimiter, LimiterConfig, SecurityEvent,
    SecurityEventKind, SecuritySink, Verdict,
};
use synapse_security::{AlertSink, AlertTransport, FanoutSink, FileSink};

pub mod launch;
pub use launch::LauncherConfig;

/// Where and how the daemon runs.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// The Synapse home (M2): holds the keystore and `mailbox.redb`.
    pub home: PathBuf,
    /// Must be a loopback address.
    pub addr: SocketAddr,
    /// How often acked history is swept (an M4 obligation).
    pub sweep_every: std::time::Duration,
}

/// Which store serves the mailbox. redb is the default; SQLite through PersistAnt exists only when
/// built with the `sqlite-store` feature (board 229: declared `Machine`, so `Mailbox::open` accepts it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreKind {
    #[default]
    Redb,
    #[cfg(feature = "sqlite-store")]
    Sqlite,
}

impl StoreKind {
    /// The file under the home that holds this store.
    #[must_use]
    pub fn file_name(self) -> &'static str {
        match self {
            StoreKind::Redb => "mailbox.redb",
            #[cfg(feature = "sqlite-store")]
            StoreKind::Sqlite => "mailbox.sqlite",
        }
    }
}

/// The daemon's mailbox store: one of [`StoreKind`], chosen once at open.
pub enum DaemonStore {
    Redb(RedbStore),
    #[cfg(feature = "sqlite-store")]
    Sqlite(synapse_mailbox_persistant::SqliteMailStore),
    /// A PersistAnt provider the operator picked by id (`mailbox-store.json`).
    #[cfg(feature = "sqlite-store")]
    Named(synapse_mailbox_persistant::needs::RegistryMailStore),
}

impl MailStore for DaemonStore {
    fn durability(&self) -> DurabilityClass {
        match self {
            DaemonStore::Redb(s) => s.durability(),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Sqlite(s) => s.durability(),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Named(s) => s.durability(),
        }
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        match self {
            DaemonStore::Redb(s) => s.write(f),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Sqlite(s) => s.write(f),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Named(s) => s.write(f),
        }
    }

    fn read(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        match self {
            DaemonStore::Redb(s) => s.read(f),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Sqlite(s) => s.read(f),
            #[cfg(feature = "sqlite-store")]
            DaemonStore::Named(s) => s.read(f),
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    /// The configured address is not loopback.
    NotLoopback,
    /// The system random source failed.
    NoRandomness,
    Keystore(KeystoreError),
    Store(StoreError),
    Mail(MailError),
    /// The security event file could not be opened safely.
    Security(String),
    /// The redb mailbox could not be moved to the SQLite store, or it is not known which holds the mail.
    Migration(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::NotLoopback => write!(f, "synapsed listens on loopback addresses only"),
            DaemonError::NoRandomness => write!(f, "the system random source failed"),
            DaemonError::Keystore(e @ KeystoreError::PermissionsTooOpen(_)) => {
                write!(f, "keystore: permissions_too_open: {e}")
            }
            DaemonError::Keystore(e) => write!(f, "keystore: {e}"),
            DaemonError::Store(e) => write!(f, "{e}"),
            DaemonError::Mail(e) => write!(f, "{e}"),
            DaemonError::Security(e) => write!(f, "security event file: {e}"),
            DaemonError::Migration(e) => write!(f, "mailbox migration: {e}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// The shared-state store under the home.
const STATE_FILE: &str = "state.redb";
/// How recently a role must have been heard from to count as online.
const ONLINE_WINDOW: chrono::Duration = chrono::Duration::seconds(90);
/// A role idle this many days is retired (hidden from `list`, kept) unless `synapsed.toml` says
/// otherwise: docs/ROLE_LIVENESS_DESIGN.md, the PM's ruling of 2026-10-24.
const DEFAULT_ROLE_TTL_DAYS: i64 = 30;
/// A session unused this many hours expires (PM ruling 2026-10-25, ROADMAP row 37b): every
/// authenticated call renews it, and an expired one answers 401 `session_expired`, after which the
/// client claims the role again. `[session] ttl_hours` in `synapsed.toml` changes it.
const DEFAULT_SESSION_TTL_HOURS: i64 = 24;
const MAX_FETCH: usize = 100;
/// The longest client-chosen message id; the stored id is `<sender>/<client id>` (review I1).
const MAX_CLIENT_ID: usize = 100;
const MAX_SUMMARY: usize = 500;
/// The most ids a fetch may exclude, and the longest one (a global id is at most 129 bytes and a
/// client id at most [`MAX_CLIENT_ID`]).
const MAX_EXCLUDE: usize = 100;
const MAX_EXCLUDE_ID: usize = 256;
/// How many superseded sessions per role still answer `superseded` instead of `unauthorized`.
const KEEP_SUPERSEDED: u64 = 8;

#[derive(Clone)]
struct Session {
    global_id: String,
    epoch: u64,
    /// The verified leaf certificate's grants at claim time.
    permissions: Vec<synapse::certificate::Permission>,
    /// When a call last used this session (the claim, until the first call): the sliding window the
    /// session ttl is measured from.
    last_used: DateTime<Utc>,
}

struct Presence {
    last_seen: DateTime<Utc>,
    summary: Option<String>,
    /// Self-reported by the session on heartbeat: untrusted, display and filtering only.
    cwd: Option<String>,
    repo: Option<String>,
}

struct Shared {
    /// Never held across an `.await`.
    mailbox: Mutex<Mailbox<DaemonStore>>,
    /// SHA-256(token) -> session.
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    /// Shared state between lanes (`state.redb`); interior-locked, so no `Mutex` here.
    state: synapse::state::StateEngine<synapse::state::RedbBackend>,
    /// Woken after a state write, so its notices go out at once rather than on the retry tick.
    state_nudge: tokio::sync::Notify,
    presence: Mutex<HashMap<String, Presence>>,
    /// Cumulative per-role counters for `/v1/stats`. In memory: a restart zeroes them, and the
    /// answer says so (`scope`, `since`).
    stats: Mutex<HashMap<String, RoleCounters>>,
    /// This daemon's account name: it serves `<role>@<account>` only.
    account: String,
    account_key_id: String,
    account_key: [u8; 32],
    /// Random per daemon start, hex. Claims must be signed for it (review I3); it is published only
    /// in the owner-only announce file, never over HTTP. Its raw bytes key the health proof (#74).
    instance_id: String,
    proof_key: ring::hmac::Key,
    home: PathBuf,
    started_at: DateTime<Utc>,
    sweep_every: std::time::Duration,
    security: Security,
    pause: Pause,
    /// Who may read launch signals, and their timing (feature off while `roles` is empty).
    launcher: LauncherConfig,
    /// Per-role launch state; in memory.
    launches: Mutex<launch::Table>,
    /// How recently a role must have been heard from to count as online.
    online_window: chrono::Duration,
    /// A role idle longer than this is retired by the sweep.
    role_ttl: chrono::Duration,
    /// A session unused longer than this is expired (401 `session_expired`).
    session_ttl: chrono::Duration,
}

/// How the daemon waits out an owed failure delay before answering. The default sleeps on the tokio
/// clock; tests inject one that records the delay instead, so they assert *which* answers were held
/// back without measuring wall time (a shared CI runner can be slow for reasons of its own).
/// A pause that returns at once disables the brute-force delay, so production never replaces it.
pub type Pause = Arc<
    dyn Fn(std::time::Duration) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync,
>;

fn sleep_pause() -> Pause {
    Arc::new(|delay| Box::pin(tokio::time::sleep(delay)))
}

/// The size at which the event file rotates to `<file>.1`.
const SECURITY_EVENTS_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// How the failure budgets and the event file are kept. No limiter ever locks (see [`Security::new`]).
struct Security {
    bearer: FailureLimiter,
    claim: FailureLimiter,
    health: FailureLimiter,
    misuse: FailureLimiter,
    sink: Arc<dyn SecuritySink>,
    event_interval: std::time::Duration,
    /// Per (kind, surface): when a line was last written, and how many were held back since.
    gate: Mutex<HashMap<(SecurityEventKind, &'static str), Gate>>,
}

#[derive(Default)]
struct Gate {
    last_written: Option<std::time::Instant>,
    held_back: u32,
}

impl Security {
    /// Every limiter's `lockout_after` is forced to `u32::MAX`: a global key that could lock would
    /// let any local user lock the owner out.
    fn new(config: SecurityConfig, sink: Arc<dyn SecuritySink>) -> Security {
        let limiter = |mut c: LimiterConfig| {
            c.lockout_after = u32::MAX;
            FailureLimiter::new(c)
        };
        Security {
            bearer: limiter(config.bearer),
            claim: limiter(config.claim),
            health: limiter(config.health),
            misuse: limiter(config.misuse),
            sink,
            event_interval: config.event_interval,
            gate: Mutex::new(HashMap::new()),
        }
    }

    /// Records a failure on `key` and returns how long its answer must wait, if at all. Never
    /// calls `record_success`: on a global key that would reset an attacker's count.
    fn fail(limiter: &FailureLimiter, key: &str) -> Option<std::time::Duration> {
        match limiter.record_failure(key, Utc::now()).0 {
            Verdict::Delay(d) => d.to_std().ok().filter(|d| !d.is_zero()),
            // `Refuse` needs a lockout, which no limiter here has.
            Verdict::Allow | Verdict::Refuse { .. } => None,
        }
    }

    /// Writes one event, unless one of the same (kind, surface) was written within
    /// `event_interval`: then it is counted, and the count rides on the next line written. The gate
    /// keys on the surface, not the subject, because a claimed subject is attacker-chosen.
    fn emit(&self, kind: SecurityEventKind, surface: &'static str, subject: &str, detail: &str) {
        let mut detail = detail.to_string();
        {
            let mut gate = self
                .gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = gate.entry((kind, surface)).or_default();
            let now = std::time::Instant::now();
            if !self.event_interval.is_zero()
                && entry
                    .last_written
                    .is_some_and(|at| now.duration_since(at) < self.event_interval)
            {
                entry.held_back = entry.held_back.saturating_add(1);
                return;
            }
            if entry.held_back > 0 {
                detail = format!("{detail}; {} similar events held back", entry.held_back);
            }
            entry.held_back = 0;
            entry.last_written = Some(now);
        }
        self.sink.record(&SecurityEvent::new(
            Utc::now(),
            kind,
            surface,
            subject,
            None,
            &detail,
        ));
    }

    /// Counts one failure against `limiter`'s `key`, and writes a `RateLimited` event only when the
    /// answer is now delayed (an occasional failure is ordinary).
    fn over_budget(
        &self,
        limiter: &FailureLimiter,
        key: &str,
        surface: &'static str,
        subject: &str,
        detail: &str,
    ) -> Option<std::time::Duration> {
        let delay = Security::fail(limiter, key);
        if delay.is_some() {
            self.emit(SecurityEventKind::RateLimited, surface, subject, detail);
        }
        delay
    }
}

/// The owner-only file in the home where a daemon announces its address and instance id. Only the
/// same user can read it, so only that user's clients learn which daemon is real (review I3).
pub const ANNOUNCE_FILE: &str = "synapsed.json";

/// The file in the home where the daemon records security events, one JSON line each.
pub const SECURITY_EVENTS_FILE: &str = "security-events.jsonl";

/// Tuning for the daemon's limiters and its event file. `Default` is what `synapsed` runs with.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Row 1, global key `bearer`.
    pub bearer: LimiterConfig,
    /// Row 2, keys: the claimed global id, and `claim` as a backstop.
    pub claim: LimiterConfig,
    /// Row 3, global key `health`; counts every challenged request.
    pub health: LimiterConfig,
    /// Rows 4 and 5, key: the session's global id.
    pub misuse: LimiterConfig,
    /// At most one event line per (kind, surface) per interval; later ones are counted and the
    /// count rides on the next line written. Zero writes every event.
    pub event_interval: std::time::Duration,
}

/// A non-locking limiter over a 5-minute window.
fn budget(free_failures: u32, base_ms: i64, max_ms: i64, max_keys: usize) -> LimiterConfig {
    LimiterConfig {
        free_failures,
        window: chrono::Duration::minutes(5),
        base_delay: chrono::Duration::milliseconds(base_ms),
        max_delay: chrono::Duration::milliseconds(max_ms),
        lockout_after: u32::MAX,
        lockout: chrono::Duration::zero(),
        max_keys,
    }
}

impl Default for SecurityConfig {
    /// Health's budget is generous because every CLI command proves the daemon first: 300
    /// challenges in 5 minutes are free, and only then do answers slow, by at most 2 s.
    fn default() -> Self {
        SecurityConfig {
            bearer: budget(10, 250, 10_000, 16),
            claim: budget(5, 500, 30_000, 10_000),
            health: budget(300, 10, 2_000, 4),
            misuse: budget(20, 250, 10_000, 10_000),
            event_interval: std::time::Duration::from_secs(1),
        }
    }
}

/// The sender of the daemon's own alert mail. `:` is not valid in a role name, so no role can claim it.
const ALERT_SENDER: &str = "daemon:alerts";

/// How many raised alerts may wait for the delivery task. A full queue is a failed send, recorded
/// as `AlertFailed` and never retried through the same transport.
const ALERT_QUEUE: usize = 256;

/// How often the delivery task asks the policy for digests that are due.
const ALERT_FLUSH_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// Hands an alert to the delivery task. It never touches the mailbox itself: the sink can be called
/// while the mailbox lock is held, and `send` must never block or lock.
struct QueueTransport(tokio::sync::mpsc::Sender<Alert>);

impl AlertTransport for QueueTransport {
    fn send(&self, alert: &Alert) -> Result<(), String> {
        self.0
            .try_send(alert.clone())
            .map_err(|_| "the alert queue is full or closed".to_string())
    }
}

/// Alert delivery by mail (ROADMAP row 9): off unless [`Daemon::with_alert_roles`] named a role.
struct AlertDelivery {
    sink: Arc<AlertSink<QueueTransport>>,
    rx: tokio::sync::mpsc::Receiver<Alert>,
    roles: Vec<String>,
    /// Where a failed delivery is recorded: the event file, not the alert sink.
    fallback: Arc<dyn SecuritySink>,
}

/// The mail body for an alert. Every field came from a [`SecurityEvent`], which sanitizes its text,
/// but a reader still treats the body as untrusted like any other.
fn alert_text(alert: &Alert) -> String {
    format!(
        "SECURITY ALERT ({:?}): {:?} on {}, {} event(s). First at {}: subject {}, detail {}",
        alert.reason,
        alert.kind,
        alert.surface,
        alert.count,
        alert.first.at.to_rfc3339(),
        alert.first.subject,
        alert.first.detail
    )
}

/// Queues `alert` for every alert role. A role that has not claimed yet gets it when it does (the
/// operator chose the recipients, so the unknown-recipient rule for senders does not apply). A
/// failure becomes an `AlertFailed` line in the event file.
fn queue_alert(shared: &Shared, roles: &[String], fallback: &Arc<dyn SecuritySink>, alert: &Alert) {
    let body = alert_text(alert).into_bytes();
    let now = Utc::now();
    for role in roles {
        let envelope = Envelope {
            message_id: format!("{ALERT_SENDER}/{}", uuid::Uuid::new_v4()),
            to: format!("{role}@{}", shared.account),
            from: format!("{ALERT_SENDER}@{}", shared.account),
            body: body.clone(),
        };
        let result = match shared.mailbox.lock() {
            Ok(mut mailbox) => mailbox.enqueue(envelope, now).map(|_| ()),
            Err(_) => Err(MailError::Store(StoreError(
                "mailbox lock poisoned".to_string(),
            ))),
        };
        if let Err(error) = result {
            fallback.record(&SecurityEvent::new(
                now,
                SecurityEventKind::AlertFailed,
                "synapsed/alert",
                role,
                None,
                &format!("alert mail not queued: {error}"),
            ));
        }
    }
}

/// The sender of shared-state change notices (see [`synapse::state::Notice`]). Like
/// [`ALERT_SENDER`], not a valid role name, so no role can claim it.
const STATE_SENDER: &str = "daemon:state";
/// Notices handed to the mailbox per pass.
const NOTICE_BATCH: usize = 100;
/// How often derived changes (a fact flipped, a record went stale) are looked for.
const DERIVED_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// How long an undelivered notice (a full queue, say) waits before the next pass.
const NOTICE_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// One pass over the undelivered notices: each becomes mail from `daemon:state@<account>` and is
/// then marked delivered. The message id is fixed per (record, revision, party), so a crash between
/// the two steps re-enqueues the same message, which the mailbox drops as a duplicate. A notice that
/// cannot be queued stays, and does not hold up the ones behind it. True if the pass was full and
/// clean, so another may be waiting.
fn deliver_state_notices_once(shared: &Shared) -> bool {
    use synapse::state::StateStore;
    let Ok(notices) = shared.state.pending_notices(NOTICE_BATCH) else {
        return false;
    };
    let mut clean = true;
    let full = notices.len() == NOTICE_BATCH;
    for notice in notices {
        let envelope = Envelope {
            message_id: notice.message_id(),
            to: format!("{}@{}", notice.to, shared.account),
            from: format!("{STATE_SENDER}@{}", shared.account),
            body: notice.body().into_bytes(),
        };
        let queued = match shared.mailbox.lock() {
            Ok(mut mailbox) => mailbox.enqueue(envelope, Utc::now()).is_ok(),
            Err(_) => false,
        };
        if queued && shared.state.notice_delivered(notice.seq).is_ok() {
            continue;
        }
        clean = false;
    }
    clean && full
}

async fn deliver_state_notices(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(NOTICE_RETRY);
    let mut refreshed = tokio::time::Instant::now();
    loop {
        // What is derived about a record (a fact flipped, it went stale) changes with time and
        // with the checker's reports; look for changes once a minute and after each report.
        if refreshed.elapsed() >= DERIVED_EVERY {
            use synapse::state::StateStore;
            let _ = shared.state.refresh_derived(Utc::now());
            refreshed = tokio::time::Instant::now();
        }
        if deliver_state_notices_once(&shared) {
            continue;
        }
        tokio::select! {
            () = shared.state_nudge.notified() => {}
            _ = tick.tick() => {}
        }
    }
}

async fn deliver_alerts(shared: Arc<Shared>, mut delivery: AlertDelivery) {
    let mut tick = tokio::time::interval(ALERT_FLUSH_EVERY);
    loop {
        tokio::select! {
            Some(alert) = delivery.rx.recv() => {
                queue_alert(&shared, &delivery.roles, &delivery.fallback, &alert);
            }
            _ = tick.tick() => delivery.sink.flush(Utc::now()),
        }
    }
}

/// An opened daemon, ready to serve.
pub struct Daemon {
    shared: Shared,
    alerts: Option<AlertDelivery>,
}

struct NoRevocations;
impl RevocationLookup for NoRevocations {
    fn is_revoked(&self, _issuer_key_id: &str, _serial: &[u8; 16]) -> bool {
        false
    }
}

impl Daemon {
    /// Open the keystore and the store under `cfg.home`. Refuses a non-loopback address, and a
    /// second daemon on the same home (redb's file lock).
    pub fn open(cfg: &DaemonConfig) -> Result<Daemon, DaemonError> {
        Self::open_with(cfg, StoreKind::default())
    }

    /// As [`Daemon::open`], serving the mailbox from `kind`.
    pub fn open_with(cfg: &DaemonConfig, kind: StoreKind) -> Result<Daemon, DaemonError> {
        Self::open_store(cfg, || {
            let path = cfg.home.join(kind.file_name());
            Ok(match kind {
                StoreKind::Redb => {
                    DaemonStore::Redb(RedbStore::open(&path).map_err(DaemonError::Store)?)
                }
                #[cfg(feature = "sqlite-store")]
                StoreKind::Sqlite => {
                    migration::prepare(&cfg.home)?;
                    DaemonStore::Sqlite(
                        synapse_mailbox_persistant::SqliteMailStore::open(&path)
                            .map_err(DaemonError::Store)?,
                    )
                }
            })
        })
    }

    /// As [`Daemon::open`], serving the mailbox from the PersistAnt provider the operator recorded
    /// (`synapsectl storage use`). PersistAnt checks the provider against the mailbox's needs again
    /// at open, with every call bounded; an id that no longer meets them stops the start.
    #[cfg(feature = "sqlite-store")]
    pub fn open_named(
        cfg: &DaemonConfig,
        choice: &synapse_mailbox_persistant::needs::StoreChoice,
    ) -> Result<Daemon, DaemonError> {
        Self::open_store(cfg, || {
            synapse_mailbox_persistant::needs::RegistryMailStore::open_choice(
                choice,
                &cfg.home,
                &synapse::mailbox::MailboxNeeds::MAILBOX,
                std::time::Duration::from_secs(30),
            )
            .map(DaemonStore::Named)
            .map_err(DaemonError::Store)
        })
    }

    fn open_store(
        cfg: &DaemonConfig,
        open: impl FnOnce() -> Result<DaemonStore, DaemonError>,
    ) -> Result<Daemon, DaemonError> {
        if !cfg.addr.ip().is_loopback() {
            return Err(DaemonError::NotLoopback);
        }
        let keystore = Keystore::open(&cfg.home).map_err(DaemonError::Keystore)?;
        let store = open()?;
        let sink = FileSink::open(
            cfg.home.join(SECURITY_EVENTS_FILE),
            SECURITY_EVENTS_MAX_BYTES,
        )
        .map_err(|e| DaemonError::Security(e.to_string()))?;
        let started_at = Utc::now();
        let mailbox =
            Mailbox::open(store, MailConfig::default(), started_at).map_err(DaemonError::Mail)?;
        let instance = random_bytes::<16>().ok_or(DaemonError::NoRandomness)?;
        let instance_id = hex(&instance);
        let summary = keystore.account();
        Ok(Daemon {
            alerts: None,
            shared: Shared {
                mailbox: Mutex::new(mailbox),
                state: synapse::state::StateEngine::new(
                    synapse::state::RedbBackend::open(&cfg.home.join(STATE_FILE))
                        .map_err(|e| DaemonError::Store(StoreError(e.to_string())))?,
                ),
                state_nudge: tokio::sync::Notify::new(),
                sessions: Mutex::new(HashMap::new()),
                presence: Mutex::new(HashMap::new()),
                stats: Mutex::new(HashMap::new()),
                account: summary.account,
                account_key_id: summary.key_id,
                account_key: keystore.account_public_key(),
                instance_id,
                proof_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &instance),
                home: cfg.home.clone(),
                started_at,
                sweep_every: cfg.sweep_every,
                security: Security::new(SecurityConfig::default(), Arc::new(sink)),
                pause: sleep_pause(),
                launcher: LauncherConfig::default(),
                launches: Mutex::new(launch::Table::new(started_at)),
                online_window: ONLINE_WINDOW,
                role_ttl: chrono::Duration::days(DEFAULT_ROLE_TTL_DAYS),
                session_ttl: chrono::Duration::hours(DEFAULT_SESSION_TTL_HOURS),
            },
        })
    }

    /// Replaces the default tuning. Call after `open`, before `serve`.
    #[must_use]
    pub fn with_security(mut self, config: SecurityConfig) -> Daemon {
        let sink = self.shared.security.sink.clone();
        self.shared.security = Security::new(config, sink);
        self
    }

    /// Delivers security alerts as mail to these roles on this account (ROADMAP row 9): what the alert
    /// policy raises (a threshold crossed, a digest due) is queued from `daemon:alerts@<account>`,
    /// and a role that has not claimed yet receives it when it does. An empty list changes nothing,
    /// which is the default. This is an internal transport only; which external channel carries
    /// alerts to a person is board 131's. Call after `open`, before `serve`.
    #[must_use]
    pub fn with_alert_roles(mut self, roles: Vec<String>) -> Daemon {
        if roles.is_empty() {
            return self;
        }
        let (tx, rx) = tokio::sync::mpsc::channel(ALERT_QUEUE);
        let fallback = self.shared.security.sink.clone();
        let sink = Arc::new(AlertSink::new(
            AlertPolicy::new(AlertConfig::default()),
            QueueTransport(tx),
            fallback.clone(),
        ));
        self.shared.security.sink = Arc::new(FanoutSink(vec![fallback.clone(), sink.clone()]));
        self.alerts = Some(AlertDelivery {
            sink,
            rx,
            roles,
            fallback,
        });
        self
    }

    /// Replaces how an owed failure delay is waited out (default: `tokio::time::sleep`). Call after
    /// `open`, before `serve`.
    #[must_use]
    pub fn with_pause(mut self, pause: Pause) -> Daemon {
        self.shared.pause = pause;
        self
    }

    /// Sets who may read launch signals (`GET /v1/waiting`) and the launch timing. The default has
    /// no launcher roles, which leaves the three launch routes answering 403. Call after `open`,
    /// before `serve`.
    #[must_use]
    pub fn with_launcher(mut self, launcher: LauncherConfig) -> Daemon {
        self.shared.launcher = launcher;
        self
    }

    /// Sets how long a session may go unused before it expires (default 24 hours). Tests use a short
    /// one; `with_session_ttl_hours` is the configured form. Call after `open`, before `serve`.
    #[must_use]
    pub fn with_session_ttl(mut self, ttl: chrono::Duration) -> Daemon {
        self.shared.session_ttl = ttl;
        self
    }

    /// [`Daemon::with_session_ttl`] in whole hours (at least 1). Call after `open`, before `serve`.
    #[must_use]
    pub fn with_session_ttl_hours(self, hours: u32) -> Daemon {
        self.with_session_ttl(chrono::Duration::hours(i64::from(hours.max(1))))
    }

    /// Sets how many days idle retires a role (default 30, at least 1). Call after `open`, before
    /// `serve`.
    #[must_use]
    pub fn with_role_ttl_days(mut self, days: u32) -> Daemon {
        self.shared.role_ttl = chrono::Duration::days(i64::from(days.max(1)));
        self
    }

    /// Replaces how recently a role must have been heard from to count as online (default 90 s).
    /// Tests shorten it; production keeps the default. Call after `open`, before `serve`.
    #[must_use]
    pub fn with_online_window(mut self, window: chrono::Duration) -> Daemon {
        self.shared.online_window = window;
        self
    }

    /// When the daemon opened its role table. Claims must be signed after this (M3), so clients
    /// read it from `/v1/health`.
    #[must_use]
    pub fn started_at(&self) -> DateTime<Utc> {
        self.shared.started_at
    }

    /// Serve on `listener` until `shutdown` resolves.
    pub async fn serve(
        self,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        let bound = listener.local_addr()?;
        if !bound.ip().is_loopback() {
            // Review M2: whatever the config said, never serve off loopback.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "synapsed serves on loopback addresses only",
            ));
        }
        let alerts = self.alerts;
        let shared = Arc::new(self.shared);
        let pause = shared.pause.clone();
        write_announce(&shared.home, bound, &shared.instance_id)?;
        // Removed however `serve` ends: shutdown, error or unwind (#74). A kill runs no code, which
        // is why clients rely on the health proof, not on the file's absence.
        let _announced = Announced {
            home: shared.home.clone(),
            instance_id: shared.instance_id.clone(),
        };
        let sweeper = {
            let shared = shared.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(shared.sweep_every);
                tick.tick().await; // the first tick is immediate
                loop {
                    tick.tick().await;
                    let now = Utc::now();
                    // Presence lives in memory; copy what the table needs out before taking the
                    // mailbox lock, so the two locks are never held together.
                    let seen: Vec<(String, DateTime<Utc>)> = shared
                        .presence
                        .lock()
                        .map(|p| p.iter().map(|(id, p)| (id.clone(), p.last_seen)).collect())
                        .unwrap_or_default();
                    if let Ok(mut mb) = shared.mailbox.lock() {
                        let _ = mb.sweep(now);
                        match mb.maintain_roles(&seen, now, shared.role_ttl) {
                            Ok(retired) => {
                                for role in retired {
                                    eprintln!(
                                        "synapsed: retired {role}: idle for more than {} days",
                                        shared.role_ttl.num_days()
                                    );
                                }
                            }
                            Err(e) => eprintln!("synapsed: role liveness not written: {e}"),
                        }
                    }
                }
            })
        };
        let alert_task =
            alerts.map(|delivery| tokio::spawn(deliver_alerts(shared.clone(), delivery)));
        let notice_task = tokio::spawn(deliver_state_notices(shared.clone()));
        let app = Router::new()
            .route(
                "/v1/health",
                get(move |state: State<Arc<Shared>>, uri: Uri| health(state, bound, uri)),
            )
            .route("/v1/claim", post(claim))
            .route("/v1/send", post(send))
            .route("/v1/fetch", post(fetch))
            .route("/v1/ack", post(ack))
            .route("/v1/dead", get(dead))
            .route("/v1/requeue", post(requeue))
            .route("/v1/heartbeat", post(heartbeat))
            .route("/v1/list", get(list))
            .route("/v1/stats", get(stats))
            .route("/v1/waiting", get(waiting))
            .route("/v1/launch-result", post(launch_result))
            .route("/v1/launch-clear", post(launch_clear))
            .route("/v1/roles/retire", post(role_retire))
            .route("/v1/roles/revive", post(role_revive))
            .route("/v1/state/create", post(state_api::create))
            .route("/v1/state/get", get(state_api::get))
            .route("/v1/state/list", get(state_api::list))
            .route("/v1/state/patch", post(state_api::patch))
            .route("/v1/state/history", get(state_api::history))
            .route("/v1/state/facts", post(state_api::facts))
            .route("/v1/state/wanted", get(state_api::wanted))
            // Inside `host_guard`, so a 421 is neither counted nor delayed.
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                delay_failures(pause.clone(), req, next)
            }))
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                host_guard(bound, req, next)
            }))
            .with_state(shared);
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await;
        sweeper.abort();
        notice_task.abort();
        if let Some(task) = alert_task {
            task.abort();
        }
        result
    }
}

/// DNS-rebinding and drive-by protection: exactly one `Host`, naming the address we are bound to
/// (or `localhost` on its port). Duplicate Host headers are refused outright (review M3).
async fn host_guard(bound: SocketAddr, req: Request, next: Next) -> Response {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = match (hosts.next(), hosts.next()) {
        (Some(only), None) => only.to_str().unwrap_or(""),
        _ => "",
    };
    let port = bound.port();
    let ours = host == bound.to_string() || host == format!("localhost:{port}");
    if !ours {
        return ApiError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "wrong_host",
            "unknown host",
        )
        .into_response();
    }
    next.run(req).await
}

/// A response extension: how long [`delay_failures`] holds the answer back before sending it.
#[derive(Clone, Copy)]
struct FailureDelay(std::time::Duration);

/// Holds a response that carries a [`FailureDelay`] back before it is sent. The request has already
/// been evaluated at full speed, so only the answer is late. This is the only `sleep` in the daemon.
async fn delay_failures(pause: Pause, req: Request, next: Next) -> Response {
    let response = next.run(req).await;
    if let Some(FailureDelay(delay)) = response.extensions().get::<FailureDelay>().copied() {
        pause(delay).await;
    }
    response
}

/// Marks `response` to be sent late, if a delay is owed.
fn delayed(mut response: Response, delay: Option<std::time::Duration>) -> Response {
    if let Some(delay) = delay {
        response.extensions_mut().insert(FailureDelay(delay));
    }
    response
}

struct ApiError {
    status: StatusCode,
    body: Value,
    delay: Option<std::time::Duration>,
}

impl ApiError {
    fn new(status: StatusCode, kind: &str, message: impl fmt::Display) -> Self {
        ApiError {
            status,
            body: json!({"error": kind, "message": message.to_string()}),
            delay: None,
        }
    }

    /// Answer this error `delay` late.
    fn after(mut self, delay: Option<std::time::Duration>) -> Self {
        self.delay = delay;
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let delay = self.delay;
        delayed((self.status, axum::Json(self.body)).into_response(), delay)
    }
}

impl From<MailError> for ApiError {
    fn from(e: MailError) -> Self {
        match &e {
            MailError::Superseded(s) => ApiError {
                status: StatusCode::CONFLICT,
                body: json!({"error": "superseded", "current": s.current, "message": e.to_string()}),
                delay: None,
            },
            MailError::MailboxFull => {
                ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "mailbox_full", e)
            }
            MailError::Malformed => ApiError::new(StatusCode::BAD_REQUEST, "malformed", e),
            MailError::LeaseOutOfRange => {
                ApiError::new(StatusCode::BAD_REQUEST, "lease_out_of_range", e)
            }
            MailError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "not_found", e),
            MailError::NotYourLease => ApiError::new(StatusCode::FORBIDDEN, "not_your_lease", e),
            MailError::Claim(c) => ApiError::new(StatusCode::FORBIDDEN, "claim_refused", c),
            MailError::InvalidState(_)
            | MailError::Store(_)
            | MailError::Poisoned
            | MailError::DurabilityTooWeak { .. } => {
                ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable", e)
            }
        }
    }
}

fn malformed(what: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, "malformed", what)
}

fn locked<T>(m: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, ApiError> {
    m.lock().map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "lock poisoned",
        )
    })
}

/// A JSON body: `application/json` only (415 otherwise), unknown fields refused (400).
fn parse<T: DeserializeOwned>(headers: &HeaderMap, body: &Bytes) -> Result<T, ApiError> {
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            "bodies must be application/json",
        ));
    }
    serde_json::from_slice(body).map_err(|e| malformed(&format!("invalid body: {e}")))
}

fn token_hash(token: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, token);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes<const N: usize>() -> Option<[u8; N]> {
    use ring::rand::SecureRandom;
    let mut out = [0u8; N];
    ring::rand::SystemRandom::new().fill(&mut out).ok()?;
    Some(out)
}

/// Write `<home>/synapsed.json` (address and instance id) atomically and owner-only: a temp file
/// created `0600` on Unix (on Windows it inherits the user-profile ACL of the home), then renamed.
fn write_announce(
    home: &std::path::Path,
    bound: SocketAddr,
    instance_id: &str,
) -> std::io::Result<()> {
    let body = json!({
        "addr": bound.to_string(),
        "instance_id": instance_id,
        "pid": std::process::id(),
    })
    .to_string();
    let temp = home.join(format!(".tmp-synapsed-{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&temp)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, home.join(ANNOUNCE_FILE))
}

/// The announce file's owner: removes it when dropped, but only while it still names this daemon
/// instance, so a newer daemon's announcement is never deleted.
struct Announced {
    home: PathBuf,
    instance_id: String,
}

impl Drop for Announced {
    fn drop(&mut self) {
        let path = self.home.join(ANNOUNCE_FILE);
        let ours = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .is_some_and(|v| v["instance_id"] == self.instance_id.as_str());
        if ours {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// What the health proof signs (#74): a domain tag, the address this daemon is bound to, and the
/// client's challenge. The address makes a relayed proof useless: a squatter on a stale port that
/// forwards the challenge to a live daemon elsewhere gets back a MAC over the wrong address.
/// `synapsectl` builds the same bytes; its tests run against this daemon, so the two must agree.
#[must_use]
pub fn health_proof_message(bound: SocketAddr, challenge: &[u8; 16]) -> Vec<u8> {
    let mut msg = format!("synapsed-health-v1\n{bound}\n").into_bytes();
    msg.extend_from_slice(challenge);
    msg
}

/// Strict lowercase-or-uppercase hex only: `u8::from_str_radix` alone would also accept `+a`,
/// giving tokens and nonces alternative encodings (review M8).
fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(N);
    for chunk in s.as_bytes().chunks(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?);
    }
    out.try_into().ok()
}

/// The caller's session: Bearer token, looked up by its hash, then checked against the role's
/// current epoch. Every authenticated call also counts as presence.
fn authed(shared: &Shared, headers: &HeaderMap) -> Result<Session, ApiError> {
    // Row 1: every 401 is counted and recorded before it is sent. A 409 `superseded` is not.
    let unauthorized = || {
        let delay = Security::fail(&shared.security.bearer, "bearer");
        shared.security.emit(
            SecurityEventKind::AuthFailure,
            "synapsed/bearer",
            "bearer",
            "unauthorized",
        );
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid session is required",
        )
        .after(delay)
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(unhex::<32>)
        .ok_or_else(unauthorized)?;
    let hash = token_hash(&token);
    let session = locked(&shared.sessions)?
        .get(&hash)
        .cloned()
        .ok_or_else(unauthorized)?;
    // Superseded outranks expired: a holder that lost the role must be told so (409), not invited
    // to claim it back. Only a current-epoch session can be merely expired.
    locked(&shared.mailbox)?.check(&session.global_id, session.epoch)?;
    let now = Utc::now();
    if now - session.last_used > shared.session_ttl {
        // Not counted as a bearer failure and not an event: an idle session is not an attack.
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "session_expired",
            "this session was idle longer than the session ttl: claim the role again",
        ));
    }
    if let Some(live) = locked(&shared.sessions)?.get_mut(&hash) {
        live.last_used = now;
    }
    let mut presence = locked(&shared.presence)?;
    let entry = presence
        .entry(session.global_id.clone())
        .or_insert(Presence {
            last_seen: now,
            summary: None,
            cwd: None,
            repo: None,
        });
    entry.last_seen = now;
    Ok(session)
}

/// Liveness, and with `?challenge=<32 hex>` proof that this daemon holds the announced instance id:
/// `proof` = HMAC-SHA256(instance id, [`health_proof_message`]). Any other query is malformed.
async fn health(
    State(shared): State<Arc<Shared>>,
    bound: SocketAddr,
    uri: Uri,
) -> Result<Response, ApiError> {
    // `ok` answers "is a synapsed here"; a non-ok reply reads as a squat to clients, which then start
    // another daemon. The mailbox's own state is a separate field (ROADMAP row 37c).
    let mut reply = json!({
        "ok": true,
        "mailbox": mailbox_state(&shared.mailbox),
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": shared.started_at.to_rfc3339(),
    });
    if let Some(query) = uri.query() {
        let challenge = query
            .strip_prefix("challenge=")
            .and_then(unhex::<16>)
            .ok_or_else(|| malformed("challenge"))?;
        let tag = ring::hmac::sign(&shared.proof_key, &health_proof_message(bound, &challenge));
        reply["proof"] = Value::String(hex(tag.as_ref()));
        // Row 3: a budget, not a failure count. Over it the proof is still sent (a non-ok reply
        // would read as a squat to the client), only later.
        let delay = shared.security.over_budget(
            &shared.security.health,
            "health",
            "synapsed/health",
            "health",
            "challenged health over budget",
        );
        return Ok(delayed(axum::Json(reply).into_response(), delay));
    }
    Ok(axum::Json(reply).into_response())
}

/// The mailbox as `/v1/health` reports it: `ok`; `poisoned` (a failed write left memory and store
/// disagreeing, every call refuses until a restart); `unavailable` (the lock itself is poisoned);
/// `busy` (a handler holds it right now). Never waits for the lock: a health check that hangs behind
/// a stuck store write would read as a dead daemon.
fn mailbox_state<S: MailStore>(mailbox: &Mutex<Mailbox<S>>) -> &'static str {
    match mailbox.try_lock() {
        Ok(mb) if mb.is_poisoned() => "poisoned",
        Ok(_) => "ok",
        Err(std::sync::TryLockError::WouldBlock) => "busy",
        Err(std::sync::TryLockError::Poisoned(_)) => "unavailable",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    #[serde(default)]
    audience: Option<String>,
    chain_pem: String,
    nonce_hex: String,
    signed_at: DateTime<Utc>,
    signature_b64: String,
}

/// Row 2: a failed claim (400 `malformed` or 403 `claim_refused`; a 415 never read a body) is
/// counted against the claimed global id and against `claim`, and answered after the larger delay.
async fn claim(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let mut claimed = None;
    match claim_inner(&shared, &headers, &body, &mut claimed) {
        Err(error) if is_failed_claim(&error) => {
            let by_id = claimed.as_deref().and_then(|id| {
                let key = format!("id:{}", id.chars().take(256).collect::<String>());
                Security::fail(&shared.security.claim, &key)
            });
            let backstop = Security::fail(&shared.security.claim, "claim");
            let kind = error.body["error"].as_str().unwrap_or("claim").to_string();
            shared.security.emit(
                SecurityEventKind::AuthFailure,
                "synapsed/claim",
                claimed.as_deref().unwrap_or("claim"),
                &kind,
            );
            Err(error.after(by_id.max(backstop)))
        }
        other => other,
    }
}

fn is_failed_claim(error: &ApiError) -> bool {
    matches!(
        (error.status, error.body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("malformed"))
            | (StatusCode::FORBIDDEN, Some("claim_refused"))
    )
}

/// The claim itself. `claimed` is set as soon as the chain parses, so a later failure can be
/// counted against the global id the caller claimed (attacker-supplied: `Security::emit` sanitizes it).
fn claim_inner(
    shared: &Shared,
    headers: &HeaderMap,
    body: &Bytes,
    claimed: &mut Option<String>,
) -> Result<Response, ApiError> {
    let body: ClaimBody = parse(headers, body)?;
    let chain = chain_from_pem(&body.chain_pem).map_err(|_| malformed("chain_pem"))?;
    *claimed = chain.first().map(|cert| cert.subject_global_id.clone());
    let req = ClaimRequest {
        chain,
        nonce: unhex::<16>(&body.nonce_hex).ok_or_else(|| malformed("nonce_hex"))?,
        signed_at: body.signed_at,
        signature: B64
            .decode(&body.signature_b64)
            .map_err(|_| malformed("signature_b64"))?,
        audience: body.audience,
    };
    // Review I3: the claim must be signed for THIS daemon instance. Checked before the claim is
    // verified, so a claim for another audience never consumes its nonce here.
    if req.audience.as_deref() != Some(shared.instance_id.as_str()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "claim_refused",
            "the claim is not addressed to this daemon",
        ));
    }
    let (key_id, key) = (shared.account_key_id.clone(), shared.account_key);
    let lookup = move |kid: &str| (kid == key_id).then_some(key);
    let grant = locked(&shared.mailbox)?.claim(&req, &lookup, &NoRevocations, Utc::now())?;

    let token = random_bytes::<32>().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            "no randomness",
        )
    })?;
    {
        let mut sessions = locked(&shared.sessions)?;
        // Superseded sessions are kept so their calls answer 409 `superseded` (telling the old
        // holder what happened) rather than 401, but only the most recent few per role.
        let floor = grant.epoch.saturating_sub(KEEP_SUPERSEDED);
        sessions.retain(|_, s| s.global_id != grant.global_id || s.epoch > floor);
        sessions.insert(
            token_hash(&token),
            Session {
                global_id: grant.global_id.clone(),
                epoch: grant.epoch,
                permissions: req
                    .chain
                    .first()
                    .map(|c| c.permissions.clone())
                    .unwrap_or_default(),
                last_used: Utc::now(),
            },
        );
    }
    Ok(axum::Json(json!({
        "global_id": grant.global_id,
        "epoch": grant.epoch,
        "session": hex(&token),
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SendBody {
    to: String,
    #[serde(default)]
    message_id: Option<String>,
    body_b64: String,
}

async fn send(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: SendBody = parse(&headers, &body)?;
    // Review I1: ids are scoped by the verified sender, so no role can take another's id first.
    // A client id stays useful for its own idempotent resends.
    let client_id = match body.message_id {
        Some(id) => {
            if id.is_empty()
                || id.len() > MAX_CLIENT_ID
                || id.contains('/')
                || id.chars().any(char::is_control)
            {
                return Err(malformed("message_id"));
            }
            id
        }
        None => uuid::Uuid::new_v4().to_string(),
    };
    let message_id = format!("{}/{client_id}", session.global_id);
    let envelope = Envelope {
        message_id: message_id.clone(),
        to: body.to,
        from: session.global_id.clone(),
        body: B64
            .decode(&body.body_b64)
            .map_err(|_| malformed("body_b64"))?,
    };
    let (to, outcome) = {
        let mut mailbox = locked(&shared.mailbox)?;
        // Review M5: re-check the sender's epoch under the same lock as the enqueue.
        mailbox.check(&session.global_id, session.epoch)?;
        // Review I2: serve this daemon's account and roles that have claimed at least once, so no
        // role can fill the disk with queues for recipients that can never read them.
        let roles = mailbox.roles_snapshot();
        let in_account = envelope
            .to
            .split_once('@')
            .is_some_and(|(_, account)| account == shared.account);
        let record = roles.roles.get(&envelope.to).filter(|_| in_account);
        // A retired role is known, not abused: refuse with its own error and no budget charge.
        // Mail already queued for it is kept (docs/ROLE_LIVENESS_DESIGN.md).
        if record.is_some_and(|r| r.retired_at.is_some()) {
            return Err(ApiError::new(
                StatusCode::GONE,
                "recipient_retired",
                format!(
                    "{} is retired: it comes back when it claims its role, or when a role-admin revives it",
                    shown_role(&envelope.to)
                ),
            ));
        }
        if record.is_none() {
            // Row 4: counted per sending role; recorded only once over budget.
            let delay = shared.security.over_budget(
                &shared.security.misuse,
                &session.global_id,
                "synapsed/recipient",
                &session.global_id,
                "unknown_recipient",
            );
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "unknown_recipient",
                format!(
                    "no such role on this daemon: {} (give role@account)",
                    shown_role(&envelope.to)
                ),
            )
            .after(delay));
        }
        let to = envelope.to.clone();
        let outcome = mailbox.enqueue(envelope, Utc::now())?;
        (to, outcome)
    };
    if outcome == Enqueued::Queued {
        count(&shared, &to, |c| c.sent += 1);
    }
    Ok(axum::Json(json!({
        "message_id": message_id,
        "outcome": match outcome { Enqueued::Queued => "queued", Enqueued::Duplicate => "duplicate" },
    }))
    .into_response())
}

/// A recipient as an error message shows it: at most a global id's length, control characters
/// escaped, so a refusal never echoes a megabyte or a terminal escape back.
fn shown_role(to: &str) -> String {
    to.chars()
        .take(129)
        .flat_map(char::escape_default)
        .collect()
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FetchBody {
    #[serde(default)]
    max: Option<usize>,
    #[serde(default)]
    lease_secs: Option<i64>,
    /// Message ids to pass over: not leased, not counted. At most [`MAX_EXCLUDE`], each at most
    /// [`MAX_EXCLUDE_ID`] bytes.
    #[serde(default)]
    exclude: Vec<String>,
}

async fn fetch(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: FetchBody = parse(&headers, &body)?;
    let max = body.max.unwrap_or(10).min(MAX_FETCH);
    // Review M1: `Duration::seconds` panics on huge values; an absurd lease is a 400.
    let lease = match body.lease_secs {
        None => None,
        Some(secs) => {
            Some(chrono::Duration::try_seconds(secs).ok_or_else(|| malformed("lease_secs"))?)
        }
    };
    if body.exclude.len() > MAX_EXCLUDE || body.exclude.iter().any(|id| id.len() > MAX_EXCLUDE_ID) {
        return Err(malformed("exclude"));
    }
    let deliveries = locked(&shared.mailbox)?.fetch_excluding(
        &session.global_id,
        session.epoch,
        max,
        lease,
        Utc::now(),
        &body.exclude,
    )?;
    // Counted after the fetch committed, never from the request: a refused fetch moves nothing.
    let redelivered = deliveries.iter().filter(|d| d.attempts > 1).count();
    let expired = deliveries.iter().filter(|d| d.prior_lease_lapsed).count();
    // The sender's current self-reported presence, untrusted display text (null when the sender
    // has no live session). One lock hold for the whole batch.
    let senders = locked(&shared.presence)?;
    let messages: Vec<Value> = deliveries
        .into_iter()
        .map(|d| {
            let seen = senders.get(&d.envelope.from);
            json!({
                "message_id": d.envelope.message_id,
                "from": d.envelope.from,
                "from_summary": seen.and_then(|p| p.summary.clone()),
                "from_cwd": seen.and_then(|p| p.cwd.clone()),
                "body_b64": B64.encode(&d.envelope.body),
                "enqueued_at": d.enqueued_at.to_rfc3339(),
                "lease_until": d.lease_until.to_rfc3339(),
                "attempts": d.attempts,
            })
        })
        .collect();
    drop(senders);
    if redelivered > 0 {
        count(&shared, &session.global_id, |c| {
            c.redelivered += redelivered as u64;
            c.expired += expired as u64;
        });
    }
    Ok(axum::Json(json!({ "messages": messages })).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckBody {
    message_id: String,
}

async fn ack(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: AckBody = parse(&headers, &body)?;
    let result = locked(&shared.mailbox)?.ack(
        &session.global_id,
        session.epoch,
        &body.message_id,
        Utc::now(),
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(e @ (MailError::NotFound | MailError::NotYourLease)) => {
            // Row 5: counted per role; recorded only once over budget.
            let delay = shared.security.over_budget(
                &shared.security.misuse,
                &session.global_id,
                "synapsed/ack",
                &session.global_id,
                if matches!(e, MailError::NotFound) {
                    "not_found"
                } else {
                    "not_your_lease"
                },
            );
            return Err(ApiError::from(e).after(delay));
        }
        Err(e) => return Err(e.into()),
    };
    if outcome == Acked::Removed {
        count(&shared, &session.global_id, |c| c.acked += 1);
    }
    Ok(axum::Json(json!({
        "outcome": match outcome { Acked::Removed => "removed", Acked::AlreadyAcked => "already_acked" },
    }))
    .into_response())
}

/// The caller's dead set (messages leased `max_deliveries` times and never acked), oldest first,
/// bodies included. Changes nothing.
async fn dead(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let stored = locked(&shared.mailbox)?.dead_letters(&session.global_id, session.epoch)?;
    let messages: Vec<Value> = stored
        .into_iter()
        .map(|s| {
            json!({
                "message_id": s.envelope.message_id,
                "from": s.envelope.from,
                "body_b64": B64.encode(&s.envelope.body),
                "enqueued_at": s.enqueued_at.to_rfc3339(),
                "attempts": s.attempts,
            })
        })
        .collect();
    Ok(axum::Json(json!({ "messages": messages })).into_response())
}

/// Put one of the caller's dead messages back in its queue with the delivery count reset. A full
/// queue refuses (`mailbox_full`) and the message stays dead.
async fn requeue(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: AckBody = parse(&headers, &body)?;
    locked(&shared.mailbox)?.requeue_dead(&session.global_id, session.epoch, &body.message_id)?;
    Ok(axum::Json(json!({ "outcome": "requeued" })).into_response())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct HeartbeatBody {
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    repo: Option<String>,
}

/// A self-reported presence text: bounded, no control characters.
fn presence_text_ok(text: &str) -> bool {
    text.len() <= MAX_SUMMARY && !text.chars().any(char::is_control)
}

/// The value of `key` in a query string, percent-decoded; the first occurrence wins.
fn query_param(uri: &Uri, key: &str) -> Option<String> {
    uri.query()?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match bytes[i] {
            b'%' if i + 2 < bytes.len()
                && hex(bytes[i + 1]).is_some()
                && hex(bytes[i + 2]).is_some() =>
            {
                out.push(
                    (hex(bytes[i + 1]).unwrap_or(0) * 16 + hex(bytes[i + 2]).unwrap_or(0)) as u8,
                );
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn heartbeat(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    let body: HeartbeatBody = parse(&headers, &body)?;
    for (name, value) in [
        ("summary", &body.summary),
        ("cwd", &body.cwd),
        ("repo", &body.repo),
    ] {
        if value.as_deref().is_some_and(|v| !presence_text_ok(v)) {
            return Err(malformed(name));
        }
    }
    if let Some(p) = locked(&shared.presence)?.get_mut(&session.global_id) {
        if body.summary.is_some() {
            p.summary = body.summary;
        }
        if body.cwd.is_some() {
            p.cwd = body.cwd;
        }
        if body.repo.is_some() {
            p.repo = body.repo;
        }
    }
    Ok(axum::Json(json!({})).into_response())
}

/// `GET /v1/list[?cwd=<exact>][&repo=<exact>]`: filters match the self-reported presence fields
/// exactly, so a role with no live presence never matches a filter.
async fn list(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    authed(&shared, &headers)?;
    let cwd = query_param(&uri, "cwd");
    let repo = query_param(&uri, "repo");
    let include_retired =
        query_param(&uri, "include_retired").is_some_and(|v| v == "true" || v == "1");
    let now = Utc::now();
    // One lock hold, so every depth is counted against the epoch listed beside it.
    let (roles, depths) = {
        let mailbox = locked(&shared.mailbox)?;
        (mailbox.roles_snapshot(), mailbox.depths(now).ok())
    };
    let presence = locked(&shared.presence)?;
    let launches = locked(&shared.launches)?;
    let mut out = list_entries(
        &roles,
        &presence,
        depths.as_ref(),
        &launches,
        shared.online_window,
        now,
        include_retired,
    );
    for (key, want) in [("cwd", &cwd), ("repo", &repo)] {
        if let Some(want) = want {
            out.retain(|entry| entry[key].as_str() == Some(want.as_str()));
        }
    }
    Ok(axum::Json(json!({ "roles": out })).into_response())
}

/// What one role has been through since the daemon started. Message counts only, never content.
#[derive(Clone, Copy, Default)]
struct RoleCounters {
    /// New messages queued for the role (a duplicate send is not one).
    sent: u64,
    /// Messages the role acked (an idempotent repeat is not one).
    acked: u64,
    /// Deliveries after a message's first: its lease ran out, or a takeover voided it.
    redelivered: u64,
    /// The subset of `redelivered` whose previous lease had run out; the rest are takeovers.
    expired: u64,
}

fn count(shared: &Shared, role: &str, bump: impl FnOnce(&mut RoleCounters)) {
    // A poisoned counter table loses a count, never the request it was riding on.
    if let Ok(mut stats) = shared.stats.lock() {
        bump(stats.entry(role.to_string()).or_default());
    }
}

/// `GET /v1/stats`: the soak's cumulative counters, per role. Per-process: `since` is when this
/// daemon started counting, and a restart begins again from zero.
async fn stats(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authed(&shared, &headers)?;
    let roles = locked(&shared.mailbox)?.roles_snapshot();
    let counters = locked(&shared.stats)?;
    let out: Vec<Value> = roles
        .roles
        .keys()
        .map(|global_id| {
            let c = counters.get(global_id).copied().unwrap_or_default();
            json!({
                "global_id": global_id,
                "sent": c.sent,
                "acked": c.acked,
                "redelivered": c.redelivered,
                "expired": c.expired,
            })
        })
        .collect();
    Ok(axum::Json(json!({
        "scope": "process",
        "since": shared.started_at.to_rfc3339(),
        "roles": out,
    }))
    .into_response())
}

/// The caller must be one of the configured launcher roles; with none configured, nobody is.
fn require_launcher(shared: &Shared, session: &Session) -> Result<(), ApiError> {
    let allowed = shared
        .launcher
        .roles
        .iter()
        .any(|role| format!("{role}@{}", shared.account) == session.global_id);
    if allowed {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this role may not use the launch routes",
        ))
    }
}

/// Roles with mail waiting and no live session, as of `now`: queued mail, offline, the oldest
/// pending message older than the grace, and the daemon up for at least the online window (before
/// that, every presence is empty and every role would look offline).
fn launch_candidates(
    shared: &Shared,
    now: DateTime<Utc>,
) -> Result<Vec<launch::Candidate>, ApiError> {
    if now - shared.started_at < shared.online_window {
        return Ok(Vec::new());
    }
    let (roles, depths) = {
        let mailbox = locked(&shared.mailbox)?;
        (mailbox.roles_snapshot(), mailbox.depths(now)?)
    };
    let presence = locked(&shared.presence)?;
    let mut out = Vec::new();
    for global_id in roles.roles.keys() {
        let Some(depth) = depths.get(global_id) else {
            continue;
        };
        let Some(oldest) = depth.oldest_enqueued_at else {
            continue;
        };
        let online = presence
            .get(global_id)
            .is_some_and(|p| now - p.last_seen <= shared.online_window);
        if depth.queued == 0 || online || now - oldest < shared.launcher.grace {
            continue;
        }
        out.push(launch::Candidate {
            global_id: global_id.clone(),
            queued: depth.queued,
            oldest_enqueued_at: oldest,
        });
    }
    Ok(out)
}

/// The longest `?wait=` a poll may hold the request.
const MAX_WAIT_SECS: u64 = 30;

/// `GET /v1/waiting[?wait=<secs>]`: the launcher's view of roles with mail and no live session.
/// Level-triggered: it is recomputed on every read. Changes no mail. Only configured launcher roles.
async fn waiting(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    require_launcher(&shared, &session)?;
    let wait = match uri.query() {
        None | Some("") => 0,
        Some(q) => q
            .strip_prefix("wait=")
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or_else(|| malformed("query"))?
            .min(MAX_WAIT_SECS),
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(wait);
    loop {
        let now = Utc::now();
        let candidates = launch_candidates(&shared, now)?;
        let signals = locked(&shared.launches)?.evaluate(&shared.launcher, &candidates, now);
        if !signals.is_empty() || tokio::time::Instant::now() >= deadline {
            return Ok(axum::Json(json!({ "roles": signals })).into_response());
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchResultBody {
    signal_id: String,
    epoch: String,
    attempt: u32,
    role: String,
    outcome: String,
    #[serde(default)]
    reason: Option<String>,
}

/// A short code, never free text: letters, digits and `-_.:`.
fn reason_ok(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// `POST /v1/launch-result`: the launcher's answer to one signal. An answer for a signal that is
/// not open (another id, epoch or attempt, or already answered) is 409 `stale_signal`.
async fn launch_result(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    require_launcher(&shared, &session)?;
    let body: LaunchResultBody = parse(&headers, &body)?;
    if !synapse::keystore::valid_name(&body.role) {
        return Err(malformed("role"));
    }
    let outcome = launch::Outcome::parse(&body.outcome).ok_or_else(|| malformed("outcome"))?;
    if body.reason.as_deref().is_some_and(|r| !reason_ok(r)) {
        return Err(malformed("reason"));
    }
    let global_id = format!("{}@{}", body.role, shared.account);
    let answer = launch::Answer {
        signal_id: body.signal_id,
        epoch: body.epoch,
        attempt: body.attempt,
        outcome,
        reason: body.reason,
    };
    locked(&shared.launches)?
        .result(&shared.launcher, &global_id, answer, Utc::now())
        .map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "stale_signal",
                "no open signal matches that id, epoch and attempt",
            )
        })?;
    Ok(axum::Json(json!({})).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchClearBody {
    role: String,
}

/// `POST /v1/launch-clear {role}`: forget a role's launch state (a `refused` or `unreachable`
/// verdict included) and start a new epoch.
async fn launch_clear(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    require_launcher(&shared, &session)?;
    let body: LaunchClearBody = parse(&headers, &body)?;
    if !synapse::keystore::valid_name(&body.role) {
        return Err(malformed("role"));
    }
    let global_id = format!("{}@{}", body.role, shared.account);
    let epoch = locked(&shared.launches)?.clear(&global_id);
    Ok(axum::Json(json!({ "epoch": epoch })).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleBody {
    role: String,
}

/// `POST /v1/roles/retire {role}`: retire a role now (hidden from `list`, kept). Needs
/// `role-admin`. Retiring a retired role succeeds; an unknown role is 404.
async fn role_retire(
    state: State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    set_role_retired(state.0, headers, body, true)
}

/// `POST /v1/roles/revive {role}`: bring a retired role back. Needs `role-admin`.
async fn role_revive(
    state: State<Arc<Shared>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    set_role_retired(state.0, headers, body, false)
}

fn set_role_retired(
    shared: Arc<Shared>,
    headers: HeaderMap,
    body: Bytes,
    retire: bool,
) -> Result<Response, ApiError> {
    let session = authed(&shared, &headers)?;
    if !session
        .permissions
        .contains(&synapse::certificate::Permission::RoleAdmin)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this role may not retire or revive roles",
        ));
    }
    let body: RoleBody = parse(&headers, &body)?;
    if !synapse::keystore::valid_name(&body.role) {
        return Err(malformed("role"));
    }
    let global_id = format!("{}@{}", body.role, shared.account);
    let found = locked(&shared.mailbox)?.set_role_retired(&global_id, retire, Utc::now())?;
    if !found {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such role",
        ));
    }
    // The role name only, as the request gave it: the account name stays out of the log (CodeQL
    // rust/cleartext-logging flags it as sensitive).
    eprintln!(
        "synapsed: role {} {} by a role-admin session",
        body.role,
        if retire { "retired" } else { "revived" },
    );
    Ok(axum::Json(json!({ "role": global_id, "retired": retire })).into_response())
}

/// `list`'s entries. When the depths could not be read (a poisoned mailbox or a failed store),
/// every `pending` is `null` and the rest is still served: presence lives in memory and is still
/// right, and a watcher that also reads `online` here must not lose it to one unreadable field
/// (S-1, PM amendment). Consumers treat `null` as unknown.
fn list_entries(
    roles: &RolesState,
    presence: &HashMap<String, Presence>,
    depths: Option<&BTreeMap<String, Depth>>,
    launches: &launch::Table,
    online_window: chrono::Duration,
    now: DateTime<Utc>,
    include_retired: bool,
) -> Vec<Value> {
    roles
        .roles
        .iter()
        .filter(|(_, record)| include_retired || record.retired_at.is_none())
        .map(|(global_id, record)| {
            let seen = presence.get(global_id);
            let pending = depths.map(|all| {
                let depth = all.get(global_id).copied().unwrap_or_default();
                json!({
                    "queued": depth.queued,
                    "leased": depth.leased,
                    "dead": depth.dead,
                    "oldest_enqueued_at": depth.oldest_enqueued_at.map(|at| at.to_rfc3339()),
                })
            });
            json!({
                "global_id": global_id,
                "epoch": record.epoch,
                "retired_at": record.retired_at.map(|at| at.to_rfc3339()),
                "online": seen.is_some_and(|p| now - p.last_seen <= online_window),
                "last_seen": seen.map(|p| p.last_seen.to_rfc3339()),
                "summary": seen.and_then(|p| p.summary.clone()),
                "cwd": seen.and_then(|p| p.cwd.clone()),
                "repo": seen.and_then(|p| p.repo.clone()),
                "pending": pending,
                "launch": launches.view(global_id),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use synapse::roles::RoleRecord;

    /// S-1: with depths, each entry carries them; without (the mailbox could not be read), every
    /// `pending` is `null` and presence is still served.
    #[test]
    fn list_entries_carry_pending_or_null() {
        let now = Utc::now();
        let mut roles = RolesState::default();
        for role in ["alpha@acct", "beta@acct"] {
            roles.roles.insert(
                role.to_string(),
                RoleRecord {
                    epoch: 4,
                    claimed_at: now,
                    last_seen: None,
                    retired_at: None,
                },
            );
        }
        let mut presence = HashMap::new();
        presence.insert(
            "alpha@acct".to_string(),
            Presence {
                last_seen: now,
                summary: Some("busy".into()),
                cwd: None,
                repo: None,
            },
        );
        let mut depths = BTreeMap::new();
        depths.insert(
            "alpha@acct".to_string(),
            Depth {
                queued: 2,
                leased: 1,
                dead: 3,
                oldest_enqueued_at: Some(now),
            },
        );

        let with = list_entries(
            &roles,
            &presence,
            Some(&depths),
            &launch::Table::new(now),
            ONLINE_WINDOW,
            now,
            false,
        );
        assert_eq!(with[0]["pending"]["queued"], 2);
        assert_eq!(with[0]["pending"]["leased"], 1);
        assert_eq!(with[0]["pending"]["dead"], 3);
        assert_eq!(with[0]["pending"]["oldest_enqueued_at"], now.to_rfc3339());
        assert_eq!(
            with[1]["pending"],
            json!({"queued": 0, "leased": 0, "dead": 0, "oldest_enqueued_at": null}),
            "a role with no mail"
        );

        let without = list_entries(
            &roles,
            &presence,
            None,
            &launch::Table::new(now),
            ONLINE_WINDOW,
            now,
            false,
        );
        for entry in &without {
            assert!(entry["pending"].is_null(), "{entry}");
            assert_eq!(entry["epoch"], 4);
        }
        assert_eq!(without[0]["online"], true, "presence survives");
        assert_eq!(without[0]["summary"], "busy");
    }

    /// L1: a retired role is left out of `list` unless asked for, and then carries `retired_at`.
    #[test]
    fn retired_roles_are_hidden_unless_asked() {
        let now = Utc::now();
        let mut roles = RolesState::default();
        for (role, retired_at) in [("alpha@acct", None), ("gone@acct", Some(now))] {
            roles.roles.insert(
                role.to_string(),
                RoleRecord {
                    epoch: 1,
                    claimed_at: now,
                    last_seen: None,
                    retired_at,
                },
            );
        }
        let entries = |include_retired| {
            list_entries(
                &roles,
                &HashMap::new(),
                None,
                &launch::Table::new(now),
                ONLINE_WINDOW,
                now,
                include_retired,
            )
        };
        let shown = entries(false);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0]["global_id"], "alpha@acct");
        assert!(shown[0]["retired_at"].is_null());
        let all = entries(true);
        assert_eq!(all.len(), 2);
        assert_eq!(all[1]["global_id"], "gone@acct");
        assert_eq!(all[1]["retired_at"], now.to_rfc3339());
    }

    /// P5: the defaults `synapsed` runs with are the plan's table, not `LimiterConfig::default()`
    /// (5 free, 1 s to 60 s), which would slow the 6th CLI command in 5 minutes.
    #[test]
    fn the_default_budgets_are_the_planned_ones() {
        let c = SecurityConfig::default();
        let row = |l: &LimiterConfig| {
            (
                l.free_failures,
                l.base_delay.num_milliseconds(),
                l.max_delay.num_milliseconds(),
                l.max_keys,
                l.lockout_after,
            )
        };
        assert_eq!(row(&c.bearer), (10, 250, 10_000, 16, u32::MAX));
        assert_eq!(row(&c.claim), (5, 500, 30_000, 10_000, u32::MAX));
        assert_eq!(row(&c.health), (300, 10, 2_000, 4, u32::MAX));
        assert_eq!(row(&c.misuse), (20, 250, 10_000, 10_000, u32::MAX));
        assert_eq!(c.event_interval, std::time::Duration::from_secs(1));
    }

    /// ROADMAP row 37c: `/v1/health` says what state the mailbox is in without ever failing the probe
    /// (a non-ok reply reads as a squat to clients). It never waits on the lock either.
    #[test]
    fn mailbox_state_reads_the_lock_without_waiting() {
        use synapse::mailbox::MemoryStore;
        let mailbox = Mutex::new(
            Mailbox::open_volatile(MemoryStore::new(), MailConfig::default(), Utc::now()).unwrap(),
        );
        assert_eq!(mailbox_state(&mailbox), "ok");
        {
            let _held = mailbox.lock().unwrap();
            assert_eq!(
                mailbox_state(&mailbox),
                "busy",
                "held by a handler: reported, not waited for"
            );
        }
        let poisoned = Arc::new(mailbox);
        let holder = Arc::clone(&poisoned);
        let _ = std::thread::spawn(move || {
            let _guard = holder.lock().unwrap();
            panic!("poison the mutex on purpose");
        })
        .join();
        assert_eq!(mailbox_state(&poisoned), "unavailable");
    }

    /// #77 D2: `locked` on a poisoned mutex is 503 `store_unavailable`; on a healthy one it yields
    /// the guard. A poisoned lock is unreachable over HTTP without a test hook, so it is poisoned
    /// directly here: a thread panics while holding the guard.
    #[test]
    fn locked_maps_a_poisoned_mutex_to_503_store_unavailable() {
        let healthy = Mutex::new(1u8);
        let Ok(guard) = locked(&healthy) else {
            panic!("a healthy mutex must lock");
        };
        assert_eq!(*guard, 1);
        drop(guard);

        let poisoned = Arc::new(Mutex::new(1u8));
        let holder = Arc::clone(&poisoned);
        let joined = std::thread::spawn(move || {
            let _guard = holder.lock().unwrap();
            panic!("poison the mutex on purpose");
        })
        .join();
        assert!(joined.is_err(), "precondition: the thread panicked");
        assert!(
            poisoned.is_poisoned(),
            "precondition: the mutex is poisoned"
        );

        let Err(error) = locked(&poisoned) else {
            panic!("a poisoned mutex must not lock");
        };
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.body["error"], "store_unavailable");
    }
}
