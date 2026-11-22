// SPDX-License-Identifier: MIT OR Apache-2.0
//! The client for `synapsed` (M5b; its own crate since M6a, so the CLI and the MCP adapters share
//! it): find the daemon through its owner-only announce
//! file, start it if nothing answers, and keep one session per role.
//!
//! Design: `docs/superpowers/specs/2026-10-02-m5-synapsed-design.md` (Q2, Q4) and the M5b plan.
//! Session tokens are cached owner-only in `<home>/sessions/<role>.json`, so commands after a claim
//! reuse it instead of re-claiming (which would supersede the role's other holder). An implicit
//! claim happens only when there is no cached session for the running daemon instance, under a
//! per-role lock so concurrent first commands claim once. A 409 `superseded` or a 401 is reported,
//! never answered by re-claiming: taking a role back is always an explicit `synapse claim`.
//!
//! **One holder per (home, role).** The cache is keyed by role, not by holder, so every `synapse`
//! command for a role in a home shares one session: a `synapse claim` re-points all of them, and
//! supersession is only ever reported to holders outside this home's cache. Per-holder sessions are
//! M5c.
//!
//! **The daemon proves itself before any credential is sent (#74).** The announce file is trusted
//! only if it, the session cache and its directory pass the keystore's owner-only check, and only
//! while its `pid` is a live process (on Windows, a live `synapsed`). Then the listener must answer a
//! fresh random health challenge with HMAC-SHA256 keyed by the announced instance id, which only
//! the owner-only file and the real daemon know. A [`Daemon`] exists only after that proof, and
//! every claim and Bearer token goes through one, so a process squatting a stale announced port
//! gets neither. A listener that fails the proof is reported on stderr and ignored.

pub mod events;
pub mod timeout;

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use synapse::certificate::chain_to_pem;
use synapse::keystore::{KeystoreError, check_owner_only, load_role};
use synapse::roles::sign_claim_for;
use synapse::security_events::SecurityEventKind;

use crate::timeout::Estimator;

/// The daemon's announce file in the home, written by `synapsed` (M5a).
const ANNOUNCE_FILE: &str = "synapsed.json";
/// Set (to anything but `0` or empty) when the daemon runs on the other side of a boundary this
/// process cannot see across (a WSL guest reaching a Windows daemon through a relay): its announced
/// pid is then another machine's, so only the pid check is skipped and the health proof decides.
const REMOTE_DAEMON_ENV: &str = "SYNAPSE_REMOTE_DAEMON";
/// Set (not empty, not `0`): `Daemon::connect` never starts a daemon, the lane's owner runs it.
/// It also never starts one from a role-only home (no account key), whatever the variable says.
const NO_AUTOSTART_ENV: &str = "SYNAPSE_NO_AUTOSTART";
/// Where to read the daemon's announce file when it is not in the caller's own home: a lane's
/// role-only home (from `synapse id provision`) holds its keys, never the daemon's `synapsed.json`.
const DAEMON_HOME_ENV: &str = "SYNAPSE_DAEMON_HOME";
/// How long a started daemon gets to announce itself and answer health.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// A starting daemon's stderr, in the home; truncated at each start.
const START_LOG: &str = "synapsed-start.err";
/// How much of it the CLI reads back.
const START_LOG_READ: u64 = 4096;
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `waiting` poll this client asks for: under `CALL_TIMEOUT`, and under the daemon's
/// own 30 s cap.
const MAX_WAITING_POLL_SECS: u64 = 25;
/// How long a command waits for another command's claim of the same role.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum MailError {
    Keystore(KeystoreError),
    /// `synapsed` could not be started or never answered.
    NoDaemon(String),
    /// The daemon could not be reached or answered something unreadable.
    Transport(String),
    /// The daemon refused the call.
    Api {
        kind: String,
        message: String,
        current: Option<u64>,
    },
    Io(std::io::Error),
    Usage(String),
}

impl fmt::Display for MailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MailError::Keystore(e) => write!(f, "{e}"),
            MailError::NoDaemon(why) => write!(f, "synapsed is not running: {why}"),
            MailError::Transport(why) => write!(f, "talking to synapsed: {why}"),
            MailError::Api {
                kind,
                current: Some(current),
                ..
            } if kind == "superseded" => write!(
                f,
                "superseded: another holder claimed this role (now epoch {current}); \
                 run `synapse claim` to take it back"
            ),
            MailError::Api { kind, .. } if kind == "unauthorized" => write!(
                f,
                "unauthorized: the daemon no longer knows this session (another holder may have \
                 claimed the role); run `synapse claim` to claim it"
            ),
            MailError::Api { kind, message, .. } => {
                write!(f, "{}: {}", printable(kind), printable(message))
            }
            MailError::Io(e) => write!(f, "{e}"),
            MailError::Usage(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for MailError {}

impl From<KeystoreError> for MailError {
    fn from(e: KeystoreError) -> Self {
        MailError::Keystore(e)
    }
}

impl From<std::io::Error> for MailError {
    fn from(e: std::io::Error) -> Self {
        MailError::Io(e)
    }
}

#[derive(Deserialize)]
struct Announce {
    addr: String,
    instance_id: String,
    pid: u32,
}

/// A session as cached on disk: valid only for the daemon instance that issued it.
#[derive(Serialize, Deserialize)]
struct Cached {
    instance_id: String,
    token: String,
    global_id: String,
    epoch: u64,
}

/// What a successful claim granted.
pub struct Claimed {
    pub global_id: String,
    pub epoch: u64,
}

/// What a launcher says about one launch signal (`POST /v1/launch-result`). These four wire
/// strings are the whole vocabulary: the daemon rejects any other `outcome` as `malformed`.
/// `launching` and `unreachable` are the daemon's own per-role launch *states* shown in
/// `/v1/list`; a launcher never sends them. A dry run launched nothing, so there is nothing to
/// answer: leave the signal open and it is re-signalled after `launch_wait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchOutcome {
    /// The lane was started; wait for it to claim.
    Started,
    /// The lane is already running (a heartbeat gap, not a launch need); wait for it to claim.
    AlreadyRunning,
    /// Policy said no; terminal for this signal until the oldest message changes or it is cleared.
    Refused,
    /// The launch failed; the daemon retries with backoff, then marks the role `unreachable`.
    Failed,
}

impl LaunchOutcome {
    /// Every outcome, for tests that must cover the whole vocabulary.
    pub const ALL: [LaunchOutcome; 4] = [
        LaunchOutcome::Started,
        LaunchOutcome::AlreadyRunning,
        LaunchOutcome::Refused,
        LaunchOutcome::Failed,
    ];

    /// The wire string the daemon parses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LaunchOutcome::Started => "started",
            LaunchOutcome::AlreadyRunning => "already-running",
            LaunchOutcome::Refused => "refused",
            LaunchOutcome::Failed => "failed",
        }
    }
}

/// A live connection to this home's daemon.
pub struct Daemon {
    http: reqwest::blocking::Client,
    home: PathBuf,
    addr: String,
    instance_id: String,
    started_at: DateTime<Utc>,
    /// How long the daemon has been taking to answer; sets how long the next probe and call wait
    /// (`docs/CLIENT_TIMEOUTS_DESIGN.md` R3).
    estimator: Mutex<Estimator>,
}

impl Daemon {
    fn http_client() -> Result<reqwest::blocking::Client, MailError> {
        reqwest::blocking::Client::builder()
            .no_proxy()
            // synapsed never redirects; following one would re-send a claim body where a squatter
            // points it (review, #74).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(CALL_TIMEOUT)
            .build()
            .map_err(|e| MailError::Transport(e.to_string()))
    }

    /// Find this home's daemon and never start one: for a long-lived caller (the MCP adapter)
    /// whose daemon is run by its owner, with the owner's environment (store, address), so a
    /// daemon it spawned itself would silently run with the wrong store.
    pub fn connect_existing(home: &Path) -> Result<Daemon, MailError> {
        let http = Self::http_client()?;
        let mut squat = Squat::default();
        let estimator = Mutex::new(seed_estimator(home));
        // A live pid that is slow to answer is waited for (R1), never read as "no daemon".
        match locate(&http, home, &mut squat, &estimator)? {
            Located::Found(found) => return Ok(Daemon::new(http, home, found, estimator)),
            Located::Slow(announce, waited) => {
                return Err(MailError::NoDaemon(slow_daemon(&announce, home, waited)));
            }
            Located::Nothing => {}
        }
        Err(MailError::NoDaemon(match &squat.0 {
            Some(addr) => format!(
                "{} (announce file {})",
                squat_warning(addr),
                announce_path(home).display()
            ),
            None => no_daemon_answered(home),
        }))
    }

    /// Whether the daemon this connection proved is gone: nothing answers at the announced
    /// address, or a different instance does. A listener that fails the proof is not "gone" (it
    /// may be a squatter or a slow daemon), so this stays false and sends nothing to it.
    pub fn instance_gone(&self) -> bool {
        let allowance = self.allowance();
        match answering(&self.http, &self.home, allowance) {
            Ok(Answer::Nothing) => true,
            Ok(Answer::Proven(announce, _)) => announce.instance_id != self.instance_id,
            // Slow is a live pid that did not answer in time: a loaded daemon, not a gone one (R1).
            Ok(Answer::Slow(_) | Answer::Unproven(_)) | Err(_) => false,
        }
    }

    /// Find this home's daemon, starting it if nothing answers.
    pub fn connect(home: &Path) -> Result<Daemon, MailError> {
        // A remote daemon is run by its owner, on the other side: starting one here would be a
        // second daemon with its own store. `SYNAPSE_NO_AUTOSTART` asks for the same on a local
        // one: the owner runs it (with its store and address), and a CLI that started its own
        // would run with the wrong environment.
        // A role-only home (a lane's, from `id provision`) can never run a daemon: it has no account
        // key, so one started from it would fail, or, with the lane's environment, be a second
        // daemon beside the owner's. The owner's is the only one lanes use.
        if remote_daemon()
            || no_autostart()
            || daemon_home().is_some()
            || synapse::keystore::Keystore::is_role_only_home(home)
        {
            return Self::connect_existing(home);
        }
        let http = Self::http_client()?;
        let mut squat = Squat::default();
        let estimator = Mutex::new(seed_estimator(home));
        // A slow answer from a live daemon is waited for, up to the ceiling, and never starts a second
        // one (R1, R2): the announce file names a live pid, so something holds the store.
        match locate(&http, home, &mut squat, &estimator)? {
            Located::Found(found) => return Ok(Daemon::new(http, home, found, estimator)),
            Located::Slow(announce, waited) => {
                return Err(MailError::NoDaemon(slow_daemon(&announce, home, waited)));
            }
            Located::Nothing => {}
        }
        // Something live holds the announced port but failed the proof. A daemon of ours that
        // would bind that very address exits "address in use" and leaves a stray store, so say so
        // instead of starting one; on any other address it can start and take over.
        if let Some(addr) = &squat.0
            && daemon_would_bind(std::env::var("SYNAPSE_ADDR").ok().as_deref(), addr)
        {
            return Err(MailError::NoDaemon(squat_warning(addr)));
        }
        // Started at most once per command (PM, #74).
        let (mut child, mut start_log) = spawn_daemon(home)?;
        eprintln!("synapse: started synapsed (pid {})", child.id());
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            // Whichever daemon answers will do: ours, or, if two CLIs raced, the one holding the
            // store (ours then exits on its lock), or a live one that was only slow to answer.
            let allowance = lock_estimator(&estimator).allowance();
            if let Some(found) = squat.check(home, answering(&http, home, allowance)?) {
                return Ok(Daemon::new(http, home, found, estimator));
            }
            // A squatter that failed the proof still holds its port, so a daemon of ours that has
            // exited is not coming back: say why now rather than wait out the deadline.
            if let (Some(addr), Ok(Some(status))) = (&squat.0, child.try_wait()) {
                return Err(MailError::NoDaemon(format!(
                    "synapsed exited ({status}){}; {}",
                    start_failure(&mut start_log, home),
                    squat_warning(addr)
                )));
            }
            if Instant::now() >= deadline {
                let why = match child.try_wait() {
                    Ok(Some(status)) => {
                        format!(
                            "synapsed exited ({status}){} and no daemon answered",
                            start_failure(&mut start_log, home)
                        )
                    }
                    _ => "synapsed did not answer within 5 s".to_string(),
                };
                return Err(MailError::NoDaemon(why));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn new(
        http: reqwest::blocking::Client,
        home: &Path,
        (announce, started_at): (Announce, DateTime<Utc>),
        estimator: Mutex<Estimator>,
    ) -> Daemon {
        Daemon {
            http,
            home: home.to_path_buf(),
            addr: announce.addr,
            instance_id: announce.instance_id,
            started_at,
            estimator,
        }
    }

    /// How long the next probe waits, from the running average of how long the daemon has taken.
    fn allowance(&self) -> Duration {
        lock_estimator(&self.estimator).allowance()
    }

    /// The instance id of the daemon this connection proved (not a secret: it is in the announce
    /// file, and a squatter cannot answer the health proof without it).
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// The session `role` holds with this daemon: the cached one, else an implicit claim (as
    /// [`Daemon::call`] does). Never returns the token.
    pub fn session_info(&self, role: &str) -> Result<Claimed, MailError> {
        let session = self.session(role)?;
        Ok(Claimed {
            global_id: session.global_id,
            epoch: session.epoch,
        })
    }

    /// Claim `role` afresh (a takeover if someone holds it) and cache the session.
    pub fn claim(&self, role: &str) -> Result<Claimed, MailError> {
        let _lock = RoleLock::acquire(&self.home, role)?;
        let cached = self.claim_session(role)?;
        Ok(Claimed {
            global_id: cached.global_id,
            epoch: cached.epoch,
        })
    }

    fn claim_session(&self, role: &str) -> Result<Cached, MailError> {
        let identity = load_role(&self.home, role, Utc::now())?;
        let nonce = random_bytes::<16>()?;
        // M3 refuses claims signed at or before the daemon's start.
        let signed_at = Utc::now().max(self.started_at + chrono::Duration::seconds(1));
        let req = sign_claim_for(&identity, &self.instance_id, nonce, signed_at)
            .map_err(|e| MailError::Usage(format!("cannot sign the claim: {e}")))?;
        let body = json!({
            "audience": req.audience,
            "chain_pem": chain_to_pem(&req.chain),
            "nonce_hex": hex(&req.nonce),
            "signed_at": req.signed_at.to_rfc3339(),
            "signature_b64": B64.encode(&req.signature),
        });
        let reply = self.request("/v1/claim", None, Some(&body))?;
        let field = |name: &str| MailError::Transport(format!("the claim reply has no `{name}`"));
        let cached = Cached {
            instance_id: self.instance_id.clone(),
            token: reply["session"]
                .as_str()
                .ok_or_else(|| field("session"))?
                .to_string(),
            global_id: reply["global_id"]
                .as_str()
                .ok_or_else(|| field("global_id"))?
                .to_string(),
            epoch: reply["epoch"].as_u64().ok_or_else(|| field("epoch"))?,
        };
        save_session(&self.home, role, &cached)?;
        Ok(cached)
    }

    /// An authenticated call as `role`: the cached session if it belongs to this daemon instance,
    /// else a fresh claim. Any refusal, 401 and 409 included, is returned as an error: a 401 for
    /// this instance's session means the daemon dropped it, which happens after enough takeovers,
    /// so re-claiming then would silently steal the role back (review I1).
    ///
    /// One exception, and only one: a 401 `session_expired` (the daemon's session ttl ran out while
    /// the session sat unused). Nobody took the role; the daemon answers a taken one with 409
    /// `superseded` before it ever considers the age. So the client claims again, under the role lock,
    /// and retries the call once.
    pub fn call(&self, role: &str, path: &str, body: Option<&Value>) -> Result<Value, MailError> {
        let session = self.session(role)?;
        match self.request_retrying(path, Some(&session.token), body) {
            Err(MailError::Api { kind, .. }) if kind == "session_expired" => {
                let fresh = self.reclaim_expired(role, &session.token)?;
                self.request_retrying(path, Some(&fresh.token), body)
            }
            other => other,
        }
    }

    /// Claim again after `expired_token` aged out, unless another process of ours already did (the
    /// cached token then differs from the expired one).
    fn reclaim_expired(&self, role: &str, expired_token: &str) -> Result<Cached, MailError> {
        let _lock = RoleLock::acquire(&self.home, role)?;
        match load_session(&self.home, role)?
            .filter(|c| c.instance_id == self.instance_id && c.token != expired_token)
        {
            Some(already) => Ok(already),
            None => self.claim_session(role),
        }
    }

    /// `GET /v1/waiting`: the launch signals for roles with mail and no live session, as the
    /// daemon's reply (`{"roles": [...]}`). Only a configured launcher role may call it (403
    /// `forbidden` otherwise). `wait_secs` holds the request that long for a signal; it is capped
    /// below the call timeout, so a poll never fails as a transport error.
    pub fn waiting(&self, role: &str, wait_secs: u64) -> Result<Value, MailError> {
        let wait = wait_secs.min(MAX_WAITING_POLL_SECS);
        let path = if wait == 0 {
            "/v1/waiting".to_string()
        } else {
            format!("/v1/waiting?wait={wait}")
        };
        self.call(role, &path, None)
    }

    /// `POST /v1/launch-result`: answer one signal with a [`LaunchOutcome`]; `reason` is a short
    /// code. A signal that is no longer open is the API error `stale_signal`.
    #[allow(clippy::too_many_arguments)]
    pub fn launch_result(
        &self,
        role: &str,
        signal_id: &str,
        epoch: &str,
        attempt: u32,
        target_role: &str,
        outcome: LaunchOutcome,
        reason: Option<&str>,
    ) -> Result<Value, MailError> {
        let mut body = serde_json::json!({
            "signal_id": signal_id,
            "epoch": epoch,
            "attempt": attempt,
            "role": target_role,
            "outcome": outcome.as_str(),
        });
        if let Some(reason) = reason {
            body["reason"] = Value::String(reason.to_string());
        }
        self.call(role, "/v1/launch-result", Some(&body))
    }

    /// `POST /v1/launch-clear`: forget `target_role`'s launch state (a `refused` or `unreachable`
    /// verdict included) and start a new epoch. Returns `{"epoch": ...}`.
    pub fn launch_clear(&self, role: &str, target_role: &str) -> Result<Value, MailError> {
        self.call(
            role,
            "/v1/launch-clear",
            Some(&serde_json::json!({ "role": target_role })),
        )
    }

    /// `POST /v1/state/create`, signed with `role`'s own key (shared-state slice S7): the daemon
    /// checks the signature against the key its claim proved and keeps it in the history entry.
    /// `new` is the record as the route takes it; it is parsed here exactly as the daemon parses it,
    /// so both sides hash the same canonical body.
    pub fn state_create_signed(&self, role: &str, new: &Value) -> Result<Value, MailError> {
        let typed: synapse::state::NewRecord = serde_json::from_value(new.clone())
            .map_err(|e| MailError::Usage(format!("not a record: {e}")))?;
        let sig =
            self.sign_state_write(role, "create", "-", 0, &synapse::state::body_hash(&typed))?;
        let mut body = new.clone();
        body["sig"] = sig;
        self.call(role, "/v1/state/create", Some(&body))
    }

    /// `POST /v1/state/patch`, signed like [`Daemon::state_create_signed`].
    pub fn state_patch_signed(
        &self,
        role: &str,
        id: &str,
        expected_revision: u64,
        patch: &Value,
    ) -> Result<Value, MailError> {
        let typed: synapse::state::Patch = serde_json::from_value(patch.clone())
            .map_err(|e| MailError::Usage(format!("not a patch: {e}")))?;
        let sig = self.sign_state_write(
            role,
            "patch",
            id,
            expected_revision,
            &synapse::state::body_hash(&typed),
        )?;
        let body = json!({
            "id": id,
            "expected_revision": expected_revision,
            "patch": patch,
            "sig": sig,
        });
        self.call(role, "/v1/state/patch", Some(&body))
    }

    /// The `sig` object of a state write: the role key's signature over the text the daemon will rebuild.
    fn sign_state_write(
        &self,
        role: &str,
        op: &str,
        target: &str,
        expected_revision: u64,
        body_hash: &str,
    ) -> Result<Value, MailError> {
        let identity = load_role(&self.home, role, Utc::now())?;
        let nonce = hex(&random_bytes::<16>()?);
        // The daemon refuses a signature dated before its own start, as it does a claim.
        let signed_at = Utc::now().max(self.started_at + chrono::Duration::seconds(1));
        let text = synapse::state::signing_text(&synapse::state::SignedWrite {
            signer: &identity.global_id,
            audience: &self.instance_id,
            op,
            target,
            expected_revision,
            body_hash,
            nonce: &nonce,
            signed_at,
        });
        let signature = identity
            .crypto
            .sign_message(&text)
            .map_err(|e| MailError::Usage(format!("cannot sign the write: {e}")))?;
        Ok(json!({
            "nonce": nonce,
            "signed_at": signed_at.to_rfc3339(),
            "signature": hex(&signature),
        }))
    }

    /// The cached session for this daemon instance, else a claim. Under the role lock, so two
    /// first commands for one role claim once rather than superseding each other (review I4).
    fn session(&self, role: &str) -> Result<Cached, MailError> {
        let current = |c: &Cached| c.instance_id == self.instance_id;
        if let Some(c) = load_session(&self.home, role)?.filter(current) {
            return Ok(c);
        }
        let _lock = RoleLock::acquire(&self.home, role)?;
        match load_session(&self.home, role)?.filter(current) {
            Some(c) => Ok(c),
            None => self.claim_session(role),
        }
    }

    /// One authenticated or open request, no retry (a claim is signed with a nonce: a repeat is refused).
    fn request(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, MailError> {
        self.attempt(path, token, body, 1, 1).map_err(|(e, _)| e)
    }

    /// `request`, repeated on a transport failure when the call is safe to repeat (R5): a send carries
    /// its own message id, so a repeat is `duplicate`; ack and nack answer `already_*`; a lost fetch
    /// reply leaves leases that expire by themselves. Claims, state writes, launch and admin routes
    /// are tried once. Bounded by the ceiling.
    fn request_retrying(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, MailError> {
        if !repeatable(path) {
            return self.request(path, token, body);
        }
        let started = Instant::now();
        let max = u32::try_from(RETRY_GAPS_MS.len()).unwrap_or(0) + 1;
        let mut tried = 1;
        loop {
            match self.attempt(path, token, body, tried, max) {
                Ok(v) => return Ok(v),
                Err((_, true)) if tried < max && started.elapsed() < crate::timeout::CEILING => {
                    let gap = RETRY_GAPS_MS[usize::try_from(tried - 1).unwrap_or(0)];
                    // Up to 25% jitter, so callers that failed together do not retry together.
                    let jitter = random_bytes::<1>().map_or(0, |b| u64::from(b[0]) * gap / 1024);
                    std::thread::sleep(Duration::from_millis(gap + jitter));
                    tried += 1;
                }
                Err((e, _)) => return Err(e),
            }
        }
    }

    /// One try. The second field says whether a failure to *send* (connect, reset, timeout) happened, which
    /// is the only failure a retry may follow.
    fn attempt(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
        tried: u32,
        max: u32,
    ) -> Result<Value, (MailError, bool)> {
        let url = format!("http://{}{path}", self.addr);
        let mut req = match body {
            Some(b) => self.http.post(url).json(b),
            None => self.http.get(url),
        };
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        // Never shorter than the old fixed limit (a long poll waits by design), longer when the daemon has
        // been slow, never past the ceiling.
        let allowance = CALL_TIMEOUT
            .max(self.allowance())
            .min(crate::timeout::CEILING);
        let started = Instant::now();
        let resp = match req.timeout(allowance).send() {
            Ok(resp) => resp,
            Err(e) => {
                let kind = transport_kind(&e);
                if kind == "timeout" {
                    lock_estimator(&self.estimator).timed_out();
                }
                let text = failure_text(
                    &e.without_url().to_string(),
                    "call",
                    kind,
                    allowance,
                    started.elapsed(),
                    tried,
                    max,
                );
                eprintln!("synapse: {path}: {text}");
                return Err((MailError::Transport(text), true));
            }
        };
        // A long poll takes as long as it was asked to and says nothing about load.
        if !path.contains("wait") {
            lock_estimator(&self.estimator).sample(started.elapsed());
        }
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| (MailError::Transport(e.without_url().to_string()), false))?;
        let value: Value = serde_json::from_str(&text).map_err(|_| {
            (
                MailError::Transport(format!("HTTP {status}, and the reply is not JSON")),
                false,
            )
        })?;
        let ok = status.is_success();
        if ok {
            return Ok(value);
        }
        Err((
            MailError::Api {
                kind: value["error"].as_str().unwrap_or("error").to_string(),
                message: value["message"].as_str().unwrap_or("").to_string(),
                current: value["current"].as_u64(),
            },
            false,
        ))
    }
}

/// Waits between the tries of a repeatable call, in milliseconds (R5).
const RETRY_GAPS_MS: [u64; 3] = [500, 1000, 2000];

/// Whether a call may be sent again after a transport failure (R5).
fn repeatable(path: &str) -> bool {
    let route = path.split('?').next().unwrap_or(path);
    matches!(
        route,
        "/v1/send" | "/v1/ack" | "/v1/nack" | "/v1/heartbeat" | "/v1/fetch"
    )
}

fn lock_estimator(estimator: &Mutex<Estimator>) -> std::sync::MutexGuard<'_, Estimator> {
    estimator
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What kind of failure a send was (R6).
fn transport_kind(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else {
        "other"
    }
}

/// A transport failure that says which timeout fired (R6).
fn failure_text(
    base: &str,
    phase: &str,
    kind: &str,
    timeout: Duration,
    elapsed: Duration,
    tried: u32,
    max: u32,
) -> String {
    format!(
        "{base} (phase={phase} kind={kind} timeout_ms={} elapsed_ms={} attempt={tried}/{max})",
        timeout.as_millis(),
        elapsed.as_millis()
    )
}

/// The latency file the daemon writes (R4), read as a starting estimate for a short-lived caller. Absent,
/// stale (over a minute) or unreadable: nothing seen yet.
fn seed_estimator(home: &Path) -> Estimator {
    #[derive(Deserialize)]
    struct Seen {
        smoothed_ms: u64,
        deviation_ms: u64,
        at: DateTime<Utc>,
    }
    let path = announce_dir(home).join(LATENCY_FILE);
    let Ok(text) = std::fs::read_to_string(path) else {
        return Estimator::new();
    };
    let Ok(seen) = serde_json::from_str::<Seen>(&text) else {
        return Estimator::new();
    };
    let age = Utc::now() - seen.at;
    if age > chrono::Duration::seconds(60) || age < chrono::Duration::seconds(-60) {
        return Estimator::new();
    }
    Estimator::seeded(
        Duration::from_millis(seen.smoothed_ms),
        Duration::from_millis(seen.deviation_ms),
    )
}

/// The file in the daemon's home where it publishes how long its requests take (R4).
pub const LATENCY_FILE: &str = "synapsed-latency.json";

/// Where `locate` ended.
enum Located {
    Found((Announce, DateTime<Utc>)),
    /// No live daemon answered: none announced, or a squatter, or nothing.
    Nothing,
    /// The announce file names a live pid that did not answer within the ceiling.
    Slow(Announce, Duration),
}

/// Find the announced daemon. Two silent or unproven tries end in `Nothing`, as before. A live pid that
/// does not answer in time is "slow", not "down" (R1): wait with a growing gap, up to the ceiling, with
/// each probe given the running-average allowance (R3).
fn locate(
    http: &reqwest::blocking::Client,
    home: &Path,
    squat: &mut Squat,
    estimator: &Mutex<Estimator>,
) -> Result<Located, MailError> {
    let started = Instant::now();
    let mut gap = Duration::from_millis(250);
    let mut quiet_tries = 0;
    let mut warned = false;
    loop {
        let allowance = lock_estimator(estimator).allowance();
        let probe = Instant::now();
        match answering(http, home, allowance)? {
            Answer::Proven(announce, started_at) => {
                lock_estimator(estimator).sample(probe.elapsed());
                return Ok(Located::Found((announce, started_at)));
            }
            Answer::Unproven(addr) => {
                squat.check(home, Answer::Unproven(addr));
                quiet_tries += 1;
            }
            Answer::Nothing => quiet_tries += 1,
            Answer::Slow(announce) => {
                lock_estimator(estimator).timed_out();
                if started.elapsed() >= crate::timeout::CEILING {
                    return Ok(Located::Slow(announce, started.elapsed()));
                }
                if !warned {
                    eprintln!(
                        "synapse: synapsed (pid {}) did not answer health within {} ms; it is alive, so waiting (phase=health kind=timeout timeout_ms={})",
                        announce.pid,
                        allowance.as_millis(),
                        allowance.as_millis()
                    );
                    warned = true;
                }
                std::thread::sleep(gap);
                gap = (gap * 2).min(Duration::from_secs(2));
                continue;
            }
        }
        if quiet_tries >= 2 {
            return Ok(Located::Nothing);
        }
    }
}

/// Why a live but silent daemon was not started over (R2).
fn slow_daemon(announce: &Announce, home: &Path, waited: Duration) -> String {
    format!(
        "synapsed (pid {}) is alive but did not answer health in {} s; not starting a second one (announce file {}; if that process is not a synapsed, remove the file)",
        announce.pid,
        waited.as_secs(),
        announce_path(home).display()
    )
}

/// What the announced address said to a challenged health request.
enum Answer {
    /// No announce file, or a dead daemon.
    Nothing,
    /// The announce file names a live pid, but the health probe got no answer in time: a loaded daemon.
    Slow(Announce),
    /// The listener answered without a valid proof of the announced instance id.
    Unproven(String),
    /// The real daemon, and its start time.
    Proven(Announce, DateTime<Utc>),
}

/// The first listener in this command that failed the proof. It is warned about, and recorded as a
/// `ProofFailure` event (hardening P8, row 3), once, however many times it is probed.
#[derive(Default)]
struct Squat(Option<String>);

impl Squat {
    fn check(&mut self, home: &Path, answer: Answer) -> Option<(Announce, DateTime<Utc>)> {
        match answer {
            Answer::Proven(announce, started_at) => Some((announce, started_at)),
            Answer::Unproven(addr) => {
                if self.0.is_none() {
                    eprintln!("synapse: {}", squat_warning(&addr));
                    crate::events::record(
                        Some(home),
                        SecurityEventKind::ProofFailure,
                        "synapsectl/health-proof",
                        &addr,
                        Some(&addr),
                        "failed the health proof; no credential sent",
                    );
                    self.0 = Some(addr);
                }
                None
            }
            Answer::Nothing | Answer::Slow(_) => None,
        }
    }
}

/// Whether a daemon started with `SYNAPSE_ADDR` = `configured` (unset: the daemon's default,
/// `synapsed`'s `DEFAULT_ADDR`) would bind `addr`.
fn daemon_would_bind(configured: Option<&str>, addr: &str) -> bool {
    let configured = configured.unwrap_or("127.0.0.1:7920");
    match (
        configured.parse::<std::net::SocketAddr>(),
        addr.parse::<std::net::SocketAddr>(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn squat_warning(addr: &str) -> String {
    format!(
        "daemon at {} failed its proof; possible port squat; not sending credentials",
        printable(addr)
    )
}

/// The announced daemon, if it is alive and proves it holds the announced instance id.
fn answering(
    http: &reqwest::blocking::Client,
    home: &Path,
    timeout: Duration,
) -> Result<Answer, MailError> {
    let Some(announce) = read_announce(home)? else {
        return Ok(Answer::Nothing);
    };
    let challenge = random_bytes::<16>()?;
    Ok(match health(http, &announce, &challenge, timeout) {
        Health::Silent => Answer::Slow(announce),
        Health::Unproven => Answer::Unproven(announce.addr),
        Health::Proven(started_at) => Answer::Proven(announce, started_at),
    })
}

/// The announce file, if present, owner-only, readable, and naming a live daemon. A file left by a
/// dead daemon is ignored, so a process that took its port gets no token (#74); a file others can
/// reach is an error, since whoever can write it chooses where the token goes.
fn read_announce(home: &Path) -> Result<Option<Announce>, MailError> {
    read_announce_with(&announce_dir(home), remote_daemon())
}

/// `SYNAPSE_DAEMON_HOME`, when set to something.
fn daemon_home() -> Option<PathBuf> {
    std::env::var_os(DAEMON_HOME_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// The directory holding the daemon's announce file: `SYNAPSE_DAEMON_HOME` if set, else `home`.
/// Keys and sessions stay in `home` either way.
fn announce_dir(home: &Path) -> PathBuf {
    daemon_home().unwrap_or_else(|| home.to_path_buf())
}

fn announce_path(home: &Path) -> PathBuf {
    announce_dir(home).join(ANNOUNCE_FILE)
}

/// Why nothing answered, naming the announce file read, so a copy gone stale at a daemon restart
/// (or a lane home with none) is told apart from a daemon that is simply down.
fn no_daemon_answered(home: &Path) -> String {
    let path = announce_path(home);
    let hint = format!(
        "start synapsed with its own environment, or point {DAEMON_HOME_ENV} at the home it announces in"
    );
    if path.try_exists().unwrap_or(false) {
        format!(
            "no daemon answered; announce file {} does not name a running daemon (a copy goes stale at every daemon restart); {hint}",
            path.display()
        )
    } else {
        format!(
            "no daemon answered; no announce file at {}; {hint}",
            path.display()
        )
    }
}

fn remote_daemon() -> bool {
    is_remote(std::env::var_os(REMOTE_DAEMON_ENV).as_deref())
}

fn no_autostart() -> bool {
    is_remote(std::env::var_os(NO_AUTOSTART_ENV).as_deref())
}

fn is_remote(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|v| !v.is_empty() && v != "0")
}

/// `read_announce`, with `remote` skipping the liveness check of the announced pid.
fn read_announce_with(home: &Path, remote: bool) -> Result<Option<Announce>, MailError> {
    let path = home.join(ANNOUNCE_FILE);
    if !path.try_exists()? {
        return Ok(None);
    }
    check_owner_only(&path, "daemon announce file")?;
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    Ok(serde_json::from_str::<Announce>(&text)
        .ok()
        .filter(|a| remote || daemon_alive(a.pid)))
}

/// Whether `pid` is a live process of this user. Defence in depth
/// in front of the health proof (#74): it skips a stale announce file without probing its port, but
/// a reused pid passes it, which is why the proof is what decides.
#[cfg(unix)]
fn daemon_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that `pid` exists and may be signalled by us; it sends nothing.
    // EPERM (another user's process) is a failure here, which is what we want.
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

#[cfg(windows)]
fn daemon_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: OpenProcess takes no pointers; a null result is handled.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut code = 0u32;
    // SAFETY: `handle` is open until the CloseHandle below; `code` is valid for writes.
    let running =
        unsafe { GetExitCodeProcess(handle, &mut code) != 0 && code == STILL_ACTIVE as u32 };
    // SAFETY: opened above and closed exactly once.
    unsafe { CloseHandle(handle) };
    // Not the image name: an upgrade renames the running `synapsed.exe` aside (the only way to
    // replace it on Windows), so a live daemon's image is `synapsed.exe.<tag>.bak` until it restarts.
    running
}

#[cfg(not(any(unix, windows)))]
fn daemon_alive(_pid: u32) -> bool {
    true
}

enum Health {
    Silent,
    Unproven,
    Proven(DateTime<Utc>),
}

/// Ask the announced address for health with `challenge`, and check the reply's `proof`:
/// HMAC-SHA256 keyed by the announced instance id over the same bytes `synapsed` signs
/// (`synapsed::health_proof_message`), compared in constant time by `ring`. Only a failed connection
/// is `Silent`: any HTTP reply at all means something holds the announced port, so a reply that is
/// not an ok health with a valid proof is `Unproven` (review: a squatter answering `ok: false` must
/// be reported too).
fn health(
    http: &reqwest::blocking::Client,
    announce: &Announce,
    challenge: &[u8; 16],
    timeout: Duration,
) -> Health {
    let Ok(resp) = http
        .get(format!(
            "http://{}/v1/health?challenge={}",
            announce.addr,
            hex(challenge)
        ))
        .timeout(timeout)
        .send()
    else {
        return Health::Silent;
    };
    let Some(reply) = resp.json::<Value>().ok().filter(|r| r["ok"] == true) else {
        return Health::Unproven;
    };
    let proven = unhex::<16>(&announce.instance_id)
        .zip(reply["proof"].as_str().and_then(unhex::<32>))
        .is_some_and(|(key, proof)| {
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
            let mut msg = format!("synapsed-health-v1\n{}\n", announce.addr).into_bytes();
            msg.extend_from_slice(challenge);
            ring::hmac::verify(&key, &msg, &proof).is_ok()
        });
    match reply["started_at"].as_str().and_then(|t| t.parse().ok()) {
        Some(started_at) if proven => Health::Proven(started_at),
        _ => Health::Unproven,
    }
}

/// `synapsed` next to this executable, else from PATH.
fn synapsed_path() -> PathBuf {
    let name = format!("synapsed{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(&name)))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Start `synapsed` detached from this process: no console, no stdio, its own process group, and
/// the home as its working directory (so it pins no directory the caller may want to delete). The
/// environment is inherited, so `SYNAPSE_HOME` and `SYNAPSE_ADDR` reach it.
fn spawn_daemon(home: &Path) -> Result<(std::process::Child, Option<std::fs::File>), MailError> {
    let mut cmd = Command::new(synapsed_path());
    let (stderr, start_log) = start_log(home);
    cmd.current_dir(home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        stop_stdio_inheritance();
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: runs in the forked child before exec; `setsid` is async-signal-safe and touches
        // no memory of ours. A new session takes the daemon out of the terminal's job control, so
        // neither Ctrl-C nor the terminal closing (SIGHUP) reaches it.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd.spawn()
        .map(|child| (child, start_log))
        .map_err(|e| MailError::NoDaemon(format!("cannot start synapsed: {e}")))
}

/// Where a starting daemon's stderr goes: a fresh file in the home, so that if it refuses to start
/// the CLI can say why. A pipe would not do: a daemon that did start keeps the pipe's write end
/// for its whole life, and one that fills it blocks on its own logging. `create_new` never
/// follows a link planted in a home others can write, and the CLI reads the file back through
/// this handle, not through the path. Any failure here means stderr is discarded, as before.
fn start_log(home: &Path) -> (Stdio, Option<std::fs::File>) {
    let path = home.join(START_LOG);
    let _ = std::fs::remove_file(&path);
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(file) = options.open(&path) else {
        return (Stdio::null(), None);
    };
    match file.try_clone() {
        Ok(clone) => (Stdio::from(clone), Some(file)),
        Err(_) => (Stdio::null(), None),
    }
}

/// The daemon's last words and the home they apply to, as ` (<reason>; home <path>)`; just the
/// home if it said nothing. Bounded and stripped of control characters, because it is a child's
/// output and goes to the user's terminal.
fn start_failure(log: &mut Option<std::fs::File>, home: &Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let mut text = String::new();
    if let Some(file) = log.as_mut()
        && file.seek(SeekFrom::Start(0)).is_ok()
    {
        let mut bytes = Vec::new();
        let _ = file.take(START_LOG_READ).read_to_end(&mut bytes);
        text = String::from_utf8_lossy(&bytes).into_owned();
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let tail = lines[lines.len().saturating_sub(2)..].join(" / ");
    let tail: String = tail.chars().filter(|c| !c.is_control()).take(512).collect();
    if tail.is_empty() {
        format!(" (home {})", home.display())
    } else {
        format!(": {tail} (home {})", home.display())
    }
}

/// A Windows child inherits every inheritable handle of its parent, not only the stdio it is given.
/// This process's stdio may be a caller's pipe: a daemon holding it would keep that pipe open, and
/// a caller reading to EOF (`Command::output`, a shell's `$(...)`) would wait for the daemon's
/// whole life. So this process's own stdio is made non-inheritable before the spawn.
#[cfg(windows)]
fn stop_stdio_inheritance() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        if !handle.is_null() {
            // SAFETY: the handle is this process's own stdio, open for the process's life;
            // clearing its inherit flag changes no ownership and frees nothing.
            unsafe {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

fn session_path(home: &Path, role: &str) -> PathBuf {
    home.join("sessions").join(format!("{role}.json"))
}

/// `<home>/sessions`, created owner-only if missing.
fn sessions_dir(home: &Path) -> Result<PathBuf, MailError> {
    let dir = home.join("sessions");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir)?;
    // `mode` applies only to a directory created now, so an existing one is checked too.
    check_owner_only(&dir, "session directory")?;
    Ok(dir)
}

/// An exclusive per-role OS lock on `<home>/sessions/<role>.lock`, held while this value lives.
/// The OS releases it when the holder exits, crashed or not, so a leftover file blocks nobody and
/// no lock is ever broken out from under a live holder. The file itself is left in place.
struct RoleLock {
    /// Held, never read: dropping it releases the OS lock.
    _file: std::fs::File,
}

impl RoleLock {
    fn acquire(home: &Path, role: &str) -> Result<RoleLock, MailError> {
        let path = sessions_dir(home)?.join(format!("{role}.lock"));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            if try_lock(&file)? {
                return Ok(RoleLock { _file: file });
            }
            if Instant::now() >= deadline {
                return Err(MailError::Usage(format!(
                    "another synapse command is claiming `{role}`; try again"
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Take an exclusive lock on `file` without waiting: `Ok(false)` if another process holds it.
/// (`File::try_lock` would do, but it needs Rust 1.89 and this crate's MSRV is 1.88.)
#[cfg(unix)]
fn try_lock(file: &std::fs::File) -> Result<bool, MailError> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: the descriptor is open for `file`'s lifetime; flock takes no pointers.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(e.into())
    }
}

#[cfg(windows)]
fn try_lock(file: &std::fs::File) -> Result<bool, MailError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    // SAFETY: an all-zero OVERLAPPED (offset 0, no event) is valid for a synchronous handle.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for `file`'s lifetime and `overlapped` outlives the call, which
    // does not wait (FAIL_IMMEDIATELY). The lock is released when the handle closes.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    } != 0;
    if locked {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(e.into())
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock(_file: &std::fs::File) -> Result<bool, MailError> {
    Ok(true)
}

/// The cached session, if any. A cache others can reach is an error: anyone who can read it holds
/// the role, and anyone who can write it chooses the token.
fn load_session(home: &Path, role: &str) -> Result<Option<Cached>, MailError> {
    sessions_dir(home)?;
    let path = session_path(home, role);
    if !path.try_exists()? {
        return Ok(None);
    }
    check_owner_only(&path, "session file")?;
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    Ok(serde_json::from_str(&text).ok())
}

/// Write the session atomically and owner-only: a fresh temp file (`create_new`, so nothing planted
/// at its name is followed) created `0600` on Unix (on Windows it inherits the checked session
/// directory's ACL), then renamed.
fn save_session(home: &Path, role: &str, cached: &Cached) -> Result<(), MailError> {
    let dir = sessions_dir(home)?;
    let temp = dir.join(format!(".tmp-{role}-{}", hex(&random_bytes::<8>()?)));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&temp)?;
        file.write_all(
            serde_json::to_string(cached)
                .map_err(|e| MailError::Usage(e.to_string()))?
                .as_bytes(),
        )?;
        file.sync_all()?;
    }
    std::fs::rename(&temp, session_path(home, role))?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Strict hex of exactly `N` bytes (no sign, no whitespace), as `synapsed` parses it.
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

fn random_bytes<const N: usize>() -> Result<[u8; N], MailError> {
    use ring::rand::SecureRandom;
    let mut out = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| MailError::Usage("the system random source failed".to_string()))?;
    Ok(out)
}

/// A fetched message as one JSON line: the daemon's fields, plus `body` when the body is UTF-8.
pub fn inbox_line(message: &Value) -> Value {
    let mut out = message.clone();
    if let Some(text) = message["body_b64"]
        .as_str()
        .and_then(|b| B64.decode(b).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
    {
        out["body"] = Value::String(text);
    }
    out
}

/// A short message id for a send, e.g. `sbv3k0-7h-0`: `<start>-<pid>-<n>`, each in base 36.
///
/// Why it is unique where it has to be. The daemon scopes every id by the verified sender
/// (`<role>@<account>/<id>`), so two senders can never collide; only one role's own ids must differ.
/// Within a process `<n>` is a counter, so ids differ. Across processes of the same role, the pair
/// `<pid>` and `<start>` (whole seconds when this process first asked for an id) differs unless two
/// processes of one role get the same pid within the same second, and a pid is not reused while its
/// process lives. A CLI call is one process per send, so it counts from 0 each time: two sends from
/// one role in the same second need different pids, which concurrent processes always have, and which
/// sequential ones almost always have. The residual case (pid reuse within a second) only turns a
/// send into a duplicate of an earlier one, the same outcome as resending with `--id`. Ids from older
/// builds (long, with nanoseconds, or UUIDs) are opaque to the daemon and still ack as before.
pub fn short_message_id() -> String {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    static START: OnceLock<u64> = OnceLock::new();
    static N: AtomicU64 = AtomicU64::new(0);
    let start = *START.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    });
    format!(
        "{}-{}-{}",
        base36(start),
        base36(u64::from(std::process::id())),
        base36(N.fetch_add(1, Ordering::Relaxed))
    )
}

fn base36(mut n: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if n == 0 {
        return "0".into();
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// Encode a message body for the wire.
pub fn encode_body(body: &[u8]) -> String {
    B64.encode(body)
}

/// Daemon text made safe for a terminal: control characters (escape sequences included) are shown
/// escaped, not sent raw. Only JSON-escaped output (`inbox`, `list`) can skip this.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod timeout_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_ids_are_short_valid_and_never_repeat_within_a_process() {
        let ids: Vec<String> = (0..10_000).map(|_| short_message_id()).collect();
        let distinct: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "a repeated id");
        for id in &ids {
            // What the daemon accepts as a client id: 1..=100 bytes, no '/', no control character.
            assert!(id.len() <= 24, "{id} is not short");
            assert!(
                !id.contains('/') && !id.chars().any(char::is_control),
                "{id}"
            );
        }
        // The old id was `mcp-<pid>-<nanoseconds>-<n>`, 30+ bytes before the counter.
        assert!(ids[0].len() < 20, "{}", ids[0]);
    }

    #[test]
    fn base36_is_the_usual_digits() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(36), "10");
        assert_eq!(base36(1_793_488_356), "tnsoh0");
    }

    fn announce_file(home: &Path, pid: u32) {
        let text = format!(
            r#"{{"addr":"127.0.0.1:1","instance_id":"{}","pid":{pid}}}"#,
            "00".repeat(16)
        );
        let path = home.join(ANNOUNCE_FILE);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    /// The announce names a pid of another machine (a Windows daemon seen from a WSL guest): no such
    /// local process, yet with the remote marker the announce is still read, so the proof can decide.
    #[test]
    fn a_remote_daemons_announced_pid_is_not_checked_locally() {
        let home = tempfile::tempdir().unwrap();
        announce_file(home.path(), u32::MAX - 1);
        assert!(read_announce_with(home.path(), false).unwrap().is_none());
        let found = read_announce_with(home.path(), true)
            .unwrap()
            .expect("announce read");
        assert_eq!(found.addr, "127.0.0.1:1");
    }

    #[test]
    fn only_a_set_non_zero_value_marks_the_daemon_remote() {
        use std::ffi::OsStr;
        assert!(!is_remote(None));
        assert!(!is_remote(Some(OsStr::new(""))));
        assert!(!is_remote(Some(OsStr::new("0"))));
        assert!(is_remote(Some(OsStr::new("1"))));
    }

    #[test]
    fn daemon_text_reaches_the_terminal_without_control_characters() {
        assert_eq!(printable("queued"), "queued");
        assert_eq!(printable("a\u{1b}[2Jb\r\n"), "a\\u{1b}[2Jb\\r\\n");
        let refused = MailError::Api {
            kind: "malformed\u{7}".into(),
            message: "\u{1b}]0;owned\u{7}".into(),
            current: None,
        }
        .to_string();
        assert!(!refused.chars().any(char::is_control), "{refused:?}");
    }

    /// An in-place upgrade on Windows renames the running `synapsed.exe` aside, so the live daemon's
    /// image is then `synapsed.exe.<tag>.bak`; the health proof, not the image name, decides.
    #[cfg(windows)]
    #[test]
    fn a_daemon_whose_image_was_renamed_aside_is_still_alive() {
        let dir = tempfile::tempdir().unwrap();
        let system = std::env::var_os("SystemRoot").unwrap();
        let renamed = dir.path().join("synapsed.exe.rc123.bak");
        std::fs::copy(
            Path::new(&system).join("System32").join("ping.exe"),
            &renamed,
        )
        .unwrap();
        let mut child = Command::new(&renamed)
            .args(["-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let alive = daemon_alive(child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(alive);
        assert!(!daemon_alive(child.id()), "an exited process is not alive");
    }

    /// A held announced port is only a reason not to start a daemon when that daemon would bind
    /// the same address; on a free-port configuration (`:0`) it can start and take over.
    #[test]
    fn a_held_port_blocks_a_daemon_only_if_it_would_bind_it() {
        assert!(daemon_would_bind(None, "127.0.0.1:7920"), "the default");
        assert!(daemon_would_bind(Some("127.0.0.1:9000"), "127.0.0.1:9000"));
        assert!(!daemon_would_bind(Some("127.0.0.1:0"), "127.0.0.1:9000"));
        assert!(!daemon_would_bind(Some("127.0.0.1:9001"), "127.0.0.1:9000"));
        assert!(!daemon_would_bind(Some("not an address"), "127.0.0.1:9000"));
    }
}
