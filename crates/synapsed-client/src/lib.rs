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

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

/// The daemon's announce file in the home, written by `synapsed` (M5a).
const ANNOUNCE_FILE: &str = "synapsed.json";
/// Set (to anything but `0` or empty) when the daemon runs on the other side of a boundary this
/// process cannot see across (a WSL guest reaching a Windows daemon through a relay): its announced
/// pid is then another machine's, so only the pid check is skipped and the health proof decides.
const REMOTE_DAEMON_ENV: &str = "SYNAPSE_REMOTE_DAEMON";
/// How long a started daemon gets to announce itself and answer health.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// A starting daemon's stderr, in the home; truncated at each start.
const START_LOG: &str = "synapsed-start.err";
/// How much of it the CLI reads back.
const START_LOG_READ: u64 = 4096;
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);
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
        // Two tries, as in `connect`: one slow answer from a live daemon is not "no daemon".
        for _ in 0..2 {
            if let Some(found) = squat.check(home, answering(&http, home)?) {
                return Ok(Daemon::new(http, home, found));
            }
        }
        Err(MailError::NoDaemon(match &squat.0 {
            Some(addr) => squat_warning(addr),
            None => "no daemon answered; start synapsed with its own environment".to_string(),
        }))
    }

    /// Whether the daemon this connection proved is gone: nothing answers at the announced
    /// address, or a different instance does. A listener that fails the proof is not "gone" (it
    /// may be a squatter or a slow daemon), so this stays false and sends nothing to it.
    pub fn instance_gone(&self) -> bool {
        match answering(&self.http, &self.home) {
            Ok(Answer::Nothing) => true,
            Ok(Answer::Proven(announce, _)) => announce.instance_id != self.instance_id,
            Ok(Answer::Unproven(_)) | Err(_) => false,
        }
    }

    /// Find this home's daemon, starting it if nothing answers.
    pub fn connect(home: &Path) -> Result<Daemon, MailError> {
        // A remote daemon is run by its owner, on the other side: starting one here would be a
        // second daemon with its own store.
        if remote_daemon() {
            return Self::connect_existing(home);
        }
        let http = Self::http_client()?;
        let mut squat = Squat::default();
        // Two tries, so one slow answer from a live daemon doesn't start a doomed second one.
        for _ in 0..2 {
            if let Some(found) = squat.check(home, answering(&http, home)?) {
                return Ok(Daemon::new(http, home, found));
            }
        }
        // Started at most once per command (PM, #74).
        let (mut child, mut start_log) = spawn_daemon(home)?;
        eprintln!("synapse: started synapsed (pid {})", child.id());
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            // Whichever daemon answers will do: ours, or, if two CLIs raced, the one holding the
            // store (ours then exits on its lock), or a live one that was only slow to answer.
            if let Some(found) = squat.check(home, answering(&http, home)?) {
                return Ok(Daemon::new(http, home, found));
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
    ) -> Daemon {
        Daemon {
            http,
            home: home.to_path_buf(),
            addr: announce.addr,
            instance_id: announce.instance_id,
            started_at,
        }
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
    pub fn call(&self, role: &str, path: &str, body: Option<&Value>) -> Result<Value, MailError> {
        let session = self.session(role)?;
        self.request(path, Some(&session.token), body)
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

    /// POST with a JSON body, or GET without one.
    fn request(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, MailError> {
        let url = format!("http://{}{path}", self.addr);
        let mut req = match body {
            Some(b) => self.http.post(url).json(b),
            None => self.http.get(url),
        };
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .map_err(|e| MailError::Transport(e.without_url().to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| MailError::Transport(e.without_url().to_string()))?;
        let value: Value = serde_json::from_str(&text).map_err(|_| {
            MailError::Transport(format!("HTTP {status}, and the reply is not JSON"))
        })?;
        let ok = status.is_success();
        if ok {
            return Ok(value);
        }
        Err(MailError::Api {
            kind: value["error"].as_str().unwrap_or("error").to_string(),
            message: value["message"].as_str().unwrap_or("").to_string(),
            current: value["current"].as_u64(),
        })
    }
}

/// What the announced address said to a challenged health request.
enum Answer {
    /// No announce file, a dead daemon, or nothing answering.
    Nothing,
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
            Answer::Nothing => None,
        }
    }
}

fn squat_warning(addr: &str) -> String {
    format!(
        "daemon at {} failed its proof; possible port squat; not sending credentials",
        printable(addr)
    )
}

/// The announced daemon, if it is alive and proves it holds the announced instance id.
fn answering(http: &reqwest::blocking::Client, home: &Path) -> Result<Answer, MailError> {
    let Some(announce) = read_announce(home)? else {
        return Ok(Answer::Nothing);
    };
    let challenge = random_bytes::<16>()?;
    Ok(match health(http, &announce, &challenge) {
        Health::Silent => Answer::Nothing,
        Health::Unproven => Answer::Unproven(announce.addr),
        Health::Proven(started_at) => Answer::Proven(announce, started_at),
    })
}

/// The announce file, if present, owner-only, readable, and naming a live daemon. A file left by a
/// dead daemon is ignored, so a process that took its port gets no token (#74); a file others can
/// reach is an error, since whoever can write it chooses where the token goes.
fn read_announce(home: &Path) -> Result<Option<Announce>, MailError> {
    read_announce_with(home, remote_daemon())
}

fn remote_daemon() -> bool {
    is_remote(std::env::var_os(REMOTE_DAEMON_ENV).as_deref())
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

/// Whether `pid` is a live process of this user (on Windows, a live `synapsed`). Defence in depth
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
        GetExitCodeProcess, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    // SAFETY: OpenProcess takes no pointers; a null result is handled.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut code = 0u32;
    let mut name = [0u16; 1024];
    let mut len = name.len() as u32;
    // SAFETY: `handle` is open until the CloseHandle below; `code`, `name` and `len` are valid for
    // writes, and `len` is `name`'s capacity in u16s.
    let (running, named) = unsafe {
        (
            GetExitCodeProcess(handle, &mut code) != 0 && code == STILL_ACTIVE as u32,
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, name.as_mut_ptr(), &mut len)
                != 0,
        )
    };
    // SAFETY: opened above and closed exactly once.
    unsafe { CloseHandle(handle) };
    let image = String::from_utf16_lossy(&name[..len as usize]);
    let file = Path::new(&image)
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase());
    running && named && file.as_deref() == Some("synapsed.exe")
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
fn health(http: &reqwest::blocking::Client, announce: &Announce, challenge: &[u8; 16]) -> Health {
    let Ok(resp) = http
        .get(format!(
            "http://{}/v1/health?challenge={}",
            announce.addr,
            hex(challenge)
        ))
        .timeout(HEALTH_TIMEOUT)
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
mod tests {
    use super::*;

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
}
