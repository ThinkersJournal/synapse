// SPDX-License-Identifier: MIT OR Apache-2.0
//! Who may see and message whom (`docs/ACCESS_CONTROL_DESIGN.md`, slice A1).
//!
//! The daemon asks an [`Authorizer`] and enforces the answer; what decides is behind the trait. A1
//! ships a minimal in-memory engine, [`Access`], persisted to `<home>/access.json`. A2 swaps in
//! auth-framework behind the same trait.
//!
//! Rules (board 384, 385, 388):
//! - A role that first claims after the upgrade can see and message nobody, itself apart.
//! - The roles that existed at the upgrade got one `legacy` grant, written once: see and message
//!   every role that existed then, and no later one.
//! - The account holder (a session with `role-admin`) is allowed everything.
//! - A sub-agent whose certificate chain has a parent is visible to that parent (its creator) and
//!   the account holder only, until a rule says otherwise. Provisioned directly: no creator.
//! - `see` and `send` are separate actions; neither implies the other.
//! - Unknown object kinds are denied: unreachable never widens.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The file in the daemon home.
pub const ACCESS_FILE: &str = "access.json";

/// What a principal may do; the registry of `docs/ACCESS_CONTROL_DESIGN.md` 3.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    See,
    Send,
    Join,
    Post,
    CreateRoom,
    ManageRoom,
    Grant,
    EditRule,
}

impl Action {
    /// The registered name, `synapse:<action>`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Action::See => "synapse:see",
            Action::Send => "synapse:send",
            Action::Join => "synapse:join",
            Action::Post => "synapse:post",
            Action::CreateRoom => "synapse:create-room",
            Action::ManageRoom => "synapse:manage-room",
            Action::Grant => "synapse:grant",
            Action::EditRule => "synapse:edit-rule",
        }
    }

    /// Changes who may do what: such a decision is always [`Freshness::Live`] (A2 acts on it).
    #[must_use]
    pub fn sensitive(self) -> bool {
        matches!(
            self,
            Action::CreateRoom | Action::ManageRoom | Action::Grant | Action::EditRule
        )
    }
}

/// How current a decision must be: served from a cache of at most 60 s, or asked of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Cached,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    #[must_use]
    pub fn allowed(self) -> bool {
        self == Decision::Allow
    }
}

/// Who asks. `account_holder` is set by the daemon from the session, never by a client.
#[derive(Debug, Clone, Copy)]
pub struct Principal<'a> {
    pub id: &'a str,
    pub account_holder: bool,
}

/// The object of an agent action: `agent:<role>@<account>`.
#[must_use]
pub fn agent_object(global_id: &str) -> String {
    format!("agent:{global_id}")
}

/// The source of decisions could not be asked (a remote engine that is down).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreachable;

pub trait Authorizer: Send + Sync {
    fn decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        freshness: Freshness,
    ) -> Decision;

    /// Like [`Authorizer::decide`], but says when the source could not be asked, so a caller can
    /// tell "denied" from "could not find out" ([`Cached`] fails closed on the second). An engine
    /// that is always reachable keeps the default.
    fn try_decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        freshness: Freshness,
    ) -> Result<Decision, Unreachable> {
        Ok(self.decide(principal, action, object, freshness))
    }
}

/// How long a [`Freshness::Cached`] decision may be reused (CireSnave: "60 seconds at the most").
pub const CACHE_TTL_SECS: i64 = 60;

/// What a [`Cached`] remembers: the decision for (principal, action, object) and when it was made.
type CacheEntries = std::collections::HashMap<(String, Action, String), (Decision, DateTime<Utc>)>;

/// A cache in front of a source of decisions (docs/ACCESS_CONTROL_DESIGN.md 3.6): a `Cached`
/// decision is reused for at most [`CACHE_TTL_SECS`], so a revoke takes effect within a minute; a
/// `Live` decision, and any decision about a sensitive action, always asks the source; and when the
/// source cannot be asked, a `Live` decision is `Deny` and a cached one is served until its minute
/// ends and then `Deny`. Unreachability never widens access.
pub struct Cached<A: Authorizer> {
    inner: A,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    entries: Mutex<CacheEntries>,
}

impl<A: Authorizer> Cached<A> {
    pub fn new(inner: A) -> Self {
        Self::with_clock(inner, Box::new(Utc::now))
    }

    /// A cache on a clock of the caller's (tests advance it instead of sleeping).
    pub fn with_clock(inner: A, clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>) -> Self {
        Cached {
            inner,
            clock,
            entries: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl<A: Authorizer> Authorizer for Cached<A> {
    fn decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        freshness: Freshness,
    ) -> Decision {
        self.try_decide(principal, action, object, freshness)
            .unwrap_or(Decision::Deny)
    }

    fn try_decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        freshness: Freshness,
    ) -> Result<Decision, Unreachable> {
        let now = (self.clock)();
        // The account holder is the daemon's own fact about the session, never the source's.
        let key = (
            format!("{}|{}", principal.id, principal.account_holder),
            action,
            object.to_string(),
        );
        let live = freshness == Freshness::Live || action.sensitive();
        let fresh = |at: DateTime<Utc>| now - at < chrono::Duration::seconds(CACHE_TTL_SECS);
        let Ok(mut entries) = self.entries.lock() else {
            return Ok(Decision::Deny);
        };
        if !live
            && let Some((decision, at)) = entries.get(&key).copied()
            && fresh(at)
        {
            return Ok(decision);
        }
        match self
            .inner
            .try_decide(principal, action, object, Freshness::Live)
        {
            Ok(decision) => {
                entries.insert(key, (decision, now));
                Ok(decision)
            }
            Err(Unreachable) => {
                if live {
                    return Ok(Decision::Deny);
                }
                match entries.get(&key).copied() {
                    Some((decision, at)) if fresh(at) => Ok(decision),
                    _ => Ok(Decision::Deny),
                }
            }
        }
    }
}

/// One rule: `principal` (or `*`) may do `actions` to `objects` (or `agent:*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub principal: String,
    pub actions: Vec<Action>,
    pub objects: Vec<String>,
    /// Written by the one-time upgrade; reports can list what is still legacy.
    #[serde(default)]
    pub legacy: bool,
    /// Names this grant for `revoke`. A grant written before ids existed gets a stable one from
    /// its content when the file is loaded.
    #[serde(default)]
    pub id: String,
    /// Who issued it: `None` for the account holder, the upgrade and a seeded file. A grant a role
    /// issued is only as good as that role's own right, now (3.4): it dies with its source.
    #[serde(default)]
    pub issued_by: Option<String>,
    /// The issuer acted as an owner of the objects (it holds `edit-rule` on them) rather than by
    /// sharing a subset of what it holds: the grant then lives while the issuer holds `edit-rule`.
    #[serde(default)]
    pub owner_edit: bool,
    #[serde(default)]
    pub issued_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// The issuer asked that decisions resting on this grant be checked live (3.6). The in-memory
    /// engine is always live; the engine behind the trait later honours it.
    #[serde(default)]
    pub sensitive: bool,
}

impl Grant {
    /// A stable id from the grant's content, for those written before ids existed.
    fn content_id(&self) -> String {
        let text = format!(
            "{}|{:?}|{:?}|{}",
            self.principal, self.actions, self.objects, self.legacy
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
        digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn covers(&self, principal: &str, action: Action, object: &str) -> bool {
        (self.principal == "*" || self.principal == principal)
            && self.actions.contains(&action)
            && self
                .objects
                .iter()
                .any(|o| o == "agent:*" && object.starts_with("agent:") || o == object)
    }
}

/// What is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AccessState {
    /// When the one-time upgrade ran.
    pub migrated_at: Option<DateTime<Utc>>,
    pub grants: Vec<Grant>,
    /// Object (`agent:role@acct`) -> the global id of the role whose certificate issued the
    /// sub-agent's, recorded at its first claim.
    #[serde(default)]
    pub created_by: BTreeMap<String, String>,
}

impl AccessState {
    fn decide(&self, principal: Principal<'_>, action: Action, object: &str) -> Decision {
        self.decide_at(principal, action, object, Utc::now(), 0)
    }

    /// Does a grant still authorise `action` on `object` for its holder? It must not have
    /// expired, and the role that issued it must still hold what it gave (3.4): a delegation dies
    /// with its source, and the chain is bounded.
    fn live_grant(
        &self,
        g: &Grant,
        action: Action,
        object: &str,
        now: DateTime<Utc>,
        depth: u8,
    ) -> bool {
        if g.expires_at.is_some_and(|e| e <= now) {
            return false;
        }
        let Some(issuer) = g.issued_by.as_deref() else {
            return true;
        };
        if depth >= MAX_CHAIN {
            return false;
        }
        let needed = if g.owner_edit {
            Action::EditRule
        } else {
            action
        };
        self.decide_at(
            Principal {
                id: issuer,
                account_holder: false,
            },
            needed,
            object,
            now,
            depth + 1,
        )
        .allowed()
    }

    fn granted(
        &self,
        principal: &str,
        action: Action,
        object: &str,
        now: DateTime<Utc>,
        depth: u8,
    ) -> bool {
        self.grants.iter().any(|g| {
            g.covers(principal, action, object) && self.live_grant(g, action, object, now, depth)
        })
    }

    fn decide_at(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        now: DateTime<Utc>,
        depth: u8,
    ) -> Decision {
        // Fail closed on any object kind but an agent or a room.
        let is_room = object.starts_with("room:");
        if !is_room && !object.starts_with("agent:") {
            return Decision::Deny;
        }
        if principal.account_holder {
            return Decision::Allow;
        }
        let creator = self
            .created_by
            .get(object)
            .is_some_and(|c| c == principal.id);
        let allowed = if is_room {
            // Board 388: a new room is visible to its creator and the account holder only, until a
            // grant says otherwise. A room's creator owns it: every action. Everyone else needs a
            // grant to see it, to post without being a member (which is what lets an announcer
            // post without joining), to edit its rules or to share it. Join, create and manage are
            // allowed here (PM, 2026-11-06) and decided by the registry and the join policy.
            if creator {
                true
            } else if matches!(
                action,
                Action::See | Action::Post | Action::EditRule | Action::Grant
            ) {
                self.granted(principal.id, action, object, now, depth)
            } else {
                true
            }
        } else {
            let target = &object["agent:".len()..];
            // A role always sees itself and may message itself: its own row, its own self-notes.
            // A creator sees and messages what it created, and owns the rules about it.
            (target == principal.id && matches!(action, Action::See | Action::Send))
                || (creator
                    && matches!(
                        action,
                        Action::See | Action::Send | Action::EditRule | Action::Grant
                    ))
                || self.granted(principal.id, action, object, now, depth)
        };
        if allowed {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

/// How many links a delegation chain may have before it stops counting.
const MAX_CHAIN: u8 = 4;

/// The engine and its file.
pub struct Access {
    state: Mutex<AccessState>,
    path: PathBuf,
}

impl Access {
    /// Load `<home>/access.json`, or on the first start write it: one `legacy` grant for each of
    /// `existing_roles` (the roles in the table now) over exactly those roles. It never runs twice:
    /// the file's existence is the record. A file that cannot be read stops the start; guessing
    /// would either lock everyone out or open everything.
    pub fn open(
        home: &Path,
        existing_roles: &[String],
        now: DateTime<Utc>,
    ) -> Result<Access, String> {
        let path = home.join(ACCESS_FILE);
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let mut state: AccessState = serde_json::from_str(&text)
                    .map_err(|e| format!("{ACCESS_FILE} is unreadable: {e}"))?;
                for g in &mut state.grants {
                    if g.id.is_empty() {
                        g.id = g.content_id();
                    }
                }
                Ok(Access {
                    state: Mutex::new(state),
                    path,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let objects: Vec<String> = existing_roles.iter().map(|r| agent_object(r)).collect();
                let state = AccessState {
                    migrated_at: Some(now),
                    grants: existing_roles
                        .iter()
                        .map(|role| {
                            let mut g = Grant {
                                principal: role.clone(),
                                actions: vec![Action::See, Action::Send],
                                objects: objects.clone(),
                                legacy: true,
                                id: String::new(),
                                issued_by: None,
                                owner_edit: false,
                                issued_at: Some(now),
                                expires_at: None,
                                sensitive: false,
                            };
                            g.id = g.content_id();
                            g
                        })
                        .collect(),
                    created_by: BTreeMap::new(),
                };
                write_file(&path, &state).map_err(|e| format!("{ACCESS_FILE} not written: {e}"))?;
                Ok(Access {
                    state: Mutex::new(state),
                    path,
                })
            }
            Err(e) => Err(format!("{ACCESS_FILE} is unreadable: {e}")),
        }
    }

    /// Record who created `global_id`, once: a later claim never rewrites it.
    pub fn record_creator(&self, global_id: &str, creator: &str) -> Result<(), String> {
        self.record_object_creator(&agent_object(global_id), creator)
    }

    /// The same for a room: `object` is `room:<name>@<account>`.
    pub fn record_object_creator(&self, object: &str, creator: &str) -> Result<(), String> {
        let Ok(mut state) = self.state.lock() else {
            return Err("access state poisoned".into());
        };
        let object = object.to_string();
        if state.created_by.contains_key(&object) {
            return Ok(());
        }
        state.created_by.insert(object.clone(), creator.to_string());
        if let Err(e) = write_file(&self.path, &state) {
            state.created_by.remove(&object);
            return Err(format!("{ACCESS_FILE} not written: {e}"));
        }
        Ok(())
    }

    /// Add a grant and persist it (the file is rewritten; a failed write leaves nothing added).
    /// Who may add it is decided by the caller (the daemon), not here. Returns the grant's id.
    pub fn add_grant(&self, mut grant: Grant) -> Result<String, String> {
        let Ok(mut state) = self.state.lock() else {
            return Err("access state poisoned".into());
        };
        grant.id = uuid::Uuid::new_v4().simple().to_string();
        let id = grant.id.clone();
        state.grants.push(grant);
        if let Err(e) = write_file(&self.path, &state) {
            state.grants.pop();
            return Err(format!("{ACCESS_FILE} not written: {e}"));
        }
        Ok(id)
    }

    /// The grant with this id, if there is one.
    #[must_use]
    pub fn grant(&self, id: &str) -> Option<Grant> {
        self.state
            .lock()
            .ok()?
            .grants
            .iter()
            .find(|g| g.id == id)
            .cloned()
    }

    /// Remove a grant by id and persist; `Ok(None)` when there is none. What it gave dies with it,
    /// and so does anything delegated from it.
    pub fn remove_grant(&self, id: &str) -> Result<Option<Grant>, String> {
        let Ok(mut state) = self.state.lock() else {
            return Err("access state poisoned".into());
        };
        let Some(at) = state.grants.iter().position(|g| g.id == id) else {
            return Ok(None);
        };
        let gone = state.grants.remove(at);
        if let Err(e) = write_file(&self.path, &state) {
            state.grants.insert(at, gone);
            return Err(format!("{ACCESS_FILE} not written: {e}"));
        }
        Ok(Some(gone))
    }

    /// Forget who created `object` (a deleted room), so a new room of that name starts clean.
    pub fn forget_object(&self, object: &str) {
        if let Ok(mut state) = self.state.lock()
            && state.created_by.remove(object).is_some()
            && let Err(e) = write_file(&self.path, &state)
        {
            eprintln!("synapsed: {ACCESS_FILE} not written: {e}");
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> AccessState {
        self.state.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Authorizer for Access {
    fn decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        _freshness: Freshness,
    ) -> Decision {
        // A1 has one source and it is in memory, so Cached and Live agree. A poisoned lock denies.
        match self.state.lock() {
            Ok(state) => state.decide(principal, action, object),
            Err(_) => Decision::Deny,
        }
    }
}

/// Temp file then rename, owner-only on Unix.
fn write_file(path: &Path, state: &AccessState) -> std::io::Result<()> {
    use std::io::Write;
    let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(&body)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A source of decisions the test controls: what it answers, and whether it can be asked.
    struct Source {
        allow: Mutex<bool>,
        up: Mutex<bool>,
        asked: Mutex<u32>,
    }

    impl Source {
        fn new() -> Arc<Source> {
            Arc::new(Source {
                allow: Mutex::new(true),
                up: Mutex::new(true),
                asked: Mutex::new(0),
            })
        }
        fn set(&self, allow: bool, up: bool) {
            *self.allow.lock().unwrap() = allow;
            *self.up.lock().unwrap() = up;
        }
        fn asked(&self) -> u32 {
            *self.asked.lock().unwrap()
        }
    }

    impl Authorizer for Arc<Source> {
        fn decide(&self, p: Principal<'_>, a: Action, o: &str, f: Freshness) -> Decision {
            self.try_decide(p, a, o, f).unwrap_or(Decision::Deny)
        }
        fn try_decide(
            &self,
            _: Principal<'_>,
            _: Action,
            _: &str,
            _: Freshness,
        ) -> Result<Decision, Unreachable> {
            if !*self.up.lock().unwrap() {
                return Err(Unreachable);
            }
            *self.asked.lock().unwrap() += 1;
            Ok(if *self.allow.lock().unwrap() {
                Decision::Allow
            } else {
                Decision::Deny
            })
        }
    }

    struct Clock(Arc<Mutex<DateTime<Utc>>>);
    impl Clock {
        fn new() -> Clock {
            Clock(Arc::new(Mutex::new(Utc::now())))
        }
        fn advance(&self, secs: i64) {
            *self.0.lock().unwrap() += chrono::Duration::seconds(secs);
        }
        fn reader(&self) -> Box<dyn Fn() -> DateTime<Utc> + Send + Sync> {
            let at = self.0.clone();
            Box::new(move || *at.lock().unwrap())
        }
    }

    const ME: Principal<'static> = Principal {
        id: "a@acct",
        account_holder: false,
    };
    const THEM: &str = "agent:b@acct";

    #[test]
    fn a_revoke_applies_within_60_seconds() {
        let (source, clock) = (Source::new(), Clock::new());
        let cache = Cached::with_clock(source.clone(), clock.reader());
        assert!(
            cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed()
        );
        source.set(false, true); // revoked at the source
        clock.advance(59);
        assert!(
            cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed(),
            "a cached decision may be reused for the minute"
        );
        clock.advance(2);
        assert!(
            !cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed(),
            "after 60 s the revoke has taken effect"
        );
    }

    #[test]
    fn a_sensitive_decision_is_checked_live_on_every_call() {
        let (source, clock) = (Source::new(), Clock::new());
        let cache = Cached::with_clock(source.clone(), clock.reader());
        for _ in 0..3 {
            assert!(
                cache
                    .decide(ME, Action::EditRule, THEM, Freshness::Cached)
                    .allowed()
            );
        }
        assert_eq!(
            source.asked(),
            3,
            "a sensitive action never rides on the cache"
        );
        source.set(false, true);
        assert!(
            !cache
                .decide(ME, Action::EditRule, THEM, Freshness::Cached)
                .allowed(),
            "a revoke is seen at once, not after a minute"
        );
        // The control: an ordinary action asked three times is asked of the source once.
        let (source, clock) = (Source::new(), Clock::new());
        let cache = Cached::with_clock(source.clone(), clock.reader());
        for _ in 0..3 {
            let _ = cache.decide(ME, Action::See, THEM, Freshness::Cached);
        }
        assert_eq!(source.asked(), 1);
        // A `Live` ask of an ordinary action also goes to the source.
        let _ = cache.decide(ME, Action::See, THEM, Freshness::Live);
        assert_eq!(source.asked(), 2);
    }

    #[test]
    fn an_unreachable_source_denies_a_live_decision_and_never_widens_a_cached_one() {
        let (source, clock) = (Source::new(), Clock::new());
        let cache = Cached::with_clock(source.clone(), clock.reader());
        assert!(
            cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed()
        );
        source.set(true, false); // the source goes away
        assert!(
            !cache
                .decide(ME, Action::See, THEM, Freshness::Live)
                .allowed(),
            "a live decision with no source is a deny"
        );
        assert!(
            !cache
                .decide(ME, Action::EditRule, THEM, Freshness::Cached)
                .allowed(),
            "so is a sensitive one"
        );
        clock.advance(30);
        assert!(
            cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed(),
            "a cached allow is served until its minute ends"
        );
        clock.advance(31);
        assert!(
            !cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed(),
            "and then it is a deny"
        );
        // Never widens: a cached deny stays a deny, and something never asked is a deny.
        let (source, clock) = (Source::new(), Clock::new());
        source.set(false, true);
        let cache = Cached::with_clock(source.clone(), clock.reader());
        assert!(
            !cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed()
        );
        source.set(true, false);
        assert!(
            !cache
                .decide(ME, Action::See, THEM, Freshness::Cached)
                .allowed()
        );
        assert!(
            !cache
                .decide(ME, Action::Send, THEM, Freshness::Cached)
                .allowed()
        );
    }

    fn state(grants: Vec<Grant>) -> AccessState {
        AccessState {
            migrated_at: None,
            grants,
            created_by: BTreeMap::new(),
        }
    }

    fn grant(to: &str, action: Action, object: &str, issued_by: Option<&str>) -> Grant {
        let mut g = Grant {
            principal: to.into(),
            actions: vec![action],
            objects: vec![object.into()],
            legacy: false,
            id: String::new(),
            issued_by: issued_by.map(str::to_string),
            owner_edit: false,
            issued_at: None,
            expires_at: None,
            sensitive: false,
        };
        g.id = g.content_id();
        g
    }

    fn can(s: &AccessState, who: &str, action: Action, object: &str) -> bool {
        s.decide(
            Principal {
                id: who,
                account_holder: false,
            },
            action,
            object,
        )
        .allowed()
    }

    #[test]
    fn a_delegation_dies_with_its_sources_grant() {
        // ann holds see on b; ann shares it with cat. When ann's own grant goes, cat's goes too.
        let root = grant("ann@acct", Action::See, THEM, None);
        let shared = grant("cat@acct", Action::See, THEM, Some("ann@acct"));
        let mut s = state(vec![root.clone(), shared]);
        assert!(can(&s, "cat@acct", Action::See, THEM));
        s.grants.retain(|g| g.id != root.id);
        assert!(
            !can(&s, "cat@acct", Action::See, THEM),
            "the delegation outlived its source"
        );
    }

    #[test]
    fn a_delegation_that_the_issuer_never_could_give_grants_nothing() {
        // ann never held send on b, so what she "gave" cat is nothing; the chain is bounded too.
        let s = state(vec![grant(
            "cat@acct",
            Action::Send,
            THEM,
            Some("ann@acct"),
        )]);
        assert!(!can(&s, "cat@acct", Action::Send, THEM));
        let other = "agent:z@acct";
        let s = state(vec![
            grant("a@acct", Action::See, other, Some("b@acct")),
            grant("b@acct", Action::See, other, Some("a@acct")),
        ]);
        assert!(
            !can(&s, "a@acct", Action::See, other),
            "a cycle of delegations grants nothing"
        );
    }

    #[test]
    fn an_expired_grant_grants_nothing() {
        let mut g = grant("ann@acct", Action::See, THEM, None);
        g.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(!can(&state(vec![g]), "ann@acct", Action::See, THEM));
        let mut g = grant("ann@acct", Action::See, THEM, None);
        g.expires_at = Some(Utc::now() + chrono::Duration::seconds(60));
        assert!(
            can(&state(vec![g]), "ann@acct", Action::See, THEM),
            "the control: not yet expired"
        );
    }
}
