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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

pub trait Authorizer: Send + Sync {
    fn decide(
        &self,
        principal: Principal<'_>,
        action: Action,
        object: &str,
        freshness: Freshness,
    ) -> Decision;
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
}

impl Grant {
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
        // Fail closed on anything but an agent object (rooms arrive with R1).
        let Some(target) = object.strip_prefix("agent:") else {
            return Decision::Deny;
        };
        if principal.account_holder {
            return Decision::Allow;
        }
        // A role always sees itself and may message itself: its own row, its own self-notes.
        if target == principal.id && matches!(action, Action::See | Action::Send) {
            return Decision::Allow;
        }
        // A creator sees and messages what it created.
        if matches!(action, Action::See | Action::Send)
            && self
                .created_by
                .get(object)
                .is_some_and(|c| c == principal.id)
        {
            return Decision::Allow;
        }
        if self
            .grants
            .iter()
            .any(|g| g.covers(principal.id, action, object))
        {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }
}

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
                let state: AccessState = serde_json::from_str(&text)
                    .map_err(|e| format!("{ACCESS_FILE} is unreadable: {e}"))?;
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
                        .map(|role| Grant {
                            principal: role.clone(),
                            actions: vec![Action::See, Action::Send],
                            objects: objects.clone(),
                            legacy: true,
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
        let Ok(mut state) = self.state.lock() else {
            return Err("access state poisoned".into());
        };
        let object = agent_object(global_id);
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
