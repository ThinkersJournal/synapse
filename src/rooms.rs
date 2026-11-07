// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rooms: the account-level registry and policy (`docs/ROOMS_DESIGN.md`, slice R1).
//!
//! A room is `name@account`, in the same namespace as roles. R1 holds only the registry and the
//! policy: create, delete, set the join policy, invite. Joining, presence and fan-out are R2 and
//! R3; their fields exist here (and decode to empty) so no later slice changes the stored shape.
//! Who may call each operation is decided by the daemon (`Authorizer`); this module enforces the
//! state rules: names, the namespace, caps, and "only the creator or a moderator manages a room".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Rooms one account may hold (`docs/ROOMS_DESIGN.md` section 10).
pub const MAX_ROOMS: usize = 16;

/// Who may join.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JoinPolicy {
    /// Any role the daemon serves.
    #[default]
    Open,
    /// Exactly the listed global ids (`role@account`, a foreign account's included).
    AllowList(BTreeSet<String>),
    /// Only an invited role.
    InviteOnly,
}

/// Whether a new joiner may post.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultSend {
    #[default]
    Speak,
    Muted,
}

/// A joined role (filled from R2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub joined_at: DateTime<Utc>,
    pub can_send: bool,
    #[serde(default)]
    pub mention_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Room {
    pub created_at: DateTime<Utc>,
    /// The global id of the role that created it, or `account` when the account holder did.
    pub creator: String,
    #[serde(default)]
    pub moderators: BTreeSet<String>,
    #[serde(default)]
    pub join_policy: JoinPolicy,
    /// Pending invitations, accepted by the invitee's own join.
    #[serde(default)]
    pub invites: BTreeSet<String>,
    #[serde(default)]
    pub default_send: DefaultSend,
    #[serde(default)]
    pub members: BTreeMap<String, Member>,
    #[serde(default)]
    pub banned: BTreeSet<String>,
}

/// Every room of the account, keyed by `name@account`. An absent blob decodes as empty.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoomsState {
    #[serde(default)]
    pub rooms: BTreeMap<String, Room>,
}

/// Why a rooms operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomError {
    /// Not `name@account` with both parts valid.
    BadName,
    /// A room or a claimed role already has this name.
    NameTaken,
    /// The account is at [`MAX_ROOMS`].
    RoomCap,
    /// No such room.
    Unknown,
    /// The actor is not the creator, a moderator, or an admin.
    NotModerator,
}

impl fmt::Display for RoomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RoomError::BadName => "a room is named name@account with valid parts",
            RoomError::NameTaken => "a room or a role already has this name",
            RoomError::RoomCap => "the account has reached its room limit",
            RoomError::Unknown => "no such room",
            RoomError::NotModerator => "only the room's creator or a moderator may do that",
        })
    }
}

impl std::error::Error for RoomError {}

impl RoomsState {
    #[must_use]
    pub fn contains(&self, global_id: &str) -> bool {
        self.rooms.contains_key(global_id)
    }

    /// Create `global_id`. `role_exists` says whether a claimed role already has the name.
    ///
    /// # Errors
    /// [`RoomError::BadName`], [`RoomError::NameTaken`], [`RoomError::RoomCap`].
    pub fn create(
        &mut self,
        global_id: &str,
        creator: &str,
        now: DateTime<Utc>,
        role_exists: bool,
    ) -> Result<(), RoomError> {
        if !valid_room_id(global_id) {
            return Err(RoomError::BadName);
        }
        if role_exists || self.rooms.contains_key(global_id) {
            return Err(RoomError::NameTaken);
        }
        if self.rooms.len() >= MAX_ROOMS {
            return Err(RoomError::RoomCap);
        }
        self.rooms.insert(
            global_id.to_string(),
            Room {
                created_at: now,
                creator: creator.to_string(),
                moderators: BTreeSet::new(),
                join_policy: JoinPolicy::default(),
                invites: BTreeSet::new(),
                default_send: DefaultSend::default(),
                members: BTreeMap::new(),
                banned: BTreeSet::new(),
            },
        );
        Ok(())
    }

    fn managed(
        &mut self,
        global_id: &str,
        actor: &str,
        admin: bool,
    ) -> Result<&mut Room, RoomError> {
        let room = self.rooms.get_mut(global_id).ok_or(RoomError::Unknown)?;
        if admin || room.creator == actor || room.moderators.contains(actor) {
            Ok(room)
        } else {
            Err(RoomError::NotModerator)
        }
    }

    /// Delete a room. `admin` is the account holder or a holder of `room-admin`.
    ///
    /// # Errors
    /// [`RoomError::Unknown`], [`RoomError::NotModerator`].
    pub fn delete(&mut self, global_id: &str, actor: &str, admin: bool) -> Result<(), RoomError> {
        self.managed(global_id, actor, admin)?;
        self.rooms.remove(global_id);
        Ok(())
    }

    /// Set the join policy and the default for new joiners.
    ///
    /// # Errors
    /// [`RoomError::Unknown`], [`RoomError::NotModerator`].
    pub fn set_policy(
        &mut self,
        global_id: &str,
        actor: &str,
        admin: bool,
        join_policy: JoinPolicy,
        default_send: DefaultSend,
    ) -> Result<(), RoomError> {
        let room = self.managed(global_id, actor, admin)?;
        room.join_policy = join_policy;
        room.default_send = default_send;
        Ok(())
    }

    /// Invite `invitee`; the invitation is accepted by the invitee's own join (R2).
    ///
    /// # Errors
    /// [`RoomError::Unknown`], [`RoomError::NotModerator`].
    pub fn invite(
        &mut self,
        global_id: &str,
        actor: &str,
        admin: bool,
        invitee: &str,
    ) -> Result<(), RoomError> {
        self.managed(global_id, actor, admin)?
            .invites
            .insert(invitee.to_string());
        Ok(())
    }
}

/// `name@account`, both parts valid role-style names.
#[must_use]
pub fn valid_room_id(global_id: &str) -> bool {
    match global_id.split_once('@') {
        Some((name, account)) => {
            crate::keystore::valid_name(name) && crate::keystore::valid_name(account)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn a_state_blob_without_rooms_decodes_empty() {
        let state: RoomsState = serde_json::from_str("{}").expect("decode");
        assert!(state.rooms.is_empty());
    }

    #[test]
    fn a_room_created_with_only_the_original_fields_decodes() {
        let text = r#"{"rooms":{"lounge@acct":{"created_at":"2026-11-07T00:00:00Z","creator":"account"}}}"#;
        let state: RoomsState = serde_json::from_str(text).expect("decode");
        assert_eq!(state.rooms["lounge@acct"].join_policy, JoinPolicy::Open);
    }

    #[test]
    fn create_refuses_bad_taken_and_capped_names() {
        let mut s = RoomsState::default();
        assert_eq!(
            s.create("lounge", "account", now(), false),
            Err(RoomError::BadName)
        );
        assert_eq!(
            s.create("a.b@acct", "account", now(), false),
            Err(RoomError::BadName)
        );
        assert_eq!(
            s.create("pm@acct", "account", now(), true),
            Err(RoomError::NameTaken)
        );
        s.create("lounge@acct", "account", now(), false)
            .expect("create");
        assert_eq!(
            s.create("lounge@acct", "account", now(), false),
            Err(RoomError::NameTaken)
        );
        for i in 1..MAX_ROOMS {
            s.create(&format!("r{i}@acct"), "account", now(), false)
                .expect("create");
        }
        assert_eq!(
            s.create("extra@acct", "account", now(), false),
            Err(RoomError::RoomCap)
        );
    }

    #[test]
    fn only_the_creator_a_moderator_or_an_admin_manages_a_room() {
        let mut s = RoomsState::default();
        s.create("lounge@acct", "pm@acct", now(), false)
            .expect("create");
        assert_eq!(
            s.set_policy(
                "lounge@acct",
                "dev@acct",
                false,
                JoinPolicy::InviteOnly,
                DefaultSend::Speak
            ),
            Err(RoomError::NotModerator)
        );
        s.set_policy(
            "lounge@acct",
            "pm@acct",
            false,
            JoinPolicy::InviteOnly,
            DefaultSend::Muted,
        )
        .expect("creator");
        s.invite("lounge@acct", "dev@acct", true, "dev@acct")
            .expect("admin");
        assert_eq!(
            s.delete("lounge@acct", "dev@acct", false),
            Err(RoomError::NotModerator)
        );
        s.delete("lounge@acct", "pm@acct", false).expect("delete");
        assert_eq!(
            s.delete("lounge@acct", "pm@acct", false),
            Err(RoomError::Unknown)
        );
    }
}
