// SPDX-License-Identifier: MIT OR Apache-2.0
//! Rooms, slice R1 (`docs/ROOMS_DESIGN.md` section 13): the registry and policy, kept in the
//! mailbox store, one namespace with roles.

use synapse::mailbox::conformance as suite;
use synapse::mailbox::{MailConfig, MailError, Mailbox, MemoryStore};
use synapse::roles::ClaimError;
use synapse::rooms::{DefaultSend, JoinPolicy, MAX_ROOMS, RoomError};

fn mailbox() -> Mailbox<MemoryStore> {
    suite::open(MemoryStore::new())
}

#[test]
fn a_room_cannot_take_the_name_of_a_claimed_role() {
    let ids = suite::Ids::new();
    let mut mb = mailbox();
    ids.claim(&mut mb, "pm", suite::t0());
    match mb.create_room("pm@acct", "account", suite::t0()) {
        Err(MailError::Room(RoomError::NameTaken)) => {}
        other => panic!("a room took a role's name: {other:?}"),
    }
}

#[test]
fn a_role_cannot_claim_the_name_of_a_room() {
    let ids = suite::Ids::new();
    let mut mb = mailbox();
    mb.create_room("lounge@acct", "account", suite::t0())
        .expect("create");
    match ids.try_claim(&mut mb, "lounge", suite::t0()) {
        Err(MailError::Claim(ClaimError::RoomNameTaken)) => {}
        other => panic!("a role claimed a room's name: {other:?}"),
    }
    // The control: a role with another name claims fine.
    ids.claim(&mut mb, "dev", suite::t0());
}

#[test]
fn only_the_creator_a_moderator_or_an_admin_changes_a_room() {
    let mut mb = mailbox();
    mb.create_room("lounge@acct", "pm@acct", suite::t0())
        .expect("create");
    match mb.set_room_policy(
        "lounge@acct",
        "dev@acct",
        false,
        JoinPolicy::InviteOnly,
        DefaultSend::Speak,
    ) {
        Err(MailError::Room(RoomError::NotModerator)) => {}
        other => panic!("a stranger changed a room: {other:?}"),
    }
    assert_eq!(
        mb.rooms_snapshot().rooms["lounge@acct"].join_policy,
        JoinPolicy::Open
    );
    mb.set_room_policy(
        "lounge@acct",
        "pm@acct",
        false,
        JoinPolicy::InviteOnly,
        DefaultSend::Muted,
    )
    .expect("creator");
    mb.invite_to_room("lounge@acct", "dev@acct", true, "dev@acct")
        .expect("admin");
    let room = &mb.rooms_snapshot().rooms["lounge@acct"];
    assert_eq!(room.join_policy, JoinPolicy::InviteOnly);
    assert_eq!(room.default_send, DefaultSend::Muted);
    assert!(room.invites.contains("dev@acct"));
}

#[test]
fn the_account_is_capped_at_its_room_limit() {
    let mut mb = mailbox();
    for i in 0..MAX_ROOMS {
        mb.create_room(&format!("r{i}@acct"), "account", suite::t0())
            .expect("create");
    }
    match mb.create_room("one-more@acct", "account", suite::t0()) {
        Err(MailError::Room(RoomError::RoomCap)) => {}
        other => panic!("the cap did not hold: {other:?}"),
    }
}

#[test]
fn a_delete_frees_the_name() {
    let mut mb = mailbox();
    mb.create_room("lounge@acct", "pm@acct", suite::t0())
        .expect("create");
    assert!(matches!(
        mb.delete_room("lounge@acct", "dev@acct", false),
        Err(MailError::Room(RoomError::NotModerator))
    ));
    mb.delete_room("lounge@acct", "pm@acct", false)
        .expect("delete");
    mb.create_room("lounge@acct", "dev@acct", suite::t0())
        .expect("name is free again");
}

#[test]
fn an_unknown_permission_string_still_invalidates_a_certificate_and_the_room_ones_parse() {
    use synapse::certificate::Permission;
    assert_eq!(
        Permission::parse("room-create"),
        Some(Permission::RoomCreate)
    );
    assert_eq!(Permission::parse("room-admin"), Some(Permission::RoomAdmin));
    assert_eq!(Permission::parse("room-typo"), None);
    assert_eq!(Permission::RoomCreate.as_str(), "room-create");
}

#[cfg(feature = "mailbox-redb")]
mod durable {
    use super::*;
    use synapse::mailbox::RedbStore;

    #[test]
    fn restart_keeps_rooms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.redb");
        let open = || {
            Mailbox::open(
                RedbStore::open(&path).unwrap(),
                MailConfig::default(),
                suite::t0() - chrono::Duration::seconds(1),
            )
            .unwrap()
        };
        {
            let mut mb = open();
            mb.create_room("lounge@acct", "pm@acct", suite::t0())
                .expect("create");
            mb.invite_to_room("lounge@acct", "pm@acct", false, "dev@acct")
                .expect("invite");
        }
        let mb = open();
        let room = &mb.rooms_snapshot().rooms["lounge@acct"];
        assert_eq!(room.creator, "pm@acct");
        assert!(room.invites.contains("dev@acct"));
    }
}
