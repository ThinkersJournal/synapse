// SPDX-License-Identifier: MIT OR Apache-2.0
//! The trust book (ROADMAP row 33, slice 1): a first contact is a knock that grants nothing, and the
//! holder pins an account key from a knock only by typing its key id back.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use synapse::CryptoManager;
use synapse::certificate::{AgentCertificate, Permission};
use synapse::keystore::trust_book::{MAX_FIELD, MAX_KNOCKS, PinError, TrustBook};
use synapse::sender_auth::{SenderVerdict, TrustStore, UnverifiableReason, key_id};
use synapse::types::{SecureMessage, SecurityLevel};

fn account_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn agent() -> CryptoManager {
    let mut crypto = CryptoManager::new();
    crypto.generate_keypair().expect("keypair");
    crypto
}

/// A certificate from `account` for `holder`, valid for an hour around now.
fn cert_for(account: &SigningKey, holder: &CryptoManager, global_id: &str) -> AgentCertificate {
    let now = Utc::now();
    AgentCertificate::sign(
        AgentCertificate {
            version: 1,
            serial: [3; 16],
            issuer_key_id: key_id(&account.verifying_key().to_bytes()),
            subject_label: "agent".to_string(),
            subject_global_id: global_id.to_string(),
            subject_signing_key: holder.public_key_bytes().expect("public key"),
            subject_sealing_key: [0u8; 32],
            not_before: now - Duration::minutes(1),
            not_after: now + Duration::hours(1),
            permissions: vec![Permission::Send],
            may_delegate: 1,
            signature: [0u8; 64],
        },
        account,
    )
}

/// A signed message from `holder` carrying a one-link chain from `account`.
fn message_from(account: &SigningKey, holder: &mut CryptoManager, from: &str) -> SecureMessage {
    let chain = vec![cert_for(account, holder, from)];
    holder.set_certificate_chain(chain);
    let mut m = SecureMessage::new(
        "bob@synapse.test",
        from,
        b"hello".to_vec(),
        SecurityLevel::Authenticated,
    );
    holder.sign_secure_message(&mut m).expect("sign");
    m
}

fn account_id(account: &SigningKey) -> String {
    key_id(&account.verifying_key().to_bytes())
}

/// A trust book in a fresh home, with one knock from `account` through `agent@alice.test`.
fn book_with_a_knock(account: &SigningKey) -> (tempfile::TempDir, TrustBook) {
    let home = tempfile::tempdir().unwrap();
    let book = TrustBook::open(home.path());
    book.record_knock(
        "agent@alice.test",
        "senderkeyid",
        Some(&account_id(account)),
        "unknown_issuer",
        Utc::now(),
    )
    .unwrap();
    (home, book)
}

#[test]
fn a_knock_alone_grants_nothing_and_a_pin_does() {
    let account = account_key(21);
    let mut alice = agent();
    let message = message_from(&account, &mut alice, "agent@alice.test");
    let (_home, book) = book_with_a_knock(&account);

    // The knock is on the book, and a store loaded from the book trusts nobody.
    assert_eq!(book.knocks().unwrap().len(), 1);
    let mut store = TrustStore::new();
    assert_eq!(book.load_into(&mut store).unwrap(), 0);
    assert!(store.account_key_ids().is_empty());
    assert_eq!(
        store.verify(&message),
        SenderVerdict::Unverifiable {
            reason: UnverifiableReason::UnknownIssuer
        },
        "a knock does not make the account believed"
    );

    // Control: the holder pins the account key from the knock, and the same message verifies.
    let pinned = book
        .pin(
            "alice",
            account.verifying_key().to_bytes(),
            &account_id(&account),
            Utc::now(),
        )
        .unwrap();
    assert_eq!(pinned.key_id, account_id(&account));
    let mut store = TrustStore::new();
    assert_eq!(book.load_into(&mut store).unwrap(), 1);
    assert!(
        matches!(store.verify(&message), SenderVerdict::Verified { .. }),
        "{:?}",
        store.verify(&message)
    );
}

#[test]
fn a_pin_needs_a_name_the_key_id_typed_back_and_a_listed_knock() {
    let account = account_key(22);
    let key = account.verifying_key().to_bytes();
    let (_home, book) = book_with_a_knock(&account);
    let id = account_id(&account);
    let now = Utc::now();

    // Each refusal writes nothing: the knock stays and nothing is pinned.
    assert_eq!(
        book.pin("not a name", key, &id, now),
        Err(PinError::BadLabel)
    );
    assert_eq!(
        book.pin("alice", key, "", now),
        Err(PinError::ConfirmationMismatch),
        "no confirmation is not a yes"
    );
    assert_eq!(
        book.pin("alice", key, &id[..32], now),
        Err(PinError::ConfirmationMismatch),
        "half the id is not the id"
    );
    let other = account_key(23);
    assert_eq!(
        book.pin("alice", key, &account_id(&other), now),
        Err(PinError::ConfirmationMismatch),
        "another key's id typed for this key"
    );
    // The right key and id, but no knock names it.
    let stranger = account_key(24);
    assert_eq!(
        book.pin(
            "stranger",
            stranger.verifying_key().to_bytes(),
            &account_id(&stranger),
            now
        ),
        Err(PinError::NoSuchKnock),
        "a pin is made only from a knock"
    );
    assert!(book.pinned().unwrap().is_empty());
    assert_eq!(book.knocks().unwrap().len(), 1);

    // Control: the id typed back (any case, with stray space) pins it, and the answered knock goes.
    let typed = format!(" {} ", id.to_ascii_uppercase());
    book.pin("alice", key, &typed, now).unwrap();
    assert_eq!(book.pinned().unwrap().len(), 1);
    assert!(book.knocks().unwrap().is_empty());

    // The same key again is refused even if it knocks again.
    book.record_knock("agent@alice.test", "k", Some(&id), "unknown_issuer", now)
        .unwrap();
    assert_eq!(
        book.pin("alice2", key, &id, now),
        Err(PinError::AlreadyPinned)
    );
}

#[test]
fn knocks_are_bounded_cut_to_length_and_counted() {
    let home = tempfile::tempdir().unwrap();
    let book = TrustBook::open(home.path());
    let t0 = Utc::now();

    // The same knock again is counted, not duplicated.
    for i in 0..3 {
        book.record_knock(
            "a@x",
            "k1",
            Some("acct1"),
            "unknown_issuer",
            t0 + Duration::seconds(i),
        )
        .unwrap();
    }
    let knocks = book.knocks().unwrap();
    assert_eq!(knocks.len(), 1);
    assert_eq!(knocks[0].count, 3);

    // Text off the wire is cut.
    let long = "x".repeat(MAX_FIELD * 3);
    book.record_knock(&long, &long, Some(&long), &long, t0)
        .unwrap();
    let cut = book
        .knocks()
        .unwrap()
        .into_iter()
        .find(|k| k.claimed_global_id.starts_with("xxx"))
        .unwrap();
    assert_eq!(cut.claimed_global_id.chars().count(), MAX_FIELD);
    assert_eq!(cut.sender_key_id.chars().count(), MAX_FIELD);
    assert_eq!(cut.account_key_id.unwrap().chars().count(), MAX_FIELD);
    assert_eq!(cut.reason.chars().count(), MAX_FIELD);

    // More distinct knocks than the bound: the book stays at the bound and the oldest went.
    for i in 0..(MAX_KNOCKS + 5) {
        book.record_knock(
            &format!("n{i}@x"),
            "k",
            None,
            "unsigned",
            t0 + Duration::seconds(10 + i64::try_from(i).unwrap()),
        )
        .unwrap();
    }
    let knocks = book.knocks().unwrap();
    assert_eq!(knocks.len(), MAX_KNOCKS);
    assert!(knocks.iter().all(|k| k.claimed_global_id != "a@x"));
    assert!(
        knocks
            .iter()
            .any(|k| k.claimed_global_id == format!("n{}@x", MAX_KNOCKS + 4)),
        "the newest is kept"
    );
    assert_eq!(
        knocks[0].claimed_global_id,
        format!("n{}@x", MAX_KNOCKS + 4),
        "newest first"
    );
}

#[test]
fn a_hand_edited_pin_is_corrupt_and_never_loaded() {
    let account = account_key(25);
    let (home, book) = book_with_a_knock(&account);
    book.pin(
        "alice",
        account.verifying_key().to_bytes(),
        &account_id(&account),
        Utc::now(),
    )
    .unwrap();
    // The file now names a key whose hash is not the id it claims.
    let path = home.path().join("trust").join("trusted_accounts.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let swapped = text.replace(
        &hex(&account.verifying_key().to_bytes()),
        &hex(&account_key(26).verifying_key().to_bytes()),
    );
    assert_ne!(swapped, text, "the edit applied");
    write_private(&path, swapped.as_bytes());
    let mut store = TrustStore::new();
    assert!(book.load_into(&mut store).is_err());
    assert!(store.account_key_ids().is_empty(), "nothing was loaded");
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write a book file by hand the way the keystore does: owner-only on Unix, which it checks.
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
