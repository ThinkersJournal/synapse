// SPDX-License-Identifier: MIT OR Apache-2.0
//! `TransportManager` and the trust book (ROADMAP row 33, slice 1b): a first contact from an
//! account nobody pinned is written down as a knock and grants nothing; the holder's pin, loaded at
//! start or by `reload_trust_book`, is what makes the account believed. Over the real UDP transport.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use synapse::CryptoManager;
use synapse::certificate::{AgentCertificate, Permission};
use synapse::keystore::trust_book::TrustBook;
use synapse::sender_auth::{SenderVerdict, key_id};
use synapse::transport::{TransportManager, TransportManagerBuilder, TransportType};
use synapse::types::{SecureMessage, SecurityLevel};

mod common;
use common::free_udp_port;

fn account_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn account_id(account: &SigningKey) -> String {
    key_id(&account.verifying_key().to_bytes())
}

fn agent() -> CryptoManager {
    let mut crypto = CryptoManager::new();
    crypto.generate_keypair().expect("keypair");
    crypto
}

fn cert_for(account: &SigningKey, holder: &CryptoManager, global_id: &str) -> AgentCertificate {
    let now = Utc::now();
    AgentCertificate::sign(
        AgentCertificate {
            version: 1,
            serial: [4; 16],
            issuer_key_id: account_id(account),
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

/// A new signed message from `holder` claiming `from`, carrying a one-link chain from `account`.
fn chain_message(account: &SigningKey, holder: &mut CryptoManager, from: &str) -> SecureMessage {
    holder.set_certificate_chain(vec![cert_for(account, holder, from)]);
    let mut m = SecureMessage::new(
        "bob@synapse.test",
        from,
        b"hello".to_vec(),
        SecurityLevel::Authenticated,
    );
    holder.sign_secure_message(&mut m).expect("sign");
    m
}

/// A UDP-only node that uses `book`.
async fn node(book: TrustBook) -> (TransportManager, u16) {
    let port = free_udp_port();
    let mut udp = std::collections::HashMap::new();
    udp.insert("bind_port".to_string(), port.to_string());
    let manager = TransportManagerBuilder::new()
        .disable_transport(TransportType::Tcp)
        .disable_transport(TransportType::Http)
        .disable_transport(TransportType::Email)
        .disable_transport(TransportType::AutoDiscovery)
        .transport_config(TransportType::Udp, udp)
        .trust_book(book)
        .build();
    manager
        .register_factory(Box::new(synapse::transport::UdpTransportFactory))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), manager.start())
        .await
        .expect("start() returns")
        .expect("start() succeeds");
    (manager, port)
}

fn send_raw(port: u16, message: &SecureMessage) {
    let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    raw.send_to(&serde_json::to_vec(message).unwrap(), ("127.0.0.1", port))
        .unwrap();
}

async fn drain(manager: &TransportManager) -> Vec<synapse::transport::ReceivedMessage> {
    let mut out = Vec::new();
    for _ in 0..15 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        out.extend(manager.receive_messages().await.expect("receive"));
    }
    out
}

fn fresh_book() -> (tempfile::TempDir, TrustBook) {
    let home = tempfile::tempdir().unwrap();
    let book = TrustBook::open(home.path());
    (home, book)
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_account_knocks_into_the_book_and_only_the_holders_pin_gets_it_believed() {
    let account = account_key(31);
    let mut alice = agent();
    let (_home, book) = fresh_book();
    let (manager, port) = node(book.clone()).await;

    // First contact: dropped, written to the book with the account key id its chain named.
    send_raw(
        port,
        &chain_message(&account, &mut alice, "agent@alice.test"),
    );
    assert!(drain(&manager).await.is_empty());
    let knocks = book.knocks().unwrap();
    assert_eq!(knocks.len(), 1, "{knocks:?}");
    assert_eq!(knocks[0].claimed_global_id, "agent@alice.test");
    assert_eq!(
        knocks[0].account_key_id.as_deref(),
        Some(account_id(&account).as_str())
    );
    assert_eq!(knocks[0].reason, "unknown_issuer");

    // The knock grants nothing: nothing is pinned, and a second message is still dropped.
    assert!(manager.trust_store().await.account_key_ids().is_empty());
    send_raw(
        port,
        &chain_message(&account, &mut alice, "agent@alice.test"),
    );
    assert!(drain(&manager).await.is_empty());

    // The holder pins from the knock and the running manager is told to reload: now it is believed.
    book.pin(
        "alice",
        account.verifying_key().to_bytes(),
        &account_id(&account),
        Utc::now(),
    )
    .unwrap();
    assert_eq!(manager.reload_trust_book().await.unwrap(), 1);
    send_raw(
        port,
        &chain_message(&account, &mut alice, "agent@alice.test"),
    );
    let got = drain(&manager).await;
    assert_eq!(got.len(), 1);
    assert!(
        matches!(got[0].sender, SenderVerdict::Verified { .. }),
        "{:?}",
        got[0].sender
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_manager_built_with_a_book_trusts_the_accounts_in_it_and_nobody_else() {
    let pinned = account_key(32);
    let stranger = account_key(33);
    let (mut alice, mut mallory) = (agent(), agent());
    let (_home, book) = fresh_book();
    book.record_knock(
        "agent@alice.test",
        "k",
        Some(&account_id(&pinned)),
        "unknown_issuer",
        Utc::now(),
    )
    .unwrap();
    book.pin(
        "alice",
        pinned.verifying_key().to_bytes(),
        &account_id(&pinned),
        Utc::now(),
    )
    .unwrap();
    let (manager, port) = node(book).await;

    send_raw(
        port,
        &chain_message(&pinned, &mut alice, "agent@alice.test"),
    );
    let got = drain(&manager).await;
    assert_eq!(
        got.len(),
        1,
        "the pinned account is believed from the start"
    );

    send_raw(
        port,
        &chain_message(&stranger, &mut mallory, "agent@mallory.test"),
    );
    assert!(
        drain(&manager).await.is_empty(),
        "an account nobody pinned is not"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn knock_writes_are_throttled_per_sender_and_per_source() {
    let account = account_key(34);
    let mut alice = agent();
    let (_home, book) = fresh_book();
    let (manager, port) = node(book.clone()).await;

    // The same sender five times inside the window: one write, not five.
    for _ in 0..5 {
        send_raw(
            port,
            &chain_message(&account, &mut alice, "agent@alice.test"),
        );
    }
    drain(&manager).await;
    let knocks = book.knocks().unwrap();
    assert_eq!(knocks.len(), 1, "{knocks:?}");
    assert_eq!(
        knocks[0].count, 1,
        "repeats inside the window are not written"
    );

    // One source claiming many ids: the book gets at most ten of them per window.
    for i in 0..15 {
        send_raw(
            port,
            &chain_message(&account, &mut alice, &format!("agent{i}@alice.test")),
        );
    }
    drain(&manager).await;
    assert_eq!(
        book.knocks().unwrap().len(),
        10,
        "one source's writes are capped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_knock_the_holder_can_act_on_is_written_to_the_book() {
    let stranger = agent();
    let (_home, book) = fresh_book();
    let (manager, port) = node(book.clone()).await;

    // Signed, but no chain: nothing names an account key to pin.
    let mut m = SecureMessage::new(
        "bob@synapse.test",
        "agent@nowhere.test",
        b"hello".to_vec(),
        SecurityLevel::Authenticated,
    );
    stranger.sign_secure_message(&mut m).expect("sign");
    send_raw(port, &m);
    assert!(drain(&manager).await.is_empty());
    assert_eq!(
        manager.knocks().await.len(),
        1,
        "the in-memory record still has it"
    );
    assert!(
        book.knocks().unwrap().is_empty(),
        "but the book only holds knocks that name an account key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_book_that_cannot_be_read_pins_nothing_and_the_manager_still_starts() {
    let account = account_key(35);
    let mut alice = agent();
    let (home, book) = fresh_book();
    book.record_knock("a@x", "k", None, "unsigned", Utc::now())
        .unwrap();
    write_private(
        &home.path().join("trust").join("trusted_accounts.json"),
        b"this is not json",
    );
    let (manager, port) = node(book).await;
    assert!(manager.trust_store().await.account_key_ids().is_empty());
    assert!(manager.reload_trust_book().await.is_err());

    send_raw(
        port,
        &chain_message(&account, &mut alice, "agent@alice.test"),
    );
    assert!(
        drain(&manager).await.is_empty(),
        "fail closed: nobody is believed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_that_fails_for_another_reason_is_not_written_to_the_book() {
    let account = account_key(36);
    let mut alice = agent();
    let (_home, book) = fresh_book();
    // The holder pinned this account (a knock first, as a pin needs one), so its chain is
    // validated; a certificate whose signature is bad is `invalid_chain`, not a first contact.
    book.record_knock(
        "agent@alice.test",
        "k",
        Some(&account_id(&account)),
        "unknown_issuer",
        Utc::now(),
    )
    .unwrap();
    book.pin(
        "alice",
        account.verifying_key().to_bytes(),
        &account_id(&account),
        Utc::now(),
    )
    .unwrap();
    let (manager, port) = node(book.clone()).await;

    let mut cert = cert_for(&account, &alice, "agent@alice.test");
    cert.signature = [0u8; 64];
    alice.set_certificate_chain(vec![cert]);
    let mut m = SecureMessage::new(
        "bob@synapse.test",
        "agent@alice.test",
        b"hello".to_vec(),
        SecurityLevel::Authenticated,
    );
    alice.sign_secure_message(&mut m).expect("sign");
    send_raw(port, &m);
    assert!(drain(&manager).await.is_empty());
    assert_eq!(manager.knocks().await[0].reason, "invalid_chain");
    assert!(
        book.knocks().unwrap().is_empty(),
        "a chain that fails its own rules is not a first contact"
    );
}
