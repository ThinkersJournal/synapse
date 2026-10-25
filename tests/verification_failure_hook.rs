// SPDX-License-Identifier: MIT OR Apache-2.0
//! QUIC pool eviction, slice 1: the manager tells the transport a message from `source` failed
//! verification. Spec: docs/superpowers/specs/2026-10-24-quic-pool-eviction-design.md.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use synapse::CryptoManager;
use synapse::error::Result;
use synapse::sealing::{self, SealingKeyPair};
use synapse::sender_auth::TrustStore;
use synapse::transport::TransportManagerBuilder;
use synapse::transport::abstraction::{
    ConnectivityResult, DeliveryReceipt, IncomingMessage, RawInbox, Transport,
    TransportCapabilities, TransportEstimate, TransportFactory, TransportMetrics, TransportReceive,
    TransportStatus, TransportTarget, TransportType, VerificationFailure,
};
use synapse::types::{SecureMessage, SecurityLevel};

const ALICE: &str = "alice@synapse.test";
const BOB: &str = "bob@synapse.test";
const CUSTOM: TransportType = TransportType::Custom(901);

type Calls = Arc<Mutex<Vec<(String, VerificationFailure)>>>;
type Queue = Arc<Mutex<Vec<IncomingMessage>>>;

/// Hands out whatever is queued, and records every `on_verification_failure` call.
struct Recording {
    queue: Queue,
    calls: Calls,
}

#[async_trait]
impl TransportReceive for Recording {
    async fn receive_raw(&self, inbox: &mut RawInbox) -> Result<()> {
        inbox.extend(std::mem::take(&mut *self.queue.lock().unwrap()));
        Ok(())
    }
}

#[async_trait]
impl Transport for Recording {
    fn transport_type(&self) -> TransportType {
        CUSTOM
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: 1024,
            reliable: true,
            real_time: false,
            broadcast: false,
            bidirectional: true,
            encrypted: false,
            network_spanning: false,
            supported_urgencies: vec![],
            features: vec![],
            unmeasured_metrics: vec![],
        }
    }
    async fn can_reach(&self, _target: &TransportTarget) -> bool {
        false
    }
    async fn estimate_metrics(&self, _target: &TransportTarget) -> Result<TransportEstimate> {
        unimplemented!("not used")
    }
    async fn send_message(
        &self,
        _target: &TransportTarget,
        _message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        unimplemented!("not used")
    }
    async fn test_connectivity(&self, _target: &TransportTarget) -> Result<ConnectivityResult> {
        unimplemented!("not used")
    }
    async fn start(&self) -> Result<()> {
        Ok(())
    }
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
    async fn status(&self) -> TransportStatus {
        TransportStatus::Running
    }
    async fn metrics(&self) -> TransportMetrics {
        TransportMetrics::default()
    }
    async fn on_verification_failure(&self, source: &str, reason: VerificationFailure) {
        self.calls
            .lock()
            .unwrap()
            .push((source.to_string(), reason));
    }
}

struct RecordingFactory {
    queue: Queue,
    calls: Calls,
}

#[async_trait]
impl TransportFactory for RecordingFactory {
    async fn create_transport(
        &self,
        _config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        Ok(Box::new(Recording {
            queue: Arc::clone(&self.queue),
            calls: Arc::clone(&self.calls),
        }))
    }
    fn transport_type(&self) -> TransportType {
        CUSTOM
    }
    fn default_config(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    fn validate_config(&self, _config: &HashMap<String, String>) -> Result<()> {
        Ok(())
    }
}

fn signer() -> CryptoManager {
    let mut crypto = CryptoManager::new();
    crypto.generate_keypair().unwrap();
    crypto
}

fn signed(who: &CryptoManager, text: &[u8]) -> SecureMessage {
    let mut m = SecureMessage::new(BOB, ALICE, text.to_vec(), SecurityLevel::Authenticated);
    who.sign_secure_message(&mut m).expect("sign");
    m
}

fn incoming(message: SecureMessage, source: &str) -> IncomingMessage {
    IncomingMessage::new(message, CUSTOM, source.to_string())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_transport_hears_of_a_rejected_or_unopenable_message_and_of_nothing_else() {
    let alice = signer();
    let stranger = signer();
    let bob_keys = SealingKeyPair::generate();
    let carol_keys = SealingKeyPair::generate();

    let mut store = TrustStore::new();
    store.pin(ALICE, alice.public_key_bytes().unwrap());

    let queue: Queue = Arc::default();
    let calls: Calls = Arc::default();
    let manager = TransportManagerBuilder::new()
        .disable_transport(TransportType::Tcp)
        .disable_transport(TransportType::Http)
        .disable_transport(TransportType::Email)
        .disable_transport(TransportType::AutoDiscovery)
        .disable_transport(TransportType::Udp)
        .enable_transport(CUSTOM)
        .trust_store(store)
        .sealing_key(bob_keys)
        .build();
    manager
        .register_factory(Box::new(RecordingFactory {
            queue: Arc::clone(&queue),
            calls: Arc::clone(&calls),
        }))
        .await
        .unwrap();
    manager.start().await.unwrap();

    // Contradicted: signed by Alice, then altered, so the signature no longer matches.
    let mut forged = signed(&alice, b"original");
    forged.to_global_id.push('x');
    // Unknown sender: a validly signed message from an id nobody pinned.
    let mut unknown = SecureMessage::new(
        BOB,
        "eve@synapse.test",
        b"who".to_vec(),
        SecurityLevel::Authenticated,
    );
    stranger.sign_secure_message(&mut unknown).unwrap();
    // Unopenable: genuinely Alice's, but sealed to Carol.
    let mut sealed = SecureMessage::new(BOB, ALICE, b"for carol".to_vec(), SecurityLevel::Secure);
    sealing::seal(&mut sealed, carol_keys.public_key()).unwrap();
    alice.sign_secure_message(&mut sealed).unwrap();

    queue.lock().unwrap().extend([
        incoming(signed(&alice, b"fine"), "10.0.0.1:1"), // verified: no call
        incoming(forged, "10.0.0.2:2"),                  // Rejected
        incoming(unknown, "10.0.0.3:3"),                 // unknown sender: no call
        incoming(sealed, "10.0.0.4:4"),                  // Unopenable
    ]);
    let delivered = manager.receive_messages().await.unwrap();
    // The verified message and the unopenable one both reach the application.
    assert_eq!(delivered.len(), 2, "verified and unopenable are delivered");

    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            ("10.0.0.2:2".to_string(), VerificationFailure::Rejected),
            ("10.0.0.4:4".to_string(), VerificationFailure::Unopenable),
        ],
        "exactly one call per rejected or unopenable message; none for a verified or unknown sender"
    );
}
