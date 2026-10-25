// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport Manager - Unified abstraction layer for all transport mechanisms
//!
//! The TransportManager provides a single interface for applications to send/receive
//! messages across all available transport types, with intelligent transport selection,
//! automatic failover, and unified metrics.

use super::abstraction::*;
use crate::certificate;
use crate::crypto::CryptoManager;
use crate::delivery_ack;
use crate::error::SynapseError;
use crate::sender_auth::{SenderVerdict, TrustStore, UnverifiableReason};
use crate::{
    circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, RequestOutcome},
    error::Result,
    types::SecureMessage,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock as TokioRwLock};
use tracing::{debug, info, warn};

/// Configuration for the TransportManager
#[derive(Debug, Clone)]
pub struct TransportManagerConfig {
    /// Enabled transport types
    pub enabled_transports: Vec<TransportType>,
    /// Transport selection policy
    pub selection_policy: TransportSelectionPolicy,
    /// Failover configuration
    pub failover_config: FailoverConfig,
    /// Maximum time to wait for transport operations
    pub operation_timeout: Duration,
    /// How often to update transport metrics
    pub metrics_update_interval: Duration,
    /// Transport-specific configurations
    pub transport_configs: HashMap<TransportType, HashMap<String, String>>,
    /// Circuit breaker configuration
    pub circuit_breaker_config: CircuitBreakerConfig,
}

impl Default for TransportManagerConfig {
    fn default() -> Self {
        Self {
            enabled_transports: vec![
                TransportType::Tcp,
                TransportType::Udp,
                TransportType::Http,
                TransportType::Email,
                TransportType::AutoDiscovery,
            ],
            selection_policy: TransportSelectionPolicy::Adaptive,
            failover_config: FailoverConfig::default(),
            operation_timeout: Duration::from_secs(30),
            metrics_update_interval: Duration::from_secs(60),
            transport_configs: HashMap::new(),
            circuit_breaker_config: CircuitBreakerConfig {
                failure_threshold: 5,
                minimum_requests: 10,
                failure_window: Duration::from_secs(60),
                recovery_timeout: Duration::from_secs(60),
                half_open_max_calls: 3,
                success_threshold: 0.6,
            },
        }
    }
}

/// Transport selection policies
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TransportSelectionPolicy {
    /// Always use the first available transport
    FirstAvailable,
    /// Select based on message urgency
    UrgencyBased,
    /// Select based on past performance metrics
    PerformanceBased,
    /// Adaptive selection using ML-style learning
    Adaptive,
    /// Round-robin across available transports
    RoundRobin,
    /// Prefer specific transport types
    PreferenceOrder,
}

/// Failover configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    /// Enable automatic failover
    pub enabled: bool,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries (with exponential backoff)
    pub retry_delay: Duration,
    /// Maximum delay between retries
    pub max_retry_delay: Duration,
    /// When to consider a transport failed
    pub failure_threshold: f64,
    /// How long to wait before retrying a failed transport
    pub recovery_timeout: Duration,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
            max_retry_delay: Duration::from_secs(30),
            failure_threshold: 0.5,                     // 50% failure rate
            recovery_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Transport selection scoring weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionWeights {
    pub latency: f64,
    pub reliability: f64,
    pub bandwidth: f64,
    pub cost: f64,
    pub capability_match: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            latency: 0.3,
            reliability: 0.3,
            bandwidth: 0.2,
            cost: 0.1,
            capability_match: 0.1,
        }
    }
}

/// A received message together with what this node concluded about its sender.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub incoming: IncomingMessage,
    pub sender: SenderVerdict,
    /// The body as this node could read it (P2 slice d): plain, opened, or marked unopenable.
    pub payload: crate::sealing::Payload,
    /// Whether the signed timestamp could be checked, and what it said (P2 slice e).
    pub freshness: crate::replay::Freshness,
    /// The certificate chain's summary (P2 slice f1) -- present only when the chain it describes
    /// is the very chain that authenticated `sender` as `Verified`: its subject names this
    /// message's claimed sender, and its subject signing key is the key `sender`'s `key_id`
    /// names. `None` for a directly pinned sender (even one whose message happens to carry an
    /// unrelated or stale chain for the same id), and for any sender that is not `Verified`.
    pub certificate: Option<crate::certificate::VerifiedChain>,
}

/// A sent message that asked for an ack (P2 slice b).
struct Outbound {
    to_global_id: String,
    digest: String,
    status: DeliveryConfirmation,
}

/// Main TransportManager that provides unified transport abstraction
pub struct TransportManager {
    /// Configuration
    config: TransportManagerConfig,
    /// Available transport instances
    transports: TokioRwLock<HashMap<TransportType, Box<dyn Transport>>>,
    /// Transport factories for creating new instances
    factories: RwLock<HashMap<TransportType, Arc<Box<dyn TransportFactory>>>>,
    /// Circuit breakers per transport
    circuit_breakers: RwLock<HashMap<TransportType, Arc<CircuitBreaker>>>,
    /// Unified metrics
    metrics: Arc<RwLock<UnifiedMetrics>>,
    /// Current transport status
    transport_status: TokioRwLock<HashMap<TransportType, TransportStatus>>,
    /// Selection weights for adaptive algorithm
    selection_weights: Arc<RwLock<SelectionWeights>>,
    /// Last selection index for round-robin
    round_robin_index: Arc<Mutex<usize>>,
    /// Failed transports and their recovery times
    failed_transports: TokioRwLock<HashMap<TransportType, Instant>>,
    /// Pinned sender keys; see `crate::sender_auth`.
    trust_store: TokioRwLock<TrustStore>,
    /// Messages sent with `request_ack`, by message id, bounded by age and count (P2 slice e).
    outbound: TokioRwLock<crate::replay::Bounded<Outbound>>,
    /// This node's X25519 sealing key; sealed bodies are opened with it.
    sealing_key: TokioRwLock<Option<crate::sealing::SealingKeyPair>>,
    /// The delivery gate and the replay record (P2 slice e).
    inbound: TokioRwLock<crate::replay::InboundState>,
    /// Security events on the receive path (hardening P6). Without a sink it records nothing.
    events: super::security::TransportEvents,
}

/// Unified metrics across all transports
#[derive(Debug, Default, Clone)]
pub struct UnifiedMetrics {
    /// Per-transport metrics
    pub transport_metrics: HashMap<TransportType, TransportMetrics>,
    /// Total messages sent across all transports
    pub total_messages_sent: u64,
    /// Total messages received across all transports
    pub total_messages_received: u64,
    /// Total failures across all transports
    pub total_failures: u64,
    /// Overall reliability score
    pub overall_reliability: f64,
    /// Average latency across all transports
    pub average_latency: Duration,
    /// Last updated timestamp
    pub last_updated_timestamp: u64,
}

impl UnifiedMetrics {
    /// Update the last updated timestamp to now
    pub fn touch(&mut self) {
        self.last_updated_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

impl TransportManager {
    /// Public API: Select optimal transport for a target
    pub async fn select_optimal_transport(
        &self,
        target: &TransportTarget,
    ) -> Result<TransportType> {
        let available_transports: Vec<_> = {
            let transports = self.transports.read().await;
            transports.keys().cloned().collect()
        };

        if available_transports.is_empty() {
            return Err(crate::error::SynapseError::TransportError(
                "No transports available".to_string(),
            ));
        }

        // Check target preferences first
        for &preferred in &target.preferred_transports {
            if available_transports.contains(&preferred) {
                let transports = self.transports.read().await;
                if let Some(transport) = transports.get(&preferred)
                    && transport.can_reach(target).await
                {
                    return Ok(preferred);
                }
            }
        }

        // Fall back to the first available transport that can reach the target
        let transports = self.transports.read().await;
        for &transport_type in &available_transports {
            if let Some(transport) = transports.get(&transport_type)
                && transport.can_reach(target).await
            {
                return Ok(transport_type);
            }
        }

        Err(crate::error::SynapseError::TransportError(
            "No suitable transport found".to_string(),
        ))
    }
    /// Create a new TransportManager
    pub fn new(config: TransportManagerConfig) -> Self {
        Self {
            config,
            transports: TokioRwLock::new(HashMap::new()),
            factories: RwLock::new(HashMap::new()),
            circuit_breakers: RwLock::new(HashMap::new()),
            metrics: Arc::new(RwLock::new(UnifiedMetrics::default())),
            transport_status: TokioRwLock::new(HashMap::new()),
            selection_weights: Arc::new(RwLock::new(SelectionWeights::default())),
            round_robin_index: Arc::new(Mutex::new(0)),
            failed_transports: TokioRwLock::new(HashMap::new()),
            trust_store: TokioRwLock::new(TrustStore::default()),
            outbound: TokioRwLock::new(crate::replay::Bounded::new(
                chrono::Duration::hours(1),
                10_000,
            )),
            sealing_key: TokioRwLock::new(None),
            inbound: TokioRwLock::new(crate::replay::InboundState::new(
                crate::replay::ReplayConfig::default(),
                crate::replay::GateConfig::default(),
                chrono::Utc::now(),
            )),
            events: super::security::TransportEvents::new(
                super::security::KnockLimits::default(),
                None,
            ),
        }
    }

    /// Register a transport factory
    pub async fn register_factory(&self, factory: Box<dyn TransportFactory>) -> Result<()> {
        let transport_type = factory.transport_type();
        info!("Registering transport factory for {:?}", transport_type);

        // Create circuit breaker for this transport
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            self.config.circuit_breaker_config.clone(),
        ));

        {
            let mut factories = self.factories.write().unwrap();
            factories.insert(transport_type, Arc::new(factory));
        }

        {
            let mut breakers = self.circuit_breakers.write().unwrap();
            breakers.insert(transport_type, circuit_breaker);
        }

        {
            let mut status = self.transport_status.write().await;
            status.insert(transport_type, TransportStatus::Stopped);
        }

        Ok(())
    }

    /// Initialize and start all enabled transports
    pub async fn start(&self) -> Result<()> {
        info!(
            "Starting TransportManager with {} enabled transports",
            self.config.enabled_transports.len()
        );

        for &transport_type in &self.config.enabled_transports {
            if let Err(e) = self.start_transport(transport_type).await {
                warn!("Failed to start transport {:?}: {}", transport_type, e);
                // Continue with other transports
            }
        }

        // Start metrics update task
        self.start_metrics_task().await;

        info!("TransportManager started successfully");
        Ok(())
    }

    /// Start a specific transport
    async fn start_transport(&self, transport_type: TransportType) -> Result<()> {
        debug!("Starting transport {:?}", transport_type);

        // Update status to starting. The guard must be released at the end of this
        // statement: the lock is taken again below, and tokio's RwLock is not
        // reentrant, so holding it here hung start() (tests/transport_manager_starts.rs).
        self.transport_status
            .write()
            .await
            .insert(transport_type, TransportStatus::Starting);

        // Hold the lock, call factory methods, and only store owned values after
        let (factory, config) = {
            let factories = self.factories.read().unwrap();
            if let Some(factory) = factories.get(&transport_type) {
                let config = self
                    .config
                    .transport_configs
                    .get(&transport_type)
                    .cloned()
                    .unwrap_or_else(|| factory.default_config());
                (Arc::clone(factory), config)
            } else {
                return Err(crate::error::SynapseError::TransportError(format!(
                    "Transport {transport_type:?} not registered"
                )));
            }
        };
        // factories guard dropped here

        let transport = match factory.create_transport(&config).await {
            Ok(transport) => transport,
            Err(e) => {
                return Err(crate::error::SynapseError::TransportError(format!(
                    "Failed to create transport {transport_type:?}: {e}"
                )));
            }
        };

        // Events a transport records itself go to the same sink as the receive path's (P7).
        if let Some(sink) = self.events.sink() {
            transport.attach_security_sink(Arc::clone(sink));
        }

        // Start the transport
        transport.start().await?;

        // Store the transport instance
        {
            let mut transports = self.transports.write().await;
            transports.insert(transport_type, transport);
        }

        // Update status to running
        {
            let mut status = self.transport_status.write().await;
            status.insert(transport_type, TransportStatus::Running);
        }

        info!("Transport {:?} started successfully", transport_type);
        Ok(())
    }

    /// Stop all transports gracefully
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping TransportManager");

        let transport_types: Vec<TransportType> = {
            let transports = self.transports.read().await;
            transports.keys().cloned().collect()
        };

        for transport_type in transport_types {
            if let Err(e) = self.stop_transport(transport_type).await {
                warn!("Failed to stop transport {:?}: {}", transport_type, e);
            }
        }

        info!("TransportManager stopped");
        Ok(())
    }

    /// Stop a specific transport
    async fn stop_transport(&self, transport_type: TransportType) -> Result<()> {
        debug!("Stopping transport {:?}", transport_type);

        // Update status to stopping
        {
            let mut status = self.transport_status.write().await;
            status.insert(transport_type, TransportStatus::Stopping);
        }

        // Stop the transport
        {
            let mut transports = self.transports.write().await;
            if let Some(transport) = transports.remove(&transport_type) {
                transport.stop().await?;
            }
        }

        // Update status to stopped
        {
            let mut status = self.transport_status.write().await;
            status.insert(transport_type, TransportStatus::Stopped);
        }

        info!("Transport {:?} stopped", transport_type);
        Ok(())
    }

    /// Send a message using the best available transport
    pub async fn send_message(
        &self,
        target: &TransportTarget,
        message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        debug!("Sending message to target: {}", target.identifier);

        let selected_transports = self.select_transports(target).await?;

        // Why each transport did not send, so the caller learns more than "all failed".
        let mut reasons = Vec::new();
        for transport_type in selected_transports {
            // Check if transport is failed and in recovery
            if self.is_transport_in_recovery(transport_type).await {
                debug!("Transport {:?} is in recovery, skipping", transport_type);
                reasons.push(format!(
                    "{transport_type:?}: in recovery after earlier failures"
                ));
                continue;
            }

            match self
                .try_send_with_transport(transport_type, target, message)
                .await
            {
                Ok(receipt) => {
                    self.record_success(transport_type).await;
                    self.update_transport_metrics(transport_type, true, receipt.delivery_time)
                        .await;
                    self.track_if_ack_requested(message).await;
                    return Ok(receipt);
                }
                // The transport refused this message (too large, say) without touching the
                // network. That says nothing about the transport's health, so it is not
                // recorded against it; another transport may still take the message.
                Err(e @ SynapseError::MessageRefused(_)) => {
                    debug!("{:?} refused the message: {}", transport_type, e);
                    reasons.push(format!("{transport_type:?}: {e}"));
                }
                Err(e) => {
                    warn!("Failed to send via {:?}: {}", transport_type, e);
                    reasons.push(format!("{transport_type:?}: {e}"));
                    self.record_failure(transport_type).await;
                    self.update_transport_metrics(transport_type, false, Duration::from_secs(0))
                        .await;

                    // Check if we should mark this transport as failed
                    if self.should_mark_transport_failed(transport_type).await {
                        self.mark_transport_failed(transport_type).await;
                    }
                }
            }
        }

        Err(crate::error::SynapseError::TransportError(format!(
            "All transports failed: {}",
            if reasons.is_empty() {
                "none was selected".to_string()
            } else {
                reasons.join("; ")
            }
        )))
    }

    /// Acknowledge a message the application has processed (P2 slice b, spec §5). Refuses, sending
    /// nothing, unless the sender was verified (anti-reflector rule), the message asked for an ack,
    /// and it is not itself an ack. Calling it again sends another ack; the sender treats the
    /// duplicate as a no-op.
    pub async fn acknowledge(
        &self,
        received: &ReceivedMessage,
        signer: &CryptoManager,
    ) -> Result<DeliveryReceipt> {
        let original = &received.incoming.message;
        if !received.sender.is_verified() {
            return Err(SynapseError::AuthenticationError(format!(
                "refusing to acknowledge {}: sender verdict is {:?}",
                original.message_id, received.sender
            )));
        }
        if let crate::sealing::Payload::CouldNotOpen(reason) = &received.payload {
            return Err(SynapseError::InvalidMessageFormat(format!(
                "refusing to acknowledge {}: its body could not be opened ({reason})",
                original.message_id
            )));
        }
        if delivery_ack::is_ack(original) {
            return Err(SynapseError::InvalidMessageFormat(format!(
                "{} is an ack; acks are never acknowledged",
                original.message_id
            )));
        }
        let Some(reply_to) = delivery_ack::reply_to(original) else {
            return Err(SynapseError::InvalidMessageFormat(format!(
                "{} did not request an ack (no {})",
                original.message_id,
                delivery_ack::REPLY_TO_KEY
            )));
        };
        let ack = delivery_ack::build_ack(original, signer)?;
        let target = TransportTarget::new(original.from_global_id.clone())
            .with_address(reply_to.to_string());
        self.send_message(&target, &ack).await
    }

    /// Delivery status of a message sent with `request_ack`; `None` if it was not tracked.
    ///
    /// Acks are applied inside `receive_messages` and the manager has no background receive loop,
    /// so a status only advances while the application keeps calling `receive_messages`.
    pub async fn delivery_status(&self, message_id: &str) -> Option<DeliveryConfirmation> {
        let now = chrono::Utc::now();
        let outbound = self.outbound.write().await;
        let ttl = outbound.ttl();
        let expired = outbound
            .age_of(message_id, now)
            .is_some_and(|age| age > ttl);
        let status = outbound.get(message_id).map(|entry| entry.status);
        // No sweep here: the spec (§6) says `Expired` is reported for as long as the entry
        // remains. `tracked_count` and `Bounded::insert` still sweep, so the map stays bounded.
        match status {
            // An ack that arrived is final; only an unacknowledged entry expires.
            Some(DeliveryConfirmation::Sent | DeliveryConfirmation::Delivered) if expired => {
                Some(DeliveryConfirmation::Expired)
            }
            other => other,
        }
    }

    /// How many messages are currently tracked for an ack, after sweeping expired entries.
    pub async fn tracked_count(&self) -> usize {
        let now = chrono::Utc::now();
        let mut outbound = self.outbound.write().await;
        outbound.sweep(now);
        outbound.len()
    }

    async fn track_if_ack_requested(&self, message: &SecureMessage) {
        if delivery_ack::reply_to(message).is_none() {
            return;
        }
        let entry = Outbound {
            to_global_id: message.to_global_id.clone(),
            digest: delivery_ack::message_digest(message),
            status: DeliveryConfirmation::Sent,
        };
        let mut outbound = self.outbound.write().await;
        // Resending a message must never downgrade an Acknowledged entry. `Bounded` has no
        // `entry` API, so check first and only insert when absent.
        if !outbound.contains_key(&message.message_id.0.to_string()) {
            outbound.insert(message.message_id.0.to_string(), entry, chrono::Utc::now());
        }
    }

    /// Spec §6: upgrade to Acknowledged only for a verified ack, for a tracked message, from its
    /// addressee, with a matching digest. Anything else is dropped.
    async fn apply_ack(&self, ack: &SecureMessage, verdict: &SenderVerdict) {
        if !verdict.is_verified() {
            debug!(
                "dropping ack {}: sender verdict {:?}",
                ack.message_id, verdict
            );
            return;
        }
        let Some(fields) = delivery_ack::ack_fields(ack) else {
            debug!("dropping ack {}: missing ack fields", ack.message_id);
            return;
        };
        let mut outbound = self.outbound.write().await;
        let Some(entry) = outbound.get_mut(fields.for_message_id) else {
            debug!(
                "dropping ack {}: no tracked message {}",
                ack.message_id, fields.for_message_id
            );
            return;
        };
        if ack.from_global_id != entry.to_global_id {
            debug!(
                "dropping ack {}: from {} but the message was to {}",
                ack.message_id, ack.from_global_id, entry.to_global_id
            );
            return;
        }
        if fields.digest != entry.digest {
            debug!(
                "dropping ack {}: digest does not match what was sent",
                ack.message_id
            );
            return;
        }
        entry.status = DeliveryConfirmation::Acknowledged;
    }

    /// Replace this node's sealing key.
    pub async fn set_sealing_key(&self, key: crate::sealing::SealingKeyPair) {
        *self.sealing_key.write().await = Some(key);
    }

    /// A snapshot of the pinned sender keys.
    pub async fn trust_store(&self) -> TrustStore {
        self.trust_store.read().await.clone()
    }

    /// Replace the pinned sender keys.
    pub async fn set_trust_store(&self, store: TrustStore) {
        *self.trust_store.write().await = store;
    }

    /// Offer `revocations` to the trust store, taking its write lock. Returns how many were newly
    /// stored -- `TrustStore::add_revocation` already refuses anything not signed by a pinned
    /// account key, so a relay (see [`Self::receive_messages`]) can deliver a revocation but never
    /// forge one.
    ///
    /// A revocation refused as foreign or forged is recorded as a security event (hardening P6,
    /// row 8); a duplicate is not.
    pub async fn add_revocations(&self, revocations: &[crate::certificate::Revocation]) -> usize {
        let mut store = self.trust_store.write().await;
        let now = chrono::Utc::now();
        revocations
            .iter()
            .filter(
                |revocation| match store.try_add_revocation((*revocation).clone()) {
                    Ok(stored) => stored,
                    Err(reason) => {
                        self.events
                            .revocation_refused(&revocation.issuer_key_id, reason, now);
                        false
                    }
                },
            )
            .count()
    }

    /// Receive messages from all active transports, each paired with a sender verdict.
    pub async fn receive_messages(&self) -> Result<Vec<ReceivedMessage>> {
        // One inbox per poll, shared (by `&mut`) across every transport this loop calls. Each
        // transport can only push into it or forward it on to a transport it wraps; it cannot
        // construct one of its own, and cannot read back what a previous transport already put
        // in it. Only this crate drains it, after every transport has had its turn.
        let mut inbox = RawInbox::new();

        let transports = self.transports.read().await;
        for (transport_type, transport) in transports.iter() {
            // Skip failed transports
            if self.is_transport_in_recovery(*transport_type).await {
                continue;
            }

            let before = inbox.len();
            match transport.receive_raw(&mut inbox).await {
                Ok(()) => {
                    let received = inbox.len() - before;
                    if received > 0 {
                        debug!("Received {} messages from {:?}", received, transport_type);
                    }
                }
                Err(e) => {
                    debug!("Failed to receive from {:?}: {}", transport_type, e);
                }
            }
        }
        let all_messages = inbox.drain();

        let store = self.trust_store.read().await;
        let sealing_key = self.sealing_key.read().await;
        let mut inbound = self.inbound.write().await;
        let now = chrono::Utc::now();
        let mut delivered = Vec::with_capacity(all_messages.len());
        let mut relayed_revocations = Vec::new();
        // `(transport, source, kind)` for each message that failed verification; the transports are
        // told once the guards below are dropped, because a transport may take locks of its own.
        let mut failures: Vec<(TransportType, String, VerificationFailure)> = Vec::new();
        for incoming in all_messages {
            let message = &incoming.message;
            let verdict = store.verify_at(message, now);
            // A verified sender may relay revocations it learned about, in metadata alongside the
            // message itself. `add_revocation` refuses anything not signed by a pinned account
            // key, so a relay can deliver a revocation but never forge one; the cap below (mirrors
            // the chain field's own cap) bounds attacker-supplied input before it is parsed at
            // all. Collected here and applied after this loop, once the read lock on the trust
            // store this loop is holding is dropped.
            if verdict.is_verified()
                && let Some(field) = message.metadata.get(certificate::REVOCATIONS_KEY)
                && field.len() <= store.max_chain_bytes
                && let Ok(parsed) = certificate::revocations_from_pem(field)
            {
                relayed_revocations.extend(parsed);
            }
            let admission = inbound.admit(
                &verdict,
                &message.from_global_id,
                &message.sender_proof.key_id,
                now,
            );
            let freshness = match admission {
                crate::replay::Admission::Reject => {
                    self.events.knock(
                        &message.from_global_id,
                        &incoming.source,
                        crate::replay::verdict_reason(&verdict),
                        &message.sender_proof.key_id,
                        now,
                    );
                    // A sender nobody pinned says the trust store lacks them, nothing about the
                    // connection it came over.
                    if !matches!(
                        verdict,
                        SenderVerdict::Unverifiable {
                            reason: UnverifiableReason::UnknownSender
                                | UnverifiableReason::UnknownIssuer
                        }
                    ) {
                        failures.push((
                            incoming.transport_type,
                            incoming.source.clone(),
                            VerificationFailure::Rejected,
                        ));
                    }
                    continue;
                }
                crate::replay::Admission::AdmitUnverified => crate::replay::Freshness::NotChecked,
                crate::replay::Admission::Admit { key_id } => {
                    match inbound.check(
                        &key_id,
                        &message.message_id.0.to_string(),
                        message.timestamp.0,
                        now,
                    ) {
                        crate::replay::Decision::Drop => {
                            debug!(
                                message_id = %message.message_id.0,
                                key_id = %key_id,
                                "dropping replayed message"
                            );
                            self.events.replay(&key_id, &incoming.source, now);
                            continue;
                        }
                        crate::replay::Decision::Deliver(freshness) => freshness,
                    }
                }
            };
            // Acks are control traffic: applied here, never handed to the application. `apply_ack`
            // locks only `outbound`, so holding `inbound`'s write guard here does not double-lock.
            if delivery_ack::is_ack(message) {
                self.apply_ack(message, &verdict).await;
                continue;
            }
            let payload = crate::sealing::open(message, sealing_key.as_ref());
            if let crate::sealing::Payload::CouldNotOpen(error) = &payload {
                self.events
                    .unopenable(&message.from_global_id, &incoming.source, *error, now);
                failures.push((
                    incoming.transport_type,
                    incoming.source.clone(),
                    VerificationFailure::Unopenable,
                ));
            }
            // Only ever attach a chain summary when the chain it describes is the SAME one that
            // authenticated this message: `verified_chain_at` resolves any well-formed
            // `CHAIN_KEY` metadata independently of which route produced the verdict (it performs
            // no binding check itself -- see its doc comment), so a directly pinned sender whose
            // message also carries an unrelated or stale chain for the same `global_id` must not
            // have that chain's (possibly different) key and permissions attached. Matching both
            // the subject id and the subject's signing key against the verdict's own `key_id`
            // (which `verify_at`'s chain route only reaches after checking exactly this) closes
            // that gap; on the chain route the check is a no-op; on the direct-pin route it can
            // reject a chain that authenticated nothing.
            let certificate = match &verdict {
                SenderVerdict::Verified { key_id } => {
                    store.verified_chain_at(message, now).filter(|chain| {
                        chain.subject_global_id == message.from_global_id
                            && crate::sender_auth::key_id(&chain.subject_signing_key) == *key_id
                    })
                }
                _ => None,
            };
            delivered.push(ReceivedMessage {
                incoming,
                sender: verdict,
                payload,
                freshness,
                certificate,
            });
        }
        drop(store);
        drop(sealing_key);
        drop(inbound);
        if !relayed_revocations.is_empty() {
            self.add_revocations(&relayed_revocations).await;
        }
        for (transport_type, source, kind) in failures {
            if let Some(transport) = transports.get(&transport_type) {
                transport.on_verification_failure(&source, kind).await;
            }
        }
        Ok(delivered)
    }

    /// Counts of what was admitted, dropped and marked (P2 slice e).
    pub async fn inbound_counters(&self) -> crate::replay::InboundCounters {
        self.inbound.read().await.counters()
    }

    /// Who tried to reach this node and was kept out. Grants nothing.
    pub async fn knocks(&self) -> Vec<crate::replay::Knock> {
        self.inbound.read().await.knocks()
    }

    /// Get status of all transports
    pub async fn get_transport_status(&self) -> HashMap<TransportType, TransportStatus> {
        self.transport_status.read().await.clone()
    }

    /// Get unified metrics
    pub async fn get_metrics(&self) -> UnifiedMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// List available transport types
    pub async fn list_available_transports(&self) -> Vec<TransportType> {
        let transports = self.transports.read().await;
        transports.keys().cloned().collect()
    }

    /// Get capabilities for a specific transport type
    pub async fn get_transport_capabilities(
        &self,
        transport_type: TransportType,
    ) -> Option<TransportCapabilities> {
        let transports = self.transports.read().await;
        transports
            .get(&transport_type)
            .map(|transport| transport.capabilities())
    }

    /// Estimate delivery for a specific transport and target
    pub async fn estimate_delivery(
        &self,
        target: &TransportTarget,
        transport_type: TransportType,
    ) -> Result<DeliveryEstimate> {
        let transports = self.transports.read().await;
        if let Some(transport) = transports.get(&transport_type) {
            let estimate = transport.estimate_metrics(target).await?;
            Ok(DeliveryEstimate {
                latency: estimate.latency,
                reliability: estimate.reliability,
                throughput_estimate: estimate.bandwidth,
                cost_score: estimate.cost,
            })
        } else {
            Err(crate::error::SynapseError::TransportError(format!(
                "Transport {transport_type:?} not available"
            )))
        }
    }

    /// Get metrics summary for all transports
    pub async fn get_metrics_summary(&self) -> std::collections::HashMap<String, TransportMetrics> {
        let metrics = self.metrics.read().unwrap();
        let mut summary = std::collections::HashMap::new();

        for (transport_type, transport_metrics) in &metrics.transport_metrics {
            summary.insert(transport_type.to_string(), transport_metrics.clone());
        }

        summary
    }

    /// Select optimal transports for a target (ordered by preference)
    async fn select_transports(&self, target: &TransportTarget) -> Result<Vec<TransportType>> {
        match self.config.selection_policy {
            TransportSelectionPolicy::FirstAvailable => self.select_first_available().await,
            TransportSelectionPolicy::UrgencyBased => self.select_by_urgency(target.urgency).await,
            TransportSelectionPolicy::PerformanceBased => self.select_by_performance(target).await,
            TransportSelectionPolicy::Adaptive => self.select_adaptive(target).await,
            TransportSelectionPolicy::RoundRobin => self.select_round_robin().await,
            TransportSelectionPolicy::PreferenceOrder => self.select_by_preference(target).await,
        }
    }

    async fn select_first_available(&self) -> Result<Vec<TransportType>> {
        let status = self.transport_status.read().await;
        let available: Vec<TransportType> = status
            .iter()
            .filter(|(_, status)| **status == TransportStatus::Running)
            .map(|(&transport_type, _)| transport_type)
            .collect();

        if available.is_empty() {
            return Err(crate::error::SynapseError::TransportError(
                "No transports available".to_string(),
            ));
        }

        Ok(available)
    }

    async fn select_by_urgency(&self, urgency: MessageUrgency) -> Result<Vec<TransportType>> {
        let mut suitable_transports = Vec::new();

        let transports = self.transports.read().await;
        for (&transport_type, transport) in transports.iter() {
            let capabilities = transport.capabilities();
            if capabilities.supported_urgencies.contains(&urgency) {
                suitable_transports.push(transport_type);
            }
        }

        // Sort by urgency preference
        match urgency {
            MessageUrgency::Critical | MessageUrgency::RealTime => {
                // Prefer fast, real-time transports
                suitable_transports.sort_by_key(|&t| match t {
                    TransportType::Udp => 0,
                    TransportType::Quic => 1,
                    TransportType::WebSocket => 2,
                    TransportType::Tcp => 3,
                    TransportType::AutoDiscovery => 4,
                    _ => 10,
                });
            }
            MessageUrgency::Interactive => {
                // Balance speed and reliability
                suitable_transports.sort_by_key(|&t| match t {
                    TransportType::Quic => 0,
                    TransportType::WebSocket => 1,
                    TransportType::Tcp => 2,
                    TransportType::Udp => 3,
                    _ => 10,
                });
            }
            MessageUrgency::Background | MessageUrgency::Batch => {
                // Prefer reliable transports
                suitable_transports.sort_by_key(|&t| match t {
                    TransportType::Email => 0,
                    TransportType::Tcp => 1,
                    TransportType::Quic => 2,
                    _ => 10,
                });
            }
        }

        Ok(suitable_transports)
    }

    async fn select_by_performance(&self, target: &TransportTarget) -> Result<Vec<TransportType>> {
        let mut candidates = Vec::new();

        let transports = self.transports.read().await;
        for (&transport_type, transport) in transports.iter() {
            if transport.can_reach(target).await
                && let Ok(estimate) = transport.estimate_metrics(target).await
            {
                candidates.push((transport_type, estimate));
            }
        }

        // Sort by performance score
        let weights = self.selection_weights.read().unwrap().clone();
        candidates.sort_by(|(_, a), (_, b)| {
            let score_a = self.calculate_performance_score(a, &weights);
            let score_b = self.calculate_performance_score(b, &weights);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(candidates.into_iter().map(|(t, _)| t).collect())
    }

    async fn select_adaptive(&self, target: &TransportTarget) -> Result<Vec<TransportType>> {
        // Start with performance-based selection
        let mut selection = self.select_by_performance(target).await?;

        let mut breaker: Option<Arc<CircuitBreaker>> = None;
        selection.retain(|&transport_type| {
            let breakers = self.circuit_breakers.read().unwrap();
            breaker = breakers.get(&transport_type).cloned();
            breaker
                .as_ref()
                .map(|b| b.get_state() != crate::circuit_breaker::CircuitState::Open)
                .unwrap_or(false)
        });

        // If no transports pass circuit breaker test, fall back to urgency-based
        if selection.is_empty() {
            warn!(
                "All transports have open circuit breakers, falling back to urgency-based selection"
            );
            selection = self.select_by_urgency(target.urgency).await?;
        }

        Ok(selection)
    }

    async fn select_round_robin(&self) -> Result<Vec<TransportType>> {
        let available = self.select_first_available().await?;
        if available.is_empty() {
            return Ok(available);
        }

        let mut index = self.round_robin_index.lock().await;
        let selected_index = *index % available.len();
        *index = (*index + 1) % available.len();

        // Return selected transport first, then others as fallback
        let mut result = vec![available[selected_index]];
        for (i, &transport) in available.iter().enumerate() {
            if i != selected_index {
                result.push(transport);
            }
        }

        Ok(result)
    }

    async fn select_by_preference(&self, target: &TransportTarget) -> Result<Vec<TransportType>> {
        let mut result = Vec::new();
        let available = self.select_first_available().await?;

        // Add preferred transports first
        for &preferred in &target.preferred_transports {
            if available.contains(&preferred) {
                result.push(preferred);
            }
        }

        // Add remaining available transports
        for &transport in &available {
            if !result.contains(&transport) {
                result.push(transport);
            }
        }

        Ok(result)
    }

    fn calculate_performance_score(
        &self,
        estimate: &TransportEstimate,
        weights: &SelectionWeights,
    ) -> f64 {
        let latency_score = 1.0 / (1.0 + estimate.latency.as_secs_f64());
        let reliability_score = estimate.reliability;
        let bandwidth_score = (estimate.bandwidth as f64).log10() / 10.0; // Normalize bandwidth
        let cost_score = 1.0 / (1.0 + estimate.cost);
        let availability_score = if estimate.available { 1.0 } else { 0.0 };

        (latency_score * weights.latency
            + reliability_score * weights.reliability
            + bandwidth_score * weights.bandwidth
            + cost_score * weights.cost
            + availability_score * weights.capability_match)
            * estimate.confidence
    }

    async fn try_send_with_transport(
        &self,
        transport_type: TransportType,
        target: &TransportTarget,
        message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        let transports = self.transports.read().await;
        if let Some(transport) = transports.get(&transport_type) {
            // Check circuit breaker state first
            let circuit_breaker = {
                let breakers = self.circuit_breakers.read().unwrap();
                breakers.get(&transport_type).cloned()
            };

            if let Some(breaker) = circuit_breaker {
                // Check if circuit breaker allows the request
                if breaker.get_state() == crate::circuit_breaker::CircuitState::Open {
                    return Err(crate::error::SynapseError::TransportError(format!(
                        "Circuit breaker is open for transport {transport_type:?}"
                    )));
                }

                // Attempt the operation
                match transport.send_message(target, message).await {
                    Ok(receipt) => {
                        breaker.record_outcome(RequestOutcome::Success).await;
                        Ok(receipt)
                    }
                    // A refusal of the message is not a failure of the transport.
                    Err(e @ SynapseError::MessageRefused(_)) => Err(e),
                    Err(e) => {
                        breaker
                            .record_outcome(RequestOutcome::Failure(e.to_string()))
                            .await;
                        Err(e)
                    }
                }
            } else {
                transport.send_message(target, message).await
            }
        } else {
            Err(crate::error::SynapseError::TransportError(format!(
                "Transport {transport_type:?} not available"
            )))
        }
    }

    async fn record_success(&self, transport_type: TransportType) {
        let breaker = {
            if let Ok(breakers) = self.circuit_breakers.read() {
                breakers.get(&transport_type).cloned()
            } else {
                None
            }
        };
        // The lock is now released here

        if let Some(breaker) = breaker {
            breaker.record_outcome(RequestOutcome::Success).await;
        }
    }

    async fn record_failure(&self, transport_type: TransportType) {
        let breaker = {
            if let Ok(breakers) = self.circuit_breakers.read() {
                breakers.get(&transport_type).cloned()
            } else {
                None
            }
        };
        // The lock is now released here

        if let Some(breaker) = breaker {
            breaker
                .record_outcome(RequestOutcome::Failure(
                    "Transport operation failed".to_string(),
                ))
                .await;
        }
    }

    async fn should_mark_transport_failed(&self, transport_type: TransportType) -> bool {
        if let Ok(breakers) = self.circuit_breakers.read()
            && let Some(breaker) = breakers.get(&transport_type)
        {
            let stats = breaker.get_stats();
            let total_requests = stats.total_requests;
            if total_requests > 0 {
                let failure_rate = stats.failure_count as f64 / total_requests as f64;
                return failure_rate > self.config.failover_config.failure_threshold;
            }
        }
        false
    }

    async fn mark_transport_failed(&self, transport_type: TransportType) {
        warn!("Marking transport {:?} as failed", transport_type);
        let recovery_time = Instant::now() + self.config.failover_config.recovery_timeout;

        {
            let mut failed = self.failed_transports.write().await;
            failed.insert(transport_type, recovery_time);
        }

        {
            let mut status = self.transport_status.write().await;
            status.insert(transport_type, TransportStatus::Failed);
        }
    }

    async fn is_transport_in_recovery(&self, transport_type: TransportType) -> bool {
        let failed = self.failed_transports.read().await;
        if let Some(&recovery_time) = failed.get(&transport_type) {
            Instant::now() < recovery_time
        } else {
            false
        }
    }

    async fn update_transport_metrics(
        &self,
        transport_type: TransportType,
        success: bool,
        latency: Duration,
    ) {
        let mut metrics = self.metrics.write().unwrap();

        if success {
            metrics.total_messages_sent += 1;
        } else {
            metrics.total_failures += 1;
        }

        // Update per-transport metrics
        let transport_metrics = metrics
            .transport_metrics
            .entry(transport_type)
            .or_insert_with(|| TransportMetrics {
                transport_type,
                ..Default::default()
            });

        if success {
            transport_metrics.messages_sent += 1;
            // Update running average latency
            let total_messages = transport_metrics.messages_sent;
            let old_avg_ms = transport_metrics.average_latency_ms as f64;
            let new_latency_ms = latency.as_millis() as f64;
            let new_avg_ms =
                (old_avg_ms * (total_messages - 1) as f64 + new_latency_ms) / total_messages as f64;
            transport_metrics.average_latency_ms = new_avg_ms as u64;
        } else {
            transport_metrics.send_failures += 1;
        }

        // Update reliability score
        let total_attempts = transport_metrics.messages_sent + transport_metrics.send_failures;
        if total_attempts > 0 {
            transport_metrics.reliability_score =
                transport_metrics.messages_sent as f64 / total_attempts as f64;
        }

        transport_metrics.touch();
        metrics.touch();
    }

    async fn start_metrics_task(&self) {
        let metrics = Arc::clone(&self.metrics);
        let interval = self.config.metrics_update_interval;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Update unified metrics
                let mut metrics_guard = metrics.write().unwrap();

                // Calculate overall reliability
                let total_sent = metrics_guard.total_messages_sent;
                let total_failed = metrics_guard.total_failures;
                let total_attempts = total_sent + total_failed;

                if total_attempts > 0 {
                    metrics_guard.overall_reliability = total_sent as f64 / total_attempts as f64;
                }

                // Calculate average latency across all transports
                let mut total_latency_ms = 0u64;
                let mut transport_count = 0;

                for transport_metrics in metrics_guard.transport_metrics.values() {
                    if transport_metrics.messages_sent > 0 {
                        total_latency_ms += transport_metrics.average_latency_ms;
                        transport_count += 1;
                    }
                }

                if let Some(avg) = total_latency_ms.checked_div(transport_count) {
                    metrics_guard.average_latency = Duration::from_millis(avg);
                }

                metrics_guard.touch();
            }
        });
    }

    // Note: Individual transport access is not exposed in the public API
    // Use the manager's methods for transport operations
}

/// Builder pattern for TransportManager configuration
pub struct TransportManagerBuilder {
    config: TransportManagerConfig,
    trust_store: TrustStore,
    sealing_key: Option<crate::sealing::SealingKeyPair>,
    replay: crate::replay::ReplayConfig,
    gate: crate::replay::GateConfig,
    tracking_ttl: chrono::Duration,
    tracking_capacity: usize,
    security_sink: Option<Arc<dyn crate::security_events::SecuritySink>>,
    knock_limits: super::security::KnockLimits,
}

impl TransportManagerBuilder {
    pub fn new() -> Self {
        Self {
            config: TransportManagerConfig::default(),
            trust_store: TrustStore::default(),
            sealing_key: None,
            replay: crate::replay::ReplayConfig::default(),
            gate: crate::replay::GateConfig::default(),
            tracking_ttl: chrono::Duration::hours(1),
            tracking_capacity: 10_000,
            security_sink: None,
            knock_limits: super::security::KnockLimits::default(),
        }
    }

    pub fn enable_transport(mut self, transport_type: TransportType) -> Self {
        if !self.config.enabled_transports.contains(&transport_type) {
            self.config.enabled_transports.push(transport_type);
        }
        self
    }

    pub fn disable_transport(mut self, transport_type: TransportType) -> Self {
        self.config
            .enabled_transports
            .retain(|&t| t != transport_type);
        self
    }

    pub fn selection_policy(mut self, policy: TransportSelectionPolicy) -> Self {
        self.config.selection_policy = policy;
        self
    }

    pub fn failover_config(mut self, config: FailoverConfig) -> Self {
        self.config.failover_config = config;
        self
    }

    pub fn operation_timeout(mut self, timeout: Duration) -> Self {
        self.config.operation_timeout = timeout;
        self
    }

    pub fn transport_config(
        mut self,
        transport_type: TransportType,
        config: HashMap<String, String>,
    ) -> Self {
        self.config.transport_configs.insert(transport_type, config);
        self
    }

    pub fn trust_store(mut self, store: TrustStore) -> Self {
        self.trust_store = store;
        self
    }

    /// This node's sealing key, used to open sealed bodies.
    pub fn sealing_key(mut self, key: crate::sealing::SealingKeyPair) -> Self {
        self.sealing_key = Some(key);
        self
    }

    /// Replay window and record size (P2 slice e). An invalid config (see
    /// [`crate::replay::ReplayConfig::validate`]) is not used: `build()` logs a warning naming the
    /// reason and falls back to [`crate::replay::ReplayConfig::default`] instead, so replay
    /// suppression is never silently disabled.
    pub fn replay_config(mut self, config: crate::replay::ReplayConfig) -> Self {
        self.replay = config;
        self
    }

    /// Which sender verdicts are admitted (P2 slice e).
    pub fn gate_config(mut self, config: crate::replay::GateConfig) -> Self {
        self.gate = config;
        self
    }

    /// How long a sent message's ack is tracked, and how many at once (P2 slice e).
    pub fn tracking_limits(mut self, ttl: chrono::Duration, capacity: usize) -> Self {
        self.tracking_ttl = ttl;
        self.tracking_capacity = capacity;
        self
    }

    /// Where receive-path security events go (hardening P6). Without one, none are recorded.
    pub fn security_sink(mut self, sink: Arc<dyn crate::security_events::SecuritySink>) -> Self {
        self.security_sink = Some(sink);
        self
    }

    /// Budgets for the knock record. They decide only which knocks are written as their own
    /// event; every message is still verified.
    pub fn knock_limits(mut self, limits: super::security::KnockLimits) -> Self {
        self.knock_limits = limits;
        self
    }

    pub fn build(self) -> TransportManager {
        let tracking_ttl = self.tracking_ttl;
        let tracking_capacity = self.tracking_capacity;
        let mut manager = TransportManager::new(self.config);
        manager.trust_store = TokioRwLock::new(self.trust_store);
        manager.sealing_key = TokioRwLock::new(self.sealing_key);
        manager.outbound =
            TokioRwLock::new(crate::replay::Bounded::new(tracking_ttl, tracking_capacity));
        let replay = match self.replay.validate() {
            Ok(()) => self.replay,
            Err(reason) => {
                warn!(
                    "invalid replay_config ({reason}); using ReplayConfig::default() instead so \
                     replay suppression is not silently disabled"
                );
                crate::replay::ReplayConfig::default()
            }
        };
        manager.inbound = TokioRwLock::new(crate::replay::InboundState::new(
            replay,
            self.gate,
            chrono::Utc::now(),
        ));
        manager.events =
            super::security::TransportEvents::new(self.knock_limits, self.security_sink);
        manager
    }
}

impl Default for TransportManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoManager;
    use crate::delivery_ack;
    use crate::sender_auth::{ContradictedReason, UnverifiableReason};
    use crate::types::SecurityLevel;

    fn signer() -> CryptoManager {
        let mut crypto = CryptoManager::new();
        crypto.generate_keypair().unwrap();
        crypto
    }

    /// A manager with no transports, and one message tracked as if `request_ack` had been sent
    /// (P2 slice b), so `apply_ack` has an entry to act on.
    async fn manager_with_tracked_ack() -> (TransportManager, SecureMessage) {
        let manager = TransportManager::new(TransportManagerConfig::default());
        let mut original = SecureMessage::new(
            "bob@t",
            "alice@t",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        original.request_ack("127.0.0.1:1");
        manager.track_if_ack_requested(&original).await;
        (manager, original)
    }

    // P2e review finding 1: `apply_ack`'s verdict guard (src/transport/manager.rs, "if
    // !verdict.is_verified()") had lost its only caller once the gate started rejecting
    // `Contradicted`/`Unverifiable` senders before they ever reach `apply_ack`. This exercises the
    // guard directly, with a control that proves the same ack DOES apply once it is `Verified`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn apply_ack_ignores_an_unverified_or_contradicted_verdict() {
        let (manager, original) = manager_with_tracked_ack().await;
        let bob = signer();
        let ack = delivery_ack::build_ack(&original, &bob).expect("build ack");
        let message_id = original.message_id.0.to_string();

        manager
            .apply_ack(
                &ack,
                &SenderVerdict::Unverifiable {
                    reason: UnverifiableReason::Unsigned,
                },
            )
            .await;
        assert_eq!(
            manager.delivery_status(&message_id).await,
            Some(DeliveryConfirmation::Sent),
            "an Unverifiable verdict must not apply the ack"
        );

        manager
            .apply_ack(
                &ack,
                &SenderVerdict::Contradicted {
                    reason: ContradictedReason::BadSignature,
                },
            )
            .await;
        assert_eq!(
            manager.delivery_status(&message_id).await,
            Some(DeliveryConfirmation::Sent),
            "a Contradicted verdict must not apply the ack"
        );

        // Control: the identical ack, now with a Verified verdict, DOES apply — distinguishing the
        // guard above from a no-op.
        manager
            .apply_ack(
                &ack,
                &SenderVerdict::Verified {
                    key_id: "irrelevant".to_string(),
                },
            )
            .await;
        assert_eq!(
            manager.delivery_status(&message_id).await,
            Some(DeliveryConfirmation::Acknowledged)
        );
    }

    // P2e review finding 2: an invalid `ReplayConfig` (e.g. `capacity: 0`) must not silently
    // disable replay suppression for a direct library consumer who bypasses an adapter's config
    // boundary. `build()` falls back to `ReplayConfig::default()` and logs why.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_invalid_replay_config_falls_back_to_default_instead_of_disabling_suppression() {
        let invalid = crate::replay::ReplayConfig {
            capacity: 0,
            ..crate::replay::ReplayConfig::default()
        };
        assert!(invalid.validate().is_err(), "the fixture must be invalid");

        let manager = TransportManagerBuilder::new()
            .replay_config(invalid)
            .build();
        let now = chrono::Utc::now();
        let mut inbound = manager.inbound.write().await;
        assert!(matches!(
            inbound.check("k", "m", now, now),
            crate::replay::Decision::Deliver(_)
        ));
        assert_eq!(
            inbound.check("k", "m", now, now),
            crate::replay::Decision::Drop,
            "a repeat must still be dropped, so capacity: 0 did not disable suppression"
        );
    }
}
