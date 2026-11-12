// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unified Transport Abstraction Layer for Synapse
//!
//! This module provides a unified interface that sits above all transport mechanisms,
//! making applications transport-agnostic while providing intelligent transport selection,
//! failover, and optimization capabilities.

use super::router::ConnectionOffer;
use crate::{error::Result, types::SecureMessage};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// A write-only sink for raw, unverified messages coming off a transport.
///
/// This is how [`TransportReceive::receive_raw`] is sealed: not with a token guarding the
/// *call* (a token is just a value -- `'static + Send + Sync`, so it can be stashed in a static
/// or handed on to any other transport a caller can reach, which would let a malicious
/// implementation read straight through another transport's `receive_raw`), but by controlling
/// what the call can *do*. A `RawInbox` can be written to by anyone holding a `&mut` reference
/// ([`push`](Self::push), [`extend`](Self::extend) are `pub`), but it can only be *constructed*
/// or *read back* from inside this crate: [`new`](Self::new) and [`drain`](Self::drain) are
/// `pub(crate)`. It deliberately implements none of `Clone`, `Default`, `Debug`, `Deref`, or
/// `IntoIterator` -- any of those would either let outside code manufacture one or let it read
/// contents back out. So an external implementation of `receive_raw` can push its own transport's
/// messages into the inbox it was handed, and can forward that same `&mut RawInbox` to another
/// transport it wraps or decorates (whose messages then land in the same inbox, still headed for
/// verification) -- but it has no way to conjure an inbox of its own to bait a call, and no way to
/// look inside the one it was given to steal what another transport already deposited there.
/// Only [`TransportManager`] (`manager.rs`) ever calls `new` and `drain`.
pub struct RawInbox {
    messages: Vec<IncomingMessage>,
}

impl RawInbox {
    pub(crate) fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add one message.
    pub fn push(&mut self, message: IncomingMessage) {
        self.messages.push(message);
    }

    /// Add every message from an iterator.
    pub fn extend(&mut self, messages: impl IntoIterator<Item = IncomingMessage>) {
        self.messages.extend(messages);
    }

    /// How many messages are currently held. Exposed so the manager can log a per-transport
    /// count without being able to read the messages themselves.
    pub(crate) fn len(&self) -> usize {
        self.messages.len()
    }

    /// Take everything out, leaving the inbox empty.
    pub(crate) fn drain(&mut self) -> Vec<IncomingMessage> {
        std::mem::take(&mut self.messages)
    }
}

/// Raw, unverified receive -- callable only by [`TransportManager`], which pairs every message
/// with a `SenderVerdict` before handing it to applications. See [`RawInbox`] for how the sealing
/// works.
#[async_trait]
pub trait TransportReceive: Send + Sync {
    /// Receive raw messages from the wire, pushing them into `inbox`.
    ///
    /// ⚠️ Unverified: senders are not authenticated here. `TransportManager::receive_messages`
    /// pairs each message with a `SenderVerdict`; that is the only public way to receive from a
    /// transport.
    ///
    /// `inbox` cannot be constructed by an implementor, and cannot be read back by one either --
    /// it can only be written to (see [`RawInbox`]). A downstream crate can implement this trait
    /// for its own transport:
    /// ```
    /// use async_trait::async_trait;
    /// use synapse::error::Result;
    /// use synapse::transport::{IncomingMessage, RawInbox, TransportReceive, TransportType};
    /// use synapse::types::{SecureMessage, SecurityLevel};
    ///
    /// struct MyTransport;
    ///
    /// #[async_trait]
    /// impl TransportReceive for MyTransport {
    ///     async fn receive_raw(&self, inbox: &mut RawInbox) -> Result<()> {
    ///         let message = SecureMessage::new("to", "from", b"hi".to_vec(), SecurityLevel::Public);
    ///         inbox.push(IncomingMessage::new(
    ///             message,
    ///             TransportType::Tcp,
    ///             "127.0.0.1:0".to_string(),
    ///         ));
    ///         Ok(())
    ///     }
    /// }
    /// # fn main() {}
    /// ```
    ///
    /// It cannot construct a `RawInbox` itself, whether by a constructor or a struct literal:
    /// ```compile_fail
    /// use synapse::transport::RawInbox;
    ///
    /// fn make_one() -> RawInbox {
    ///     // No public constructor exists outside this crate, and its field is private, so
    ///     // neither `RawInbox::new()` nor a struct literal can compile here.
    ///     RawInbox::new()
    /// }
    /// # fn main() {}
    /// ```
    ///
    /// Nor can it read back an inbox it was handed, to see what another transport already put in
    /// it:
    /// ```compile_fail
    /// use synapse::transport::RawInbox;
    ///
    /// fn peek(inbox: &mut RawInbox) {
    ///     // `drain` is `pub(crate)`, and `RawInbox` implements no `IntoIterator`/`Deref` to
    ///     // read it another way, so this cannot compile here.
    ///     let _ = inbox.drain();
    /// }
    /// # fn main() {}
    /// ```
    async fn receive_raw(&self, inbox: &mut RawInbox) -> Result<()>;
}

/// Unified transport interface that all transport mechanisms must implement
#[async_trait]
pub trait Transport: TransportReceive + Send + Sync {
    /// Get the transport type identifier
    fn transport_type(&self) -> TransportType;

    /// Get transport capabilities
    fn capabilities(&self) -> TransportCapabilities;

    /// Check if this transport can reach a specific target
    async fn can_reach(&self, target: &TransportTarget) -> bool;

    /// Get estimated metrics for reaching a target
    async fn estimate_metrics(&self, target: &TransportTarget) -> Result<TransportEstimate>;

    /// Send a message via this transport
    async fn send_message(
        &self,
        target: &TransportTarget,
        message: &SecureMessage,
    ) -> Result<DeliveryReceipt>;

    /// Test connectivity to a target
    async fn test_connectivity(&self, target: &TransportTarget) -> Result<ConnectivityResult>;

    /// Start the transport (if needed)
    async fn start(&self) -> Result<()>;

    /// Stop the transport gracefully
    async fn stop(&self) -> Result<()>;

    /// Get current transport status
    async fn status(&self) -> TransportStatus;

    /// Get transport metrics
    async fn metrics(&self) -> TransportMetrics;

    /// Gives the transport the manager's security sink, before `start`, for events it records
    /// itself (hardening P7: Direct-mode email's inbound limits). Most transports record nothing of
    /// their own, so the default ignores it.
    fn attach_security_sink(&self, sink: std::sync::Arc<dyn crate::security_events::SecuritySink>) {
        let _ = sink;
    }

    /// Tells the transport that a message which arrived from `source` (the same string it put in
    /// [`IncomingMessage::source`]) failed verification, after the manager had finished with it.
    /// A transport that keeps per-peer connection state can use it to drop a stale entry; the
    /// default does nothing, so existing implementors are unaffected. It carries only the kind of
    /// failure, never the message or a key, and is called with no manager lock held.
    async fn on_verification_failure(&self, source: &str, reason: VerificationFailure) {
        let _ = (source, reason);
    }

    /// Send a connection offer to a target
    async fn send_connection_offer(&self, target: &str, offer: ConnectionOffer) -> Result<String> {
        let _ = (target, offer);
        Err(crate::error::SynapseError::TransportError(
            "Connection offers not supported by this transport".to_string(),
        ))
    }
}

/// Why [`Transport::on_verification_failure`] was called.
///
/// A sender the trust store simply does not know (`UnknownSender`, `UnknownIssuer`) is not a
/// failure of the connection and is never reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerificationFailure {
    /// The admission step refused the sender's verdict (the manager records a knock).
    Rejected,
    /// The message was admitted but its sealed payload could not be opened.
    Unopenable,
}

/// Transport types supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportType {
    Tcp,
    Udp,
    WebSocket,
    Http,
    Email,
    AutoDiscovery, // Replaces Mdns with more comprehensive discovery
    Quic,
    NatTraversal,
    Custom(u32), // For extensibility
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "TCP"),
            TransportType::Udp => write!(f, "UDP"),
            TransportType::WebSocket => write!(f, "WebSocket"),
            TransportType::Http => write!(f, "HTTP"),
            TransportType::Email => write!(f, "Email"),
            TransportType::AutoDiscovery => write!(f, "Auto-Discovery"),
            TransportType::Quic => write!(f, "QUIC"),
            TransportType::NatTraversal => write!(f, "NAT-Traversal"),
            TransportType::Custom(id) => write!(f, "Custom({id})"),
        }
    }
}

/// A [`TransportMetrics`] field that a transport's `metrics()` does not actually measure.
///
/// `TransportMetrics`'s numeric fields cannot themselves be absent -- the struct always has a
/// value in every field -- so a caller cannot tell "this is a real observation" from "this is a
/// placeholder" by looking at the metrics alone. `TransportCapabilities::unmeasured_metrics`
/// closes that gap: a variant listed here means the corresponding `TransportMetrics` field is not
/// evidence for this transport, whatever value happens to be in it. Check `capabilities()` before
/// trusting either field for transport selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnmeasuredMetric {
    /// `TransportMetrics::average_latency_ms` is not computed from real observations.
    AverageLatency,
    /// `TransportMetrics::reliability_score` is not computed from real observations.
    ReliabilityScore,
}

/// Transport capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCapabilities {
    /// Maximum message size supported
    pub max_message_size: usize,
    /// Whether transport supports reliable delivery
    pub reliable: bool,
    /// Whether transport supports real-time communication
    pub real_time: bool,
    /// Whether transport supports broadcast/multicast
    pub broadcast: bool,
    /// Whether transport supports bidirectional communication
    pub bidirectional: bool,
    /// Whether transport supports encryption
    pub encrypted: bool,
    /// Whether transport works across networks (not just local)
    pub network_spanning: bool,
    /// Supported message urgency levels
    pub supported_urgencies: Vec<MessageUrgency>,
    /// Transport-specific features
    pub features: Vec<String>,
    /// `TransportMetrics` fields this transport does not measure. Empty means every numeric
    /// field `metrics()` returns reflects a real observation of this transport's own activity.
    /// See [`UnmeasuredMetric`].
    pub unmeasured_metrics: Vec<UnmeasuredMetric>,
}

/// Message urgency levels for transport selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageUrgency {
    /// Immediate delivery required (< 100ms)
    Critical,
    /// Real-time delivery preferred (< 1s)
    RealTime,
    /// Interactive response time (< 5s)
    Interactive,
    /// Background processing acceptable
    Background,
    /// Store and forward acceptable
    Batch,
}

/// Transport target specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportTarget {
    /// Primary identifier (entity ID, email, IP, etc.)
    pub identifier: String,
    /// Optional specific address/endpoint
    pub address: Option<String>,
    /// Preferred transport types (in order of preference)
    pub preferred_transports: Vec<TransportType>,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
    /// Urgency level for this target
    pub urgency: MessageUrgency,
}

impl TransportTarget {
    pub fn new(identifier: String) -> Self {
        Self {
            identifier,
            address: None,
            preferred_transports: Vec::new(),
            required_capabilities: Vec::new(),
            urgency: MessageUrgency::Interactive,
        }
    }

    pub fn with_address(mut self, address: String) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_urgency(mut self, urgency: MessageUrgency) -> Self {
        self.urgency = urgency;
        self
    }

    pub fn prefer_transport(mut self, transport: TransportType) -> Self {
        self.preferred_transports.push(transport);
        self
    }

    pub fn require_capability(mut self, capability: String) -> Self {
        self.required_capabilities.push(capability);
        self
    }
}

/// Transport performance estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportEstimate {
    /// Estimated latency
    pub latency: Duration,
    /// Estimated reliability (0.0-1.0)
    pub reliability: f64,
    /// Estimated bandwidth (bytes/sec)
    pub bandwidth: u64,
    /// Estimated cost (arbitrary units)
    pub cost: f64,
    /// Whether the transport is currently available
    pub available: bool,
    /// Confidence in these estimates (0.0-1.0)
    pub confidence: f64,
}

/// Delivery receipt from successful message send
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// Unique message ID
    pub message_id: String,
    /// Transport used for delivery
    pub transport_used: TransportType,
    /// Actual delivery time
    pub delivery_time: Duration,
    /// Target that was reached
    pub target_reached: String,
    /// Delivery confirmation level
    pub confirmation: DeliveryConfirmation,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Levels of delivery confirmation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryConfirmation {
    /// Message was sent to transport layer
    Sent,
    /// Message was delivered to target network
    Delivered,
    /// The receiving application acknowledged the message with a verified, signed ack whose
    /// digest matches what was sent (P2 slice b).
    Acknowledged,
    /// No acknowledgement arrived within the tracking window (P2 slice e). It says nothing about
    /// whether the message was delivered.
    Expired,
}

/// Incoming message with transport context
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// The message content
    pub message: SecureMessage,
    /// Transport that received the message
    pub transport_type: TransportType,
    /// Source address/identifier
    pub source: String,
    /// When the message was received (as timestamp)
    pub received_timestamp: u64,
    /// Additional transport-specific metadata
    pub metadata: HashMap<String, String>,
}

impl IncomingMessage {
    /// Create a new incoming message with current timestamp
    pub fn new(message: SecureMessage, transport_type: TransportType, source: String) -> Self {
        Self {
            message,
            transport_type,
            source,
            received_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            metadata: HashMap::new(),
        }
    }

    /// Get received time as Duration since epoch
    pub fn received_at(&self) -> Duration {
        Duration::from_secs(self.received_timestamp)
    }
}

/// Result of connectivity test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityResult {
    /// Whether connection was successful
    pub connected: bool,
    /// Round-trip time if successful
    pub rtt: Option<Duration>,
    /// Error message if failed
    pub error: Option<String>,
    /// Connection quality score (0.0-1.0)
    pub quality: f64,
    /// Additional test results
    pub details: HashMap<String, String>,
}

/// Current transport status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportStatus {
    /// Transport is not yet started
    Stopped,
    /// Transport is starting up
    Starting,
    /// Transport is running normally
    Running,
    /// Transport is experiencing issues but functional
    Degraded,
    /// Transport is not functional
    Failed,
    /// Transport is shutting down
    Stopping,
}

/// Transport performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportMetrics {
    /// Transport type
    pub transport_type: TransportType,
    /// Number of messages sent
    pub messages_sent: u64,
    /// Number of messages received
    pub messages_received: u64,
    /// Number of send failures
    pub send_failures: u64,
    /// Number of receive failures
    pub receive_failures: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Average latency in milliseconds
    pub average_latency_ms: u64,
    /// Current reliability score (0.0-1.0)
    pub reliability_score: f64,
    /// Number of active connections
    pub active_connections: u32,
    /// Last update time as Unix timestamp
    pub last_updated_timestamp: u64,
    /// Transport-specific metrics
    pub custom_metrics: HashMap<String, f64>,
}

impl Default for TransportMetrics {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Tcp,
            messages_sent: 0,
            messages_received: 0,
            send_failures: 0,
            receive_failures: 0,
            bytes_sent: 0,
            bytes_received: 0,
            average_latency_ms: 0,
            reliability_score: 1.0,
            active_connections: 0,
            last_updated_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            custom_metrics: HashMap::new(),
        }
    }
}

impl TransportMetrics {
    /// Get average latency as Duration
    pub fn average_latency(&self) -> Duration {
        Duration::from_millis(self.average_latency_ms)
    }

    /// Set average latency from Duration
    pub fn set_average_latency(&mut self, latency: Duration) {
        self.average_latency_ms = latency.as_millis() as u64;
    }

    /// Get last updated time as Instant (approximate)
    pub fn last_updated(&self) -> Instant {
        // This is approximate since we can't perfectly convert back to Instant
        Instant::now() // For now, just return current time
    }

    /// Update the last updated timestamp to now
    pub fn touch(&mut self) {
        self.last_updated_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }
}

/// Delivery estimate for UI display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryEstimate {
    /// Estimated latency
    pub latency: Duration,
    /// Estimated reliability (0.0-1.0)
    pub reliability: f64,
    /// Estimated throughput in bytes per second
    pub throughput_estimate: u64,
    /// Cost score (lower is better)
    pub cost_score: f64,
}

/// Helper implementations for common capability sets
impl TransportCapabilities {
    /// TCP transport capabilities
    pub fn tcp() -> Self {
        Self {
            max_message_size: 64 * 1024 * 1024, // 64MB
            reliable: true,
            real_time: false,
            broadcast: false,
            bidirectional: true,
            encrypted: false, // Depends on TLS
            network_spanning: true,
            supported_urgencies: vec![
                MessageUrgency::Interactive,
                MessageUrgency::Background,
                MessageUrgency::Batch,
            ],
            features: vec![
                "connection_oriented".to_string(),
                "stream_based".to_string(),
                "flow_control".to_string(),
            ],
            // `tcp_unified.rs` computes a real running average latency (see `connect_and_send`)
            // but never writes `reliability_score` after its `TransportMetrics::default()` of
            // `1.0`, so that field is a constant, not an observation.
            unmeasured_metrics: vec![UnmeasuredMetric::ReliabilityScore],
        }
    }

    /// UDP transport capabilities
    pub fn udp() -> Self {
        Self {
            max_message_size: 65507, // Max UDP payload
            reliable: false,
            real_time: true,
            broadcast: true,
            bidirectional: true,
            encrypted: false,
            network_spanning: true,
            supported_urgencies: vec![
                MessageUrgency::Critical,
                MessageUrgency::RealTime,
                MessageUrgency::Interactive,
            ],
            features: vec![
                "connectionless".to_string(),
                "datagram_based".to_string(),
                "low_overhead".to_string(),
                "multicast".to_string(),
            ],
            // Same gap as `tcp()`: `udp_unified.rs` computes a real running average latency but
            // never writes `reliability_score` past its `TransportMetrics::default()` of `1.0`.
            unmeasured_metrics: vec![UnmeasuredMetric::ReliabilityScore],
        }
    }

    /// Email transport capabilities
    pub fn email() -> Self {
        Self {
            max_message_size: 25 * 1024 * 1024, // 25MB typical limit
            reliable: true,
            real_time: false,
            broadcast: true,
            bidirectional: true,
            encrypted: true, // Usually TLS
            network_spanning: true,
            supported_urgencies: vec![MessageUrgency::Background, MessageUrgency::Batch],
            features: vec![
                "store_and_forward".to_string(),
                "federation".to_string(),
                "authentication".to_string(),
                "persistent".to_string(),
            ],
            // Unused by any live transport: no real `metrics()` backs either field here, so both
            // are honestly unmeasured.
            unmeasured_metrics: vec![
                UnmeasuredMetric::AverageLatency,
                UnmeasuredMetric::ReliabilityScore,
            ],
        }
    }

    /// Auto-Discovery transport capabilities
    pub fn auto_discovery() -> Self {
        Self {
            max_message_size: 1024, // Smallest for discovery
            reliable: false,
            real_time: true,
            broadcast: true,
            bidirectional: true,
            encrypted: false,
            network_spanning: false, // Local network only
            supported_urgencies: vec![MessageUrgency::Critical, MessageUrgency::RealTime],
            features: vec![
                "service_discovery".to_string(),
                "zero_configuration".to_string(),
                "local_network".to_string(),
                "multicast".to_string(),
            ],
            // Unused by any live transport (`discovery.rs` and `mdns_enhanced.rs` each construct
            // their own literal): no real `metrics()` backs either field here.
            unmeasured_metrics: vec![
                UnmeasuredMetric::AverageLatency,
                UnmeasuredMetric::ReliabilityScore,
            ],
        }
    }

    /// WebSocket transport capabilities
    pub fn websocket() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024, // 16MB typical
            reliable: true,
            real_time: true,
            broadcast: false,
            bidirectional: true,
            encrypted: true, // WSS
            network_spanning: true,
            supported_urgencies: vec![
                MessageUrgency::Critical,
                MessageUrgency::RealTime,
                MessageUrgency::Interactive,
            ],
            features: vec![
                "web_compatible".to_string(),
                "full_duplex".to_string(),
                "frame_based".to_string(),
                "http_upgrade".to_string(),
            ],
            // Unused by any live transport (`websocket_unified.rs` constructs its own literal,
            // which does compute both fields for real): no real `metrics()` backs this preset.
            unmeasured_metrics: vec![
                UnmeasuredMetric::AverageLatency,
                UnmeasuredMetric::ReliabilityScore,
            ],
        }
    }

    /// QUIC transport capabilities, as actually implemented (`quic_unified.rs`) -- not what QUIC
    /// in general can do. `zero_rtt` and `connection_migration` are deliberately absent: this
    /// implementation disables 0-RTT (spec §5) and does not implement migration.
    pub fn quic() -> Self {
        Self {
            max_message_size: 1024 * 1024, // the configured default; see quic_unified::DEFAULT_MAX_MESSAGE_SIZE
            reliable: true,
            real_time: true,
            broadcast: false,
            bidirectional: true,
            encrypted: true,
            network_spanning: true,
            supported_urgencies: vec![
                MessageUrgency::Critical,
                MessageUrgency::RealTime,
                MessageUrgency::Interactive,
            ],
            features: vec![
                "multiplexed_streams".to_string(),
                "connection_pooling".to_string(),
            ],
            // `quic_unified.rs`'s `metrics()` computes a real `reliability_score` from atomic
            // send/failure counters, but takes `average_latency_ms` from
            // `TransportMetrics::default()` (`0`) -- it is never sampled.
            unmeasured_metrics: vec![UnmeasuredMetric::AverageLatency],
        }
    }

    /// HTTP transport capabilities
    pub fn http() -> Self {
        Self {
            max_message_size: 10 * 1024 * 1024, // 10MB typical limit
            reliable: true,
            real_time: false, // HTTP has higher latency
            broadcast: false,
            bidirectional: true,
            encrypted: false, // Depends on HTTPS
            network_spanning: true,
            supported_urgencies: vec![
                MessageUrgency::Interactive,
                MessageUrgency::Background,
                MessageUrgency::Batch,
            ],
            features: vec![
                "firewall_friendly".to_string(),
                "web_compatible".to_string(),
                "request_response".to_string(),
                "standard_protocol".to_string(),
            ],
            // Unused by any live transport (`http_unified.rs` constructs its own literal, which
            // does compute both fields for real): no real `metrics()` backs this preset.
            unmeasured_metrics: vec![
                UnmeasuredMetric::AverageLatency,
                UnmeasuredMetric::ReliabilityScore,
            ],
        }
    }

    /// HTTPS transport capabilities
    pub fn https() -> Self {
        let mut caps = Self::http();
        caps.encrypted = true;
        caps.features.push("encrypted".to_string());
        caps.features.push("authenticated".to_string());
        caps
    }
}

/// Transport factory trait for creating transport instances
#[async_trait]
pub trait TransportFactory: Send + Sync {
    /// Create a new transport instance
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>>;

    /// Get the transport type this factory creates
    fn transport_type(&self) -> TransportType;

    /// Get default configuration for this transport
    fn default_config(&self) -> HashMap<String, String>;

    /// Validate configuration for this transport
    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()>;
}

// Factory implementations for unified transports

/// UDP Transport Factory (temporarily disabled)
pub struct UdpTransportFactory;

#[async_trait]
impl TransportFactory for UdpTransportFactory {
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        // Remove SocketAddr creation, pass config directly
        let transport = crate::transport::udp_unified::UdpTransportImpl::new(config).await?;
        Ok(Box::new(transport) as Box<dyn Transport>)
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Udp
    }

    fn default_config(&self) -> HashMap<String, String> {
        let mut cfg = HashMap::new();
        cfg.insert("listen_port".to_string(), "9000".to_string());
        cfg
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        if let Some(port_str) = config.get("listen_port")
            && port_str.parse::<u16>().is_err()
        {
            return Err(crate::error::SynapseError::Config(
                "Invalid port number".to_string(),
            ));
        }
        Ok(())
    }
}

// Email Transport Factory: moved to `email_unified::EmailTransportFactory`, which actually sends
// and receives (Direct mode) instead of always refusing. Registered in `transport/mod.rs`.

// mDNS Transport Factory (COMMENTED OUT - TO BE FIXED)
pub struct MdnsTransportFactory;

#[async_trait]
impl TransportFactory for MdnsTransportFactory {
    async fn create_transport(
        &self,
        _config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        use crate::transport::mdns_enhanced::{EnhancedMdnsTransport, MdnsConfig};
        let entity_id = "mdns-factory-instance".to_string();
        let local_port = 5353;
        let config = Some(MdnsConfig::default());
        match EnhancedMdnsTransport::new(entity_id, local_port, config).await {
            Ok(transport) => Ok(Box::new(transport) as Box<dyn Transport>),
            Err(e) => Err(crate::error::SynapseError::TransportError(format!(
                "Failed to create mDNS transport: {e}"
            ))),
        }
    }

    fn transport_type(&self) -> TransportType {
        TransportType::AutoDiscovery
    }

    fn default_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert(
            "service_name".to_string(),
            "_synapse._tcp.local".to_string(),
        );
        config.insert("local_port".to_string(), "0".to_string());
        config.insert("discovery_timeout_ms".to_string(), "5000".to_string());
        config.insert("max_message_size".to_string(), "65507".to_string()); // Max UDP
        config
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        if let Some(service_name) = config.get("service_name")
            && !service_name.contains("._tcp.")
            && !service_name.contains("._udp.")
        {
            return Err(crate::error::SynapseError::Config(
                "Service name must include protocol (_tcp. or _udp.)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Factory for the WebSocket transport (`websocket_unified`). The config keys, their defaults, and
/// what the limits bound are in that module's documentation; `create_transport` and
/// `validate_config` refuse the same invalid values.
pub struct WebSocketTransportFactory;

#[async_trait]
impl TransportFactory for WebSocketTransportFactory {
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        let transport =
            crate::transport::websocket_unified::WebSocketTransportImpl::new(config).await?;
        Ok(Box::new(transport))
    }

    fn transport_type(&self) -> TransportType {
        TransportType::WebSocket
    }

    fn default_config(&self) -> HashMap<String, String> {
        use crate::transport::websocket_unified as ws;
        [
            (ws::LOCAL_PORT_KEY, 0),
            (
                ws::CONNECTION_TIMEOUT_MS_KEY,
                ws::DEFAULT_CONNECTION_TIMEOUT_MS,
            ),
            // In bytes of serialized JSON, the unit sender and receiver both enforce.
            (ws::MAX_MESSAGE_SIZE_KEY, ws::DEFAULT_MAX_MESSAGE_SIZE),
            (
                ws::MAX_CONCURRENT_CONNECTIONS_KEY,
                ws::DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            ),
            (ws::MAX_QUEUED_BYTES_KEY, ws::DEFAULT_MAX_QUEUED_BYTES),
            (
                ws::HANDSHAKE_TIMEOUT_MS_KEY,
                ws::DEFAULT_HANDSHAKE_TIMEOUT_MS,
            ),
            (ws::IDLE_TIMEOUT_MS_KEY, ws::DEFAULT_IDLE_TIMEOUT_MS),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        // The same check `new` applies, so validating and constructing cannot disagree.
        crate::transport::websocket_unified::validate_config(config)
    }
}

/// Factory for the NAT traversal transport (`nat_traversal`). `local_port` (default 0, meaning
/// let the OS choose) is the only config key it reads, plus the shared bind-scope key.
pub struct NatTraversalTransportFactory;

#[async_trait]
impl TransportFactory for NatTraversalTransportFactory {
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        self.validate_config(config)?;
        let local_port = config
            .get("local_port")
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| crate::error::SynapseError::Config("Invalid port number".to_string()))?
            .unwrap_or(0);
        let bind_scope = crate::network_scope::BindScope::from_config_map(config)?;
        let transport = crate::transport::nat_traversal::NatTraversalTransport::new_with_scope(
            local_port, bind_scope,
        )
        .await?;
        Ok(Box::new(transport))
    }

    fn transport_type(&self) -> TransportType {
        TransportType::NatTraversal
    }

    fn default_config(&self) -> HashMap<String, String> {
        let mut cfg = HashMap::new();
        cfg.insert("local_port".to_string(), "0".to_string());
        cfg
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        if let Some(port_str) = config.get("local_port")
            && port_str.parse::<u16>().is_err()
        {
            return Err(crate::error::SynapseError::Config(
                "Invalid port number".to_string(),
            ));
        }
        Ok(())
    }
}

// The HTTP transport's factory is `http_unified::HttpTransportFactory`, beside the transport it
// builds. A second `HttpTransportFactory` here, with its own and weaker config check, was removed
// (PR B, Task 9), as `abstraction`'s shadowing `TcpTransportFactory` was in Task 7.
