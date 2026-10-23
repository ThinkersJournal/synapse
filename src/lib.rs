// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Synapse: Neural Communication Network
//!
//! **A revolutionary neural communication network for AI entities, distributed systems, and modern applications
//! with federated identity management, dual trust systems, and privacy-respecting discovery.**
//!
//! ## 🌟 What Makes Synapse Special?
//! - **🧠 Neural Identity**: Contextual participant discovery with natural language
//! - **🌍 Federated Network**: Cross-organizational communication and trust
//! - **⚡ Intelligent Routing**: Multi-speed communication with smart transport selection
//! - **🔒 Privacy First**: Advanced privacy controls with stealth and unlisted modes
//! - **🤖 AI-Native**: Designed for AI-to-AI and human-to-AI interaction
//! - **🏛️ Pluggable Trust**: authenticated senders (pinned keys, certificate chains, revocations) in
//!   the core, and an optional `TrustSource` hook for a score from elsewhere
//!
//! ## 🎯 The Neural Identity System
//! One of Synapse's most powerful features is its **contextual identity system**:
//!
//! ```text
//! Simple Name → Global ID → Network Discovery → Smart Transport Selection
//!
//! "Alice" → alice@ai-lab.example.com → 192.168.1.100:8080 → TCP (real-time)
//! "Assistant" → assistant@ai-lab.example.com → [external] → Email (reliable)
//! "LocalBot" → bot@localhost → 127.0.0.1:9090 → UDP (fast local)
//! ```
//! This means you can send messages using simple, human-readable names, and Synapse
//! automatically figures out:
//! - Where the recipient is located (email address, IP, domain)
//! - How to reach them (direct connection, relay, email)
//! - What transport to use (TCP for speed, email for reliability)
//! - What security to apply (encryption level, authentication)
//! ## 🏗️ Architecture Overview
//!
//! Synapse operates on multiple intelligent layers:
//! ### Layer 1: Message Layer
//! - Simple message types: Direct, Broadcast, Conversation, Notification
//! - Automatic serialization and security wrapping
//! - Metadata handling and routing information
//!
//! ### Layer 2: Identity Resolution
//! - **Local Names**: `"Alice"`, `"Bob"`, `"MyAI"` (human-friendly)
//! - **Global IDs**: `"alice@company.com"` (globally unique)
//! - **Network Addresses**: IP addresses, ports, service endpoints
//! - **Capability Discovery**: What transports and features each peer supports
//!
//! ### Layer 3: Multi-Transport Intelligence
//! - **Real-time Transports**: TCP, UDP, WebSocket for <100ms messaging
//! - **Local Discovery**: mDNS, LAN scanning, Bluetooth for peer finding
//! - **Email Backbone**: SMTP/IMAP for reliable, federated communication
//! - **NAT Traversal**: STUN/TURN/UPnP for firewall penetration
//!
//! ### Layer 4: Email Server Integration
//! - **Full Server Mode**: Run your own SMTP/IMAP when externally accessible
//! - **Relay Mode**: Outgoing only when behind firewall/NAT
//! - **External Provider**: Fall back to Gmail, Outlook, etc. when restricted
//! ## 🚀 Quick Start Example
//!
//! ```rust
//! use synapse::*;
//! use synapse::types::{MessageType, SecurityLevel};
//! use synapse::transport::abstraction::MessageUrgency;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize with your identity
//!     let config = Config::default();
//!     let router = SynapseRouter::new(config, "MyBot@example.com".to_string()).await?;
//!
//!     // Register some contacts (or use auto-discovery) - using register_entity
//!     // router.register_peer("Alice", "alice@ai-lab.example.com").await?;
//!
//!     // Start all services
//!     router.start().await?;
//!
//!     // Send messages using simple names! (commented out for doctest)
//!     // router.send_message_smart(
//!     //     "alice@example.com",             // Use email address instead
//!     //     "Hello from Synapse!",           // Your message
//!     //     MessageType::Direct,             // Type of communication
//!     //     SecurityLevel::Authenticated,    // Security level
//!     //     MessageUrgency::Interactive,     // Speed vs reliability preference
//!     // ).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## 🎛️ Advanced Features
//!
//! ### Automatic Transport Selection
//! Synapse intelligently chooses the best transport based on:
//! - **Message urgency**: Real-time vs. reliable delivery
//! - **Network conditions**: Latency, bandwidth, connectivity
//! - **Security requirements**: Encryption levels, authentication
//! - **Peer capabilities**: What transports the recipient supports
//! ```rust
//! # use synapse::*;
//! # use synapse::types::{MessageType, SecurityLevel};
//! # use synapse::transport::abstraction::MessageUrgency;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let config = Config::default();
//! # let router = SynapseRouter::new(config, "test@example.com".to_string()).await?;
//! // Real-time collaboration (prefers TCP/UDP) - commented out for doctest
//! // router.send_message_smart(
//! //     "ai-partner@example.com",
//! //     "Quick question about the algorithm...",
//! //     MessageType::Direct,
//! //     SecurityLevel::Public,
//! //     MessageUrgency::RealTime,  // <100ms preferred
//! // ).await?;
//! //
//! // // Reliable file sharing (uses email for guaranteed delivery) - simplified message
//! // router.send_message_smart(
//! //     "research-team@example.com",
//! //     "Important results file: important_results.pdf",
//! //     MessageType::Direct,
//! //     SecurityLevel::Secure,
//! //     MessageUrgency::Background,  // Reliability over speed
//! // ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Email Server Capabilities
//!
//! When your system is externally accessible, EMRP can run a full email server:
//! ```rust
//! # use synapse::*;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let config = Config::default();
//! let router = SynapseRouter::new(config, "bot@mydomain.com".to_string()).await?;
//!
//! if router.is_running_email_server() {
//!     // You can receive emails directly at bot@mydomain.com
//!     // Other EMRP systems can send messages to your domain
//!     // Supports both EMRP messages and standard emails
//!     println!("🏃 Running full email infrastructure");
//! } else {
//!     // Falls back to external providers (Gmail, etc.)
//!     println!("🌐 Using external email services");
//! }
//! # Ok(())
//! # }
//! ```
//! ### Security by Design
//!
//! All messages are automatically secured:
//! - **🔒 Content Confidentiality**: Not implemented -- `SecurityLevel::Private`/`Secure` are
//!   refused (see `SynapseError::UnsupportedSecurityLevel`); messages are signed, not encrypted
//! - **✍️ Digital Signatures**: Verify sender authenticity
//! - **🛡️ TLS Transport**: Encrypted connections on transports that support it (QUIC, HTTPS);
//!   TCP, UDP and WebSocket transports in this build are unencrypted
//! - **🔑 Explicit Key Management**: Keys must be generated via `generate_keypair()`; there is no
//!   automatic key distribution
//! ## 📚 Module Overview
//!
//! - [`router_merged`]: Main interface (`SynapseRouter`) - start here for most use cases
//! - [`identity`]: Name resolution and identity management
//! - [`transport`]: Multi-transport layer and intelligent routing
//! - [`email_server`]: SMTP/IMAP server implementation
//! - [`types`]: Core message types and data structures
//! - [`crypto`]: Encryption, signatures, and key management
//! - [`config`]: Configuration and setup
//! ## 🎯 Use Cases
//!
//! ### AI & Machine Learning
//! - Multi-agent AI systems coordinating in real-time
//! - AI-human collaboration with natural addressing
//! - Federated learning with secure model sharing
//! - Research collaboration between AI entities worldwide
//! ### Enterprise & Distributed Systems
//! - Microservice communication with email-based service discovery
//! - Cross-organization messaging leveraging existing email infrastructure
//! - Reliable async processing with email-based job queuing
//! - Legacy system integration through email gateways
//! ### IoT & Edge Computing
//! - Device-to-cloud communication using email when internet is limited
//! - Peer-to-peer IoT networks with automatic discovery
//! - Edge AI coordination across distributed deployments
//! - Resilient communication in unstable network conditions
//! ## 🔧 Getting Started
//!
//! 1. **Add to Cargo.toml**: `synapse = { git = "https://github.com/ThinkersJournal/synapse" }` (the 6.0.0
//!    release candidates are not on crates.io yet)
//! 2. **See examples**: `cargo run --example email_integration_test`
//! 3. **Read the docs**: Full API documentation and guides
//! 4. **Join the community**: Contribute and get support
//!
//! The combination of email's universal reach with modern real-time transports
//! creates a communication system that's both globally federated and
//! performance-optimized - perfect for the AI-driven future.
pub mod synapse;
pub mod types;
pub mod wire;
pub use crate::types::SecureMessage;

pub mod config;
pub mod error;
pub mod security;
pub mod security_events;
pub mod state;

pub mod certificate;
pub mod circuit_breaker;
pub mod connectivity;
pub mod crypto;
pub mod delivery_ack;
pub mod email;
pub mod email_server;
pub mod identity;
pub mod keystore;
pub mod mailbox;
pub mod monitoring;
pub mod network_scope;
pub mod replay;
pub mod roles;
pub mod router_merged;
pub mod sealing;
pub mod sender_auth;
pub mod streaming;

pub mod transport;

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use email::EmailTransport;
pub use sender_auth::{SenderProof, SenderVerdict, TrustStore};

// Re-export transport types needed for tests
pub use config::Config;
pub use transport::providers::{
    MockTransport, ProductionTransportProvider, TestTransportProvider, TransportProvider,
};
pub use transport::{HybridConnection, NatMethod, Transport, TransportMetrics, TransportSelector};

// Synapse Neural Communication Network

// WebAssembly support
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Re-export key types for convenience
pub use error::SynapseError;

// Re-export transport types for tests and external usage
pub use transport::TransportRoute;
pub use transport::abstraction::MessageUrgency;

// Re-export the merged router type for tests and external usage.
// MultiTransportRouter stays reachable as crate::transport::router::MultiTransportRouter for
// anything that needs direct access, but is no longer part of the top-level surface.
pub use router_merged::SynapseRouter;

// Re-export Synapse key types (only on non-WASM platforms)
pub use synapse::models::{DiscoverabilityLevel, EntityType, ParticipantProfile};

// Re-export synapse submodules
pub use synapse::api;
pub use synapse::models;
pub use synapse::services;

/// Initialize the Synapse system with logging (not available on WASM)
#[cfg(not(target_arch = "wasm32"))]
pub fn init_logging() {
    tracing_subscriber::fmt::init();
}

/// Current protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Standard email headers for Synapse
pub mod headers {
    pub const VERSION: &str = "X-Synapse-Version";
    pub const MESSAGE_TYPE: &str = "X-Synapse-Message-Type";
    pub const FROM_ENTITY: &str = "X-Synapse-From-Entity";
    pub const TO_ENTITY: &str = "X-Synapse-To-Entity";
    pub const ENTITY_TYPE: &str = "X-Synapse-Entity-Type";
    pub const CAPABILITIES: &str = "X-Synapse-Capabilities";
    pub const ENCRYPTED: &str = "X-Synapse-Encrypted";
    pub const SIGNED: &str = "X-Synapse-Signed";
    pub const REQUEST_ID: &str = "X-Synapse-Request-ID";
    pub const TIMESTAMP: &str = "X-Synapse-Timestamp";
}
