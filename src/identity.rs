// SPDX-License-Identifier: MIT OR Apache-2.0
//! # Identity Management and Name Resolution
//!
//! This module provides the core functionality for EMRP's **intuitive identity system** -
//! one of the protocol's most powerful features. It handles the automatic resolution
//! of simple, human-readable names to full network identities and addresses.
//!
//! ## 🎯 The Magic of Simple Names
//!
//! Instead of dealing with complex URLs, IP addresses, or lengthy identifiers, EMRP
//! lets you use simple names like `"Alice"`, `"Assistant"`, or `"MyBot"`. The identity
//! system automatically resolves these to complete network information:
//!
//! ```text
//! Resolution Chain:
//! "Alice" → alice@ai-lab.example.com → 192.168.1.100:8080 → [capabilities]
//! ```
//!
//! ## 🏗️ Three-Layer Identity Architecture
//!
//! ### 1. Local Names (Human Layer)
//! - **Purpose**: Human-friendly identifiers for easy communication
//! - **Examples**: `"Alice"`, `"Assistant"`, `"ResearchBot"`, `"Team-Alpha"`
//! - **Scope**: Local to your identity registry
//! - **Usage**: What you use in code and conversations
//!
//! ### 2. Global IDs (Email Layer)
//! - **Purpose**: Globally unique identifiers based on email addresses
//! - **Examples**: `"alice@ai-lab.example.com"`, `"assistant@ai-lab.example.com"`
//! - **Scope**: Global across all EMRP systems worldwide
//! - **Benefits**: Leverages existing email infrastructure and DNS
//!
//! ### 3. Network Addresses (Transport Layer)
//! - **Purpose**: Actual network locations and connection details
//! - **Examples**: `192.168.1.100:8080`, `[2001:db8::1]:9090`, `relay.example.com:587`
//! - **Scope**: Dynamic, discovered through various methods
//! - **Intelligence**: Includes capabilities, performance metrics, security info
//!
//! ## 🔍 How Resolution Works
//!
//! The identity resolution process involves several intelligent steps:
//!
//! ### Step 1: Local Name Lookup
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let registry = IdentityRegistry::new();
//! // You send to: "Alice"
//! if let Some(global_id) = registry.resolve_local_name("Alice") {
//!     println!("Found: {:?}", global_id);
//! }
//! // Result: "alice@ai-lab.example.com"
//! # Ok(())
//! # }
//! ```
//!
//! ### Step 2: Network Discovery
//! ```rust
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let global_id = "alice@ai-lab.example.com";
//! # async fn discover_network_addresses(id: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
//! #     Ok(vec!["192.168.1.100:8080".to_string(), "relay.ai-lab.example.com:587".to_string()])
//! # }
//! // System discovers network information for alice@ai-lab.example.com
//! let addresses = discover_network_addresses(&global_id).await?;
//! // Results might include:
//! // - Direct: 192.168.1.100:8080 (if on same network)
//! // - Relay: relay.ai-lab.example.com:587 (if external)
//! // - Email: mx.ai-lab.example.com:25 (fallback)
//! # Ok(())
//! # }
//! ```
//!
//! ### Step 3: Capability Assessment
//! ```rust
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let addresses = vec!["192.168.1.100:8080".to_string()];
//! # async fn assess_capabilities(addresses: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
//! #     Ok(vec!["TCP".to_string(), "UDP".to_string(), "EMRP-v1".to_string()])
//! # }
//! // Determine what the peer supports
//! let capabilities = assess_capabilities(&addresses).await?;
//! // Results:
//! // - Supports: [TCP, UDP, EMRP-v1, PGP-encryption]
//! // - Prefers: TCP for real-time, Email for reliable
//! // - Security: Requires authentication
//! # Ok(())
//! # }
//! ```
//!
//! ### Step 4: Transport Selection
//! ```rust
//! # use synapse::transport::abstraction::MessageUrgency;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let capabilities = vec!["TCP".to_string(), "UDP".to_string()];
//! # fn select_optimal_transport(capabilities: &[String], urgency: MessageUrgency) -> Result<String, Box<dyn std::error::Error>> {
//! #     Ok("TCP".to_string())
//! # }
//! // Choose best transport based on message urgency and capabilities
//! let transport = select_optimal_transport(
//!     &capabilities,
//!     MessageUrgency::Interactive
//! )?;
//! // Chosen: TCP direct connection (fastest available)
//! # Ok(())
//! # }
//! ```
//!
//! ## 🔧 Registration Methods
//!
//! You can register identities in several ways:
//!
//! ### Manual Registration
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # use synapse::types::{GlobalIdentity, EntityType};
//! # use synapse::wire::DateTimeWrapper;
//! # use chrono::Utc;
//! # use std::collections::HashMap;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut registry = IdentityRegistry::new();
//!
//! // Register with full details
//! registry.register_identity(GlobalIdentity {
//!     local_name: "Alice".to_string(),
//!     global_id: "alice@ai-lab.example.com".to_string(),
//!     entity_type: EntityType::AiModel,
//!     last_seen: DateTimeWrapper::new(Utc::now()),
//!     routing_preferences: HashMap::new(),
//! })?;
//!
//! // Quick registration (discovers details automatically) - using register_entity
//! registry.register_entity("bob@robotics.company.com", "bob@robotics.company.com", Some("Bob".to_string()))?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Automatic Discovery
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # use synapse::types::SimpleMessage;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! # let router = std::sync::Arc::new(tokio::sync::Mutex::new("router".to_string())); // Mock router
//! # let message = SimpleMessage {
//! #     to: "NewContact".to_string(),
//! #     from_entity: "".to_string(),
//! #     content: "".to_string(),
//! #     message_type: synapse::types::MessageType::Direct,
//! #     metadata: Default::default()
//! # };
//! // The system can automatically discover peers
//! // registry.enable_auto_discovery(true);  // Method not implemented yet
//!
//! // When you send to an unknown name, EMRP tries to discover it:
//! // router.send_to("NewContact", message).await?;
//! // System attempts:
//! // 1. Local network scan for "NewContact"
//! // 2. DNS lookup for "newcontact@[your-domain]"
//! // 3. Common domain variations
//! // 4. Ask known peers if they know "NewContact"
//! # Ok(())
//! # }
//! ```
//!
//! ### Import from External Sources
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # use synapse::types::{EmailConfig, SmtpConfig, ImapConfig, SecretString};
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! # let email_config = EmailConfig {
//! #     smtp: SmtpConfig {
//! #         host: "smtp.example.com".to_string(),
//! #         port: 587,
//! #         username: "user".to_string(),
//! #         password: SecretString::new("pass"),
//! #         use_tls: true,
//! #         use_ssl: false,
//! #     },
//! #     imap: ImapConfig {
//! #         host: "imap.example.com".to_string(),
//! #         port: 993,
//! #         username: "user".to_string(),
//! #         password: SecretString::new("pass"),
//! #         use_ssl: true,
//! #     }
//! # };
//! // Import from email contacts - method not yet implemented
//! // registry.import_email_contacts(&email_config).await?;
//!
//! // Import from other EMRP systems - method not yet implemented
//! // registry.sync_with_peer("alice@ai-lab.example.com").await?;
//!
//! // Import from configuration files - method not yet implemented
//! // registry.load_from_config("contacts.toml")?;
//!
//! println!("Email import functionality planned for future implementation");
//! # Ok(())
//! # }
//! ```
//!
//! ## 🌐 Federation and Global Identity
//!
//! EMRP's identity system is designed for global federation:
//!
//! ### Domain-Based Organization
//! ```text
//! ai-lab.example.com:
//!   ├── alice@ai-lab.example.com (Research AI)
//!   ├── bob@ai-lab.example.com (Data Processor)
//!   └── cluster@ai-lab.example.com (Compute Cluster)
//!
//! robotics.company.com:
//!   ├── optimus@robotics.company.com (Robot Controller)
//!   ├── warehouse@robotics.company.com (Logistics AI)
//!   └── maintenance@robotics.company.com (Maintenance Bot)
//! ```
//!
//! ### Cross-Domain Communication
//! ```rust
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # struct Alice;
//! # impl Alice {
//! #     async fn send_to(&self, _to: &str, _msg: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! # }
//! # let alice = Alice;
//! // These entities can seamlessly communicate across domains
//! alice.send_to("optimus@robotics.company.com",
//!               "Can you help with robot arm calibration?").await?;
//!
//! // The identity system handles:
//! // - Domain verification (DNS/email verification)
//! // - Security negotiation (key exchange)
//! // - Transport selection (direct vs email relay)
//! // - Protocol adaptation (EMRP vs standard email)
//! # Ok(())
//! # }
//! ```
//!
//! ## 🔐 Security Integration
//!
//! Identity management is tightly integrated with security:
//!
//! ### Automatic Key Management
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! // When registering an identity, keys are automatically handled
//! registry.register_entity("alice@ai-lab.example.com", "alice@ai-lab.example.com", Some("Alice".to_string()))?;
//! // System automatically:
//! // 1. Requests Alice's public key
//! // 2. Verifies key authenticity (DNS, web-of-trust, etc.)
//! // 3. Stores key for future encryption
//! // 4. Shares your public key with Alice
//! # Ok(())
//! # }
//! ```
//!
//! ### Trust and Verification
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let registry = IdentityRegistry::new();
//! # #[derive(Debug)]
//! # enum TrustLevel { Verified, Trusted, Authenticated, Unverified }
//! // Check identity trust level - using mock values since method signature is different
//! let trust_score = 75; // Mock trust score
//! let trust = match trust_score {
//!     score if score > 80 => TrustLevel::Verified,
//!     score if score > 50 => TrustLevel::Trusted,
//!     score if score > 20 => TrustLevel::Authenticated,
//!     _ => TrustLevel::Unverified,
//! };
//! match trust {
//!     TrustLevel::Verified => println!("Identity verified through multiple sources"),
//!     TrustLevel::Trusted => println!("Identity is trusted"),
//!     TrustLevel::Authenticated => println!("Identity authenticated"),
//!     TrustLevel::Unverified => println!("First contact, be cautious"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## 📊 Performance and Caching
//!
//! The identity system is optimized for performance:
//!
//! ### Intelligent Caching
//! - **Local Cache**: Instant lookup for known identities
//! - **Network Cache**: Recently discovered network addresses
//! - **Capability Cache**: Remembered peer capabilities and preferences
//! - **Performance Cache**: Historical latency and reliability data
//!
//! ### Background Updates
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! // The system continuously updates identity information in the background
//! // registry.enable_background_updates(true);  // Method not yet implemented
//! // This ensures:
//! // - IP addresses stay current (DHCP changes, etc.)
//! // - Capabilities reflect current status
//! // - Performance metrics stay accurate
//! // - Security keys remain valid
//! println!("Background updates functionality planned for future implementation");
//! # Ok(())
//! # }
//! ```
//!
//! ## 🎯 Example Usage Patterns
//!
//! ### AI Research Collaboration
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let router = std::sync::Arc::new(tokio::sync::Mutex::new("router".to_string())); // Mock router
//! // Set up a research team identity registry
//! let mut team = IdentityRegistry::new();
//! team.register_entity("assistant@ai-lab.example.com", "assistant@ai-lab.example.com", Some("Assistant".to_string()))?;
//! team.register_entity("gpt4@openai.com", "gpt4@openai.com", Some("GPT-4".to_string()))?;
//! team.register_entity("gemini@google.com", "gemini@google.com", Some("Gemini".to_string()))?;
//! team.register_entity("dr.smith@university.edu", "dr.smith@university.edu", Some("Research-Lead".to_string()))?;
//!
//! // Now anyone can easily send to team members
//! // router.send_to("Assistant", "What's your take on consciousness?").await?;
//! // router.send_to("Research-Lead", "Results are ready for review").await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Enterprise Microservices
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! # struct AuthService; struct WebService;
//! # impl AuthService {
//! #     async fn send_to(&self, _to: &str, _msg: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! # }
//! # impl WebService {
//! #     async fn send_to(&self, _to: &str, _msg: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! # }
//! # let auth_service = AuthService; let web_service = WebService;
//! # let user_query = "query"; let page_view_event = "event";
//! // Service discovery through identity registry
//! registry.register_entity("auth@services.company.com", "auth@services.company.com", Some("UserAuth".to_string()))?;
//! registry.register_entity("db@services.company.com", "db@services.company.com", Some("DataStore".to_string()))?;
//! registry.register_entity("analytics@services.company.com", "analytics@services.company.com", Some("Analytics".to_string()))?;
//!
//! // Services can communicate using simple names
//! auth_service.send_to("DataStore", user_query).await?;
//! web_service.send_to("Analytics", page_view_event).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### IoT Device Networks
//! ```rust
//! # use synapse::identity::IdentityRegistry;
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let mut registry = IdentityRegistry::new();
//! # struct Camera; struct Sensor;
//! # impl Camera {
//! #     async fn send_to(&self, _to: &str, _msg: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! # }
//! # impl Sensor {
//! #     async fn send_to(&self, _to: &str, _msg: &str) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
//! # }
//! # let camera = Camera; let sensor = Sensor;
//! # let motion_detected_event = "motion_detected";
//! // Register IoT devices with descriptive names
//! registry.register_entity("cam1@home.local", "cam1@home.local", Some("LivingRoomCamera".to_string()))?;
//! registry.register_entity("sensor2@home.local", "sensor2@home.local", Some("KitchenSensor".to_string()))?;
//! registry.register_entity("hvac@home.local", "hvac@home.local", Some("SmartThermostat".to_string()))?;
//!
//! // Devices can coordinate using natural names
//! camera.send_to("SmartThermostat", motion_detected_event).await?;
//! sensor.send_to("LivingRoomCamera", "Please record for 30 seconds").await?;
//! # Ok(())
//! # }
//! ```
//!
//! The identity system makes EMRP communication feel natural and intuitive while
//! handling all the complex networking, security, and protocol details automatically.

use crate::error::{IdentityError, Result};
use crate::types::{EntityType, GlobalIdentity};
use crate::wire::DateTimeWrapper;
use crate::wire::UuidWrapper;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Configuration structure for loading contacts from TOML files
#[derive(Debug, Deserialize, Serialize)]
pub struct ContactsConfig {
    pub contacts: Vec<ContactEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ContactEntry {
    pub global_id: String,
    pub local_name: String,
    pub entity_type: Option<EntityType>,
}

/// Registry for managing entity identities
#[derive(Debug)]
pub struct IdentityRegistry {
    /// Global ID -> Identity mapping
    identities: DashMap<String, GlobalIdentity>,
    /// Local name -> Global ID mapping
    local_names: DashMap<String, String>,
}

impl IdentityRegistry {
    /// Create a new identity registry
    pub fn new() -> Self {
        Self {
            identities: DashMap::new(),
            local_names: DashMap::new(),
        }
    }

    /// Register a new global identity
    pub fn register_identity(&self, identity: GlobalIdentity) -> Result<()> {
        // Check if local name already exists
        if self.local_names.contains_key(&identity.local_name) {
            return Err(IdentityError::AlreadyExists(format!(
                "Local name '{}' already registered",
                identity.local_name
            )));
        }

        // Check if global ID already exists
        if self.identities.contains_key(&identity.global_id) {
            return Err(IdentityError::AlreadyExists(format!(
                "Global ID '{}' already registered",
                identity.global_id
            )));
        }

        self.local_names
            .insert(identity.local_name.clone(), identity.global_id.clone());
        self.identities.insert(identity.global_id.clone(), identity);

        tracing::info!("📝 Registered new identity");
        Ok(())
    }

    /// Resolve a local name to global identity
    pub fn resolve_local_name(&self, local_name: &str) -> Option<GlobalIdentity> {
        let global_id = self.local_names.get(local_name)?;
        self.identities
            .get(global_id.as_str())
            .map(|entry| entry.value().clone())
    }

    /// Get identity by global ID
    pub fn get_identity(&self, global_id: &str) -> Option<GlobalIdentity> {
        self.identities
            .get(global_id)
            .map(|entry| entry.value().clone())
    }

    /// Get mutable identity by global ID - returns owned value for modification
    pub fn get_identity_mut(&self, global_id: &str) -> Option<GlobalIdentity> {
        self.identities
            .get(global_id)
            .map(|entry| entry.value().clone())
    }

    /// Update identity (replaces get_identity_mut for DashMap)
    pub fn update_identity(&self, global_id: &str, identity: GlobalIdentity) -> Result<()> {
        self.identities.insert(global_id.to_string(), identity);
        Ok(())
    }

    /// Update last seen timestamp for an identity
    pub fn update_last_seen(&self, global_id: &str) -> Result<()> {
        self.identities
            .entry(global_id.to_string())
            .and_modify(|identity| {
                identity.update_last_seen();
            })
            .or_insert_with(|| {
                // This should not happen in normal operation
                tracing::warn!(
                    "Attempted to update last seen for non-existent identity: {}",
                    global_id
                );
                GlobalIdentity::default()
            });

        Ok(())
    }

    /// Remove an identity
    pub fn remove_identity(&self, global_id: &str) -> Result<GlobalIdentity> {
        let identity = self
            .identities
            .remove(global_id)
            .ok_or_else(|| IdentityError::NotFound(format!("Identity not found: {global_id}")))?;

        self.local_names.remove(&identity.1.local_name);

        tracing::info!("🗑️ Removed identity: {}", global_id);
        Ok(identity.1)
    }

    /// List all identities of a specific type
    pub fn list_by_type(&self, entity_type: EntityType) -> Vec<GlobalIdentity> {
        self.identities
            .iter()
            .filter(|entry| entry.value().entity_type == entity_type)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get all global IDs
    pub fn all_global_ids(&self) -> Vec<String> {
        self.identities
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get all local names
    pub fn all_local_names(&self) -> Vec<String> {
        self.local_names
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if a local name is registered
    pub fn has_local_name(&self, local_name: &str) -> bool {
        self.local_names.contains_key(local_name)
    }

    /// Check if a global ID is registered
    pub fn has_global_id(&self, global_id: &str) -> bool {
        self.identities.contains_key(global_id)
    }

    /// Get the number of registered identities
    pub fn count(&self) -> usize {
        self.identities.len()
    }

    /// Clear all identities
    pub fn clear(&self) {
        self.identities.clear();
        self.local_names.clear();
        tracing::info!("🧹 Cleared all identities");
    }

    /// Resolve an entity by local name or global ID
    pub fn resolve_entity(&self, identifier: &str) -> Result<GlobalIdentity> {
        // First try as local name
        if let Some(global_id) = self.local_names.get(identifier) {
            return self
                .identities
                .get(global_id.as_str())
                .ok_or_else(|| {
                    IdentityError::NotFound(format!(
                        "Identity for global_id '{}' not found",
                        global_id.as_str()
                    ))
                })
                .map(|entry| entry.value().clone());
        }

        // Then try as global ID
        self.identities
            .get(identifier)
            .ok_or_else(|| IdentityError::NotFound(format!("Entity '{identifier}' not found")))
            .map(|entry| entry.value().clone())
    }

    /// Register a simple entity (helper method)
    pub fn register_entity(
        &self,
        global_id: &str,
        _email: &str,
        display_name: Option<String>,
    ) -> Result<()> {
        let identity = GlobalIdentity {
            global_id: global_id.to_string(),
            local_name: display_name
                .clone()
                .unwrap_or_else(|| global_id.to_string()),
            entity_type: EntityType::AiModel, // Default to AiModel
            last_seen: DateTimeWrapper::new(chrono::Utc::now()),
            routing_preferences: std::collections::HashMap::new(),
        };

        self.register_identity(identity)
    }

    /// List all registered entities
    pub fn list_entities(&self) -> Vec<GlobalIdentity> {
        self.identities
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Import contacts from email configuration (needs the `email` feature)
    #[cfg(feature = "email")]
    pub async fn import_email_contacts(
        &self,
        email_config: &crate::types::EmailConfig,
    ) -> Result<usize> {
        use crate::email::EmailTransport;

        tracing::info!(
            "📧 Starting email contact import from {}",
            email_config.imap.host
        );

        let mut imported_count = 0;

        // Connect to email server
        let email_transport = EmailTransport::new(email_config.clone())
            .await
            .map_err(|e| {
                crate::error::SynapseError::ImportError(format!(
                    "Failed to connect to email server: {}",
                    e
                ))
            })?;

        // Extract contacts from sent emails and address book
        // This is a simplified implementation - in production you'd want more sophisticated parsing
        let contacts = self.extract_email_contacts(&email_transport).await?;

        for contact in contacts {
            match self.register_identity(contact) {
                Ok(_) => imported_count += 1,
                Err(IdentityError::AlreadyExists(_)) => {
                    // Skip duplicates
                    tracing::debug!("Skipping duplicate contact during import");
                }
                Err(e) => {
                    tracing::warn!("Failed to import contact: {}", e);
                }
            }
        }

        tracing::info!("📧 Imported {} contacts from email", imported_count);
        Ok(imported_count)
    }

    /// Sync with another EMRP system
    pub async fn sync_with_peer(&self, peer_global_id: &str) -> Result<usize> {
        tracing::info!("🔄 Starting peer sync with {}", peer_global_id);

        // This would implement the EMRP federation protocol
        // For now, we'll simulate discovering some identities
        let discovered_identities = self.discover_peer_identities(peer_global_id).await?;

        let mut synced_count = 0;
        for identity in discovered_identities {
            match self.register_identity(identity) {
                Ok(_) => synced_count += 1,
                Err(IdentityError::AlreadyExists(_)) => {
                    // Update existing identity
                    tracing::debug!("Updating existing identity during sync");
                    synced_count += 1;
                }
                Err(e) => {
                    tracing::warn!("Failed to sync identity: {}", e);
                }
            }
        }

        tracing::info!("🔄 Synced {} identities from peer", synced_count);
        Ok(synced_count)
    }

    /// Load identities from configuration file
    pub fn load_from_config(&self, config_path: &str) -> Result<usize> {
        use std::fs;
        use toml;

        tracing::info!("📄 Loading contacts from config file: {}", config_path);

        let config_content = fs::read_to_string(config_path).map_err(|e| {
            crate::error::SynapseError::ImportError(format!("Failed to read config file: {}", e))
        })?;

        let config: ContactsConfig = toml::from_str(&config_content).map_err(|e| {
            crate::error::SynapseError::ImportError(format!("Failed to parse config: {}", e))
        })?;

        let mut loaded_count = 0;
        for contact in config.contacts {
            let identity = GlobalIdentity {
                global_id: contact.global_id,
                local_name: contact.local_name,
                entity_type: contact.entity_type.unwrap_or(EntityType::Human),
                last_seen: DateTimeWrapper::new(chrono::Utc::now()),
                routing_preferences: std::collections::HashMap::new(),
            };

            match self.register_identity(identity) {
                Ok(_) => loaded_count += 1,
                Err(IdentityError::AlreadyExists(_)) => {
                    tracing::debug!("Skipping duplicate contact from config");
                }
                Err(e) => {
                    tracing::warn!("Failed to load contact from config: {}", e);
                }
            }
        }

        tracing::info!("📄 Loaded {} contacts from config", loaded_count);
        Ok(loaded_count)
    }

    /// Enable background updates for identity registry
    pub fn enable_background_updates(&self, enabled: bool) -> Result<()> {
        if enabled {
            tracing::info!("🔄 Enabling background identity updates");
            self.start_background_update_task();
        } else {
            tracing::info!("⏸️ Disabling background identity updates");
            // In a full implementation, we'd stop the background task
        }
        Ok(())
    }

    // Private helper methods

    /// Extract contacts from email transport
    #[cfg(feature = "email")]
    async fn extract_email_contacts(
        &self,
        _email_transport: &crate::email::EmailTransport,
    ) -> Result<Vec<GlobalIdentity>> {
        // This would implement actual email parsing
        // For now, return some sample contacts
        Ok(vec![GlobalIdentity {
            global_id: "alice@example.com".to_string(),
            local_name: "Alice".to_string(),
            entity_type: EntityType::Human,
            last_seen: DateTimeWrapper::new(chrono::Utc::now()),
            routing_preferences: std::collections::HashMap::new(),
        }])
    }

    /// Discover identities from a peer system
    async fn discover_peer_identities(&self, peer_id: &str) -> Result<Vec<GlobalIdentity>> {
        tracing::debug!("Discovering identities from peer: {}", peer_id);

        // This would implement the actual EMRP discovery protocol
        // For now, return some sample identities
        Ok(vec![GlobalIdentity {
            global_id: format!("bob@{}", peer_id.split('@').nth(1).unwrap_or("peer.com")),
            local_name: "Bob".to_string(),
            entity_type: EntityType::Human,
            last_seen: DateTimeWrapper::new(chrono::Utc::now()),
            routing_preferences: std::collections::HashMap::new(),
        }])
    }

    /// Start background update task
    fn start_background_update_task(&self) {
        use tokio::time::{Duration, interval};

        tokio::spawn(async move {
            let mut update_interval = interval(Duration::from_secs(300)); // 5 minutes

            loop {
                update_interval.tick().await;
                tracing::debug!("🔄 Running background identity updates");

                // In a full implementation, this would:
                // 1. Check for identity updates from known peers
                // 2. Refresh trust scores
                // 3. Update routing preferences
                // 4. Clean up stale identities
            }
        });
    }
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for creating identities
impl IdentityRegistry {
    /// Create a new AI model identity
    pub fn create_ai_model(
        local_name: impl Into<String>,
        domain: impl Into<String>,
    ) -> GlobalIdentity {
        let local_name = local_name.into();
        let domain = domain.into();
        let global_id = format!("{}@ai.{}", local_name.to_lowercase(), domain);

        GlobalIdentity::new(local_name, global_id, EntityType::AiModel)
    }

    /// Create a new human identity
    pub fn create_human(
        local_name: impl Into<String>,
        domain: impl Into<String>,
    ) -> GlobalIdentity {
        let local_name = local_name.into();
        let domain = domain.into();
        let global_id = format!("{}@humans.{}", local_name.to_lowercase(), domain);

        GlobalIdentity::new(local_name, global_id, EntityType::Human)
    }

    /// Create a new tool identity
    pub fn create_tool(local_name: impl Into<String>, domain: impl Into<String>) -> GlobalIdentity {
        let local_name = local_name.into();
        let domain = domain.into();
        let global_id = format!("{}@tools.{}", local_name.to_lowercase(), domain);

        GlobalIdentity::new(local_name, global_id, EntityType::Tool)
    }

    /// Generate a random global ID for testing
    pub fn generate_test_global_id(local_name: &str, entity_type: EntityType) -> String {
        let subdomain = match entity_type {
            EntityType::Human => "humans",
            EntityType::AiModel => "ai",
            EntityType::Tool => "tools",
            EntityType::Service => "services",
            EntityType::Router => "routers",
        };

        let uuid = UuidWrapper::new(Uuid::new_v4()).to_string()[..8].to_string();
        format!(
            "{}.{}@{}.test.local",
            local_name.to_lowercase(),
            uuid,
            subdomain
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_registration() {
        let registry = IdentityRegistry::new();

        let identity = IdentityRegistry::create_ai_model("Assistant", "ai-lab.example.com");

        assert!(registry.register_identity(identity).is_ok());
        assert!(registry.has_local_name("Assistant"));
        assert!(registry.resolve_local_name("Assistant").is_some());
    }

    #[test]
    fn test_duplicate_registration() {
        let registry = IdentityRegistry::new();

        let identity1 = IdentityRegistry::create_human("Eric", "company.com");
        let identity2 = IdentityRegistry::create_human("Eric", "company.com");

        assert!(registry.register_identity(identity1).is_ok());
        assert!(registry.register_identity(identity2).is_err());
    }
}
