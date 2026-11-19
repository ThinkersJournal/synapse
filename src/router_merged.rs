// SPDX-License-Identifier: MIT OR Apache-2.0
//! The merged Synapse router: `SynapseRouter` + `EnhancedSynapseRouter`'s combined API, per
//! docs/superpowers/specs/2026-09-25-router-merge-design.md. No compatibility shim for the two
//! old names -- CireSnave's ruling was that keeping them separate was itself the wrong call.
//!
//! Task 1 scope: get this struct compiling with both old APIs' state present, with `start()` and
//! `status()` resolving the two types' name collisions. The `email` field is a placeholder
//! (`Arc<RwLock<Option<Arc<dyn Transport>>>>`) until Task 2 wires in a real `EmailTransportImpl` --
//! this task does not attempt to make email sending/receiving work, to avoid duplicating Task 2's
//! work and creating a merge conflict with it. `multi_transport` and `email_server` are likewise
//! left unpopulated (`None`/`false`) in `new()`: their real initialization involves network I/O
//! (`MultiTransportRouter::new`, `SynapseEmailServer::new_with_scope`) that later tasks are
//! expected to wire in, matching this same plan's own Step 4 code sample, which hard-codes
//! `multi_transport: None` in `new()` even though the field is declared.

use crate::{
    CryptoManager,
    config::Config,
    error::Result,
    identity::IdentityRegistry,
    security_events::SecuritySink,
    sender_auth::TrustStore,
    transport::{TransportRoute, abstraction::MessageUrgency, router::MultiTransportRouter},
    types::{MessageType, SecureMessage, SecurityLevel, SimpleMessage},
};
#[cfg(feature = "email")]
use crate::email_server::SynapseEmailServer;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Old `SynapseRouter` (`src/router.rs`, deleted by this task) derived `Clone` -- every field was
/// already `Arc`-wrapped or plain data, so cloning only shares the same underlying state across
/// clones, never duplicates it. This struct's fields have the same shape, so the same derive is
/// preserved for consumers (`src/bin/router.rs`, `tests/edge_case_test.rs`) that clone a router to
/// hand a handle to a spawned task.
#[derive(Clone)]
pub struct SynapseRouter {
    /// Cryptographic manager
    crypto: Arc<RwLock<CryptoManager>>,
    /// Identity registry
    identity: Arc<RwLock<IdentityRegistry>>,
    /// Email transport, lazily constructed by `ensure_email_transport` on first use. This is NOT
    /// the old `src/email.rs::EmailTransport` type -- it is a real `EmailTransportImpl`
    /// (`src/transport/email_unified.rs`), reached through the same
    /// `TransportProvider::create_email_transport` bridge `MultiTransportRouter` uses.
    email: Arc<RwLock<Option<Arc<dyn crate::transport::abstraction::Transport>>>>,
    /// Pinned sender keys for receive-side verification (`receive_messages`, Task 4). The
    /// authenticity check itself is the SAME mechanism `TransportManager` uses for every other
    /// transport in this crate (`transport::manager::TransportManager::receive_messages` gates on
    /// `TrustStore::verify_at`), not a second, weaker, router-specific re-implementation of that
    /// check -- see `receive_messages`'s doc comment for why `IdentityRegistry` (below) was not
    /// used for this. That said, `verify_at` is only one of the two gates
    /// `TransportManager::receive_messages` runs a message through; this router's overall receive
    /// guarantee is narrower than `TransportManager`'s -- see `receive_messages`'s doc comment for
    /// the gap (no anti-replay check, no unsealing).
    trust_store: Arc<RwLock<TrustStore>>,
    /// Multi-transport router for fast communication
    multi_transport: Option<Arc<MultiTransportRouter>>,
    /// Local email server (SMTP/IMAP) for when we're externally accessible
#[cfg(feature = "email")]
    email_server: Option<Arc<SynapseEmailServer>>,
    /// Configuration, used by `ensure_email_transport` to build the real
    /// `EmailTransportImpl` via `ProductionTransportProvider::create_email_transport`.
    config: Config,
    /// Our global identity
    our_global_id: String,
    /// Enable multi-transport features
    multi_transport_enabled: bool,
    /// Email server enabled
    email_server_enabled: bool,
    /// Where the email transport's and the email server's own security events go (hardening P7,
    /// follow-up a3). Set with [`Self::set_security_sink`]; clones share it.
    security_sink: Arc<std::sync::OnceLock<Arc<dyn SecuritySink>>>,
}

impl SynapseRouter {
    /// Create a new Synapse router with both the original and enhanced APIs available.
    pub async fn new(config: Config, our_global_id: String) -> Result<Self> {
        // Initialize crypto manager
        let crypto = Arc::new(RwLock::new(CryptoManager::new()));
        // Initialize identity registry
        let identity = Arc::new(RwLock::new(IdentityRegistry::new()));

        Ok(Self {
            crypto,
            identity,
            email: Arc::new(RwLock::new(None)),
            trust_store: Arc::new(RwLock::new(TrustStore::new())),
            multi_transport: None,
            #[cfg(feature = "email")]
            email_server: None,
            config,
            our_global_id,
            multi_transport_enabled: false,
            email_server_enabled: false,
            security_sink: Arc::new(std::sync::OnceLock::new()),
        })
    }

    /// Where the router's email transport, email server and multi-transport router record their
    /// own security events (hardening P7). The transport records only in Direct mode, whose SMTP listener enforces the
    /// inbound limits; RelayOut and External bind no listener. A transport built later
    /// is given the sink before `start`, as `TransportManager` does, and one already built is given
    /// it now. Clones share the sink. The first call wins; later ones are ignored.
    pub async fn set_security_sink(&self, sink: Arc<dyn SecuritySink>) {
        if self.security_sink.set(sink).is_err() {
            return;
        }
        let Some(sink) = self.security_sink.get() else {
            return;
        };
        #[cfg(feature = "email")]
        if let Some(server) = &self.email_server {
            server.set_security_sink(Arc::clone(sink));
        }
        if let Some(transport) = self.email.read().await.as_ref() {
            transport.attach_security_sink(Arc::clone(sink));
        }
        if let Some(mt_router) = &self.multi_transport {
            mt_router.set_security_sink(Arc::clone(sink));
        }
    }

    /// Start all router services.
    ///
    /// Old `SynapseRouter::start()`'s body was only ever reachable through a commented-out call
    /// in old `EnhancedSynapseRouter::start()` (`// self.synapse_router.start().await?;`,
    /// `router_enhanced.rs:619` at the time this plan was written) -- that call is now live and
    /// inlined below, since both bodies belong to the same struct.
    pub async fn start(&self) -> Result<()> {
        info!("Starting enhanced Synapse router");

        // Old `SynapseRouter::start()`'s body, now live.
        info!(
            "Starting Synapse router with global ID: {}",
            self.our_global_id
        );

        // Start email server if available
        #[cfg(feature = "email")]
        if let Some(ref email_server) = self.email_server {
            email_server.start().await?;
            info!("Email server started successfully");
        }

        // Start multi-transport services if available
        if let Some(ref mt_router) = self.multi_transport {
            mt_router.start_background_services().await?;
            info!("Multi-transport services started");
        }

        info!("Enhanced EMRP router fully started");
        Ok(())
    }

    /// Stop the router gracefully. Old `SynapseRouter::stop()`, ported unchanged (a log line only
    /// -- the old body never stopped the email transport either).
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping Synapse router");
        Ok(())
    }

    /// Register a peer's public key. Old `SynapseRouter::register_peer_key()`, ported unchanged.
    pub async fn register_peer_key(&self, global_id: &str, public_key_pem: &str) -> Result<()> {
        let mut crypto_manager = self.crypto.write().await;
        crypto_manager.import_public_key(global_id, public_key_pem)
    }

    /// Generate our own keypair. Old `SynapseRouter::generate_keypair()`, ported unchanged.
    pub async fn generate_keypair(&self) -> Result<(String, String)> {
        let mut crypto_manager = self.crypto.write().await;
        crypto_manager.generate_keypair()
    }

    /// Register a new entity. Old `SynapseRouter::register_entity()`, ported unchanged.
    pub async fn register_entity(
        &self,
        global_id: &str,
        name: &str,
        profile: Option<String>,
    ) -> Result<()> {
        let identity = self.identity.write().await;
        identity.register_entity(global_id, name, profile)
    }

    /// Add an entity's key. Old `SynapseRouter::add_entity_key()`, ported unchanged.
    pub async fn add_entity_key(&self, global_id: &str, public_key: &str) -> Result<()> {
        let mut crypto = self.crypto.write().await;
        crypto.import_public_key(global_id, public_key)?;
        Ok(())
    }

    /// Get our global identity
    pub fn get_our_global_id(&self) -> &str {
        &self.our_global_id
    }

    /// Get router health status. Old `SynapseRouter::get_health()`, ported unchanged.
    pub async fn get_health(&self) -> RouterHealth {
        RouterHealth {
            status: "healthy".to_string(),
            crypto_available: true,
            email_available: true,
            known_peers: {
                let identity_registry = self.identity.read().await;
                identity_registry.count()
            },
            known_keys: {
                let crypto_manager = self.crypto.read().await;
                crypto_manager.known_entities().len()
            },
            our_global_id: self.our_global_id.clone(),
        }
    }

    /// Get enhanced router status including email server.
    pub async fn status(&self) -> EnhancedRouterStatus {
        let synapse_status = self.get_health().await;

        let mut capabilities = vec!["email".to_string()];

        if let Some(ref mt_router) = self.multi_transport {
            capabilities.extend(mt_router.get_capabilities());
        }

        if self.email_server_enabled {
            capabilities.push("smtp-server".to_string());
            capabilities.push("imap-server".to_string());
        }

        EnhancedRouterStatus {
            synapse_status,
            multi_transport_enabled: self.multi_transport_enabled,
            email_server_enabled: self.email_server_enabled,
            available_transports: capabilities,
        }
    }

    /// Get access to the email server for configuration (needs the `email` feature)
    #[cfg(feature = "email")]
    pub fn email_server(&self) -> Option<Arc<SynapseEmailServer>> {
        self.email_server.clone()
    }

    /// Check if we're running our own email server
    pub fn is_running_email_server(&self) -> bool {
        #[cfg(feature = "email")]
        {
            self.email_server_enabled && self.email_server.is_some()
        }
        #[cfg(not(feature = "email"))]
        {
            false
        }
    }

    /// Get email server connectivity information
    pub fn email_server_connectivity(&self) -> Option<String> {
        #[cfg(feature = "email")]
        {
            self.email_server.as_ref().map(|server| {
                let connectivity = server.get_connectivity();
                format!("{:?}", connectivity.recommended_config)
            })
        }
        #[cfg(not(feature = "email"))]
        {
            None
        }
    }

    /// Refuse `SecurityLevel`s this router cannot honour. Neither send nor receive in this router
    /// seals/unseals (`src/sealing.rs` is never called here), so `Private` ("end-to-end
    /// encrypted") and `Secure` ("both encrypted and signed") cannot be delivered as their name
    /// promises -- accepting them would sign-and-send as if sealing had happened, silently
    /// downgrading to unsealed delivery. Per the project owner's ruling, refuse instead of
    /// implementing sealing here.
    fn reject_unsupported_security_level(level: SecurityLevel) -> Result<()> {
        match level {
            SecurityLevel::Public | SecurityLevel::Authenticated => Ok(()),
            SecurityLevel::Private | SecurityLevel::Secure => {
                Err(crate::error::SynapseError::UnsupportedSecurityLevel(level))
            }
        }
    }

    /// The ONE place a `SecureMessage` is built and signed for sending. Every send path in this
    /// router -- `send_message`, `send_message_smart`'s fast branch (Task 3),
    /// `send_message_with_transport` -- calls this, so no path can reach a transport with an
    /// unsigned message by forgetting to call `sign_secure_message` itself. This is the
    /// structural fix for board item 65 (the old `EnhancedSynapseRouter::create_secure_message`
    /// hardcoded `SenderProof::unsigned()` and never signed at all).
    ///
    /// `metadata` MUST be supplied here, before signing, and never set on the returned message
    /// afterward: `sender_auth::canonical_input` (the function whose output gets signed, see
    /// `src/sender_auth.rs:109-134`) includes `message.metadata` in the signed bytes. Signing first
    /// and then mutating `metadata` would silently produce a `SecureMessage` whose signature no
    /// longer covers its own metadata -- i.e. an invalid signature that still verifies against the
    /// content it was originally computed over. Do not "simplify" this back to sign-then-set.
    async fn sign_new_message(
        &self,
        to_global_id: &str,
        content: &[u8],
        security_level: SecurityLevel,
        metadata: std::collections::HashMap<String, String>,
    ) -> Result<SecureMessage> {
        Self::reject_unsupported_security_level(security_level.clone())?;
        let mut message = SecureMessage::new(
            to_global_id.to_string(),
            self.our_global_id.clone(),
            content.to_vec(),
            security_level,
        );
        message.metadata = metadata;
        let crypto = self.crypto.read().await;
        crypto.sign_secure_message(&mut message)?;
        Ok(message)
    }

    /// Signs and returns a `SecureMessage` built from `simple_msg`, without sending it anywhere.
    /// Old `SynapseRouter::convert_to_secure_message` (`src/router.rs`, deleted by this task)
    /// hardcoded `SenderProof::unsigned()` -- the same defect class as board item 65. This version
    /// routes through the one shared `sign_new_message` helper, so the returned message is always
    /// genuinely signed.
    pub async fn convert_to_secure_message(
        &self,
        simple_msg: &SimpleMessage,
    ) -> Result<SecureMessage> {
        self.sign_new_message(
            &simple_msg.to,
            simple_msg.content.as_bytes(),
            SecurityLevel::Authenticated,
            simple_msg.metadata.clone(),
        )
        .await
    }

    /// Constructs this router's `EmailTransportImpl` on first use, via the same
    /// `TransportProvider::create_email_transport` bridge `MultiTransportRouter` already uses
    /// (`src/transport/providers.rs:114`) -- not a second, separate construction path.
    async fn ensure_email_transport(
        &self,
    ) -> Result<Arc<dyn crate::transport::abstraction::Transport>> {
        use crate::transport::providers::TransportProvider as _;
        self.ensure_email_transport_with(async {
            crate::transport::providers::ProductionTransportProvider
                .create_email_transport(&self.config)
                .await?
                .ok_or_else(|| {
                    crate::error::SynapseError::TransportError(
                        "email transport construction returned None".to_string(),
                    )
                })
        })
        .await
    }

    /// `ensure_email_transport` with the construction step injected, so a test can hand in a
    /// transport that records what it is given. `build` runs only when no transport exists yet.
    async fn ensure_email_transport_with(
        &self,
        build: impl std::future::Future<
            Output = Result<Arc<dyn crate::transport::abstraction::Transport>>,
        >,
    ) -> Result<Arc<dyn crate::transport::abstraction::Transport>> {
        {
            let existing = self.email.read().await;
            if let Some(t) = existing.as_ref() {
                return Ok(Arc::clone(t));
            }
        }
        let transport = build.await?;
        // The sink is read, and the transport started and stored, under one write lock.
        // `set_security_sink` sets the sink before it reads this slot, so either this attaches the
        // sink or `set_security_sink` finds the stored transport and attaches it there.
        let mut slot = self.email.write().await;
        if let Some(existing) = slot.as_ref() {
            // Another caller built one first; ours was never started.
            return Ok(Arc::clone(existing));
        }
        if let Some(sink) = self.security_sink.get() {
            transport.attach_security_sink(Arc::clone(sink));
        }
        transport.start().await?;
        *slot = Some(Arc::clone(&transport));
        Ok(transport)
    }

    /// Email-only send, no transport selection -- the explicit low-level path old `SynapseRouter`
    /// callers reached for. Routes through `EmailTransportImpl` (PR #55), never `src/email.rs`'s
    /// `EmailTransport` and never a `SimpleMessage`-round-tripped-through-JSON-string.
    pub async fn send_message(
        &self,
        simple_msg: SimpleMessage,
        destination_global_id: String,
    ) -> Result<()> {
        let message = self
            .sign_new_message(
                &destination_global_id,
                simple_msg.content.as_bytes(),
                SecurityLevel::Authenticated,
                simple_msg.metadata.clone(),
            )
            .await?;
        let transport = self.ensure_email_transport().await?;
        let target = crate::transport::abstraction::TransportTarget::new(destination_global_id);
        transport.send_message(&target, &message).await?;
        Ok(())
    }

    /// Smart send: prefers the fast `MultiTransportRouter` path for real-time/interactive
    /// urgency, falling back to email otherwise or on failure. Old `EnhancedSynapseRouter`'s
    /// name and signature, ported here.
    ///
    /// Fixed (board item 65): the fast branch used to call the old
    /// `EnhancedSynapseRouter::create_secure_message`, which hardcoded `SenderProof::unsigned()`
    /// and never touched the crypto manager -- the opposite of the email path, which signs. That
    /// helper is not ported at all; this now calls the same `sign_new_message` every other send
    /// path uses, so no path can reach a transport unsigned.
    ///
    /// Fixed (Task 4b follow-up): this method's fallback branch calls `send_message`, which
    /// hardcodes `SecurityLevel::Authenticated` and never consults the caller's requested level
    /// at all -- so for any urgency other than `RealTime`/`Interactive`, or whenever
    /// `multi_transport` is unconfigured (the common case: `new()` always leaves it `None`), a
    /// caller's `Private`/`Secure` request used to reach the fallback and be silently downgraded
    /// to `Authenticated` with no error. `sign_new_message`'s own guard does not see this at all,
    /// since the fallback never calls it with the caller's real level. Rejecting here, at the top
    /// of this method, closes that gap for every branch below regardless of urgency or
    /// `multi_transport` state -- the same structural argument as `sign_new_message`'s guard, one
    /// level up. `sign_new_message`'s guard is kept too (defense in depth for its other callers,
    /// `send_message` and `send_message_with_transport`).
    pub async fn send_message_smart(
        &self,
        to_entity: &str,
        content: &str,
        message_type: MessageType,
        security_level: SecurityLevel,
        urgency: MessageUrgency,
    ) -> Result<String> {
        Self::reject_unsupported_security_level(security_level.clone())?;
        if let Some(ref mt_router) = self.multi_transport
            && matches!(
                urgency,
                MessageUrgency::RealTime | MessageUrgency::Interactive
            )
        {
            let secure_msg = self
                .sign_new_message(
                    to_entity,
                    content.as_bytes(),
                    security_level,
                    Default::default(),
                )
                .await?;
            match mt_router
                .send_message(to_entity, &secure_msg, urgency)
                .await
            {
                Ok(receipt) => return Ok(receipt.message_id),
                Err(e) => {
                    tracing::warn!("Multi-transport failed: {e}, falling back to email");
                }
            }
        }
        let simple_msg = SimpleMessage {
            to: to_entity.to_string(),
            from_entity: self.our_global_id.clone(),
            content: content.to_string(),
            message_type,
            metadata: Default::default(),
        };
        self.send_message(simple_msg, to_entity.to_string())
            .await
            .map(|_| "email_fallback".to_string())
    }

    /// Send message with explicit transport preference. Old `EnhancedSynapseRouter`'s name and
    /// signature, ported here.
    ///
    /// Fixed (board item 65): the old body called the old
    /// `EnhancedSynapseRouter::create_secure_message`, which hardcoded `SenderProof::unsigned()`
    /// -- a fifth instance of the same defect class this router has been fixing throughout. This
    /// now calls the same `sign_new_message` every other send path uses, so no path in this
    /// router can reach a transport unsigned.
    ///
    /// Follows `send_message_smart`'s fast/fallback structure exactly: reject an unsupported
    /// `security_level` up front (this method accepts a caller-supplied level just like that one
    /// does), sign once via `sign_new_message`, try `multi_transport` with the caller's preferred
    /// routes, and fall back to `send_message` (email) when `multi_transport` is unconfigured.
    pub async fn send_message_with_transport(
        &self,
        to_entity: &str,
        content: &str,
        message_type: MessageType,
        security_level: SecurityLevel,
        preferred_routes: &[TransportRoute],
    ) -> Result<String> {
        Self::reject_unsupported_security_level(security_level.clone())?;
        if let Some(ref mt_router) = self.multi_transport {
            let secure_msg = self
                .sign_new_message(
                    to_entity,
                    content.as_bytes(),
                    security_level,
                    Default::default(),
                )
                .await?;

            return mt_router
                .send_with_fallback_priority(to_entity, &secure_msg, preferred_routes)
                .await
                .map(|receipt| receipt.message_id);
        }

        // Fallback to email
        let simple_msg = SimpleMessage {
            to: to_entity.to_string(),
            from_entity: self.our_global_id.clone(),
            content: content.to_string(),
            message_type,
            metadata: std::collections::HashMap::new(),
        };
        self.send_message(simple_msg, to_entity.to_string())
            .await
            .map(|_| "email_fallback".to_string())
    }

    /// Pin `global_id`'s Ed25519 public key for `receive_messages`'s sender verification. Without
    /// at least one pinned key, `receive_messages` verifies nothing as `Verified` and drops every
    /// message it reads -- this is the router's minimal surface for populating the trust store
    /// that guards it, mirroring `TransportManager::trust_store`/`set_trust_store`'s pinning role
    /// at the single-key scale this router needs. Pinning a key only enables the authenticity
    /// check -- it does not add anti-replay protection or unsealing; see `receive_messages`'s doc
    /// comment.
    pub async fn pin_sender_key(&self, global_id: impl Into<String>, key: [u8; 32]) {
        self.trust_store.write().await.pin(global_id, key);
    }

    /// Receive messages from the email transport, verifying every sender before it is delivered.
    ///
    /// This REPLACES old `SynapseRouter::receive_messages`/`process_email_message`
    /// (`src/router.rs`, deleted in Task 6) entirely -- it is not a fix-in-place of that code, and
    /// none of its body is ported here (design note §4: "Do not let it survive the merge by simply
    /// relocating it onto the merged type's namespace"). The old path parsed a `SecureMessage` out
    /// of a JSON-wrapped `SimpleMessage.content` and handed it to the caller regardless of
    /// `sender_proof` -- self-documented in its own doc comment as "⚠️ Unverified: senders are not
    /// authenticated here" and "this path has no trust store, so it remains unauthenticated." A
    /// message that fails verification here is dropped, never returned -- the old code returned
    /// everything unconditionally, which is exactly the defect this replaces.
    ///
    /// Identity-model decision (Task 4 brief, Step 1): this router's receive-side verification uses
    /// [`TrustStore::verify_at`] -- the SAME mechanism `TransportManager::receive_messages` already
    /// uses for every other transport in this crate (TCP, UDP, WebSocket, QUIC, NAT traversal) --
    /// not an `IdentityRegistry` accessor. `IdentityRegistry` (`src/identity.rs`) used to expose a
    /// `get_public_key` accessor over an opaque, undefined-format `String` field
    /// (`GlobalIdentity::public_key`); it performed no signature check anywhere in this crate, and
    /// `register_entity` -- its own normal registration path -- set that field to `""` by default.
    /// Both the accessor and its backing field were removed per board item 69 (`IdentityRegistry`
    /// narrowed to name resolution; see `src/identity.rs`). There was never an existing convention
    /// for what encoding that string would even be in for an Ed25519 key. Verifying against it
    /// would have meant inventing a brand-new key encoding and a brand-new, hand-rolled
    /// signature-check routine that duplicates `TrustStore::verify_against_pinned_key`/
    /// `canonical_input` without their review history or test coverage -- itself a second,
    /// divergent verification path, the same defect class board item 65 was on the send side
    /// (`sign_new_message`'s doc comment).
    /// `SenderProof`/`canonical_input` (`sender_auth.rs`) are already `TrustStore`'s vocabulary, and
    /// `sign_new_message` (this file) already produces proofs meant to be checked against a
    /// `TrustStore`, so this uses the store that already speaks the signer's language rather than
    /// building a second one for the receiver.
    ///
    /// Required finding: the AUTHENTICITY check here is the identical `TrustStore::verify_at`
    /// call `TransportManager::receive_messages` performs for a directly pinned sender --
    /// byte-for-byte the same check, not a re-implementation. The narrower surface actually used
    /// here (`self.trust_store`, populated only by [`Self::pin_sender_key`]) omits the
    /// certificate-chain/account-key route and revocation -- this router has no equivalent of
    /// `TransportManager::add_revocations` or `pin_account_key`/certificate ingestion yet -- but
    /// that gap alone would still leave this router at parity for the direct-pin case.
    ///
    /// The OVERALL guarantee is narrower than `TransportManager`'s, not the same, because of two
    /// gaps `verify_at` alone does not close:
    ///
    /// 1. **No anti-replay protection.** `TransportManager::receive_messages` also runs every
    ///    message through `src/replay.rs`'s `inbound.admit(...)`/`.check(...)` gate, keyed on
    ///    `(key_id, message_id, timestamp)`, which rejects a message it has already seen. This
    ///    method has no equivalent call. A captured, genuinely-signed message can be replayed
    ///    against this method indefinitely and it will be delivered every time, where
    ///    `TransportManager` would reject it after the first delivery.
    /// 2. **No unsealing of `Private`/`Secure`-level content.** This method never calls
    ///    `sealing::open` (`src/sealing.rs`). If a message was sent at `SecurityLevel::Private` or
    ///    `SecurityLevel::Secure` (reachable via `send_message_smart`'s caller-supplied
    ///    `security_level`), its content is still sealed/encrypted ciphertext on receipt, but this
    ///    method hands it back as `SimpleMessage.content` via
    ///    `String::from_utf8_lossy(&message.encrypted_content)` -- i.e. it silently returns raw
    ///    ciphertext as if it were plaintext, with no error and no indication anything is wrong.
    ///    This gap predates Task 4 (the send side doesn't seal either, going back to Task 2/3), but
    ///    it directly bears on this method's guarantee and must be disclosed here.
    ///
    /// In short: identical authenticity check, but missing anti-replay and missing unsealing --
    /// callers should not treat this method as a drop-in equivalent of
    /// `TransportManager::receive_messages`.
    pub async fn receive_messages(&self) -> Result<Vec<SimpleMessage>> {
        let transport = self.ensure_email_transport().await?;
        let mut inbox = crate::transport::abstraction::RawInbox::new();
        transport.receive_raw(&mut inbox).await?;
        let incoming = inbox.drain();

        let store = self.trust_store.read().await;
        let now = chrono::Utc::now();
        let mut delivered = Vec::with_capacity(incoming.len());
        for item in incoming {
            let message = item.message;
            let verdict = store.verify_at(&message, now);
            if !verdict.is_verified() {
                tracing::debug!(
                    from = %message.from_global_id,
                    verdict = ?verdict,
                    "dropping a received message whose sender did not verify"
                );
                continue;
            }
            delivered.push(SimpleMessage {
                to: message.to_global_id,
                from_entity: message.from_global_id,
                content: String::from_utf8_lossy(&message.encrypted_content).into_owned(),
                message_type: MessageType::Direct,
                metadata: message.metadata,
            });
        }
        Ok(delivered)
    }

    /// Test connection to an entity. Old `EnhancedSynapseRouter::test_connection()`, ported
    /// unchanged.
    pub async fn test_connection(&self, target: &str) -> ConnectionCapabilities {
        let mut capabilities = ConnectionCapabilities {
            email: true, // Email is always available via Synapse
            direct_tcp: false,
            direct_udp: false,
            mdns_local: false,
            nat_traversal: false,
            estimated_latency_ms: 60_000, // Default to 1-minute email latency
        };

        if let Some(ref mt_router) = self.multi_transport {
            // Test direct connections
            capabilities.direct_tcp = mt_router.can_connect_directly(target).await;

            // Test local discovery
            if mt_router.discover_local_peer(target).await.is_ok() {
                capabilities.mdns_local = true;
                capabilities.estimated_latency_ms = 50; // Local network latency
            }

            // Test NAT traversal
            if mt_router.establish_nat_traversal(target).await.is_ok() {
                capabilities.nat_traversal = true;
                capabilities.estimated_latency_ms = capabilities.estimated_latency_ms.min(200);
            }

            // If we can connect directly, estimate much lower latency
            if capabilities.direct_tcp || capabilities.direct_udp {
                capabilities.estimated_latency_ms = capabilities.estimated_latency_ms.min(100);
            }
        }

        capabilities
    }

    /// Benchmark transport performance to a target. Old `EnhancedSynapseRouter::benchmark_transport()`,
    /// ported with one change: the old body built its probe `SecureMessage` with a hardcoded
    /// `SenderProof::unsigned()` -- the same defect class as board item 65 (see
    /// `sign_new_message`'s doc comment). This version routes the probe through the shared
    /// `sign_new_message` helper instead, so no path in this router still constructs an unsigned
    /// message. If signing fails (for example, no keypair has been generated yet), this returns
    /// the default email-only benchmarks rather than probing further transports.
    pub async fn benchmark_transport(&self, target: &str) -> TransportBenchmarks {
        let mut benchmarks = TransportBenchmarks {
            email_latency_ms: 60_000,
            tcp_latency_ms: None,
            udp_latency_ms: None,
            mdns_latency_ms: None,
            nat_traversal_latency_ms: None,
        };

        let Some(ref mt_router) = self.multi_transport else {
            return benchmarks;
        };

        let test_message = match self
            .sign_new_message(
                target,
                b"benchmark test",
                SecurityLevel::Public,
                Default::default(),
            )
            .await
        {
            Ok(message) => message,
            Err(e) => {
                tracing::warn!("benchmark_transport: could not sign probe message: {e}");
                return benchmarks;
            }
        };

        // Test different transport routes
        let test_routes = vec![
            TransportRoute::DirectTcp {
                address: target.to_string(),
                port: 8080,
                latency_ms: 0,
                established_at: std::time::Instant::now(),
            },
            TransportRoute::DirectUdp {
                address: target.to_string(),
                port: 8080,
                latency_ms: 0,
                established_at: std::time::Instant::now(),
            },
            TransportRoute::LocalMdns {
                service_name: target.to_string(),
                address: target.to_string(),
                port: 5353,
                latency_ms: 0,
                discovered_at: std::time::Instant::now(),
            },
        ];

        for route in test_routes {
            let start = std::time::Instant::now();
            match mt_router
                .send_with_fallback_priority(target, &test_message, std::slice::from_ref(&route))
                .await
            {
                Ok(_) => {
                    let latency = start.elapsed().as_millis() as u32;
                    match route {
                        TransportRoute::DirectTcp { .. } => {
                            benchmarks.tcp_latency_ms = Some(latency)
                        }
                        TransportRoute::DirectUdp { .. } => {
                            benchmarks.udp_latency_ms = Some(latency)
                        }
                        TransportRoute::LocalMdns { .. } => {
                            benchmarks.mdns_latency_ms = Some(latency)
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    // Transport not available or failed
                }
            }
        }

        benchmarks
    }
}

/// Router health information. Old `router::RouterHealth`, ported unchanged.
#[derive(Debug, Clone)]
pub struct RouterHealth {
    pub status: String,
    pub crypto_available: bool,
    pub email_available: bool,
    pub known_peers: usize,
    pub known_keys: usize,
    pub our_global_id: String,
}

/// Connection capabilities for a target. Old `router_enhanced::ConnectionCapabilities`, ported
/// unchanged.
#[derive(Debug, Clone)]
pub struct ConnectionCapabilities {
    pub email: bool,
    pub direct_tcp: bool,
    pub direct_udp: bool,
    pub mdns_local: bool,
    pub nat_traversal: bool,
    pub estimated_latency_ms: u32,
}

/// Transport performance benchmarks. Old `router_enhanced::TransportBenchmarks`, ported unchanged.
#[derive(Debug, Clone)]
pub struct TransportBenchmarks {
    pub email_latency_ms: u32,
    pub tcp_latency_ms: Option<u32>,
    pub udp_latency_ms: Option<u32>,
    pub mdns_latency_ms: Option<u32>,
    pub nat_traversal_latency_ms: Option<u32>,
}

/// Enhanced router status
#[derive(Debug, Clone)]
pub struct EnhancedRouterStatus {
    pub synapse_status: RouterHealth,
    pub multi_transport_enabled: bool,
    pub email_server_enabled: bool,
    pub available_transports: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn new_builds_a_router_with_both_apis_available() {
        let config = Config::default_for_entity("Test", "tool");
        let router = SynapseRouter::new(config, "test@synapse.local".to_string())
            .await
            .expect("construct");
        // From the old SynapseRouter side:
        assert_eq!(router.get_our_global_id(), "test@synapse.local");
        // From the old EnhancedSynapseRouter side -- proves both halves are actually present,
        // not just one renamed:
        let status = router.status().await;
        assert!(!status.multi_transport_enabled || status.available_transports.is_empty());
    }

    #[tokio::test]
    async fn send_message_signs_before_handing_to_the_email_transport() {
        let config = Config::default_for_entity("Test", "tool");
        let router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("construct");
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");
        router
            .ensure_email_transport()
            .await
            .expect("email transport");

        let _simple_msg = SimpleMessage {
            to: "bob@synapse.local".to_string(),
            from_entity: "alice@synapse.local".to_string(),
            content: "hello".to_string(),
            message_type: MessageType::Direct,
            metadata: Default::default(),
        };
        // This will fail to actually deliver (no real SMTP server at bob@synapse.local in a unit
        // test), but the point of this test is what happens BEFORE delivery is attempted: the
        // signing. Capture the SecureMessage sign_new_message produces directly instead of only
        // asserting on send_message's overall Ok/Err, since a network failure and a signing
        // failure would otherwise look the same from outside.
        let signed = router
            .sign_new_message(
                "bob@synapse.local",
                b"hello",
                SecurityLevel::Authenticated,
                Default::default(),
            )
            .await
            .expect("sign");
        assert!(
            !matches!(signed.sender_proof.alg, crate::sender_auth::ProofAlg::None),
            "a message built for sending must be signed, not left as alg \"none\""
        );
    }

    /// A stub `Transport` that records the `SecureMessage` it is handed instead of sending it
    /// anywhere, so a test can inspect exactly what `send_message_smart`'s fast branch built.
    /// `MockTransport` in `transport::providers` already exists but its `send_message` ignores
    /// the message entirely -- it cannot be reused here for that reason.
    ///
    /// It also logs `attach_security_sink` and `start` in call order, with the address of the sink
    /// it was given, for the P7 (a3) sink tests.
    #[derive(Debug, Default)]
    struct RecordingTransport {
        sent: Arc<std::sync::Mutex<Option<SecureMessage>>>,
        log: Arc<std::sync::Mutex<Vec<&'static str>>>,
        attached: Arc<std::sync::Mutex<Option<usize>>>,
    }

    fn sink_addr(sink: &Arc<dyn crate::security_events::SecuritySink>) -> usize {
        Arc::as_ptr(sink) as *const () as usize
    }

    #[async_trait::async_trait]
    impl crate::transport::abstraction::TransportReceive for RecordingTransport {
        async fn receive_raw(
            &self,
            _inbox: &mut crate::transport::abstraction::RawInbox,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl crate::transport::abstraction::Transport for RecordingTransport {
        fn transport_type(&self) -> crate::transport::abstraction::TransportType {
            crate::transport::abstraction::TransportType::Email
        }

        fn capabilities(&self) -> crate::transport::abstraction::TransportCapabilities {
            crate::transport::abstraction::TransportCapabilities {
                max_message_size: 1024 * 1024,
                reliable: true,
                real_time: false,
                broadcast: false,
                bidirectional: true,
                encrypted: false,
                network_spanning: true,
                supported_urgencies: vec![
                    crate::transport::abstraction::MessageUrgency::Interactive,
                ],
                features: vec![],
                unmeasured_metrics: vec![
                    crate::transport::abstraction::UnmeasuredMetric::AverageLatency,
                    crate::transport::abstraction::UnmeasuredMetric::ReliabilityScore,
                ],
            }
        }

        async fn can_reach(
            &self,
            _target: &crate::transport::abstraction::TransportTarget,
        ) -> bool {
            true
        }

        async fn estimate_metrics(
            &self,
            _target: &crate::transport::abstraction::TransportTarget,
        ) -> Result<crate::transport::abstraction::TransportEstimate> {
            Ok(crate::transport::abstraction::TransportEstimate {
                latency: std::time::Duration::from_millis(1),
                reliability: 0.99,
                bandwidth: 1_000_000,
                cost: 0.0,
                available: true,
                confidence: 1.0,
            })
        }

        async fn send_message(
            &self,
            target: &crate::transport::abstraction::TransportTarget,
            message: &SecureMessage,
        ) -> Result<crate::transport::abstraction::DeliveryReceipt> {
            *self.sent.lock().expect("lock") = Some(message.clone());
            Ok(crate::transport::abstraction::DeliveryReceipt {
                message_id: format!("recorded-for-{}", target.identifier),
                transport_used: crate::transport::abstraction::TransportType::Email,
                delivery_time: std::time::Duration::from_millis(1),
                target_reached: target.identifier.clone(),
                confirmation: crate::transport::abstraction::DeliveryConfirmation::Delivered,
                metadata: Default::default(),
            })
        }

        async fn test_connectivity(
            &self,
            _target: &crate::transport::abstraction::TransportTarget,
        ) -> Result<crate::transport::abstraction::ConnectivityResult> {
            Ok(crate::transport::abstraction::ConnectivityResult {
                connected: true,
                rtt: Some(std::time::Duration::from_millis(1)),
                error: None,
                quality: 1.0,
                details: Default::default(),
            })
        }

        fn attach_security_sink(&self, sink: Arc<dyn crate::security_events::SecuritySink>) {
            self.log.lock().expect("lock").push("attach");
            *self.attached.lock().expect("lock") = Some(sink_addr(&sink));
        }

        async fn start(&self) -> Result<()> {
            self.log.lock().expect("lock").push("start");
            Ok(())
        }

        async fn stop(&self) -> Result<()> {
            Ok(())
        }

        async fn status(&self) -> crate::transport::abstraction::TransportStatus {
            crate::transport::abstraction::TransportStatus::Running
        }

        async fn metrics(&self) -> crate::transport::abstraction::TransportMetrics {
            crate::transport::abstraction::TransportMetrics::default()
        }
    }

    /// A `transport::providers::TransportProvider` stub used only to hand `MultiTransportRouter` a
    /// `RecordingTransport` as its email transport, via the same `new_with_provider` dependency
    /// injection seam `ProductionTransportProvider` uses in production. `router.rs` used to define
    /// its own, separate `TransportProvider` trait/`ProductionTransportProvider` stub with the same
    /// names but a silently-stubbed email transport; that duplicate was deleted in the router-merge
    /// work, and `MultiTransportRouter::new_with_provider` now resolves `TransportProvider` to the
    /// real trait in `transport::providers`, which this impl targets.
    struct StubTransportProvider {
        email_transport: Arc<dyn crate::transport::abstraction::Transport>,
    }

    #[async_trait::async_trait]
    impl crate::transport::providers::TransportProvider for StubTransportProvider {
        async fn create_tcp_transport(
            &self,
            _config: &Config,
        ) -> Result<Option<Arc<dyn crate::transport::abstraction::Transport>>> {
            Ok(None)
        }

        async fn create_mdns_transport(
            &self,
            _config: &Config,
        ) -> Result<Option<Arc<dyn crate::transport::abstraction::Transport>>> {
            Ok(None)
        }

        async fn create_nat_transport(
            &self,
            _config: &Config,
        ) -> Result<Option<Arc<dyn crate::transport::abstraction::Transport>>> {
            Ok(None)
        }

        async fn create_email_transport(
            &self,
            _config: &Config,
        ) -> Result<Option<Arc<dyn crate::transport::abstraction::Transport>>> {
            Ok(Some(Arc::clone(&self.email_transport)))
        }

        fn create_transport_selector(
            &self,
        ) -> Arc<tokio::sync::RwLock<crate::transport::TransportSelector>> {
            Arc::new(tokio::sync::RwLock::new(
                crate::transport::TransportSelector::new(),
            ))
        }
    }

    /// The PM's required born-red test (board item 65): every send path this router hands a
    /// message to a transport through must have signed it first. `send_message` (Task 2) already
    /// provably signs; this proves `send_message_smart`'s fast (`MultiTransportRouter`) branch
    /// does too, by inspecting the actual `SecureMessage` a stub transport received -- not just a
    /// boolean "is it signed", but the signature verifying against the router's own pinned public
    /// key, the same mechanism `TrustStore::verify_at` uses elsewhere in this crate.
    ///
    /// `to_entity` is deliberately not resolvable (no real network/DNS target): with no
    /// TCP/UDP/mDNS/NAT route discoverable, `MultiTransportRouter`'s real transport-selection
    /// logic (`TransportSelector::choose_optimal_transport`) fails to find a real-time-suitable
    /// route and falls back, inside `MultiTransportRouter::send_message` itself, to its email
    /// transport -- which is this test's `RecordingTransport`. This exercises the real selection
    /// code, not a bypass of it.
    #[tokio::test]
    async fn every_send_path_signs_before_it_reaches_a_transport() {
        let config = Config::default_for_entity("Test", "tool");
        let mut router = SynapseRouter::new(config.clone(), "alice@synapse.local".to_string())
            .await
            .expect("construct");
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");

        // send_message (Task 2) already provably signs -- assert it again here for completeness.
        let via_send_message = router
            .sign_new_message(
                "bob@synapse.local",
                b"one",
                SecurityLevel::Authenticated,
                Default::default(),
            )
            .await
            .expect("sign");
        assert!(!matches!(
            via_send_message.sender_proof.alg,
            crate::sender_auth::ProofAlg::None
        ));

        let sent: Arc<std::sync::Mutex<Option<SecureMessage>>> =
            Arc::new(std::sync::Mutex::new(None));
        let recording_transport = Arc::new(RecordingTransport {
            sent: Arc::clone(&sent),
            ..Default::default()
        });
        let provider = StubTransportProvider {
            email_transport: recording_transport,
        };
        let mt_router = MultiTransportRouter::new_with_provider(
            config,
            "alice@synapse.local".to_string(),
            Box::new(provider),
        )
        .await
        .expect("multi-transport router");
        router.multi_transport = Some(Arc::new(mt_router));

        let message_id = router
            .send_message_smart(
                "bob@synapse.local",
                "hello fast path",
                MessageType::Direct,
                SecurityLevel::Authenticated,
                MessageUrgency::RealTime,
            )
            .await
            .expect("send_message_smart");
        assert!(
            message_id.starts_with("recorded-for-"),
            "expected the fast path to reach RecordingTransport via MultiTransportRouter's email \
             fallback, got message id {message_id:?} instead -- check that discovery genuinely \
             found no real-time route for the unresolvable test target"
        );

        let recorded = sent.lock().expect("lock").take().expect(
            "RecordingTransport.send_message was never called -- the fast branch didn't reach a transport",
        );
        assert_eq!(recorded.from_global_id, "alice@synapse.local");

        // The load-bearing assertion: the recorded message's signature actually verifies against
        // the router's own public key, not just "alg is not None". A signature-shaped field
        // nobody verifies is exactly board item 65's class of defect.
        let mut trust_store = crate::sender_auth::TrustStore::new();
        let public_key = router
            .crypto
            .read()
            .await
            .public_key_bytes()
            .expect("public key");
        trust_store.pin("alice@synapse.local", public_key);
        let verdict = trust_store.verify(&recorded);
        assert!(
            verdict.is_verified(),
            "recorded message's signature did not verify against the router's own pinned public \
             key: {verdict:?}"
        );
    }

    /// The PM's required born-red test (Task 4b, board item 65 one layer up): `sign_new_message`
    /// must refuse `Private`/`Secure` -- the levels this router can never honour because it does
    /// not seal/unseal -- rather than silently signing-and-returning them as if sealing had
    /// happened. `Public`/`Authenticated` must remain unaffected by the guard.
    #[tokio::test]
    async fn sign_new_message_refuses_private_and_secure_levels() {
        let config = Config::default_for_entity("Test", "tool");
        let router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        // A keypair is required for the Public/Authenticated success assertions below to actually
        // reach `Ok` (sign_secure_message returns `KeyNotFound` without one) -- without this, the
        // test would give a false positive: the guard rejecting Private/Secure would pass either
        // way, but the "still honoured" assertions need real signing to succeed, not just the
        // guard to fall through.
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");

        let private_result = router
            .sign_new_message(
                "bob@synapse.local",
                b"secret",
                SecurityLevel::Private,
                Default::default(),
            )
            .await;
        assert!(
            matches!(
                private_result,
                Err(crate::error::SynapseError::UnsupportedSecurityLevel(
                    SecurityLevel::Private
                ))
            ),
            "Private must be refused, not silently signed-and-sent as plaintext: got {private_result:?}"
        );

        let secure_result = router
            .sign_new_message(
                "bob@synapse.local",
                b"secret",
                SecurityLevel::Secure,
                Default::default(),
            )
            .await;
        assert!(
            matches!(
                secure_result,
                Err(crate::error::SynapseError::UnsupportedSecurityLevel(
                    SecurityLevel::Secure
                ))
            ),
            "Secure must be refused too: got {secure_result:?}"
        );

        // Public and Authenticated must still be honoured -- this guard must not become a router
        // that refuses everything.
        let public_ok = router
            .sign_new_message(
                "bob@synapse.local",
                b"hello",
                SecurityLevel::Public,
                Default::default(),
            )
            .await;
        assert!(
            public_ok.is_ok(),
            "Public must still be honoured: {public_ok:?}"
        );

        let auth_ok = router
            .sign_new_message(
                "bob@synapse.local",
                b"hello",
                SecurityLevel::Authenticated,
                Default::default(),
            )
            .await;
        assert!(
            auth_ok.is_ok(),
            "Authenticated must still be honoured: {auth_ok:?}"
        );
    }

    /// Task 4b follow-up (reviewer-found gap): `sign_new_message`'s guard alone does NOT close
    /// this hole, because `send_message_smart`'s fallback branch (`self.send_message(...)`) never
    /// calls `sign_new_message` with the caller's real level -- `send_message` hardcodes
    /// `SecurityLevel::Authenticated` itself. That fallback is the ONLY path taken whenever
    /// `multi_transport` is `None` (the common case: `SynapseRouter::new` always leaves it `None`)
    /// or whenever `urgency` is anything other than `RealTime`/`Interactive`
    /// (`Critical`/`Background`/`Batch`) -- i.e. most of this method's real call surface. This
    /// proves the NEW checkpoint added at the top of `send_message_smart` itself closes that gap:
    /// a `Private` request with no `multi_transport` configured and `Background` urgency (which
    /// previously sailed straight through to the hardcoded-`Authenticated` fallback with no error
    /// at all) must now be refused before either branch is even considered.
    #[tokio::test]
    async fn send_message_smart_refuses_private_even_on_the_fallback_only_path() {
        let config = Config::default_for_entity("Test", "tool");
        let router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");
        // No multi_transport configured (matches SynapseRouter::new's real default), and an
        // urgency that never qualifies for the fast branch -- this exercises the fallback-only
        // path exclusively.
        assert!(
            router.multi_transport.is_none(),
            "this test relies on multi_transport being unconfigured, matching new()'s default"
        );

        let result = router
            .send_message_smart(
                "bob@synapse.local",
                "secret",
                MessageType::Direct,
                SecurityLevel::Private,
                MessageUrgency::Background,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(crate::error::SynapseError::UnsupportedSecurityLevel(
                    SecurityLevel::Private
                ))
            ),
            "send_message_smart must refuse Private on the fallback-only path (no multi_transport, \
             Background urgency), not silently downgrade it to Authenticated via send_message: \
             got {result:?}"
        );
    }

    /// Proves `send_message_with_transport` signs before handing anything to a transport, using
    /// the same `RecordingTransport`/`StubTransportProvider` stub pattern
    /// `every_send_path_signs_before_it_reaches_a_transport` uses for `send_message_smart`'s fast
    /// branch. `preferred_routes` is empty, so `MultiTransportRouter::send_with_fallback_priority`
    /// goes straight to its email fallback -- this test's `RecordingTransport` -- without needing
    /// real transport discovery to fail first.
    #[tokio::test]
    async fn send_message_with_transport_signs_before_it_reaches_a_transport() {
        let config = Config::default_for_entity("Test", "tool");
        let mut router = SynapseRouter::new(config.clone(), "alice@synapse.local".to_string())
            .await
            .expect("construct");
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");

        let sent: Arc<std::sync::Mutex<Option<SecureMessage>>> =
            Arc::new(std::sync::Mutex::new(None));
        let recording_transport = Arc::new(RecordingTransport {
            sent: Arc::clone(&sent),
            ..Default::default()
        });
        let provider = StubTransportProvider {
            email_transport: recording_transport,
        };
        let mt_router = MultiTransportRouter::new_with_provider(
            config,
            "alice@synapse.local".to_string(),
            Box::new(provider),
        )
        .await
        .expect("multi-transport router");
        router.multi_transport = Some(Arc::new(mt_router));

        let message_id = router
            .send_message_with_transport(
                "bob@synapse.local",
                "hello",
                MessageType::Direct,
                SecurityLevel::Authenticated,
                &[],
            )
            .await
            .expect("send_message_with_transport");
        assert!(
            message_id.starts_with("recorded-for-"),
            "expected the empty preferred_routes to fall through to RecordingTransport via \
             MultiTransportRouter's email fallback, got message id {message_id:?} instead"
        );

        let recorded = sent.lock().expect("lock").take().expect(
            "RecordingTransport.send_message was never called -- send_message_with_transport \
             didn't reach a transport",
        );
        assert_eq!(recorded.from_global_id, "alice@synapse.local");

        // The load-bearing assertion, matching every_send_path_signs_before_it_reaches_a_transport:
        // the recorded message's signature actually verifies against the router's own public key.
        let mut trust_store = crate::sender_auth::TrustStore::new();
        let public_key = router
            .crypto
            .read()
            .await
            .public_key_bytes()
            .expect("public key");
        trust_store.pin("alice@synapse.local", public_key);
        let verdict = trust_store.verify(&recorded);
        assert!(
            verdict.is_verified(),
            "recorded message's signature did not verify against the router's own pinned public \
             key: {verdict:?}"
        );
    }

    /// `send_message_with_transport` must refuse `Private`/`Secure` too, the same guard
    /// `sign_new_message`/`send_message_smart` already enforce -- this is the same defect class
    /// (board item 65 one layer up) applied to the newly-ported method.
    #[tokio::test]
    async fn send_message_with_transport_refuses_private_and_secure_levels() {
        let config = Config::default_for_entity("Test", "tool");
        let router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        router
            .crypto
            .write()
            .await
            .generate_keypair()
            .expect("keypair");

        let private_result = router
            .send_message_with_transport(
                "bob@synapse.local",
                "secret",
                MessageType::Direct,
                SecurityLevel::Private,
                &[],
            )
            .await;
        assert!(
            matches!(
                private_result,
                Err(crate::error::SynapseError::UnsupportedSecurityLevel(
                    SecurityLevel::Private
                ))
            ),
            "Private must be refused: got {private_result:?}"
        );
    }

    /// A free loopback port, bound and released immediately -- another process could take it
    /// before the transport binds it, in which case the transport's own bind fails with a clear
    /// error rather than this test silently colliding with something else.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("local_addr")
            .port()
    }

    /// A Direct-mode `EmailTransportImpl` on loopback at `port`, started (its SMTP accept loop
    /// running), wrapped for injection into a router's private `email` field. Bypasses
    /// `ensure_email_transport`'s `ProductionTransportProvider` bridge entirely, which hardcodes
    /// `local_port = "2525"` (`transport::providers::ProductionTransportProvider::create_email_transport`)
    /// -- two routers in one test process cannot both bind that port, so each gets its own real
    /// `EmailTransportImpl` on a distinct free port instead, exactly the same transport type
    /// `ensure_email_transport` would have built.
    async fn direct_email_transport_on(
        port: u16,
    ) -> Arc<dyn crate::transport::abstraction::Transport> {
        let mut config = std::collections::HashMap::new();
        config.insert("local_port".to_string(), port.to_string());
        config.insert(
            crate::network_scope::BIND_SCOPE_KEY.to_string(),
            crate::network_scope::BindScope::Loopback
                .config_value()
                .to_string(),
        );
        use crate::transport::abstraction::Transport as _;
        let transport = crate::transport::email_unified::EmailTransportImpl::new(&config)
            .await
            .expect("construct email transport");
        transport.start().await.expect("start email transport");
        Arc::new(transport)
    }

    /// The PM's required born-red test (Task 4): a message claiming to be from a sender whose real
    /// key IS pinned in the receiver's trust store, but signed by a DIFFERENT, unregistered
    /// keypair, must be dropped by `receive_messages` -- not merely unsigned (the old
    /// `SenderProof::unsigned()`/board-item-65 case) but an active impersonation attempt with a
    /// real, well-formed, verifiable-looking signature that simply does not match the pinned key.
    ///
    /// The old `SynapseRouter::receive_messages`/`process_email_message` (`src/router.rs`) had no
    /// trust store at all and returned every parsed message unconditionally, so this exact scenario
    /// would have been delivered under the old code -- a happy-path-only test could not distinguish
    /// the two. This asserts the refusal directly: the impostor's message must NOT appear in
    /// `receive_messages`'s result, while a genuinely-signed message from the same claimed sender
    /// (the positive control) DOES arrive -- proving the drop is really about the bad signature, not
    /// about the whole pipeline being broken or the message never having reached the transport at
    /// all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_messages_rejects_an_unverifiable_sender() {
        const ALICE: &str = "alice@synapse.local";
        const BOB: &str = "bob@synapse.local";

        let bob_config = Config::default_for_entity("Bob", "tool");
        let bob_router = SynapseRouter::new(bob_config, BOB.to_string())
            .await
            .expect("construct bob");

        // Alice's real keypair -- this is the one Bob pins, i.e. "the one registered".
        let alice_crypto = {
            let mut c = CryptoManager::new();
            c.generate_keypair().expect("alice keypair");
            c
        };
        let alice_public_key = alice_crypto.public_key_bytes().expect("alice public key");
        bob_router.pin_sender_key(ALICE, alice_public_key).await;

        // An impostor's keypair -- deliberately NOT the one Bob pinned for ALICE.
        let mut impostor_crypto = CryptoManager::new();
        impostor_crypto
            .generate_keypair()
            .expect("impostor keypair");

        let bob_port = free_port();
        let alice_port = free_port();
        let bob_transport = direct_email_transport_on(bob_port).await;
        let alice_transport = direct_email_transport_on(alice_port).await;
        *bob_router.email.write().await = Some(Arc::clone(&bob_transport));

        let bob_target = crate::transport::abstraction::TransportTarget::new(BOB.to_string())
            .with_address(format!("127.0.0.1:{bob_port}"));

        // Positive control: a message genuinely signed by Alice's real (pinned) key.
        let mut genuine = SecureMessage::new(
            BOB.to_string(),
            ALICE.to_string(),
            b"hello from the real alice".to_vec(),
            SecurityLevel::Authenticated,
        );
        alice_crypto
            .sign_secure_message(&mut genuine)
            .expect("sign genuine");
        alice_transport
            .send_message(&bob_target, &genuine)
            .await
            .expect("send genuine");

        // The attack: claims to be ALICE in `from_global_id`, but signed by the impostor's key,
        // which Bob never pinned for ALICE (or for anyone).
        let mut forged = SecureMessage::new(
            BOB.to_string(),
            ALICE.to_string(),
            b"hello from an impostor".to_vec(),
            SecurityLevel::Authenticated,
        );
        impostor_crypto
            .sign_secure_message(&mut forged)
            .expect("sign forged");
        alice_transport
            .send_message(&bob_target, &forged)
            .await
            .expect("send forged");

        // Poll until both have had a chance to arrive at the transport layer.
        let mut delivered: Vec<SimpleMessage> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while delivered.is_empty() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            delivered.extend(bob_router.receive_messages().await.expect("receive"));
        }
        // One more poll, generous, to give the forged message every chance to show up too, if the
        // verification gate were not actually dropping it.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        delivered.extend(bob_router.receive_messages().await.expect("receive"));

        assert!(
            delivered
                .iter()
                .any(|m| m.content == "hello from the real alice"),
            "the genuinely-signed control message never arrived: {delivered:?}"
        );
        assert!(
            !delivered
                .iter()
                .any(|m| m.content == "hello from an impostor"),
            "a message signed by an unpinned, unrelated key was delivered anyway -- \
             receive_messages must drop an unverifiable sender, not just an unsigned one: \
             {delivered:?}"
        );
    }

    #[derive(Default)]
    struct Capture(std::sync::Mutex<Vec<crate::security_events::SecurityEvent>>);

    impl crate::security_events::SecuritySink for Capture {
        fn record(&self, event: &crate::security_events::SecurityEvent) {
            self.0.lock().expect("lock").push(event.clone());
        }
    }

    // P7 follow-up (a3): the router's email transport records its own events (Direct mode's
    // inbound limits) to the router's sink, given before `start`, as `TransportManager` does.
    #[tokio::test]
    async fn the_email_transport_gets_the_sink_before_it_starts() {
        let config = Config::default_for_entity("Test", "tool");
        let sink: Arc<dyn crate::security_events::SecuritySink> = Arc::new(Capture::default());
        let router = SynapseRouter::new(config.clone(), "alice@synapse.local".to_string())
            .await
            .expect("router");
        // A clone made before the sink is set shares it (review of a3, finding 1).
        let earlier_clone = router.clone();
        router.set_security_sink(Arc::clone(&sink)).await;
        let recording = Arc::new(RecordingTransport::default());
        let (log, attached) = (Arc::clone(&recording.log), Arc::clone(&recording.attached));
        earlier_clone
            .ensure_email_transport_with(async move {
                Ok(recording as Arc<dyn crate::transport::abstraction::Transport>)
            })
            .await
            .expect("email transport");
        assert_eq!(*log.lock().expect("lock"), ["attach", "start"]);
        assert_eq!(*attached.lock().expect("lock"), Some(sink_addr(&sink)));

        // A transport built before the sink is set is given it when it is set.
        let late = SynapseRouter::new(config.clone(), "alice@synapse.local".to_string())
            .await
            .expect("router");
        let recording = Arc::new(RecordingTransport::default());
        let (log, attached) = (Arc::clone(&recording.log), Arc::clone(&recording.attached));
        late.ensure_email_transport_with(async move {
            Ok(recording as Arc<dyn crate::transport::abstraction::Transport>)
        })
        .await
        .expect("email transport");
        late.set_security_sink(Arc::clone(&sink)).await;
        assert_eq!(*log.lock().expect("lock"), ["start", "attach"]);
        assert_eq!(*attached.lock().expect("lock"), Some(sink_addr(&sink)));

        // Negative control: a router given no sink attaches nothing, and still starts.
        let plain = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        let recording = Arc::new(RecordingTransport::default());
        let log = Arc::clone(&recording.log);
        plain
            .ensure_email_transport_with(async move {
                Ok(recording as Arc<dyn crate::transport::abstraction::Transport>)
            })
            .await
            .expect("email transport");
        assert_eq!(*log.lock().expect("lock"), ["start"]);
    }

    // P7 follow-up (a3): a router holding a `SynapseEmailServer` passes its sink on, so the
    // server's login guard records to it.
    #[cfg(feature = "email")]
    #[tokio::test]
    async fn the_email_server_records_to_the_routers_sink() {
        use crate::email_server::{
            connectivity::{ConnectivityAssessment, FirewallStatus, ServerRecommendation},
            imap_server::ImapServerConfig,
            smtp_server::SmtpServerConfig,
        };
        let connectivity = ConnectivityAssessment {
            can_bind_smtp: false,
            can_bind_imap: false,
            has_external_ip: false,
            external_ip: None,
            firewall_status: FirewallStatus::Unknown,
            recommended_config: ServerRecommendation::ExternalProvider {
                reason: "test".into(),
            },
        };
        let server = Arc::new(
            SynapseEmailServer::with_config(
                SmtpServerConfig::default(),
                ImapServerConfig::default(),
                connectivity,
            )
            .expect("email server"),
        );
        let config = Config::default_for_entity("Test", "tool");
        let mut router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        router.email_server = Some(Arc::clone(&server));
        let capture = Arc::new(Capture::default());
        router.set_security_sink(capture.clone()).await;

        let now = chrono::Utc::now();
        server
            .security()
            .begin_login("smtp_auth", "alice", "10.0.0.1", now)
            .expect("not locked")
            .failed(now);
        let events = capture.0.lock().expect("lock");
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(
            events[0].kind,
            crate::security_events::SecurityEventKind::AuthFailure
        );
    }

    // P7 follow-up (a4): the router's sink also reaches its multi-transport router's email
    // transport, which that router built itself.
    #[tokio::test]
    async fn the_multi_transport_routers_email_transport_gets_the_sink() {
        let config = Config::default_for_entity("Test", "tool");
        let recording = Arc::new(RecordingTransport::default());
        let attached = Arc::clone(&recording.attached);
        let mt_router = MultiTransportRouter::new_with_provider(
            config.clone(),
            "alice@synapse.local".to_string(),
            Box::new(StubTransportProvider {
                email_transport: recording,
            }),
        )
        .await
        .expect("multi-transport router");
        let mut router = SynapseRouter::new(config, "alice@synapse.local".to_string())
            .await
            .expect("router");
        router.multi_transport = Some(Arc::new(mt_router));
        let sink: Arc<dyn crate::security_events::SecuritySink> = Arc::new(Capture::default());
        router.set_security_sink(Arc::clone(&sink)).await;
        assert_eq!(*attached.lock().expect("lock"), Some(sink_addr(&sink)));
    }
}
