// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pushing mail into a running MCP client, with the client-specific part behind [`Renderer`].
//!
//! Design: `docs/superpowers/specs/2026-10-12-agent-facing-mcp-adapter.md` sections 2 and 5.3.
//!
//! A [`PushServer`] serves the same tools as [`SynapseMcpServer`] and adds one task: every
//! [`PushConfig::poll_every`] it leases mail from the daemon and sends each message to the client as
//! a notification, leaving it leased. What the notification is called, what capability announces it,
//! how a message is written into it and which protocol revision it can ride on are the
//! [`Renderer`]'s; the wire format is portable and the method name and rendering are client
//! behaviour. The daemon's lease, ack and dedupe are never decided here.
//!
//! A write that succeeded says the bytes left this process, not that the client showed the event, so
//! the message stays leased and comes back when the lease ends (the receiver can tell a repeat by
//! its `message_id`) until the model calls the `ack` tool or [`should_ack`] says this adapter should.
//! That is bounded delivery ATTEMPTS, not at-least-once. The task is one sequential loop, so a slow
//! tick delays the next rather than pushing a message twice.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmcp::handler::server::ServerHandler;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CustomNotification, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig, ServerNotification,
    Tool,
};
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{ErrorData, RoleServer};
use serde_json::Value;

use crate::{McpConfig, MessageView, SynapseMcpServer};

/// How the adapter treats a message after it has been written to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckPolicy {
    /// The adapter never removes a message; only the receiver's `ack` does. After
    /// [`PushConfig::max_pushes`] (at least 2) successful writes of one message by this process the adapter stops
    /// pushing it and asks the daemon to pass over it (`exclude`), so the message stays pending,
    /// is still returned by the `fetch` tool at once (it is no longer re-leased every tick), and
    /// nothing is lost by the adapter's hand. A new adapter process has an empty list and pushes it
    /// up to the bound again. Right for a client with no measured behaviour: a client that never
    /// reads a push (FAM's measured case) loses nothing.
    ReceiverOnly,
    /// After a SUCCESSFUL write the adapter acks the message itself once [`should_ack`] holds: the
    /// daemon's `attempts` has reached [`PushConfig::max_pushes`] AND this process has written it
    /// at least twice. Bounded attempts, not a confirmation that anything was shown.
    BoundedAttempts,
    /// The adapter never acks and never stops pushing: every time the daemon hands the message out
    /// again (on its back-off schedule) it is written to the client again, and only the receiver's
    /// `ack`, or the daemon setting the message aside after its last delivery, ends it. A receiver that
    /// restarts therefore always gets the message again.
    Never,
}

/// What differs between MCP clients that accept pushed mail.
pub trait Renderer: Send + Sync + 'static {
    /// The key declared under `capabilities.experimental` at `initialize`, so a client can learn
    /// that this server pushes and how, instead of being told the method name out of band.
    fn capability_key(&self) -> &str;
    /// The notification method the client listens for.
    fn method(&self) -> &str;
    /// The newest protocol revision this renderer's notification can be delivered on.
    fn protocol_cap(&self) -> ProtocolVersion;
    /// The server `instructions` (trusted text; says what a repeat means and how to ack).
    fn instructions(&self) -> &str;
    /// One message in, the notification's `params` out. It receives the same [`MessageView`] the
    /// `fetch` tool shows, so the two surfaces cannot disagree about which message it is.
    fn render(&self, message: &MessageView) -> Value;
    /// What the adapter does after a successful write. The default removes nothing on the
    /// receiver's behalf; a renderer opts into [`AckPolicy::BoundedAttempts`] only for a client whose
    /// behaviour has been measured to need it.
    fn ack_policy(&self) -> AckPolicy {
        AckPolicy::ReceiverOnly
    }
}

/// Timing of the push loop.
#[derive(Clone, Copy)]
pub struct PushConfig {
    /// How often to look for mail.
    pub poll_every: Duration,
    /// How long a leased message stays hidden from other fetches before it is redelivered.
    pub lease_secs: i64,
    /// Most messages leased per look.
    pub batch: u32,
    /// The daemon's delivery-attempt count at which the adapter acks a message itself (see
    /// [`should_ack`]), so a session that never acks cannot make the same text repeat forever. The
    /// count is the daemon's, kept with the message across sessions and adapter restarts. The ack
    /// also needs two pushes by one process, so a value of 0 or 1 acts as 2 pushes.
    pub max_pushes: u32,
}

impl Default for PushConfig {
    fn default() -> Self {
        Self {
            poll_every: Duration::from_secs(1),
            lease_secs: 30,
            batch: 10,
            max_pushes: 3,
        }
    }
}

/// Where a notification goes. Real servers send to the MCP peer; tests can fail it.
pub trait Notifier: Send + Sync + 'static {
    fn notify(&self, params: Value) -> impl Future<Output = Result<(), String>> + Send;
}

struct PeerNotifier {
    peer: rmcp::service::Peer<RoleServer>,
    method: String,
}

impl Notifier for PeerNotifier {
    async fn notify(&self, params: Value) -> Result<(), String> {
        self.peer
            .send_notification(ServerNotification::CustomNotification(
                CustomNotification::new(self.method.as_str(), Some(params)),
            ))
            .await
            .map_err(|_| "the notification could not be written".to_string())
    }
}

/// How many times THIS process has pushed each `message_id` (in memory only). An entry is forgotten
/// once no pull has returned its message for a while, which is how an acked message leaves it.
#[derive(Default)]
pub struct PushLedger {
    seen: Mutex<HashMap<String, Entry>>,
    /// Ids this process has pushed up to the bound and stopped pushing ([`AckPolicy::ReceiverOnly`]),
    /// oldest first, at most [`MAX_PARKED`].
    parked: Mutex<VecDeque<String>>,
}

/// The most ids the ledger passes over, which is what the daemon accepts in one fetch. Past it the
/// oldest is dropped and is pushed up to the bound again.
pub const MAX_PARKED: usize = 100;

struct Entry {
    pushes: u32,
    last_seen: Instant,
}

impl PushLedger {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Ids this process has stopped pushing, to be passed over by the next pull.
    pub fn parked(&self) -> Vec<String> {
        self.parked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Stop passing over every parked id (they are pushed up to the bound again).
    pub fn unpark_all(&self) {
        self.parked
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    fn park(&self, id: &str) {
        let mut parked = self.parked.lock().unwrap_or_else(|p| p.into_inner());
        if parked.iter().any(|p| p == id) {
            return;
        }
        if parked.len() >= MAX_PARKED {
            parked.pop_front();
        }
        parked.push_back(id.to_string());
    }

    /// Times `id` has been pushed.
    pub fn pushes(&self, id: &str) -> u32 {
        self.lock().get(id).map_or(0, |e| e.pushes)
    }

    /// `id` was acked: drop its entry.
    fn forget(&self, id: &str) {
        self.lock().remove(id);
    }

    /// A pull returned `id` at `now`.
    fn saw(&self, id: &str, now: Instant) {
        if let Some(e) = self.lock().get_mut(id) {
            e.last_seen = now;
        }
    }

    fn pushed(&self, id: &str, now: Instant) {
        let mut seen = self.lock();
        let e = seen.entry(id.to_string()).or_insert(Entry {
            pushes: 0,
            last_seen: now,
        });
        e.pushes += 1;
        e.last_seen = now;
    }

    /// Forget ids no pull has returned since `now - keep`. A leased message is not returned until its
    /// lease ends, so `keep` must exceed the lease or a live message would lose its count.
    fn forget_unseen(&self, now: Instant, keep: Duration) {
        self.lock()
            .retain(|_, e| now.saturating_duration_since(e.last_seen) <= keep);
    }
}

/// Whether the adapter acks a message after a successful write.
///
/// `attempts` is the daemon's delivery-attempt count for the message (it counts leases, across
/// sessions and adapter restarts; `None` from a daemon that does not send it falls back to this
/// process's pushes). `local_pushes` is how many writes of it THIS process has made, the one just
/// made included. Both must hold: `attempts >= max` bounds the delivery attempts, and
/// `local_pushes >= 2` means a fresh session never removes a message after a single push (the first
/// push can precede the client's registration: the c7 case). The bound on pushes per message across
/// sessions is therefore `max(max, attempts_at_first_pull + 2)`, not `max`.
pub fn should_ack(attempts: Option<u64>, local_pushes: u32, max: u32) -> bool {
    let attempts = attempts.unwrap_or_else(|| u64::from(local_pushes));
    attempts >= u64::from(max) && local_pushes >= 2
}

/// One look at the mailbox: lease and push, rendered by `renderer`. A failed write leaves the lease
/// and does not count toward the two pushes the ack needs. Returns how many messages were pushed.
pub async fn push_once_with<R: Renderer, N: Notifier>(
    renderer: &R,
    source: &SynapseMcpServer,
    notifier: &N,
    config: &PushConfig,
    ledger: &PushLedger,
) -> Result<usize, String> {
    let parked = ledger.parked();
    let messages = match source
        .pull_views_excluding(config.batch, config.lease_secs, &parked)
        .await
    {
        Ok(messages) => messages,
        Err(e) => {
            // A refused look with `exclude` on it may be a daemon that predates the field (it
            // answers 400 and would refuse every look). Forget the parked list so the next look
            // carries none: messages are then pushed up to the bound again, and push keeps working.
            if !parked.is_empty() {
                ledger.unpark_all();
            }
            return Err(e);
        }
    };
    let now = Instant::now();
    let keep = Duration::from_secs(
        u64::try_from(config.lease_secs)
            .unwrap_or(0)
            .saturating_mul(2),
    )
    .max(config.poll_every.saturating_mul(2));
    // Mark everything this pull returned as seen first, so a gap in successful pulls (daemon down)
    // cannot make `forget_unseen` drop the count of a message that is still pending.
    for id in messages.iter().filter_map(MessageView::message_id) {
        ledger.saw(id, now);
    }
    ledger.forget_unseen(now, keep);
    let mut pushed = 0;
    for message in &messages {
        let Some(id) = message.message_id() else {
            continue;
        };
        // Only a write that happened counts.
        if notifier.notify(renderer.render(message)).await.is_ok() {
            ledger.pushed(id, now);
            pushed += 1;
            let ack = match renderer.ack_policy() {
                AckPolicy::BoundedAttempts => {
                    should_ack(message.attempts(), ledger.pushes(id), config.max_pushes)
                }
                AckPolicy::Never => false,
                AckPolicy::ReceiverOnly => {
                    // Two writes at least, as for `BoundedAttempts`: the first can precede the
                    // client's registration (the c7 case).
                    if ledger.pushes(id) >= config.max_pushes.max(2) {
                        ledger.park(id);
                    }
                    false
                }
            };
            if ack {
                // A refused ack leaves the message pending, and this process stops pushing it
                // (parked); the receiver's own `ack` or the daemon's delivery cap ends it. Logged:
                // the text is fixed and key-free, like the loop's.
                match source.confirm(id.to_string()).await {
                    Ok(()) => ledger.forget(id),
                    Err(e) => {
                        // Park it for this process: pulled again, it would be pushed every lease
                        // with the ack refused every time (#119). The daemon's delivery cap
                        // (`max_deliveries`) sets it aside in the dead set for good.
                        ledger.park(id);
                        tracing::warn!(
                            "synapse push: the adapter's ack was refused; the message is parked: {e}"
                        );
                    }
                }
            }
        }
    }
    Ok(pushed)
}

/// The push server: the generic tools plus the push task, for the client `R` renders for.
#[derive(Clone)]
pub struct PushServer<R: Renderer> {
    inner: SynapseMcpServer,
    renderer: Arc<R>,
    config: PushConfig,
    started: Arc<AtomicBool>,
}

impl<R: Renderer> PushServer<R> {
    /// Check the role, find (or start) the daemon, take the role if needed, and begin heartbeating.
    pub async fn start_with(
        mcp: McpConfig,
        config: PushConfig,
        renderer: R,
    ) -> Result<Self, String> {
        let inner = SynapseMcpServer::start(mcp)
            .await?
            .with_push(renderer.capability_key(), renderer.method());
        Ok(Self {
            inner,
            renderer: Arc::new(renderer),
            config,
            started: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl<R: Renderer + Default> PushServer<R> {
    /// [`Self::start_with`] using the renderer's default.
    pub async fn start(mcp: McpConfig, config: PushConfig) -> Result<Self, String> {
        Self::start_with(mcp, config, R::default()).await
    }
}

impl<R: Renderer> ServerHandler for PushServer<R> {
    fn get_info(&self) -> ServerConfig {
        let mut experimental = BTreeMap::new();
        experimental.insert(
            self.renderer.capability_key().to_string(),
            serde_json::Map::new(),
        );
        let mut info = ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_experimental_with(experimental)
                .build(),
        )
        .with_server_info(Implementation::new("synapse", env!("CARGO_PKG_VERSION")))
        .with_instructions(self.renderer.instructions());
        info.protocol_version = self.renderer.protocol_cap();
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&self.renderer.protocol_cap()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let tcc = ToolCallContext::new(&self.inner, request, context);
        SynapseMcpServer::tool_router().call(tcc).await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: SynapseMcpServer::tool_router().list_all(),
            ..Default::default()
        })
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        SynapseMcpServer::tool_router().get(name).cloned()
    }

    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let source = self.inner.clone();
        let renderer = self.renderer.clone();
        let config = self.config;
        let peer = context.peer;
        let notifier = PeerNotifier {
            peer: peer.clone(),
            method: renderer.method().to_string(),
        };
        let ledger = PushLedger::default();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(config.poll_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                // Once the client is gone nothing can be pushed, and leasing mail would only hide
                // it from this role's next session until the lease ran out.
                if peer.is_transport_closed() {
                    return;
                }
                // A refused look (superseded, daemon gone) is retried next tick. The text is
                // fixed and key-free, so it is safe to log.
                if let Err(e) =
                    push_once_with(&*renderer, &source, &notifier, &config, &ledger).await
                {
                    tracing::warn!("synapse push: {e}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pushed_id_is_remembered_and_an_unseen_one_is_forgotten_after_the_window() {
        let ledger = PushLedger::default();
        let t0 = Instant::now();
        ledger.pushed("a", t0);
        ledger.pushed("a", t0);
        ledger.pushed("b", t0);
        assert_eq!(ledger.pushes("a"), 2);

        // "a" is returned by a later pull, "b" is not (acked): only "b" is forgotten.
        let t1 = t0 + Duration::from_secs(50);
        ledger.saw("a", t1);
        ledger.forget_unseen(t1, Duration::from_secs(40));
        assert_eq!(ledger.pushes("a"), 2);
        assert_eq!(ledger.pushes("b"), 0);
    }

    #[test]
    fn should_ack_needs_both_the_daemon_attempts_and_two_pushes_by_this_process() {
        // Below the cap: never.
        assert!(!should_ack(Some(2), 2, 3));
        // At the cap but only one push by this process (the c7 case): not yet.
        assert!(!should_ack(Some(3), 1, 3));
        assert!(!should_ack(Some(7), 1, 3));
        // Both hold.
        assert!(should_ack(Some(3), 2, 3));
        assert!(should_ack(Some(5), 2, 3));
        // A daemon that sends no count: this process's pushes stand in for it.
        assert!(!should_ack(None, 2, 3));
        assert!(should_ack(None, 3, 3));
    }

    #[test]
    fn the_parked_list_has_no_duplicates_is_capped_and_can_be_cleared() {
        let ledger = PushLedger::default();
        ledger.park("a");
        ledger.park("a");
        assert_eq!(ledger.parked(), ["a"]);
        for i in 0..(MAX_PARKED + 5) {
            ledger.park(&format!("m{i}"));
        }
        let parked = ledger.parked();
        assert_eq!(parked.len(), MAX_PARKED);
        // The oldest were dropped, the newest kept.
        assert!(!parked.contains(&"a".to_string()));
        assert_eq!(parked.last().unwrap(), &format!("m{}", MAX_PARKED + 4));
        ledger.unpark_all();
        assert!(ledger.parked().is_empty());
    }

    #[test]
    fn forgetting_an_acked_id_drops_its_count() {
        let ledger = PushLedger::default();
        ledger.pushed("a", Instant::now());
        ledger.forget("a");
        assert_eq!(ledger.pushes("a"), 0);
    }

    #[test]
    fn a_message_inside_its_lease_keeps_its_count() {
        let ledger = PushLedger::default();
        let t0 = Instant::now();
        ledger.pushed("a", t0);
        // 30 s lease, window 60 s: not returned for 30 s must not reset it.
        ledger.forget_unseen(t0 + Duration::from_secs(30), Duration::from_secs(60));
        assert_eq!(ledger.pushes("a"), 1);
    }
}
