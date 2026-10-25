// SPDX-License-Identifier: MIT OR Apache-2.0
//! QUIC transport conforming to the unified `Transport`/`TransportReceive` traits.
//!
//! # Wire format: one connection, one stream, per message
//!
//! `send_message` reuses a pooled connection to the target where one exists, or connects (a full
//! handshake; no 0-RTT -- spec §5), opens one bidirectional QUIC stream, writes the serialized
//! `SecureMessage` as JSON, and finishes the send side so the receiver reads to a clean stream
//! end. The receiver accepts the stream, reads to its end, and parses it the same way
//! TCP/WebSocket/HTTP do.
//!
//! # Connection pooling
//!
//! One `quinn::Connection` is kept per peer address and reused across sends; concurrent sends to
//! the same peer open independent, multiplexed streams on that one connection rather than
//! blocking each other or paying for a fresh handshake each time. The pool's lock
//! ([`QuicTransportImpl::pooled_connection`]) is never held across the handshake `await`: a miss
//! releases the lock, connects, then re-acquires it to insert, keeping a connection a racing
//! sender already established instead of overwriting it. A background sweep evicts entries idle
//! for longer than [`IDLE_TIMEOUT_MS_KEY`]; the next send to that peer transparently reopens a
//! connection. [`QuicTransportImpl::evict`] removes a specific peer's entry on demand, and the
//! manager calls [`Transport::on_verification_failure`] when a message from an address fails
//! verification, which evicts that address (at most once per [`DEFAULT_EVICT_COOLDOWN_MS`]).
//!
//! # Delivery claim
//!
//! `Sent` only, never `Delivered` -- see
//! `docs/superpowers/specs/2026-09-22-quic-transport-design.md` §4. QUIC has no synchronous
//! request/response the way HTTP does; a QUIC-level ACK proves the peer's kernel got the bytes,
//! not that its application processed them. `delivery_ack.rs` remains the only mechanism for
//! that, transport-agnostic, and needs no QUIC-specific code.
//!
//! # Config keys
//!
//! | key | default | meaning |
//! |---|---|---|
//! | [`LOCAL_PORT_KEY`] (`local_port`) | `0` | the port `start` listens on; `0` lets the OS choose |
//! | `bind_scope` | `loopback` | which interfaces the endpoint binds ([`crate::network_scope::BindScope`]) |
//! | [`IDLE_TIMEOUT_MS_KEY`] (`idle_timeout_ms`) | [`DEFAULT_IDLE_TIMEOUT_MS`] (300000) | how long a pooled connection may go unused before the idle sweep evicts it, *and* the QUIC connection's own `max_idle_timeout` (with `keep_alive_interval` set to half of it), so the wire-level connection and this transport's pool agree on what "idle" means |
//! | [`MAX_MESSAGE_SIZE_KEY`] (`max_message_size`) | [`DEFAULT_MAX_MESSAGE_SIZE`] (1 MiB) | the largest message, in bytes of serialized JSON, a stream will carry either way |
//! | [`MAX_QUEUED_BYTES_KEY`] (`max_queued_bytes`) | [`DEFAULT_MAX_QUEUED_BYTES`] (4 MiB) | how many bytes of received messages, counted as serialized JSON, may wait for the application to poll; at least `max_message_size` and at most `u32::MAX` |
//! | [`FIRST_BYTE_TIMEOUT_MS_KEY`] (`first_byte_timeout_ms`) | [`DEFAULT_FIRST_BYTE_TIMEOUT_MS`] (5000) | see "Per-stream read timeout" below |
//! | [`STREAM_IDLE_TIMEOUT_MS_KEY`] (`stream_idle_timeout_ms`) | [`DEFAULT_STREAM_IDLE_TIMEOUT_MS`] (5000) | see "Per-stream read timeout" below -- a different, per-*stream* concept from [`IDLE_TIMEOUT_MS_KEY`], which is per pooled *connection* |
//! | [`SEND_TIMEOUT_MS_KEY`] (`send_timeout_ms`) | [`DEFAULT_SEND_TIMEOUT_MS`] (10000) | how long `send_message` may take end to end (handshake/pool-acquire, stream open, write, and the peer's acknowledgment) before it gives up on a dead or slow peer |
//!
//! # Size limits and backpressure
//!
//! `send_message` refuses (`SynapseError::MessageRefused`), before touching the connection pool,
//! any message whose serialized JSON is over `max_message_size` -- following `tcp_unified.rs`'s
//! rule that a local refusal must never touch connection setup or the circuit breaker. On the
//! receive side, each stream's `read_to_end` is bounded by `max_message_size` instead of a
//! hardcoded figure, and a handler takes queue budget for a message's byte length (a
//! `tokio::sync::Semaphore` sized by `max_queued_bytes`, via `acquire_many_owned`) before parsing
//! it; the permit is held by the queued `IncomingMessage` until `receive_raw` drains it, exactly
//! following `tcp_unified.rs`'s `queue_budget` pattern.
//!
//! # Per-stream read timeout (spec §6)
//!
//! A stream that opens but never sends, or stalls mid-message, must not hold resources
//! indefinitely -- bounded only by the connection-level `max_idle_timeout` would let a peer evade
//! this by sending keepalives on the connection while never writing to this particular stream.
//! Each stream's whole `read_to_end` call is wrapped in one
//! `tokio::time::timeout(first_byte_timeout_ms + stream_idle_timeout_ms, ...)`.
//!
//! This is a **deliberate simplification**, not a byte-for-byte "gap between reads" timeout like
//! `websocket_unified.rs`'s `IdleTimeoutStream` adapter: `quinn::RecvStream::read_to_end` reads
//! everything in one call with no exposed per-chunk progress, so a true version of that would need
//! the receive path rewritten to manual chunked reads -- disproportionate to what this gap needs.
//! Bounding total read time this way satisfies the actual security property the spec requirement
//! exists for (a peer cannot hold a stream open indefinitely) without giving the finer-grained
//! diagnostic distinction its wording technically implies ("no first byte yet" vs. "stalled after
//! some bytes arrived"). A future task could replace this with true chunked reads if that
//! distinction is ever needed. On timeout, the stream is dropped like any other receive-side
//! failure in this file (logged, not propagated) -- dropping `quinn::RecvStream` before it has
//! read to completion sends the peer a `STOP_SENDING`.

use super::abstraction::{
    self, ConnectivityResult, DeliveryConfirmation, DeliveryReceipt, IncomingMessage, RawInbox,
    Transport, TransportCapabilities, TransportEstimate, TransportFactory, TransportMetrics,
    TransportStatus, TransportTarget, TransportType, VerificationFailure,
};
use crate::error::{Result, SynapseError};
use crate::types::SecureMessage;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub const LOCAL_PORT_KEY: &str = "local_port";

/// The shortest time between two verification-failure evictions of the same address: 5 seconds. A
/// peer able to push bad messages down a pooled connection could otherwise make us reconnect on
/// every one. See [`QuicTransportImpl::with_evict_cooldown`].
pub const DEFAULT_EVICT_COOLDOWN_MS: u64 = 5_000;

/// The config key for how long, in milliseconds, a pooled connection may go unused before the
/// idle sweep evicts it. See the module documentation.
pub const IDLE_TIMEOUT_MS_KEY: &str = "idle_timeout_ms";

/// The default for [`IDLE_TIMEOUT_MS_KEY`]: 5 minutes.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;

/// The config key for the largest message, in bytes of serialized JSON, a stream will carry
/// either way. See the module documentation.
pub const MAX_MESSAGE_SIZE_KEY: &str = "max_message_size";

/// The default for [`MAX_MESSAGE_SIZE_KEY`]: 1 MiB of serialized JSON.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// The config key for how many bytes of received messages, counted as serialized JSON, may wait
/// for the application to poll. It must be at least [`MAX_MESSAGE_SIZE_KEY`] and at most
/// `u32::MAX`. See the module documentation.
pub const MAX_QUEUED_BYTES_KEY: &str = "max_queued_bytes";

/// The default for [`MAX_QUEUED_BYTES_KEY`]: 4 MiB of serialized JSON.
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

/// The config key for how long, in milliseconds, a stream may go without its first byte arriving.
/// Added together with [`STREAM_IDLE_TIMEOUT_MS_KEY`] to bound one stream's whole `read_to_end`
/// call. See "Per-stream read timeout" in the module documentation.
pub const FIRST_BYTE_TIMEOUT_MS_KEY: &str = "first_byte_timeout_ms";

/// The default for [`FIRST_BYTE_TIMEOUT_MS_KEY`].
pub const DEFAULT_FIRST_BYTE_TIMEOUT_MS: usize = 5_000;

/// The config key for how long, in milliseconds, a stream may take to finish once its first byte
/// has arrived. A different, per-*stream* concept from [`IDLE_TIMEOUT_MS_KEY`], which is
/// per pooled *connection* -- see "Per-stream read timeout" in the module documentation.
pub const STREAM_IDLE_TIMEOUT_MS_KEY: &str = "stream_idle_timeout_ms";

/// The default for [`STREAM_IDLE_TIMEOUT_MS_KEY`].
pub const DEFAULT_STREAM_IDLE_TIMEOUT_MS: usize = 5_000;

/// The config key for how long, in milliseconds, `send_message` may take end to end (acquiring or
/// establishing a pooled connection, opening a stream, writing, and waiting for the peer's
/// acknowledgment) before it gives up on a dead or slow peer. Every sibling transport
/// (`tcp_unified.rs`, `websocket_unified.rs`, `http_unified.rs`) has an equivalent
/// `connection_timeout_ms`-style bound; QUIC needs its own because, once `idle_timeout_ms`
/// actually governs the underlying `quinn` connection (see the module documentation), a send
/// against a half-dead pooled connection could otherwise block for as long as that configured
/// value.
pub const SEND_TIMEOUT_MS_KEY: &str = "send_timeout_ms";

/// The default for [`SEND_TIMEOUT_MS_KEY`].
pub const DEFAULT_SEND_TIMEOUT_MS: usize = 10_000;

/// `config[key]` as a positive integer, or `default` when the key is absent. A value that does not
/// parse, or is zero, is an error: silently falling back to the default would hide a typo. Mirrors
/// `tcp_unified.rs`'s `positive_limit`.
fn parse_positive(config: &HashMap<String, String>, key: &str, default: usize) -> Result<usize> {
    match config.get(key) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<usize>() {
            Ok(0) => Err(SynapseError::Config(format!(
                "{key} must be a positive integer, got 0"
            ))),
            Ok(limit) => Ok(limit),
            Err(e) => Err(SynapseError::Config(format!(
                "{key} must be a positive integer, got {value:?}: {e}"
            ))),
        },
    }
}

/// Parse `idle_timeout_ms` the way `websocket_unified.rs`'s `Limits::from_config` parses its own
/// millisecond keys: a positive integer, or the default when absent; anything else is refused
/// rather than silently replaced.
fn parse_idle_timeout_ms(config: &HashMap<String, String>) -> Result<u64> {
    match config.get(IDLE_TIMEOUT_MS_KEY) {
        None => Ok(DEFAULT_IDLE_TIMEOUT_MS),
        Some(value) => match value.trim().parse::<u64>() {
            Ok(0) => Err(SynapseError::Config(format!(
                "{IDLE_TIMEOUT_MS_KEY} must be a positive integer, got 0"
            ))),
            Ok(ms) => Ok(ms),
            Err(e) => Err(SynapseError::Config(format!(
                "{IDLE_TIMEOUT_MS_KEY} must be a positive integer, got {value:?}: {e}"
            ))),
        },
    }
}

/// A pooled connection together with when it was last used, keyed by peer address. The last-use
/// `Instant` is refreshed on every hit or insert and read by the idle sweep spawned in `start`.
type ConnectionPool = Arc<Mutex<HashMap<SocketAddr, (Arc<quinn::Connection>, Instant)>>>;

/// A received message waiting for the application, holding queue budget for its serialized JSON
/// length until it is drained. Mirrors `tcp_unified.rs`'s `Queued`.
struct Queued {
    message: IncomingMessage,
    _budget: OwnedSemaphorePermit,
}

pub struct QuicTransportImpl {
    endpoint: quinn::Endpoint,
    received: Arc<Mutex<Vec<Queued>>>,
    is_running: Arc<Mutex<bool>>,
    /// One connection per peer, reused across sends; see the module documentation.
    pool: ConnectionPool,
    /// How long a pooled connection may go unused before the idle sweep evicts it.
    idle_timeout: Duration,
    /// The shortest time between two verification-failure evictions of one address.
    evict_cooldown: Duration,
    /// When each address was last evicted for a verification failure. Entries older than
    /// `evict_cooldown` are dropped on every call, so it holds at most the addresses evicted
    /// within one cooldown.
    last_evicted: std::sync::Mutex<HashMap<SocketAddr, Instant>>,
    /// The largest message, in bytes of serialized JSON, `send_message` will send and a stream's
    /// `read_to_end` will accept.
    max_message_size: usize,
    /// Free bytes of queue budget, one permit per byte of serialized JSON. A stream handler takes
    /// its message's length before it parses and keeps it with the queued message; `receive_raw`
    /// releases it by draining the message. See `tcp_unified.rs`'s `queue_budget`.
    queue_budget: Arc<Semaphore>,
    /// `first_byte_timeout_ms` + `stream_idle_timeout_ms`, bounding one stream's whole
    /// `read_to_end` call. See "Per-stream read timeout" in the module documentation.
    stream_read_timeout: Duration,
    /// How long `send_message` may take end to end before it gives up. See
    /// [`SEND_TIMEOUT_MS_KEY`].
    send_timeout: Duration,
    /// Real counters backing `metrics()`. Plain atomics, not a lock, because
    /// `send_message` and the accept loop's per-stream tasks increment these independently and
    /// concurrently, and `metrics()` only ever needs a snapshot sum, never a consistent multi-field
    /// read -- the same reason `websocket_unified.rs` keeps `active_connections` as an `AtomicU64`
    /// alongside its lock-guarded `TransportMetrics`.
    messages_sent: AtomicU64,
    bytes_sent: AtomicU64,
    send_failures: AtomicU64,
    /// Shared with the accept loop's per-stream tasks (spawned in `start`), which is why these
    /// three are `Arc`-wrapped while the send-side counters above are not: `send_message` runs on
    /// `&self` and never needs to move its counters into a spawned task.
    messages_received: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    receive_failures: Arc<AtomicU64>,
}

impl QuicTransportImpl {
    pub async fn new(config: &HashMap<String, String>) -> Result<Self> {
        validate_config(config)?;
        let local_port = config
            .get(LOCAL_PORT_KEY)
            .map(|p| p.parse::<u16>())
            .transpose()
            .map_err(|_| SynapseError::Config("Invalid port number".to_string()))?
            .unwrap_or(0);
        let bind_scope = crate::network_scope::BindScope::from_config_map(config)?;

        let idle_timeout = Duration::from_millis(parse_idle_timeout_ms(config)?);
        // Make `idle_timeout_ms` govern the real connection, not just this transport's own idle
        // sweep: `quinn`'s own default `max_idle_timeout` is 30 seconds, and without an explicit
        // `keep_alive_interval` a connection with no application traffic goes silent and hits
        // that default long before a larger configured `idle_timeout_ms` would ever matter.
        // `keep_alive_interval` is set to half of `idle_timeout_ms` so at least one keepalive
        // reaches the peer before quinn's own idle timer could otherwise fire, mirroring the
        // sweep's own "woken at twice the idle rate" margin below.
        let mut quic_transport_config = quinn::TransportConfig::default();
        quic_transport_config
            .max_idle_timeout(Some(quinn::IdleTimeout::try_from(idle_timeout).map_err(
                |e| SynapseError::Config(format!("{IDLE_TIMEOUT_MS_KEY} is too large: {e}")),
            )?))
            .keep_alive_interval(Some(idle_timeout / 2));
        let quic_transport_config = Arc::new(quic_transport_config);

        let (cert, key) = super::quic_tls::generate_self_signed_cert()?;
        let server_tls = super::quic_tls::server_config(cert, key)?; // Arc<rustls::ServerConfig>
        let mut server_quic_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).map_err(|e| {
                SynapseError::TransportError(format!("QUIC server TLS setup failed: {e}"))
            })?,
        ));
        server_quic_config.transport_config(Arc::clone(&quic_transport_config));

        let bind_addr = bind_scope.listen_addr(local_port);
        let mut endpoint = quinn::Endpoint::server(server_quic_config, bind_addr).map_err(|e| {
            SynapseError::TransportError(format!(
                "Failed to bind QUIC endpoint to {bind_addr}: {e}"
            ))
        })?;

        let client_tls = super::quic_tls::client_config()?; // Arc<rustls::ClientConfig>
        let mut client_quic_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).map_err(|e| {
                SynapseError::TransportError(format!("QUIC client TLS setup failed: {e}"))
            })?,
        ));
        client_quic_config.transport_config(quic_transport_config);
        endpoint.set_default_client_config(client_quic_config);

        let max_message_size =
            parse_positive(config, MAX_MESSAGE_SIZE_KEY, DEFAULT_MAX_MESSAGE_SIZE)?;
        let max_queued_bytes =
            parse_positive(config, MAX_QUEUED_BYTES_KEY, DEFAULT_MAX_QUEUED_BYTES)?;
        let first_byte_timeout_ms = parse_positive(
            config,
            FIRST_BYTE_TIMEOUT_MS_KEY,
            DEFAULT_FIRST_BYTE_TIMEOUT_MS,
        )?;
        let stream_idle_timeout_ms = parse_positive(
            config,
            STREAM_IDLE_TIMEOUT_MS_KEY,
            DEFAULT_STREAM_IDLE_TIMEOUT_MS,
        )?;
        let stream_read_timeout =
            Duration::from_millis((first_byte_timeout_ms + stream_idle_timeout_ms) as u64);
        let send_timeout = Duration::from_millis(parse_positive(
            config,
            SEND_TIMEOUT_MS_KEY,
            DEFAULT_SEND_TIMEOUT_MS,
        )? as u64);

        Ok(Self {
            endpoint,
            received: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(Mutex::new(false)),
            pool: Arc::new(Mutex::new(HashMap::new())),
            idle_timeout,
            evict_cooldown: Duration::from_millis(DEFAULT_EVICT_COOLDOWN_MS),
            last_evicted: std::sync::Mutex::new(HashMap::new()),
            max_message_size,
            queue_budget: Arc::new(Semaphore::new(max_queued_bytes)),
            send_timeout,
            stream_read_timeout,
            messages_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            messages_received: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            receive_failures: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Replaces the verification-failure eviction cooldown ([`DEFAULT_EVICT_COOLDOWN_MS`]).
    pub fn with_evict_cooldown(mut self, cooldown: Duration) -> Self {
        self.evict_cooldown = cooldown;
        self
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(|e| {
            SynapseError::TransportError(format!("QUIC endpoint has no local address: {e}"))
        })
    }

    /// Reuse a pooled connection to `addr`, or establish one. The pool's lock is never held
    /// across the handshake `await` (spec §3, condition 2): a miss releases the lock, connects,
    /// then re-acquires it to insert -- double-checking for a connection a racing sender
    /// established first, keeping that one and dropping the one just established, rather than
    /// overwrite it. Every return path refreshes the entry's last-use `Instant`, so the idle
    /// sweep (spawned in `start`) only evicts a connection nothing has used recently.
    async fn pooled_connection(&self, addr: SocketAddr) -> Result<Arc<quinn::Connection>> {
        {
            let mut pool = self.pool.lock().await;
            if let Some((conn, last_used)) = pool.get_mut(&addr)
                && conn.close_reason().is_none()
            {
                *last_used = Instant::now();
                return Ok(Arc::clone(conn));
            }
        }
        let connecting = self
            .endpoint
            .connect(addr, "synapse-quic")
            .map_err(|e| SynapseError::TransportError(format!("QUIC connect setup failed: {e}")))?;
        let fresh =
            Arc::new(connecting.await.map_err(|e| {
                SynapseError::TransportError(format!("QUIC handshake failed: {e}"))
            })?);
        let mut pool = self.pool.lock().await;
        if let Some((existing, last_used)) = pool.get_mut(&addr)
            && existing.close_reason().is_none()
        {
            // A racing sender inserted a connection to the same peer while we were connecting:
            // keep it, and let `fresh` be dropped (which closes it cleanly).
            *last_used = Instant::now();
            return Ok(Arc::clone(existing));
        }
        pool.insert(addr, (Arc::clone(&fresh), Instant::now()));
        Ok(fresh)
    }

    /// Evict a pooled connection to `addr` -- for when a message received over it fails
    /// application-layer verification, so a connection that has started reaching the wrong peer
    /// (NAT rebinding, address reuse) is not silently reused again. Called by
    /// [`Transport::on_verification_failure`], which adds the per-address cooldown; calling it
    /// directly has none. See `docs/superpowers/specs/2026-10-24-quic-pool-eviction-design.md`
    /// and <https://github.com/ciresnave/synapse/issues/49>.
    pub async fn evict(&self, addr: SocketAddr) {
        if let Some((conn, _)) = self.pool.lock().await.remove(&addr) {
            conn.close(0u32.into(), b"evicted: verification failure");
        }
    }

    /// How many entries the pool currently holds, including any that have already closed but the
    /// idle sweep has not yet noticed and dropped. Exposed as a plain `pub` method rather than
    /// `#[cfg(test)]`-gated: the integration tests in `tests/transport_repairs.rs` link against
    /// this crate's normal build, which does not include `cfg(test)` items, so a gated accessor
    /// would not exist in the binary they run against. `metrics()`'s `active_connections` uses
    /// [`Self::live_connection_count`] instead, which is the number that actually answers "how
    /// many connections are active" -- this raw count stays a plain length because the pooling
    /// tests use it to assert on pool *entries* (e.g. "one entry per peer"), independent of
    /// whether that entry's connection happens to still be live at the moment of the check.
    pub async fn pool_size(&self) -> usize {
        self.pool.lock().await.len()
    }

    /// How many pooled connections are actually live right now (`close_reason().is_none()`),
    /// as opposed to [`Self::pool_size`]'s raw entry count, which can include a connection that
    /// has already closed but that the idle sweep has not yet run to drop. This is what
    /// `metrics()` reports as `active_connections`: counting every pooled entry as "active"
    /// would overclaim what an idle-but-not-yet-swept entry is doing.
    async fn live_connection_count(&self) -> usize {
        self.pool
            .lock()
            .await
            .values()
            .filter(|(conn, _)| conn.close_reason().is_none())
            .count()
    }
}

pub fn validate_config(config: &HashMap<String, String>) -> Result<()> {
    if let Some(port_str) = config.get(LOCAL_PORT_KEY)
        && port_str.parse::<u16>().is_err()
    {
        return Err(SynapseError::Config("Invalid port number".to_string()));
    }
    parse_idle_timeout_ms(config)?;
    let max_message_size = parse_positive(config, MAX_MESSAGE_SIZE_KEY, DEFAULT_MAX_MESSAGE_SIZE)?;
    let max_queued_bytes = parse_positive(config, MAX_QUEUED_BYTES_KEY, DEFAULT_MAX_QUEUED_BYTES)?;
    // A message the size check accepts must fit the queue budget, or its handler would wait
    // forever for room that never comes (mirrors `tcp_unified.rs`'s `Limits::from_config`).
    if max_queued_bytes < max_message_size {
        return Err(SynapseError::Config(format!(
            "{MAX_QUEUED_BYTES_KEY} ({max_queued_bytes}) must be at least \
             {MAX_MESSAGE_SIZE_KEY} ({max_message_size}), or a message of that size could \
             never be queued"
        )));
    }
    // A handler takes budget for a whole message in one `acquire_many_owned`, which counts in
    // `u32`. A message is at most the budget, so a budget that fits `u32` makes every acquire fit
    // too.
    if u32::try_from(max_queued_bytes).is_err() {
        return Err(SynapseError::Config(format!(
            "{MAX_QUEUED_BYTES_KEY} ({max_queued_bytes}) must be at most {}",
            u32::MAX
        )));
    }
    parse_positive(
        config,
        FIRST_BYTE_TIMEOUT_MS_KEY,
        DEFAULT_FIRST_BYTE_TIMEOUT_MS,
    )?;
    parse_positive(
        config,
        STREAM_IDLE_TIMEOUT_MS_KEY,
        DEFAULT_STREAM_IDLE_TIMEOUT_MS,
    )?;
    parse_positive(config, SEND_TIMEOUT_MS_KEY, DEFAULT_SEND_TIMEOUT_MS)?;
    Ok(())
}

#[async_trait]
impl Transport for QuicTransportImpl {
    fn transport_type(&self) -> TransportType {
        TransportType::Quic
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            max_message_size: self.max_message_size,
            ..TransportCapabilities::quic()
        }
    }

    async fn can_reach(&self, target: &TransportTarget) -> bool {
        parse_target(target).is_ok()
    }

    async fn estimate_metrics(&self, target: &TransportTarget) -> Result<TransportEstimate> {
        // A real connectivity probe, bounded so a target that never answers cannot hang this
        // call: `test_connectivity` itself only returns once its direct handshake attempt either
        // succeeds or fails, and a QUIC handshake to an address nothing listens on can otherwise
        // ride quinn's own (much longer) idle/retry timers.
        let timeout = Duration::from_millis(2000);
        let live = tokio::time::timeout(timeout, self.test_connectivity(target)).await;
        match live {
            Ok(Ok(result)) if result.connected => Ok(TransportEstimate {
                latency: result.rtt.unwrap_or(timeout),
                reliability: 0.9,
                bandwidth: 1,
                cost: 1.0,
                available: true,
                confidence: 1.0,
            }),
            _ => Ok(TransportEstimate {
                latency: timeout,
                reliability: 0.0,
                bandwidth: 0,
                cost: 1.0,
                available: false,
                confidence: 0.3,
            }),
        }
    }

    async fn send_message(
        &self,
        target: &TransportTarget,
        message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        let start = std::time::Instant::now();
        let addr = parse_target(target)?;

        // Serialize and check the size before touching the connection pool: a local refusal must
        // never open a connection or reach the circuit breaker (see `tcp_unified.rs`'s
        // `connect_and_send`, which refuses the same way before connecting).
        let data = serde_json::to_vec(message).map_err(|e| {
            SynapseError::TransportError(format!("Failed to serialize message: {e}"))
        })?;
        if data.len() > self.max_message_size {
            return Err(SynapseError::MessageRefused(format!(
                "message is {} bytes, over the max_message_size limit of {} bytes",
                data.len(),
                self.max_message_size
            )));
        }

        // The whole handshake-acquire-write-stopped sequence is bounded by `send_timeout_ms`:
        // without this, a send against a half-dead pooled connection could block for as long as
        // the connection's own `max_idle_timeout` (`idle_timeout_ms`), which -- now that
        // `idle_timeout_ms` actually governs the underlying `quinn` connection -- could be
        // configured arbitrarily large.
        let send_future = async {
            let connection = self.pooled_connection(addr).await.inspect_err(|_| {
                self.send_failures.fetch_add(1, Ordering::Relaxed);
            })?;

            let (mut send, _recv) = connection
                .open_bi()
                .await
                .inspect_err(|_| {
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                })
                .map_err(|e| {
                    SynapseError::TransportError(format!("QUIC stream open failed: {e}"))
                })?;

            send.write_all(&data)
                .await
                .inspect_err(|_| {
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                })
                .map_err(|e| {
                    SynapseError::TransportError(format!("QUIC stream write failed: {e}"))
                })?;
            send.finish()
                .inspect_err(|_| {
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                })
                .map_err(|e| {
                    SynapseError::TransportError(format!("QUIC stream finish failed: {e}"))
                })?;
            // Wait for the peer to acknowledge receipt of the whole stream before returning:
            // without this, a caller could observe `Sent` before the peer's application ever saw
            // the bytes. It also still guards the connection-drop race this was originally added
            // for (dropping the last handle to a `quinn::Connection` that isn't already closing
            // sends an abrupt CONNECTION_CLOSE -- see `quinn`'s `ConnectionRef::drop` ->
            // `implicit_close` -- which can race the still-in-flight STREAM/FIN frame and reset
            // the stream before the receiver finishes reading it): now that `connection` comes
            // from the pool, the last handle is usually held there rather than dropped here, but
            // a connection that lost the insert-race in `pooled_connection` (or one evicted
            // concurrently) can still be the last handle at this point.
            match send.stopped().await {
                Ok(None) => {
                    // The peer acknowledged receipt of all stream data. Proceed as success.
                    Ok(())
                }
                Ok(Some(error_code)) => {
                    // The peer sent STOP_SENDING: it explicitly did not accept the stream. This
                    // must not be reported as `Sent` -- that would be exactly the
                    // silent-loss-on-send this wait was added to close.
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                    Err(SynapseError::TransportError(format!(
                        "QUIC peer rejected the stream (STOP_SENDING, code {error_code})"
                    )))
                }
                Err(e) => {
                    self.send_failures.fetch_add(1, Ordering::Relaxed);
                    Err(SynapseError::TransportError(format!(
                        "QUIC stream was not acknowledged by the peer: {e}"
                    )))
                }
            }
        };
        match tokio::time::timeout(self.send_timeout, send_future).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                self.send_failures.fetch_add(1, Ordering::Relaxed);
                return Err(SynapseError::TransportError(format!(
                    "QUIC send to {addr} did not complete within send_timeout_ms ({} ms)",
                    self.send_timeout.as_millis()
                )));
            }
        }

        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(DeliveryReceipt {
            message_id: message.message_id.0.to_string(),
            transport_used: TransportType::Quic,
            delivery_time: start.elapsed(),
            target_reached: target.identifier.clone(),
            confirmation: DeliveryConfirmation::Sent,
            metadata: HashMap::new(),
        })
    }

    async fn test_connectivity(&self, target: &TransportTarget) -> Result<ConnectivityResult> {
        let addr = match parse_target(target) {
            Ok(addr) => addr,
            Err(e) => {
                return Ok(ConnectivityResult {
                    connected: false,
                    rtt: None,
                    error: Some(e.to_string()),
                    quality: 0.0,
                    details: HashMap::new(),
                });
            }
        };
        let start = Instant::now();
        // A real probe, but deliberately not through `pooled_connection`: a mere connectivity
        // check must not retain a connection in the pool, which would inflate `metrics()`'s
        // `active_connections` and leave a stale entry behind after `stop()` (which does not
        // clear the pool). Connecting directly here means this probe's connection is dropped
        // (and so closed) as soon as this call returns, regardless of outcome. A malformed
        // address never gets here (handled above); an address nothing answers fails the
        // handshake below, which is the only way `connected` becomes `false` from here on.
        let outcome: Result<quinn::Connection> = async {
            let connecting = self.endpoint.connect(addr, "synapse-quic").map_err(|e| {
                SynapseError::TransportError(format!("QUIC connect setup failed: {e}"))
            })?;
            connecting
                .await
                .map_err(|e| SynapseError::TransportError(format!("QUIC handshake failed: {e}")))
        }
        .await;
        match outcome {
            Ok(conn) => Ok(ConnectivityResult {
                connected: true,
                rtt: Some(start.elapsed()),
                error: None,
                quality: 0.9,
                details: {
                    let mut d = HashMap::new();
                    d.insert("rtt_ms".to_string(), conn.rtt().as_millis().to_string());
                    d
                },
            }),
            Err(e) => Ok(ConnectivityResult {
                connected: false,
                rtt: None,
                error: Some(e.to_string()),
                quality: 0.0,
                details: HashMap::new(),
            }),
        }
    }

    async fn start(&self) -> Result<()> {
        let mut running = self.is_running.lock().await;
        if *running {
            return Ok(());
        }
        let local_addr = self.local_addr()?;
        tracing::info!("QUIC transport bound to {}", local_addr);

        let endpoint = self.endpoint.clone();
        let received = Arc::clone(&self.received);
        let max_message_size = self.max_message_size;
        let queue_budget = Arc::clone(&self.queue_budget);
        let stream_read_timeout = self.stream_read_timeout;
        let messages_received = Arc::clone(&self.messages_received);
        let bytes_received = Arc::clone(&self.bytes_received);
        let receive_failures = Arc::clone(&self.receive_failures);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let received = Arc::clone(&received);
                let queue_budget = Arc::clone(&queue_budget);
                let messages_received = Arc::clone(&messages_received);
                let bytes_received = Arc::clone(&bytes_received);
                let receive_failures = Arc::clone(&receive_failures);
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("QUIC handshake failed: {e}");
                            receive_failures.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    let source = connection.remote_address().to_string();
                    // Keep accepting streams for as long as the peer keeps the connection open
                    // (the sender pools and reuses one connection for many messages, so the
                    // receiver must accept more than the first stream on it). Each stream is
                    // handled on its own task so concurrent sends on the same connection don't
                    // wait on each other (multiplexing). `accept_bi` returning `Err` means the
                    // connection closed -- gracefully (idle timeout, `stop()`, or the peer's own
                    // pool evicting it) or otherwise -- either way there is nothing left to accept.
                    loop {
                        let (_send, mut recv) = match connection.accept_bi().await {
                            Ok(streams) => streams,
                            Err(e) => {
                                tracing::debug!("QUIC connection from {source} closed: {e}");
                                break;
                            }
                        };
                        let received = Arc::clone(&received);
                        let queue_budget = Arc::clone(&queue_budget);
                        let messages_received = Arc::clone(&messages_received);
                        let bytes_received = Arc::clone(&bytes_received);
                        let receive_failures = Arc::clone(&receive_failures);
                        let source = source.clone();
                        tokio::spawn(async move {
                            // Bounded by the configured `max_message_size`, not a hardcoded
                            // figure; `capabilities()` reports that same configured value.
                            //
                            // The whole call is also bounded by `stream_read_timeout`
                            // (`first_byte_timeout_ms` + `stream_idle_timeout_ms`), so a stream
                            // that opens but never sends, or stalls mid-message, cannot hold this
                            // task (and its buffer) open indefinitely -- see "Per-stream read
                            // timeout" in the module documentation for why this bounds total read
                            // time rather than distinguishing "no first byte" from "stalled
                            // mid-message", and why that is enough. On timeout, `recv` is dropped
                            // (below, via `return`) before it has read to completion, which sends
                            // the peer a `STOP_SENDING`.
                            let data = match tokio::time::timeout(
                                stream_read_timeout,
                                recv.read_to_end(max_message_size),
                            )
                            .await
                            {
                                Ok(Ok(d)) => d,
                                Ok(Err(e)) => {
                                    tracing::warn!("QUIC stream read failed from {source}: {e}");
                                    receive_failures.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        "Dropped QUIC stream from {source}: no complete message within {stream_read_timeout:?} \
                                         (first_byte_timeout_ms + stream_idle_timeout_ms)"
                                    );
                                    receive_failures.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                            };

                            // Wait for queue budget before parsing, so a waiting handler holds
                            // only its raw bytes, not the several times larger parsed message.
                            // `validate_config` guarantees
                            // `data.len() <= max_message_size <= max_queued_bytes <= u32::MAX`,
                            // so the conversion cannot fail and the acquire never asks for more
                            // than the budget holds. The acquire fails only once `stop` has
                            // closed the budget (mirrors `tcp_unified.rs`'s `handle_connection`).
                            let Ok(wanted) = u32::try_from(data.len()) else {
                                tracing::error!(
                                    "Dropped QUIC message from {source}: {} bytes is over the queue budget's u32 limit",
                                    data.len()
                                );
                                receive_failures.fetch_add(1, Ordering::Relaxed);
                                return;
                            };
                            let Ok(budget) = queue_budget.acquire_many_owned(wanted).await else {
                                tracing::error!(
                                    "Dropped QUIC message from {source}: the receive queue was closed"
                                );
                                receive_failures.fetch_add(1, Ordering::Relaxed);
                                return;
                            };

                            let message: SecureMessage = match serde_json::from_slice(&data) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::warn!(
                                        "Dropped QUIC message from {source}: {} bytes did not parse as a SecureMessage: {e}",
                                        data.len()
                                    );
                                    receive_failures.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                            };
                            let data_len = data.len() as u64;
                            let incoming_message =
                                IncomingMessage::new(message, TransportType::Quic, source);
                            received.lock().await.push(Queued {
                                message: incoming_message,
                                _budget: budget,
                            });
                            messages_received.fetch_add(1, Ordering::Relaxed);
                            bytes_received.fetch_add(data_len, Ordering::Relaxed);
                        });
                    }
                });
            }
        });

        // Idle-timeout eviction sweep: a connection nothing has used in `idle_timeout` is closed
        // and dropped from the pool; the next send to that peer transparently reopens one.
        // Woken at twice the idle rate so an entry is evicted within `idle_timeout` of going
        // idle, not up to `idle_timeout` late.
        //
        // The sweep holds only a `Weak` reference to the pool, never `Arc::clone(&self.pool)`, so
        // it terminates on its own once `QuicTransportImpl` itself is dropped (`pool.upgrade()`
        // then fails and the loop breaks) instead of running forever -- no explicit shutdown
        // signal needed, and `stop()` does not need to coordinate with this spawned task at all.
        // This does not by itself stop `start()`/`stop()`/`start()` from spawning a second sweep
        // (`stop()` clears `is_running`, so a later `start()` does not hit the already-running
        // early return). In practice this is harmless, not merely unlikely: `stop()` closes both
        // `endpoint` and `queue_budget` irreversibly, so a "restarted" transport can neither
        // receive nor usefully connect -- restart is not a supported lifecycle -- and two sweeps
        // over the same pool with the same `idle_timeout` are idempotent (`retain` with a pure
        // predicate, `conn.close()` on an already-closed connection is a no-op); the only cost of
        // a redundant sweep would be one extra timer, and both still exit on drop.
        {
            let pool = Arc::downgrade(&self.pool);
            let idle_timeout = self.idle_timeout;
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(idle_timeout / 2);
                loop {
                    interval.tick().await;
                    let Some(pool) = pool.upgrade() else {
                        break;
                    };
                    let now = Instant::now();
                    let mut pool = pool.lock().await;
                    // Inlined rather than calling `evict()`: `evict()` takes the pool lock itself,
                    // and this closure already runs with it held (via `retain`) -- calling it here
                    // would deadlock. Keep this in sync with `evict()`'s close-and-drop behavior by
                    // hand if either changes.
                    pool.retain(|_, (conn, last_used)| {
                        let keep = now.duration_since(*last_used) < idle_timeout
                            && conn.close_reason().is_none();
                        if !keep {
                            conn.close(0u32.into(), b"idle timeout");
                        }
                        keep
                    });
                }
            });
        }

        *running = true;
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut running = self.is_running.lock().await;
        self.endpoint.close(0u32.into(), b"stopping");
        // Close the queue budget, so any stream handler waiting for it gets an error, drops its
        // message and returns, instead of waiting forever for a poll that will never come.
        // Mirrors `tcp_unified.rs`'s `stop`.
        self.queue_budget.close();
        *running = false;
        Ok(())
    }

    /// Evicts the pooled connection to `source` after a message from it failed verification, at
    /// most once per [`DEFAULT_EVICT_COOLDOWN_MS`] per address. A `source` that is not a socket
    /// address is ignored.
    async fn on_verification_failure(&self, source: &str, reason: VerificationFailure) {
        let Ok(addr) = source.parse::<SocketAddr>() else {
            tracing::debug!(
                source,
                ?reason,
                "QUIC: failure source is not an address; ignored"
            );
            return;
        };
        {
            let now = Instant::now();
            let mut last = self.last_evicted.lock().unwrap();
            last.retain(|_, at| now.duration_since(*at) < self.evict_cooldown);
            if last.contains_key(&addr) {
                return;
            }
            last.insert(addr, now);
        }
        self.evict(addr).await;
    }

    async fn status(&self) -> TransportStatus {
        if *self.is_running.lock().await {
            TransportStatus::Running
        } else {
            TransportStatus::Stopped
        }
    }

    async fn metrics(&self) -> TransportMetrics {
        let messages_sent = self.messages_sent.load(Ordering::Relaxed);
        let send_failures = self.send_failures.load(Ordering::Relaxed);
        let attempts = messages_sent + send_failures;
        // Mirrors `websocket_unified.rs`'s `metrics()`: reliability is the fraction of attempted
        // sends that succeeded, and an untried transport claims perfect reliability rather than
        // zero (no evidence either way yet).
        let reliability_score = if attempts == 0 {
            1.0
        } else {
            messages_sent as f64 / attempts as f64
        };
        TransportMetrics {
            transport_type: TransportType::Quic,
            messages_sent,
            messages_received: self.messages_received.load(Ordering::Relaxed),
            send_failures,
            receive_failures: self.receive_failures.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            reliability_score,
            active_connections: self.live_connection_count().await as u32,
            ..Default::default()
        }
    }
}

#[async_trait]
impl abstraction::TransportReceive for QuicTransportImpl {
    async fn receive_raw(&self, inbox: &mut RawInbox) -> Result<()> {
        // Draining a message drops the queue budget it held, so a handler waiting for budget can
        // queue its message as soon as this lock is released.
        let mut received = self.received.lock().await;
        inbox.extend(received.drain(..).map(|queued| queued.message));
        Ok(())
    }
}

fn parse_target(target: &TransportTarget) -> Result<SocketAddr> {
    target
        .address
        .as_ref()
        .ok_or_else(|| SynapseError::TransportError("No target address provided".to_string()))?
        .parse::<SocketAddr>()
        .map_err(|e| SynapseError::TransportError(format!("Invalid QUIC target address: {e}")))
}

pub struct QuicTransportFactory;

#[async_trait]
impl TransportFactory for QuicTransportFactory {
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        let transport = QuicTransportImpl::new(config).await?;
        Ok(Box::new(transport))
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Quic
    }

    fn default_config(&self) -> HashMap<String, String> {
        let mut cfg = HashMap::new();
        cfg.insert(LOCAL_PORT_KEY.to_string(), "0".to_string());
        cfg.insert(
            IDLE_TIMEOUT_MS_KEY.to_string(),
            DEFAULT_IDLE_TIMEOUT_MS.to_string(),
        );
        cfg.insert(
            MAX_MESSAGE_SIZE_KEY.to_string(),
            DEFAULT_MAX_MESSAGE_SIZE.to_string(),
        );
        cfg.insert(
            MAX_QUEUED_BYTES_KEY.to_string(),
            DEFAULT_MAX_QUEUED_BYTES.to_string(),
        );
        cfg.insert(
            FIRST_BYTE_TIMEOUT_MS_KEY.to_string(),
            DEFAULT_FIRST_BYTE_TIMEOUT_MS.to_string(),
        );
        cfg.insert(
            STREAM_IDLE_TIMEOUT_MS_KEY.to_string(),
            DEFAULT_STREAM_IDLE_TIMEOUT_MS.to_string(),
        );
        cfg.insert(
            SEND_TIMEOUT_MS_KEY.to_string(),
            DEFAULT_SEND_TIMEOUT_MS.to_string(),
        );
        cfg
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        validate_config(config)
    }
}

// A test attempting to cover the `Ok(Some(error_code))` (STOP_SENDING) branch above was tried and
// removed: see the task report's fix-report section for why a bare `quinn` peer that calls
// `recv.stop()` right after `accept_bi()` still measured `send.stopped()` resolving to `Ok(None)`
// on loopback with a small payload -- `stopped()`'s own documentation explains why (once the
// peer's transport layer has acknowledged all stream data, "the peer closing the stream is no
// longer meaningful", independent of whether the application later calls `stop()`), so this is a
// structural property of small loopback messages, not a flaky test. Known gap, flagged for a
// later task's test coverage.
