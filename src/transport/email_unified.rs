// SPDX-License-Identifier: MIT OR Apache-2.0
//! Email transport: SMTP send, SMTP-server receive (Direct mode); relay/smart-host SMTP send and
//! IMAP-polling receive (RelayOut/External modes).
//!
//! # Three modes, chosen at construction
//!
//! [`EmailMode`] is decided once, in [`EmailTransportImpl::new`], from
//! [`ConnectivityDetector::assess_connectivity`] -- unless the config map's `email_mode` key names
//! one explicitly (`"direct"`/`"relay_out"`/`"external"`), which skips the detector entirely. That
//! override exists for two reasons: an operator who already knows their network shape (e.g. "this
//! box is firewalled, don't bother probing") can say so directly, and it is the only way to test
//! RelayOut/External deterministically -- `ConnectivityDetector::assess_connectivity` probes fixed
//! ports (25/587/2525, 143/993/1143) that other loopback tests in the same `cargo test` run bind
//! and release, so a real assessment can flap between `RelayOnly`/`ExternalProvider` and
//! `RunLocalServer` from one run to the next.
//!
//! ## Direct mode
//!
//! Direct mode is literal direct-to-recipient SMTP: this transport connects straight to the
//! target's own mail server (its address, `host:port`, comes from [`TransportTarget::address`] --
//! in production that would be resolved via the target's MX record; in this crate's loopback
//! tests it is the peer's own `SynapseSmtpServer` port) rather than relaying through a
//! statically-configured smart host. That is why `send_message` builds a fresh, unauthenticated
//! `lettre` client per send targeting `target.address` in this mode, instead of the configured
//! `smtp_host`. This is the only mode that binds an inbound `SynapseSmtpServer`, in
//! [`EmailTransportImpl::new`] (see [`Transport::start`]'s doc on binding-in-constructor).
//!
//! Per the Global Constraints (spec §3): this transport never bases any trust or authorization
//! decision on `MAIL FROM`, `From:`, or the connecting client's address. Sender authentication is
//! the `SecureMessage` signature alone, verified downstream by `TransportManager`. The SMTP
//! envelope's `MAIL FROM`/`RCPT TO` are accepted unconditionally by this transport's own
//! `SynapseSmtpServer` instance -- see [`AcceptAllAuthHandler`] -- because this is a private,
//! single-tenant server (one `EmailTransportImpl` per bound port, not a shared multi-user mail
//! server), so there is no local recipient identity to check against, and even if there were,
//! checking it would not be a security control (spec §3 forbids treating it as one).
//!
//! Because there is no configured local recipient address to filter by (see above),
//! `receive_raw` drains every message the whole store holds
//! ([`SynapseSmtpServer::drain_all_messages`]), not a single recipient's queue -- matching every
//! other transport's shape, where `receive_raw` empties this instance's own inbound queue
//! wholesale rather than filtering by identity (identity is `TransportManager`'s job, from the
//! `SecureMessage`'s signature).
//!
//! ## RelayOut and External modes
//!
//! Per spec §1a(4) (CireSnave verbatim, design doc): IMAP here exists so one server can send and
//! receive on behalf of another as a proxy, when direct SMTP isn't reachable (firewalled network,
//! corporate policy) -- never for a human to read agent traffic. Both modes share one
//! implementation, because from this transport's point of view they are the same shape: it cannot
//! run an inbound listener (`start` is a no-op; no `SynapseSmtpServer` is ever constructed), so
//! `send_message` relays through the configured `smtp_host`/`smtp_port` smart host instead of
//! dialing `target.address` directly, and `receive_raw` polls the configured
//! `imap_host`/`imap_port` mailbox over `async-imap` instead of draining an owned store. They
//! differ only in *why* a direct listener isn't available (`RelayOnly` vs `ExternalProvider`,
//! from [`ServerRecommendation`]), which changes nothing about how this transport behaves.
//!
//! `SynapseImapServer` (the only IMAP peer any test here is allowed to use -- spec §7 forbids a
//! live external provider in any test) implements no `SEARCH` command and tracks no `\Seen` flag,
//! so "fetch only unseen" is not literally available against it. `receive_raw` asks instead for the
//! UIDs it has not seen: it keeps the mailbox's `UIDVALIDITY` and the next UID to ask for
//! ([`EmailTransportImpl::imap_cursor`]) and sends `UID FETCH <next>:*`, so a poll with nothing new
//! fetches nothing and a poll's cost follows what arrived, not the size of the mailbox. A server that
//! reports no `UIDNEXT` is polled with the old whole-mailbox `FETCH`. Either way delivery is
//! de-duplicated client-side by `message_id` in a bounded set ([`EmailTransportImpl::imap_seen_ids`],
//! oldest forgotten first): nothing is ever removed from the mailbox, but nothing already delivered to
//! a caller's inbox is delivered again. A message whose fetched body does not
//! parse as a `SecureMessage` increments `receive_failures` and is skipped, not fatal to the poll
//! -- mirroring `nat_traversal.rs`'s `receive_raw` handling of an unparseable UDP datagram.
//!
//! # Size limits and backpressure (Task 4)
//!
//! [`MAX_MESSAGE_SIZE_KEY`] (`max_message_size`) and [`MAX_QUEUED_BYTES_KEY`]
//! (`max_queued_bytes`) are validated exactly as `tcp_unified.rs`'s own `Limits::from_config`
//! does (see [`EmailLimits::from_config`]): an unparseable or zero value is refused, not
//! defaulted, and `max_queued_bytes` must be at least `max_message_size` and at most `u32::MAX`.
//! `send_message` refuses a message whose serialized JSON is over `max_message_size` with
//! [`SynapseError::MessageRefused`](crate::error::SynapseError::MessageRefused), before building
//! a `lettre::Message` or touching an SMTP client -- Direct and RelayOut/External alike. In Direct
//! mode, the same limit is handed to this instance's own `SynapseSmtpServer`
//! (`SmtpServerConfig::max_message_size`), whose `DATA` handler refuses an over-limit body with
//! SMTP `552` before it is parsed or stored (`smtp_server.rs`'s `handle_connection`/
//! `store_message`), and a `max_queued_bytes`-sized semaphore (`SynapseSmtpServer::queue_budget`)
//! gates how many stored-but-undrained bytes may accumulate, the same shape as `tcp_unified.rs`'s
//! `queue_budget` (see that server's own field docs for exactly how bytes are acquired and
//! released, since its store's shape -- a `HashMap` keyed by recipient, shared with
//! `SynapseImapServer` and seeded directly in some tests -- does not carry a queued message's size
//! alongside it the way `tcp_unified.rs`'s `Queued` does).
//!
//! ## The adversarial parsing factor, measured for this transport's actual path
//!
//! `tcp_unified.rs`'s module docs measure `f`, the heap a `SecureMessage` takes while it is parsed
//! and after, per byte of its **serialized JSON**, for a bare `serde_json` parse of the wire
//! bytes. This transport's receive path is not that: Direct mode's `DATA` handler and
//! `poll_imap_inbox` both first parse an RFC 5322 envelope and extract the body (`mail_parser`,
//! reversing whatever transfer encoding `lettre` applied) *before* the `serde_json` parse that
//! actually produces a `SecureMessage` -- an extra pass over the bytes this transport's own
//! `send_message` produced, that TCP's wire format never has. Per this crate's standing
//! discipline (the portfolio's measurement rule: state a measurement with its method, don't assume another
//! transport's number applies), `f` was re-measured for this transport's real pipeline rather than
//! reusing TCP's ≈18/≈12, the same way `http_unified.rs` measured its own connection-buffer
//! overhead instead of assuming TCP's.
//!
//! **Method** (mirrors `tcp_unified.rs`'s): a `GlobalAlloc` wrapper counting live and peak bytes
//! (a reallocation counted as a new block, a copy, and a free, so its transient is in the peak --
//! the same convention `http_unified.rs`'s module docs state), around a release build on Windows.
//! For each of `tcp_unified.rs`'s three representative `SecureMessage` shapes at about 1.4-1.8 MiB
//! of serialized JSON (a `routing_path` of empty strings, one of one-character strings, and
//! `metadata` with short keys), a `lettre::Message` was built exactly as `send_message` builds one
//! (a `SinglePart`, `TEXT_PLAIN`, body the JSON text) and its raw RFC 5322 bytes
//! (`Message::formatted()`) fed through the exact receive-path pipeline: `mail_parser` envelope
//! parse and `body_text(0)` extraction, then `serde_json::from_slice` into a `SecureMessage`. A
//! fourth shape -- one large `encrypted_content` byte array, the size a sender would most
//! naturally reach for, as opposed to the other three's adversarial string/map shapes -- was
//! measured too, as a lower bound. The harness itself (`examples/measure_email_parse_factor.rs` at
//! the time of this measurement) was throwaway, not shipped with the crate, the same as
//! `tcp_unified.rs`'s and `http_unified.rs`'s own measurement code evidently was.
//!
//! **Measured**, relative to the serialized-JSON bytes `max_message_size` counts (the unit this
//! module's size checks use): `routing_path` of empty strings peaked at 13.00x and retained 9.00x;
//! one of one-character strings peaked at 14.69x and retained 10.25x; `metadata` with short keys
//! peaked at 12.65x and retained 9.00x; the large `encrypted_content` shape peaked at 2.12x and
//! retained 1.28x. So take `f` ≈ 15 while parsing and ≈ 10 retained for this transport's own
//! receive path -- the largest factors measured across these four shapes, not proven maxima, and
//! **lower** than TCP's own previously-measured ≈18/≈12 despite the added MIME/RFC822 decoding
//! pass: the dominant cost in both is the same `serde_json` parse of a `Vec<String>`/
//! `HashMap<String, String>` full of small heap allocations, and that cost evidently varies with
//! `serde_json`'s version and the optimizer more than the extra `mail_parser` pass adds on top of
//! it. This is a measured result, not a derivation from TCP's figure -- the direction was not
//! assumed either way before measuring.
//!
//! Direct mode's worst case, using this factor: with `C` inbound connections' `DATA` bodies each
//! bounded during read at `max_message_size + 64 KiB` (`handle_connection`'s `read_cap`, a coarse
//! bound checked against the raw RFC 5322 bytes, looser than the exact check `store_message` makes
//! against the extracted body) and no cap today on how many connections `SynapseSmtpServer::serve`
//! accepts at once (unlike `tcp_unified.rs`'s `connection_permits`), the read-buffer term is
//! unbounded in the number of concurrent connections; only the **queued** term is bounded, at
//! `max_queued_bytes × f` while a batch is parsed (`Bₚ × f`) plus `max_queued_bytes` retained
//! once every stored message is drained and kept (`Bₚ × 12`, using `f` ≈ 10 rounded up to
//! `tcp_unified.rs`'s own retained figure for a conservative shared bound where the two differ).
//! With the default `max_queued_bytes` (40 MiB, [`DEFAULT_MAX_QUEUED_BYTES`]), that is up to
//! 40 MiB × 15 = 600 MiB while a full queue is parsed at once, an upper bound this crate has not
//! needed to defend against with a connection cap the way `tcp_unified.rs` does, since Direct
//! mode's `SynapseSmtpServer` has no `max_concurrent_connections` config key today -- a gap this
//! task does not close (out of scope: the brief asks for `max_message_size`/`max_queued_bytes`
//! and the refusal/backpressure they gate, not a new connection-limiting config key).
//!
//! The single-line-with-no-CRLF gap `handle_connection`'s DATA-loop comment notes (a peer that
//! never sends a newline can still make `read_line` buffer without bound before the loop's own
//! cap is ever checked) is pre-existing to this server's line-oriented command/DATA reader, shared
//! by every command it reads, not introduced or closed by this task.

use super::abstraction::*;
use super::tcp_unified::positive_limit;
use crate::{
    email_server::{
        AuthHandler, ConnectivityDetector, ServerRecommendation, SmtpServerConfig,
        SynapseSmtpServer, security::InboundLimits,
    },
    error::{Result, SynapseError},
    types::{EmailConfig, ImapConfig, SecureMessage, SmtpConfig},
};
use async_trait::async_trait;
use futures::StreamExt;
use lettre::{
    SmtpTransport, Transport as LettreTransport,
    message::{Mailbox, Message, SinglePart, header},
    transport::smtp::authentication::Credentials,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::net::TcpListener;

/// The config key for the largest message, in bytes of serialized JSON, this transport sends and
/// (in Direct mode) its own `SynapseSmtpServer` accepts. Same unit and meaning as
/// `tcp_unified.rs`'s `MAX_MESSAGE_SIZE_KEY`.
pub const MAX_MESSAGE_SIZE_KEY: &str = "max_message_size";

/// The default for [`MAX_MESSAGE_SIZE_KEY`]: 10 MiB of serialized JSON -- the figure
/// `capabilities()` reported before this task, now actually enforced rather than only advertised.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// The config key for how many bytes of received-but-undrained message bodies (Direct mode's
/// `SynapseSmtpServer` store) may accumulate at once. Same unit and meaning as `tcp_unified.rs`'s
/// `MAX_QUEUED_BYTES_KEY`: must be at least [`MAX_MESSAGE_SIZE_KEY`] and at most `u32::MAX`.
pub const MAX_QUEUED_BYTES_KEY: &str = "max_queued_bytes";

/// The default for [`MAX_QUEUED_BYTES_KEY`]: 4x [`DEFAULT_MAX_MESSAGE_SIZE`], the same ratio
/// `tcp_unified.rs` defaults to.
pub const DEFAULT_MAX_QUEUED_BYTES: usize = 4 * DEFAULT_MAX_MESSAGE_SIZE;

/// [`MAX_MESSAGE_SIZE_KEY`]/[`MAX_QUEUED_BYTES_KEY`], parsed and cross-checked exactly as
/// `tcp_unified.rs`'s `Limits::from_config` does: an unparseable or zero value is refused (not
/// defaulted), and `max_queued_bytes` must be at least `max_message_size` (or a message that
/// passed the size check could never be queued) and at most `u32::MAX` (the most one
/// `acquire_many_owned` call can take).
struct EmailLimits {
    max_message_size: usize,
    max_queued_bytes: usize,
    /// Direct mode's per-source inbound limits (hardening P7, audit row 13).
    inbound: InboundLimits,
}

/// The config key for how many connections per minute Direct mode's `SynapseSmtpServer` accepts
/// from one source IP (hardening P7). A positive integer; defaults to `InboundLimits::default()`.
pub const INBOUND_CONNECTIONS_PER_MINUTE_KEY: &str = "email_inbound_connections_per_minute";

/// The config key for how many messages (`MAIL` commands) per minute Direct mode's
/// `SynapseSmtpServer` accepts from one source IP (hardening P7). A positive integer.
pub const INBOUND_MESSAGES_PER_MINUTE_KEY: &str = "email_inbound_messages_per_minute";

/// A positive per-minute limit that fits a `u32`.
fn per_minute_limit(config: &HashMap<String, String>, key: &str, default: u32) -> Result<u32> {
    let limit = positive_limit(config, key, default as usize)?;
    u32::try_from(limit)
        .map_err(|_| SynapseError::Config(format!("{key} ({limit}) must be at most {}", u32::MAX)))
}

impl EmailLimits {
    fn from_config(config: &HashMap<String, String>) -> Result<Self> {
        let max_message_size =
            positive_limit(config, MAX_MESSAGE_SIZE_KEY, DEFAULT_MAX_MESSAGE_SIZE)?;
        let max_queued_bytes =
            positive_limit(config, MAX_QUEUED_BYTES_KEY, DEFAULT_MAX_QUEUED_BYTES)?;
        if max_queued_bytes < max_message_size {
            return Err(SynapseError::Config(format!(
                "{MAX_QUEUED_BYTES_KEY} ({max_queued_bytes}) must be at least \
                 {MAX_MESSAGE_SIZE_KEY} ({max_message_size}), or a message of that size could \
                 never be queued"
            )));
        }
        if u32::try_from(max_queued_bytes).is_err() {
            return Err(SynapseError::Config(format!(
                "{MAX_QUEUED_BYTES_KEY} ({max_queued_bytes}) must be at most {}",
                u32::MAX
            )));
        }
        let defaults = InboundLimits::default();
        let inbound = InboundLimits {
            connections_per_minute: per_minute_limit(
                config,
                INBOUND_CONNECTIONS_PER_MINUTE_KEY,
                defaults.connections_per_minute,
            )?,
            messages_per_minute: per_minute_limit(
                config,
                INBOUND_MESSAGES_PER_MINUTE_KEY,
                defaults.messages_per_minute,
            )?,
            ..defaults
        };
        Ok(Self {
            max_message_size,
            max_queued_bytes,
            inbound,
        })
    }
}

/// Which of the three shapes (module docs) this transport instance is operating in, decided once
/// at construction. `RelayOut` and `External` are kept as separate variants (rather than one
/// `Proxied` variant) to preserve *why* -- useful in logs/metrics -- even though `send_message`
/// and `receive_raw` dispatch on them identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailMode {
    /// Owns an inbound `SynapseSmtpServer`; sends straight to `target.address`.
    Direct,
    /// Can bind locally but not reach the internet directly (behind NAT/firewall): send relays
    /// through the configured smart host, receive polls the configured IMAP mailbox.
    RelayOut,
    /// Cannot bind an inbound listener at all: same send/receive shape as `RelayOut`.
    External,
}

/// The one address validator `can_reach`/`test_connectivity` use: exactly one `@`, a non-empty
/// local part, and a domain containing a `.` with non-empty labels on each side of it. Copied
/// verbatim from the former `email_simple` transport's validator of the same name (since removed)
/// rather than reinvented, since a looser check here (e.g. "just contains `@`") would accept
/// malformed addresses like `"invalid@"` that the old transport correctly refused --
/// `tests/transport_error_handling_test.rs::test_transport_error_handling` exercises exactly this.
fn valid_address(address: &str) -> bool {
    let mut parts = address.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        // More than one '@'.
        return false;
    }
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    domain.contains('.') && domain.split('.').all(|label| !label.is_empty())
}

/// Accepts every SMTP envelope unconditionally. This transport's `SynapseSmtpServer` is a
/// private, single-tenant listener (see module docs): nothing about `MAIL FROM`/`RCPT TO` is ever
/// used for a security or routing decision here, per the Global Constraints (spec §3) that forbid
/// treating SMTP-level identity as meaningful for anything security-relevant. `authenticate` is
/// never reached because `SmtpServerConfig::require_auth` is `false` for Direct mode: real
/// senders on the internet are not expected to authenticate to deliver mail directly, the same as
/// any ordinary receiving mail server.
struct AcceptAllAuthHandler;

impl AuthHandler for AcceptAllAuthHandler {
    fn authenticate(&self, _username: &str, _password: &str) -> Result<bool> {
        Ok(true)
    }

    fn is_authorized_sender(&self, _email: &str) -> Result<bool> {
        Ok(true)
    }

    fn is_authorized_recipient(&self, _email: &str) -> Result<bool> {
        Ok(true)
    }
}

/// Email transport, dispatching `send_message`/`start`/`receive_raw` on [`EmailMode`] (module
/// docs). Direct mode's listener is bound synchronously in [`new`](Self::new), not in
/// [`start`](Self::start): every other transport in this contract (`tcp_unified.rs`'s
/// `start_server` comment documents the bug this avoids) binds its socket during construction so
/// that, by the time `TransportManager` reports this transport `Running`, the port is actually
/// held. `start` only spawns the accept loop over the listener `new` already bound. RelayOut and
/// External modes bind no listener at all (module docs), so `smtp_server`/`listener` stay `None`.
pub struct EmailTransportImpl {
    config: EmailConfig,
    mode: EmailMode,
    /// The largest message, in bytes of serialized JSON, `send_message` will send. Checked before
    /// building any `lettre::Message` or touching an SMTP client (Task 4); in Direct mode this is
    /// also the value `smtp_server`'s own `SmtpServerConfig::max_message_size` enforces, so what is
    /// advertised (`capabilities()`) is what both sides enforce, the same invariant
    /// `tcp_unified.rs`'s module docs state for its own `max_message_size`.
    max_message_size: usize,
    smtp_server: Option<Arc<SynapseSmtpServer>>,
    listener: StdMutex<Option<TcpListener>>,
    /// `message_id`s already delivered by a RelayOut/External poll (module docs) -- unused in
    /// Direct mode, which drains its own store instead.
    imap_seen_ids: StdMutex<SeenIds>,
    /// Where the last IMAP poll stopped: the mailbox's UIDVALIDITY and the next UID to ask for, so
    /// a poll fetches only what arrived since and its cost does not grow with the mailbox.
    imap_cursor: StdMutex<ImapCursor>,
    /// Real counter: incremented only where an IMAP-fetched body actually failed to parse as a
    /// `SecureMessage` (module docs).
    receive_failures: AtomicU64,
    /// Real counter, incremented once per successful `send_message` (i.e. `LettreTransport::send`
    /// actually returned `Ok`) -- never on a local refusal (oversized message, bad address, no
    /// `smtp_host` configured), matching `quic_unified.rs`'s convention of only counting
    /// network-touching outcomes.
    messages_sent: AtomicU64,
    /// Bytes of serialized `SecureMessage` JSON sent, incremented alongside `messages_sent`. Same
    /// unit `max_message_size` counts.
    bytes_sent: AtomicU64,
    /// Incremented only when the real SMTP send (`LettreTransport::send`) itself fails -- never on
    /// a local refusal that never touched the network (see `messages_sent`'s doc).
    send_failures: AtomicU64,
    /// Real counter, incremented once per `SecureMessage` actually handed to a caller's inbox by
    /// `receive_raw` (Direct's drain or an IMAP fetch that parsed and was not a duplicate).
    messages_received: AtomicU64,
    /// Bytes of serialized `SecureMessage` JSON received, incremented alongside
    /// `messages_received`.
    bytes_received: AtomicU64,
    /// Running sum of `send_message`'s own `start.elapsed()` (constructor to the real SMTP `Ok`
    /// return, mirroring `tcp_unified.rs`'s `total_time`) for every send counted in
    /// `messages_sent`, in milliseconds. `metrics()` divides this by `messages_sent` to report a
    /// genuine, real running average -- not an invented constant (Global Constraints).
    latency_sum_ms: AtomicU64,
}

impl EmailTransportImpl {
    pub async fn new(config: &HashMap<String, String>) -> Result<Self> {
        let local_port: u16 = config
            .get("local_port")
            .map(|p| p.parse())
            .transpose()
            .map_err(|_| SynapseError::Config("invalid local_port: must be a u16".to_string()))?
            .unwrap_or(0);
        let bind_scope = crate::network_scope::BindScope::from_config_map(config)?;

        let email_config = Self::email_config_from_map(config)?;
        let mode = Self::determine_mode(config, bind_scope).await?;
        let EmailLimits {
            max_message_size,
            max_queued_bytes,
            inbound,
        } = EmailLimits::from_config(config)?;

        let (smtp_server, listener) = if mode == EmailMode::Direct {
            let bind_addr = bind_scope.listen_addr(local_port);
            let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
                SynapseError::NetworkError(format!(
                    "failed to bind email transport's SMTP server to {bind_addr}: {e}"
                ))
            })?;

            let auth_handler: Arc<dyn AuthHandler + Send + Sync> = Arc::new(AcceptAllAuthHandler);
            let message_store = Arc::new(StdMutex::new(HashMap::new()));
            let smtp_server = SynapseSmtpServer::new(
                SmtpServerConfig {
                    port: local_port,
                    bind_scope,
                    // Direct mode receives mail addressed to us from arbitrary senders on the
                    // internet, the same as any ordinary mail server -- it does not require SMTP
                    // AUTH from them. SMTP AUTH governs *relay-out submission* (RelayOut/External
                    // modes), never inbound delivery, and per the Global Constraints must never
                    // stand in for sender identity either way.
                    require_auth: false,
                    // What `capabilities()` advertises is what this server enforces (Task 4): see
                    // `max_message_size`'s field doc.
                    max_message_size,
                    max_queued_bytes,
                    ..Default::default()
                },
                auth_handler,
                message_store,
            );
            let smtp_server = Arc::new(smtp_server.with_inbound_limits(inbound));
            (Some(smtp_server), Some(listener))
        } else {
            // RelayOut/External: no inbound listener (module docs) -- send relays through
            // `email_config.smtp`, receive polls `email_config.imap`.
            (None, None)
        };

        Ok(Self {
            config: email_config,
            mode,
            max_message_size,
            smtp_server,
            listener: StdMutex::new(listener),
            imap_seen_ids: StdMutex::new(SeenIds::new(SEEN_IDS_CAP)),
            imap_cursor: StdMutex::new(ImapCursor::default()),
            receive_failures: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            send_failures: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
        })
    }

    /// `config`'s `email_mode` key, if present, names the mode directly (`"direct"`/
    /// `"relay_out"`/`"external"`) and skips connectivity detection entirely -- see the module
    /// docs for why (determinism in tests; an operator who already knows their network shape).
    ///
    /// Absent that override, `bind_scope` decides whether detection can say anything useful at
    /// all: `ConnectivityDetector::detect_external_ip` (spec: `network_scope.rs` module docs) is
    /// switched off entirely under `BindScope::Loopback`, so a real assessment there can *never*
    /// recommend `RunLocalServer` (`connectivity.rs`'s `determine_recommendation` has no arm that
    /// reaches it without `external_ip: Some`) -- it would always force RelayOut/External, which
    /// would silently break every loopback deployment, including Task 1's own established
    /// contract (`docs/superpowers/specs/2026-09-24-email-transport-design.md`'s Direct-mode
    /// loopback tests, e.g. `tests/transport_repairs.rs::email_direct_mode_carries_a_verified_message_end_to_end`).
    /// So `BindScope::Loopback` keeps defaulting to `Direct` without invoking the detector; only
    /// `BindScope::AllInterfaces` (a real, off-box deployment, where external-IP detection
    /// actually runs) calls [`ConnectivityDetector::assess_connectivity`] and maps its
    /// [`ServerRecommendation`] onto [`EmailMode`].
    async fn determine_mode(
        config: &HashMap<String, String>,
        bind_scope: crate::network_scope::BindScope,
    ) -> Result<EmailMode> {
        if let Some(forced) = config.get("email_mode") {
            return match forced.as_str() {
                "direct" => Ok(EmailMode::Direct),
                "relay_out" => Ok(EmailMode::RelayOut),
                "external" => Ok(EmailMode::External),
                other => Err(SynapseError::Config(format!(
                    "email_mode must be \"direct\", \"relay_out\" or \"external\", not {other:?}"
                ))),
            };
        }

        if !bind_scope.is_all_interfaces() {
            return Ok(EmailMode::Direct);
        }

        let assessment = ConnectivityDetector::default()
            .with_bind_scope(bind_scope)
            .assess_connectivity()
            .await?;
        Ok(match assessment.recommended_config {
            ServerRecommendation::RunLocalServer { .. } => EmailMode::Direct,
            ServerRecommendation::RelayOnly { .. } => EmailMode::RelayOut,
            ServerRecommendation::ExternalProvider { .. } => EmailMode::External,
        })
    }

    /// Build `EmailConfig` from the factory's `HashMap<String, String>` config, the same shape
    /// every other `_unified.rs` factory takes. All keys are optional in Task 1: Direct mode sends
    /// straight to `target.address`, needing no configured SMTP account, and does not use IMAP at
    /// all, so nothing here is load-bearing yet. They exist so a later task's relay/proxy modes
    /// can populate the same `EmailConfig` without a second, separate parsing path. Config keys:
    /// `smtp_host`, `smtp_port` (default 25), `smtp_username`, `smtp_password`, `smtp_use_tls`,
    /// `smtp_use_ssl`, `imap_host`, `imap_port` (default 143), `imap_username`, `imap_password`,
    /// `imap_use_ssl`.
    fn email_config_from_map(config: &HashMap<String, String>) -> Result<EmailConfig> {
        fn optional(config: &HashMap<String, String>, key: &str) -> String {
            config.get(key).cloned().unwrap_or_default()
        }
        fn port(config: &HashMap<String, String>, key: &str, default: u16) -> Result<u16> {
            match config.get(key) {
                None => Ok(default),
                Some(v) if v.is_empty() => Ok(default),
                Some(v) => v.parse().map_err(|_| {
                    SynapseError::Config(format!("{key} must be a valid port number"))
                }),
            }
        }
        fn flag(config: &HashMap<String, String>, key: &str) -> bool {
            config.get(key).map(|v| v == "true").unwrap_or(false)
        }

        Ok(EmailConfig {
            smtp: SmtpConfig {
                host: optional(config, "smtp_host"),
                port: port(config, "smtp_port", 25)?,
                username: optional(config, "smtp_username"),
                password: crate::types::SecretString::new(optional(config, "smtp_password")),
                use_tls: flag(config, "smtp_use_tls"),
                use_ssl: flag(config, "smtp_use_ssl"),
            },
            imap: ImapConfig {
                host: optional(config, "imap_host"),
                port: port(config, "imap_port", 143)?,
                username: optional(config, "imap_username"),
                password: crate::types::SecretString::new(optional(config, "imap_password")),
                use_ssl: flag(config, "imap_use_ssl"),
            },
        })
    }

    /// Split `host:port` out of a [`TransportTarget`]'s address, the peer's SMTP server for
    /// Direct-mode delivery. Direct mode has no other source for this: there is no configured
    /// smart host to fall back to (see module docs), so a target with no address, or a malformed
    /// one, is refused rather than silently guessing a host.
    fn target_smtp_addr(target: &TransportTarget) -> Result<(String, u16)> {
        let addr = target.address.as_ref().ok_or_else(|| {
            SynapseError::TransportError(format!(
                "email Direct mode needs target.address (host:port of the recipient's SMTP \
                 server); {} has none",
                target.identifier
            ))
        })?;
        let (host, port_str) = addr.rsplit_once(':').ok_or_else(|| {
            SynapseError::TransportError(format!("email target address {addr:?} is not host:port"))
        })?;
        let port: u16 = port_str.parse().map_err(|_| {
            SynapseError::TransportError(format!(
                "email target address {addr:?} has an invalid port"
            ))
        })?;
        Ok((host.to_string(), port))
    }
}

#[async_trait]
impl Transport for EmailTransportImpl {
    fn transport_type(&self) -> TransportType {
        TransportType::Email
    }

    /// Direct mode's own `SynapseSmtpServer` records its inbound limits' events here (hardening
    /// P7). RelayOut and External bind no listener, so they have nothing to record.
    fn attach_security_sink(&self, sink: Arc<dyn crate::security_events::SecuritySink>) {
        if let Some(server) = &self.smtp_server {
            server.set_security_sink(sink);
        }
    }

    fn capabilities(&self) -> TransportCapabilities {
        // `features` names the mode actually in effect, not a placeholder.
        let features = match self.mode {
            EmailMode::Direct => vec!["direct_smtp".to_string()],
            EmailMode::RelayOut => vec!["relay_smtp".to_string(), "imap_poll".to_string()],
            EmailMode::External => vec!["external_smtp".to_string(), "imap_poll".to_string()],
        };
        TransportCapabilities {
            max_message_size: self.max_message_size,
            reliable: true,
            real_time: false,
            broadcast: false,
            bidirectional: true,
            encrypted: self.config.smtp.use_tls || self.config.smtp.use_ssl,
            network_spanning: true,
            supported_urgencies: vec![MessageUrgency::Background, MessageUrgency::Batch],
            features,
            // Both `reliability_score` (from real messages_sent/send_failures counters) and
            // `average_latency_ms` (a real running average of send_message's own elapsed time,
            // see `latency_sum_ms`'s field doc) are backed by real measurements for this
            // transport in every mode, so nothing is declared unmeasured here -- unlike QUIC,
            // which never samples latency at all. `send_message` still only ever returns
            // `DeliveryConfirmation::Sent` (a `250 OK` from one SMTP hop, not end-to-end
            // delivery); nothing here claims otherwise.
            unmeasured_metrics: vec![],
        }
    }

    async fn can_reach(&self, target: &TransportTarget) -> bool {
        valid_address(&target.identifier)
    }

    async fn estimate_metrics(&self, target: &TransportTarget) -> Result<TransportEstimate> {
        let available = self.can_reach(target).await;
        Ok(TransportEstimate {
            latency: std::time::Duration::from_secs(5),
            reliability: if available { 0.5 } else { 0.0 },
            bandwidth: 0,
            cost: 0.1,
            available,
            confidence: 0.3,
        })
    }

    async fn send_message(
        &self,
        target: &TransportTarget,
        message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        let start = std::time::Instant::now();
        let to_email = &target.identifier;

        // Whole SecureMessage as JSON -- never hand-picked fields (Global Constraints, spec §4).
        let body = serde_json::to_vec(message)
            .map_err(|e| SynapseError::TransportError(format!("serialize failed: {e}")))?;

        // Refuse before building a `lettre::Message` or touching an SMTP client (Direct and
        // RelayOut/External alike), the same as `tcp_unified.rs`'s `connect_and_send`: writing a
        // message a receiver with this limit would drop is not a "Sent" this transport may claim.
        if body.len() > self.max_message_size {
            return Err(SynapseError::MessageRefused(format!(
                "email message {} serializes to {} bytes, over this transport's {} of {} bytes \
                 (serialized JSON); a receiver with that limit would drop it",
                message.message_id.0,
                body.len(),
                MAX_MESSAGE_SIZE_KEY,
                self.max_message_size
            )));
        }

        let from_mailbox: Mailbox = "synapse-agent@localhost"
            .parse()
            .map_err(|e| SynapseError::TransportError(format!("invalid from address: {e}")))?;
        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| SynapseError::TransportError(format!("invalid to address: {e}")))?;

        let email = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject("Synapse")
            .singlepart(
                SinglePart::builder()
                    .header(header::ContentType::TEXT_PLAIN)
                    .body(String::from_utf8_lossy(&body).into_owned()),
            )
            .map_err(|e| SynapseError::TransportError(format!("build failed: {e}")))?;

        let smtp_client = match self.mode {
            EmailMode::Direct => {
                // Connect straight to the target's own SMTP server (its address, not a configured
                // smart host -- see module docs), unauthenticated, no TLS. `builder_dangerous` is
                // lettre's name for "plain SMTP, no implicit TLS wrapping" -- appropriate here
                // since our own `SynapseSmtpServer` speaks plain SMTP with no STARTTLS support.
                let (host, port) = Self::target_smtp_addr(target)?;
                SmtpTransport::builder_dangerous(&host).port(port).build()
            }
            EmailMode::RelayOut | EmailMode::External => {
                // No direct route to the target (module docs): relay through the configured smart
                // host/external provider instead. SMTP AUTH here governs who may submit to that
                // relay -- never a claim about the sender's identity, which is the
                // `SecureMessage` signature alone (Global Constraints, spec §3).
                if self.config.smtp.host.is_empty() {
                    return Err(SynapseError::TransportError(
                        "email RelayOut/External mode needs a configured smtp_host".to_string(),
                    ));
                }
                let mut builder = SmtpTransport::builder_dangerous(&self.config.smtp.host)
                    .port(self.config.smtp.port);
                if !self.config.smtp.username.is_empty() {
                    builder = builder.credentials(Credentials::new(
                        self.config.smtp.username.clone(),
                        self.config.smtp.password.expose().to_string(),
                    ));
                }
                builder.build()
            }
        };

        // Only a real, network-touching outcome moves `messages_sent`/`send_failures` (module
        // docs on the fields themselves): everything above this point (size check, address
        // parsing, message building, missing smtp_host) is a local refusal that never reached the
        // network and is deliberately not counted here, matching `quic_unified.rs`'s convention
        // of only counting failures from an actual connect/write attempt.
        if let Err(e) = LettreTransport::send(&smtp_client, &email) {
            self.send_failures.fetch_add(1, Ordering::Relaxed);
            return Err(SynapseError::TransportError(format!(
                "SMTP send failed: {e}"
            )));
        }

        let elapsed = start.elapsed();
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        self.latency_sum_ms
            .fetch_add(elapsed.as_millis() as u64, Ordering::Relaxed);

        Ok(DeliveryReceipt {
            message_id: message.message_id.0.to_string(),
            transport_used: TransportType::Email,
            delivery_time: elapsed,
            target_reached: to_email.clone(),
            confirmation: DeliveryConfirmation::Sent,
            metadata: HashMap::new(),
        })
    }

    async fn test_connectivity(&self, target: &TransportTarget) -> Result<ConnectivityResult> {
        Ok(ConnectivityResult {
            connected: self.can_reach(target).await,
            rtt: None,
            error: None,
            quality: 0.5,
            details: HashMap::new(),
        })
    }

    async fn start(&self) -> Result<()> {
        match self.mode {
            EmailMode::Direct => {
                let listener = self.listener.lock().unwrap().take().ok_or_else(|| {
                    SynapseError::TransportError("email transport already started".to_string())
                })?;
                let server = Arc::clone(self.smtp_server.as_ref().ok_or_else(|| {
                    SynapseError::TransportError(
                        "email transport in Direct mode has no SynapseSmtpServer (bug)".to_string(),
                    )
                })?);
                tokio::spawn(async move {
                    if let Err(e) = server.serve(listener).await {
                        tracing::warn!("email SMTP server error: {e}");
                    }
                });
            }
            EmailMode::RelayOut | EmailMode::External => {
                // No inbound listener to run (module docs): sending relays out per-call, and
                // receiving polls IMAP per-call from `receive_raw`. Nothing to spawn here.
            }
        }
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        Ok(())
    }

    async fn status(&self) -> TransportStatus {
        TransportStatus::Running
    }

    async fn metrics(&self) -> TransportMetrics {
        let messages_sent = self.messages_sent.load(Ordering::Relaxed);
        let send_failures = self.send_failures.load(Ordering::Relaxed);
        let attempts = messages_sent + send_failures;
        // QUIC's exact formula (Global Constraints): an untried transport claims perfect
        // reliability rather than zero, since there is no evidence either way yet.
        let reliability_score = if attempts == 0 {
            1.0
        } else {
            messages_sent as f64 / attempts as f64
        };
        // A genuine running average of real send_message timings (latency_sum_ms's field doc),
        // never an invented constant. Zero sends means zero average (`checked_div` covers it),
        // not a guess.
        let average_latency_ms = self
            .latency_sum_ms
            .load(Ordering::Relaxed)
            .checked_div(messages_sent)
            .unwrap_or(0);
        TransportMetrics {
            transport_type: TransportType::Email,
            messages_sent,
            messages_received: self.messages_received.load(Ordering::Relaxed),
            send_failures,
            receive_failures: self.receive_failures.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            reliability_score,
            average_latency_ms,
            // This transport holds no persistent connection or pool in any mode: the SMTP client
            // (`SmtpTransport::builder_dangerous(..).build()`, `send_message` above) and the IMAP
            // session (`async_imap::Client::new(stream)`, `receive_raw` below) are both constructed
            // fresh per call. So `active_connections: 0` is an explicit, measured true count, not a
            // default standing in for one -- verified rather than left to `..Default::default()`,
            // since a correct value reached by accident is one refactor away from becoming wrong.
            // `SynapseSmtpServer.clients` (Direct mode's inbound side) is a field that is
            // constructed but never populated anywhere (no `.insert`/`.remove` calls exist on it) --
            // dead state that reads empty forever. Do not mistake it for a connection source: wiring
            // `active_connections` to `clients.len()` would look like connecting an unmeasured field
            // to real data, but since `clients` is never populated it would just turn this honest,
            // correct `0` into a fabricated-looking one.
            active_connections: 0,
            ..Default::default()
        }
    }
}

#[async_trait]
impl TransportReceive for EmailTransportImpl {
    async fn receive_raw(&self, inbox: &mut RawInbox) -> Result<()> {
        match self.mode {
            EmailMode::Direct => {
                // Drain our own SMTP server's whole message store. There is no configured local
                // recipient address to filter by (module docs); this instance is single-tenant,
                // so everything that landed here is ours.
                let smtp_server = self.smtp_server.as_ref().ok_or_else(|| {
                    SynapseError::TransportError(
                        "email transport in Direct mode has no SynapseSmtpServer (bug)".to_string(),
                    )
                })?;
                let messages = smtp_server.drain_all_messages()?;
                for secure_message in messages {
                    // Same unit `bytes_sent` counts (serialized JSON): re-serializing here is the
                    // only way to know how many bytes this particular message was, since
                    // `drain_all_messages` hands back the parsed `SecureMessage`, not its wire
                    // bytes.
                    let bytes = serde_json::to_vec(&secure_message)
                        .map(|v| v.len() as u64)
                        .unwrap_or(0);
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
                    inbox.push(IncomingMessage::new(
                        secure_message,
                        TransportType::Email,
                        "smtp".to_string(),
                    ));
                }
                Ok(())
            }
            EmailMode::RelayOut | EmailMode::External => self.poll_imap_inbox(inbox).await,
        }
    }
}

impl EmailTransportImpl {
    /// RelayOut/External receive (module docs): log in to the configured IMAP mailbox, select
    /// `INBOX`, fetch every message and parse each one as a `SecureMessage` -- same wire format as
    /// the SMTP path (`serde_json`, after stripping the RFC 5322 envelope with `mail_parser` the
    /// same way `smtp_server.rs`'s `handle_connection` does for its DATA body). A body that does
    /// not parse increments `receive_failures` and is skipped, not fatal to the poll (matches
    /// `nat_traversal.rs`'s `receive_raw` handling of an unparseable UDP datagram). A message
    /// already delivered on an earlier poll (tracked by `imap_seen_ids`) is skipped silently, not
    /// counted as a failure.
    async fn poll_imap_inbox(&self, inbox: &mut RawInbox) -> Result<()> {
        let imap = &self.config.imap;
        let addr = (imap.host.as_str(), imap.port);
        let stream = tokio::net::TcpStream::connect(addr).await.map_err(|e| {
            SynapseError::TransportError(format!(
                "IMAP connect to {}:{} failed: {e}",
                imap.host, imap.port
            ))
        })?;

        let client = async_imap::Client::new(stream);
        let mut session = client
            .login(&imap.username, imap.password.expose())
            .await
            .map_err(|(e, _client)| {
                SynapseError::TransportError(format!("IMAP login failed: {e}"))
            })?;

        let mailbox = session
            .select("INBOX")
            .await
            .map_err(|e| SynapseError::TransportError(format!("IMAP SELECT INBOX failed: {e}")))?;

        // Ask only for UIDs from the cursor on. A server that reports no UIDNEXT or UIDVALIDITY gets
        // the old whole-mailbox FETCH, de-duplicated below. A changed UIDVALIDITY means the old UIDs
        // mean nothing: start over (the de-duplication still keeps a message from arriving twice).
        // The std guard is dropped before any await: this future must stay Send.
        let (nothing_new, from_uid) = {
            let mut cursor = self.imap_cursor.lock().unwrap();
            if cursor.validity != mailbox.uid_validity {
                *cursor = ImapCursor {
                    validity: mailbox.uid_validity,
                    next_uid: 1,
                };
            }
            match mailbox.uid_next {
                Some(uid_next) if uid_next <= cursor.next_uid => (true, None),
                Some(_) => (false, Some(cursor.next_uid)),
                None => (false, None),
            }
        };
        if nothing_new {
            if let Err(e) = session.logout().await {
                tracing::debug!("IMAP LOGOUT failed (non-fatal): {e}");
            }
            return Ok(());
        }
        let mut highest_uid = 0u32;

        // No SEARCH support to ask for UNSEEN (module docs): fetch everything, de-dupe below.
        // Scoped in its own block so the mutable borrow `fetch_stream` holds on `session` (via
        // `std::pin::pin!`'s hidden local, which otherwise lives to the end of this function) ends
        // before `session.logout()` below needs its own `&mut session`.
        {
            type FetchResult =
                std::result::Result<async_imap::types::Fetch, async_imap::error::Error>;
            let fetch_failed = |e: async_imap::error::Error| {
                SynapseError::TransportError(format!("IMAP FETCH failed: {e}"))
            };
            let fetch_stream: std::pin::Pin<
                Box<dyn futures_util::Stream<Item = FetchResult> + Send + '_>,
            > = match from_uid {
                Some(uid) => Box::pin(
                    session
                        .uid_fetch(format!("{uid}:*"), "(UID RFC822)")
                        .await
                        .map_err(fetch_failed)?,
                ),
                None => Box::pin(session.fetch("1:*", "RFC822").await.map_err(fetch_failed)?),
            };
            let mut fetch_stream = std::pin::pin!(fetch_stream);

            while let Some(fetch_result) = fetch_stream.next().await {
                let fetch = match fetch_result {
                    Ok(fetch) => fetch,
                    Err(e) => {
                        self.receive_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("IMAP FETCH response did not parse: {e}");
                        continue;
                    }
                };
                // `n:*` always names the last message, even when it is older than `n`.
                if let (Some(from), Some(uid)) = (from_uid, fetch.uid) {
                    if uid < from {
                        continue;
                    }
                    highest_uid = highest_uid.max(uid);
                }
                let Some(raw) = fetch.body() else {
                    continue;
                };

                // Same extraction as `smtp_server.rs`'s DATA handler: strip the RFC 5322 envelope
                // and reverse whatever transfer encoding `lettre` applied, rather than assuming
                // the body starts unencoded right after the first blank line.
                let body = mail_parser::MessageParser::default()
                    .parse(raw)
                    .and_then(|parsed| {
                        parsed
                            .body_text(0)
                            .map(|text| text.into_owned().into_bytes())
                    })
                    .unwrap_or_else(|| raw.to_vec());

                let secure_message: SecureMessage = match serde_json::from_slice(&body) {
                    Ok(message) => message,
                    Err(e) => {
                        self.receive_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "IMAP message did not parse as a SecureMessage: {} bytes, {e}",
                            body.len()
                        );
                        continue;
                    }
                };

                let already_delivered = {
                    let mut seen = self.imap_seen_ids.lock().unwrap();
                    !seen.insert(secure_message.message_id.0)
                };
                if already_delivered {
                    continue;
                }

                self.messages_received.fetch_add(1, Ordering::Relaxed);
                self.bytes_received
                    .fetch_add(body.len() as u64, Ordering::Relaxed);
                inbox.push(IncomingMessage::new(
                    secure_message,
                    TransportType::Email,
                    "imap".to_string(),
                ));
            }
        }

        if highest_uid > 0 {
            let mut cursor = self.imap_cursor.lock().unwrap();
            cursor.next_uid = cursor.next_uid.max(highest_uid + 1);
        }
        if let Err(e) = session.logout().await {
            tracing::debug!("IMAP LOGOUT failed (non-fatal): {e}");
        }
        Ok(())
    }
}

/// How many delivered `message_id`s a transport remembers. Past it the oldest are forgotten, so a
/// long-running daemon's memory stays flat; a forgotten id can only matter to a message the cursor
/// would fetch again, and the replay guard above this transport drops a stale one anyway.
const SEEN_IDS_CAP: usize = 10_000;

/// A bounded set of ids, oldest evicted first.
struct SeenIds {
    cap: usize,
    order: std::collections::VecDeque<uuid::Uuid>,
    set: HashSet<uuid::Uuid>,
}

impl SeenIds {
    fn new(cap: usize) -> Self {
        SeenIds {
            cap: cap.max(1),
            order: std::collections::VecDeque::new(),
            set: HashSet::new(),
        }
    }

    /// `true` when `id` was not already present. Inserting past the cap evicts the oldest.
    fn insert(&mut self, id: uuid::Uuid) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        true
    }
}

/// Where the last IMAP poll stopped (see `EmailTransportImpl::imap_cursor`).
#[derive(Default)]
struct ImapCursor {
    validity: Option<u32>,
    /// The next UID to ask for; 0 until the first poll sets it.
    next_uid: u32,
}

pub struct EmailTransportFactory;

#[async_trait]
impl TransportFactory for EmailTransportFactory {
    async fn create_transport(
        &self,
        config: &HashMap<String, String>,
    ) -> Result<Box<dyn Transport>> {
        Ok(Box::new(EmailTransportImpl::new(config).await?))
    }

    fn transport_type(&self) -> TransportType {
        TransportType::Email
    }

    fn default_config(&self) -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert(
            MAX_MESSAGE_SIZE_KEY.to_string(),
            DEFAULT_MAX_MESSAGE_SIZE.to_string(),
        );
        config.insert(
            MAX_QUEUED_BYTES_KEY.to_string(),
            DEFAULT_MAX_QUEUED_BYTES.to_string(),
        );
        config
    }

    fn validate_config(&self, config: &HashMap<String, String>) -> Result<()> {
        // The same check `new` applies (via `EmailTransportImpl::new`'s own
        // `EmailLimits::from_config` call), so validating and constructing cannot disagree --
        // mirrors `tcp_unified.rs`'s `TcpTransportFactory::validate_config`.
        EmailLimits::from_config(config)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SeenIds;

    #[test]
    fn the_seen_set_is_bounded_and_forgets_the_oldest_first() {
        let ids: Vec<uuid::Uuid> = (0..5).map(|_| uuid::Uuid::new_v4()).collect();
        let mut seen = SeenIds::new(3);
        for id in &ids[..3] {
            assert!(seen.insert(*id), "new");
        }
        assert!(!seen.insert(ids[0]), "a repeat inside the cap is a repeat");
        assert!(seen.insert(ids[3]), "a fourth evicts ids[0]");
        assert_eq!(
            (seen.order.len(), seen.set.len()),
            (3, 3),
            "the size stays at the cap"
        );
        assert!(
            seen.insert(ids[0]),
            "the oldest was forgotten, so it counts as new again"
        );
        assert!(!seen.insert(ids[3]), "a recent one is still remembered");
        assert!(seen.insert(ids[4]));
        assert!(seen.set.len() <= 3);
    }
}
