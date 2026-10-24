# QUIC pool eviction on verification failure: design (#49, spec condition 3)

Status: design, no code. 2026-10-24, read against `origin/main` 033f399 (6.0.0-rc.149). Parent:
`docs/superpowers/specs/2026-09-22-quic-transport-design.md` section 3, condition 3: *any application-layer
verification failure on a message received over a pooled connection evicts that pool entry.* Issue #49.

## The gap
`QuicTransportImpl::evict(addr)` (`src/transport/quic_unified.rs`) closes and drops a pooled connection and is tested
(`tests/transport_repairs.rs`, `quic_evict_drops_the_pooled_connection_and_the_next_send_reopens_one`). Nothing in
production calls it. Verification happens in `TransportManager::receive_messages` (`src/transport/manager.rs`), which
holds `Box<dyn Transport>` and knows nothing of QUIC. Severity as in the issue: sealing and signing rule out disclosure
and forgery, so this is silent misdelivery to a stale address after a NAT rebind or address reuse, not a security hole.

## Design
1. **A hook on `Transport`**, default no-op, so no existing or downstream implementor breaks:
   `async fn on_verification_failure(&self, source: &str, reason: VerificationFailure) {}`.
   `VerificationFailure` is a small `#[non_exhaustive]` enum: `Rejected` (the admission step refused the verdict,
   where the manager already calls `events.knock`) and `Unopenable` (sealing could not be opened, where it already
   calls `events.unopenable`). It carries no message and no key, only the kind.
2. **One call site pair in the manager**, from those two existing points. The loop holds the `transports`, trust-store
   and `inbound` guards, and `QuicTransportImpl::evict` takes the pool lock itself (the comment at
   `quic_unified.rs:825` records the deadlock it would cause if called under that lock). So the manager only
   *records* `(transport_type, source, kind)` in the loop and calls the hooks after it drops its guards, as it already
   does for `relayed_revocations`.
3. **QUIC implements the hook**: parse `source` back to a `SocketAddr`; if it parses and is pooled, `evict` it; a
   `source` that does not parse is ignored (logged at debug).
4. **Bounded effect.** Eviction costs one reconnect. A sender able to push bad messages down a pooled connection could
   make us reconnect repeatedly, so the hook evicts at most once per address per `evict_cooldown` (default 5 s). The
   next send after an eviction reopens the connection, which is the behaviour the existing test pins.

## What counts as a failure (open call 1)
Recommended: only `Rejected` and `Unopenable`. An `Unverified` verdict (sender not pinned) says the trust store lacks
the sender, nothing about the connection, and must not evict.

## Other transports (open call 2)
The default is a no-op, so TCP, UDP, WebSocket, HTTP, NAT traversal, email, mDNS and discovery change nothing. A
survey of which of them keep per-peer connection state that could go stale is slice 3; this spec makes no claim
about them.

## Slices (each red-first)
1. Trait hook + `VerificationFailure` + the manager records and fires after the guards drop. Test: a recording
   transport sees exactly one call per rejected message and none for a verified or unverified one.
2. QUIC implementation + cooldown. Test: a rejected message on a pooled connection evicts it and the next send reopens
   one; a second rejection inside the cooldown does not evict again.
3. Survey of the other transports; one issue per transport that needs it.

Each bumps the version; the PM allocates numbers.

## Open calls
1. Which verdicts evict (recommendation above).
2. Whether slice 3 is wanted now or only when a second transport shows the problem.
