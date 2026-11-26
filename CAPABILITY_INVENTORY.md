# Synapse — Measured Capability Inventory

**Measured 2026-09-09** against `main` @ `f0f570c` (verified current: `git rev-parse main` ==
`git ls-remote origin main`, 0 commits behind), on `rustc 1.100.0-nightly (cea272fa3, 2026-09-07)`,
`cargo 1.100.0-nightly`, host `x86_64-pc-windows-msvc`.

> **Note (rc.57, 2026-10-14):** this inventory is a measurement at the ref above and is not rewritten. Since then the eight
> completion/audit reports it cites by bare name moved to `docs/archive/`, and the four 0-byte root files it lists
> (`WINDOWS_LINKER_WORKAROUND.md`, `build-debug.ps1`, `test-build.ps1`, `err.txt`) and `docs/STREAMING_SUPPORT.md` were deleted.

Every number below is the output of a command that was run. Where I state an absence, I state the
positive control that proves the query could have found something. Nothing here is inferred from a
document, a filename, or a commit message.

**Read this before the README.** The README is marketing copy, not a specification; §6 lists the
specific properties it asserts that the code has never had.

---

## 0. The one-line summary

At `f0f570c`, **no invocation of cargo in this repository succeeded — in any feature
configuration.** Not `build`, not `check`, not `test`, not `clippy`. The repo did not reach the
compiler. Two defects caused this; both are now fixed, and the library builds and 102 tests run.

| | at `f0f570c` | now |
|---|---|---|
| `cargo check --lib` (default features) | **fails at dependency resolution** | **EXIT 0** |
| `cargo test` | **fails at dependency resolution** | **106 tests, 105 pass, 1 fail** (and now runs in CI) |
| feature configurations that resolve | **0 of 10** | 10 of 10 |
| feature configurations that compile | **0 of 10** | **1 of 10** (`native` only — see §3) |

**And the question nothing in the repository answers — does a message actually get from A to B?** No
test sends one over a socket, so I ran the probes myself (§2.2):

| | result |
|---|---|
| **UDP round trip** | ✅ **DELIVERS** — payload intact, ~1 ms, via the factory path with `bind_port` set |
| **TCP round trip** | 🔴 **SILENTLY DROPS** — `send_message` returns `Ok(confirmation: Sent)`; nothing ever arrives |
| **WebSocket** | ✅ **DELIVERS** over loopback — a sealed, signed message arrives `Verified` and opens intact; the receipt claims `Sent` (transport contract PR B, Task 8) |
| **HTTP** | ✅ **DELIVERS** over loopback — a sealed, signed message arrives `Verified` and opens intact; the receipt claims `Delivered`, because the receiver answers `2xx` only once the message is in its queue (transport contract PR B, Task 9) |
| **QUIC** | 🔴 **simulation** — binds nothing, fabricates connections with a hardcoded RTT |

> **Status, 2026-09-18, PR A of the transport contract (PR #44, on `main` as `b6a1904`):** QUIC — **deleted**: `quic_unified.rs` is gone and
> `QuicTransportFactory` refuses to construct until the QUIC slice. PR A made WebSocket's
> `send_message` refuse instead of claiming a delivery; PR B, Task 8 repaired it (below). The TCP
> and UDP rows are unchanged by PR A.

> **Status, 2026-09-23, the QUIC slice (branch `design/quic-transport`, not yet on `main`):** QUIC —
> **DELIVERS** over loopback, a real `quinn`-backed implementation this time: a sealed, signed
> message arrives `Verified` and opens intact (`quic_carries_a_verified_message_end_to_end`); the
> receipt claims `Sent`, never `Delivered` (spec §4 — QUIC has no synchronous request/response the
> way HTTP does, and delivery confirmation stays `delivery_ack.rs`'s job, transport-agnostic, unlike
> the old simulation's fabricated `Delivered`). Self-signed TLS, connections pooled and reused per
> peer with multiplexed streams, 0-RTT explicitly disabled, honest `capabilities()`/`metrics()`
> replacing the old aspirational preset. Staged as 5 reviewed tasks; see
> `docs/superpowers/specs/2026-09-22-quic-transport-design.md` and
> `docs/superpowers/plans/2026-09-22-quic-transport.md`.
>
> **One known gap, not fixed here:** a misdirected pooled connection (NAT rebinding, address reuse)
> is supposed to self-heal by evicting on the next application-layer verification failure (spec §3
> condition 3) — the eviction method exists and is directly tested, but nothing calls it yet,
> because `TransportManager` has no way to reach a concrete `QuicTransportImpl` to invoke it.
> Not a confidentiality or spoofing hole (sealing/signing already rule those out) — the cost is
> silent, indefinitely-repeating misdelivery to a stale address, a robustness defect. Tracked as
> [issue #49](https://github.com/ciresnave/synapse/issues/49); needs a `Transport`/
> `TransportReceive` contract change touching every transport, deliberately its own slice.

> **Status, 2026-09-18, PR B of the transport contract, Task 7 (branch `feat/transport-contract-b`, not
> yet on `main`):** TCP — the public `synapse::transport::TcpTransportFactory` built `tcp_simple`, which
> had no listener, not `tcp_unified`: `abstraction.rs` defined a second `TcpTransportFactory` and the
> glob re-export made it the public one. That factory and `tcp_simple.rs` are deleted, and
> `tcp_unified::TcpTransportFactory` is re-exported by name (transport contract PR B, Task 7); against the old factory the
> end-to-end test fails at send (`All transports failed`: nothing listens on the receiver's port).
> A review of that commit then found two ways `tcp_unified`'s receiver still lost messages behind a
> `Sent` receipt: it did one `read` of at most 8192 bytes, so any message whose JSON was larger was
> dropped (a 2,000 B body is about 9.2 KB of JSON), and it queued with `try_lock`, dropping the message
> whenever the queue was busy. The fix-round commits on the same branch read each connection to EOF
> (the sender now shuts down its write half) and wait for the queue lock. Everything the receiver
> holds, it holds before any signature is checked. Writing `C` = `max_concurrent_connections`
> (default 64), `M` = `max_message_size` (default 1 MiB), `B` = `max_queued_bytes` (default 4 MiB,
> counted in bytes of serialized JSON; construction refuses `B` < `M` and `B` > `u32::MAX`) and `f`
> for the parse factor (heap per byte of JSON while parsing and after), the worst case is read
> buffers `C × (M + 1 + 8 KiB)` (each handler's buffer plus its 8 KiB read chunk) plus parsed
> messages `B × f`: a handler takes budget for its message's JSON length before parsing, and the
> queued message keeps it until drained, so everything being parsed or queued holds at most `B`
> bytes of budget. The sender chooses the JSON, so `f` is adversarial. Measured with a counting
> allocator on about 1 MiB of JSON `SecureMessage`: a `routing_path` of empty strings peaks at 18.0×
> and retains 12.0× (`Vec` capacity doubling is never shrunk); one of one-character strings peaks at
> 9.1× and retains 6.3×, about 14× with per-allocation heap overhead; short-key `metadata` peaks at
> 9.5× and retains 6.6×. So `f` ≈ 18 while parsing and ≈ 12 retained — the largest measured, not
> proven maxima. With the defaults that is 64 × (1 MiB + 1 B + 8 KiB) + 4 MiB × 18 = 143,130,688
> bytes, about 136.5 MiB at peak (112.5 MiB with everything retained at `f` = 12); the old 16 MiB
> default would have allowed about 352.5 MiB. The bound ends where a message is drained:
> `receive_raw` releases its budget before the manager verifies and opens it, so while the manager
> processes a batch, up to `B × f` of drained messages sit outside the bound while the queue refills
> another `B`, and whatever the application keeps afterwards is outside it too. At `C` the accept loop waits, so later connections queue in
> the kernel's backlog; with the budget spent, a handler waits for budget holding its connection, so
> an application that never polls stops the listener (backpressure) rather than losing messages. A connection is closed if it sends nothing
> for `first_byte_timeout_ms` (default 5 s), goes silent for `idle_timeout_ms` (default 5 s), or has
> not ended after 30 s, so a round of `C` silent peers holds every connection for at most 5 s and a
> round of peers trickling bytes for at most 30 s; a legitimate connection still waits behind every
> connection queued ahead of it in the backlog. `max_message_size` counts serialized JSON bytes,
> not body bytes (`encrypted_content` serializes as a number array, a few characters per body byte);
> the sender refuses (`SynapseError::MessageRefused`), rather than claiming `Sent`, any message over
> its own limit, and `capabilities()` reports the configured limit. The manager does not count a
> refusal against the transport: before, one oversize send marked TCP failed for 300 s, receive
> included. When every transport fails, the manager's error now carries each transport's own
> reason. A limit or timeout that does not parse, or is 0, fails construction instead of silently
> becoming the default. What `tests/transport_repairs.rs` shows, over loopback in one process only:
> a sealed, signed message with an 8-byte and with a 16 KiB body arrives `Verified`, pinned to the
> sender's certificate, and opens intact; 400 signed sends, 32 in flight at a time, all arrive once, each pinned
> to the sender and carrying its own body; a message over a 4096-byte limit is refused at send
> while one under it arrives; after such a refusal TCP stays `Running` and the next message
> arrives; with a cap of 2 and two connections held open, a third is read only after one closes;
> with two silent connections and a 500 ms first-byte timeout, a message behind them arrives after
> that timeout, not after 30 s; with a queue budget that holds two of its messages but not three and
> no polling, four messages sent leave only two queued at the first poll, and all four arrive once
> polling continues; a `max_queued_bytes` below `max_message_size`, above `u32::MAX`, zero or
> unparseable fails construction; `stop()` closes the queue budget, so handlers waiting for it
> return and release their connection permits instead of leaking. Each receipt still claims only
> `Sent`. Nothing here was run across machines.
>
> **Known gaps, not fixed in Task 7 (follow-ups):**
> - `stop()` leaves TCP's accept loop running: it still accepts and reads connections, then drops
>   each message at the closed budget.
> - The manager does not drain a transport in recovery, so after one real send failure marks TCP
>   failed, inbound TCP stalls for the 300 s recovery window.
> - UDP (`udp_unified.rs:157`) still returns `TransportError` for an oversize message, which counts
>   against the transport; UDP needs its own fix. (WebSocket's refusal is `MessageRefused` since
>   PR B, Task 8, and HTTP's since PR B, Task 9.)
> - Cap `routing_path` and `metadata` lengths during deserialization, to bound `f` itself.

> **Status, 2026-09-19, PR B of the transport contract, Task 8 (branch `feat/transport-contract-b`, not
> yet on `main`):** WebSocket — `start()` bound a listener, stored it, then bound the same port again
> inside the spawned accept task and swallowed that failure, so the accept loop never ran; the
> client skipped the handshake (a bare TCP connect); `send_via_existing_connection` never wrote its
> data; and `receive_raw` put back everything it drained, so every poll returned every message
> again. Now `start()` binds once on the `BindScope` address (loopback by default) and the accept
> loop serves that same listener; the server runs `tokio_tungstenite::accept_async` and the client
> `connect_async`, a real HTTP-upgrade handshake; each message is one binary frame on its own
> connection (as for TCP: no connection is kept per peer), and the receipt claims `Sent` once the
> frame is written and flushed — never `Delivered`, since the receiver sends no application-level
> acknowledgement; `receive_raw` drains. Limits are TCP's, with the same keys and defaults where
> they overlap: `max_message_size` (1 MiB of serialized JSON, also tungstenite's message and frame
> limit), `max_concurrent_connections` (64), `max_queued_bytes` (4 MiB, taken before parsing and
> held until drained, closed by `stop()`), `handshake_timeout_ms` and `idle_timeout_ms` (5 s each),
> and `connection_timeout_ms` (30 s, the sender's connect-and-handshake and write limit); an
> unparseable or zero value, a bad `local_port`, or a `max_queued_bytes` below `max_message_size` or
> above `u32::MAX` fails construction. The worst case an unauthenticated peer can make the receiver
> hold is about `C × (2.625M + 75 KiB) + B × f`, about 245 MiB at peak with the defaults and `f` =
> 18. The `2.625M` per connection (2.63 MiB at `M` = 1 MiB, a fragmented message's transient peak;
> 2.06 MiB held for one whole frame) and the 11 KiB each connection holds after its handshake were
> measured with a counting allocator, release build, Windows, 16 connections at once; the 64 KiB
> write-buffer cap, and the scaling to other `M`, are derived. `2.625M` is the largest of the four
> frame shapes measured, not a proven maximum: a shape not tried could grow tungstenite's buffers
> further. (As first built, `22e68c5` stated
> `C × (4M + 80 KiB)`, about 333 MiB, an estimate from reading tungstenite 0.30 that the
> measurement showed was high.) Fix round 1 also closed a hole the formula did not cover: the
> receiver answered pings, with an unbounded write buffer, so one peer that pinged and never read
> grew the receiver's heap by 4 GiB in 8.4 s (measured by the reviewer at `22e68c5`); the receiver
> now closes a connection on any Ping, Pong or other control frame but Close, and caps its write
> buffer at 64 KiB (the same flood, re-measured: 0.1 MiB of growth, the connection closed after
> 0.2 MiB had been sent). `idle_timeout_ms` is a gap between reads, as TCP's is, not a deadline for
> a whole message, and a target with any scheme but `ws://`, an empty host, or a missing, zero or
> invalid port is refused (`22e68c5` accepted `http://host:80` and dialled `ws://http://host:80/`).
> A target is checked by the parser that dials it (`http::Uri`, through tungstenite's
> `IntoClientRequest`), so what is accepted is exactly what is dialled; `c604d57` checked with the
> `url` crate, which accepted `ws://a\b:9000`, `ws://%61:80`, `ws://bücher.test:80` and a path
> with a space, all then refused at send, read `ws://0x7f.1:80` as 127.0.0.1 where the dialler
> resolves the name, and dropped a fragment. The scheme matches in any case (`WS://h:80`).
> The sender refuses an oversize message with `SynapseError::MessageRefused` before connecting.
> `test_connectivity` reports connected, with the handshake's measured round trip, only after a
> real handshake; `estimate_metrics` probes the same way and reports observed values (a failed probe
> reports unavailable, the connection timeout as latency, and confidence 0.3); `metrics()`
> counts real sends, receives and failures. `tokio-tungstenite` moved from 0.27.0 to 0.30.0, the
> latest published; the direct `tungstenite` dependency, which nothing used, was removed. What `tests/transport_repairs.rs` shows, over loopback in one
> process only: a sealed, signed message with an 8-byte and with a 16 KiB body arrives `Verified`
> and opens intact; five messages each arrive once however often Bob polls; 200 signed sends, 32 in
> flight at a time, all arrive once; a peer that sends a Ping or a Pong is closed within 2 s and,
> under a cap of 1, its permit goes to the next message; a frame trickled in 100 ms apart over about
> 0.9 s arrives under a 300 ms idle timeout, while one with a 900 ms gap is cut off; an oversize
> message is `MessageRefused` even to a port where nothing
> listens, and ten refusals through the manager leave WebSocket `Running` with the next message
> arriving; two peers that never handshake, under a cap of 2 and a 500 ms handshake timeout, delay a
> message behind them by that timeout, not 30 s; connectivity is reported against a live node and
> not against a closed port. That a listener that accepts TCP but never upgrades is reported not
> connected is shown by the unit test `a_bare_tcp_listener_is_not_a_websocket_connection` in
> `src/transport/websocket_unified.rs`, not by `tests/transport_repairs.rs`. Nothing here was run
> across machines.
>
> **Known gaps, not fixed in Task 8 (follow-ups):** as for TCP, `stop()` leaves the accept loop (and
> so the listener) running; each send to a peer costs two handshakes through the manager, because
> adaptive selection calls `estimate_metrics`, which probes; `wss://` is refused, since
> `tokio-tungstenite` is built without TLS; `TransportCapabilities::websocket()` in `abstraction.rs`
> still advertises 16 MB and WSS (the transport reports its own capabilities and does not use it).

> **Status, 2026-09-19, PR B of the transport contract, Task 9 (branch `feat/transport-contract-b`, not
> yet on `main`):** HTTP — `start_server` bound nothing: it built an `HttpServer` record, logged
> "HTTP server started", and returned, so nothing listened and nothing ever filled the queue
> `receive_raw` drained; `abstraction.rs` held a second `HttpTransportFactory` with a weaker config
> check. Now `start()` binds once on the `BindScope` address (loopback by default) at `server_port`,
> keeps the listener, and serves it with `axum` on hyper's HTTP/1.1 server: one route,
> `POST /synapse/message`, whose handler reads the JSON body, takes queue budget for it, parses it,
> queues it, and only then answers `202`. So the sender's receipt is `Delivered`, resting on that
> `2xx`; any other status is an error, never `Sent`. The server answers `413` for a `Content-Length`
> over `max_message_size` and `411` for a body without one (chunked), both before reading any of
> the body; `400` for a body that is empty, short or does not parse; `408` when the body goes
> silent; `503` while the transport is stopping or when no queue budget frees before the request's
> deadline. Keep-alive is off: one request per connection, so a connection permit bounds one
> message, as for TCP and WebSocket, and a pipelined second request is never read. Limits are TCP's,
> with the same keys and defaults where they overlap (`max_message_size` 1 MiB of serialized JSON,
> `max_concurrent_connections` 64, `max_queued_bytes` 4 MiB), plus `header_read_timeout_ms` (5 s,
> hyper's header timeout, which also closes a connection that sends nothing), `idle_timeout_ms` (5 s,
> a gap between body reads) and `request_timeout_ms` (20 s, the whole connection including the wait
> for queue budget, under the sender's 30 s `timeout_ms`); an unparseable or zero value, a bad
> `server_port` or `use_https`, a `max_queued_bytes` below `max_message_size` or above `u32::MAX`,
> or the retired keys `server_address` and `max_connections`, fails construction and
> `validate_config` alike. A full queue makes requests wait, holding their connection permits, until
> the application polls or the deadline passes. The worst case an unauthenticated peer can make the
> receiver hold is about `C × (M + 140 KiB) + B × f`, about 145 MiB at peak with the defaults and `f`
> = 18. The handler allocates exactly the declared body length, once, so a body costs at most `M`;
> the rest of a connection was measured at 137 to 138 KiB at `M` = 256 KiB, 1 MiB and 4 MiB, with
> up to four write patterns, 16 connections at once (a counting allocator that counts a
> reallocation's transient, release build, Windows); the 140 KiB rounds that up and is not a proven
> maximum, and that it holds for 64 connections is derived. A target is an `http://` or `https://`
> URL or `host:port`, with a host and a port; it is checked as the `reqwest::Url` that is then
> dialled, and refused if the parser would dial a different host or port than the address names
> (`127.1`, `0x7f.1`, a percent-encoded or non-ASCII host), or if it has userinfo or a fragment; the
> client follows no redirect and uses no proxy. `https://` is accepted because `reqwest` is built
> with TLS (rustls); a unit test shows an `https://` send opens with a TLS handshake. The sender
> refuses an oversize message with `SynapseError::MessageRefused` before connecting.
> `test_connectivity` and `estimate_metrics` report connected and available only after a real HTTP
> exchange (any response; this server answers the `HEAD` probe `405`), a failed probe reporting
> unavailable, the request timeout as latency and confidence 0.3; bandwidth is measured from sends,
> or 1 until there is one. `stop()` closes the queue budget, ends the accept loop and releases the
> listener. `reqwest` moved from 0.12.22 to 0.13.5; `axum` 0.8.9, `hyper` 1.11.1, `hyper-util`
> 0.1.20, `tower` 0.5.3, `tower-http` 0.7.1 and `http-body-util` 0.1.5 were added at their latest
> versions, under the `http` feature. What `tests/transport_repairs.rs` shows, over loopback in one
> process only: a sealed, signed message with an 8-byte and with a 16 KiB body arrives `Verified`
> and opens intact, receipted `Delivered` with status `202`; five messages each arrive once, all of
> them at the first poll after their receipts; 200 signed sends, 32 in flight at a time, all arrive
> once; an oversize message is `MessageRefused` even to a port where nothing listens, and ten
> refusals through the manager leave HTTP `Running` with the next message delivered; a 1 GB
> `Content-Length` trickled a byte every 100 ms is answered `413` within 2 s, after at most 5 bytes,
> and a chunked body `411`; with a queue budget for two of four messages sent at once and no polling,
> exactly two sends are answered and two wait until Bob polls, then all four arrive once; with a 1 s
> `request_timeout_ms` and a full budget, a send is answered `503` at the deadline and its message
> never arrives; under a cap of 2 with two silent connections, a third request is not read until one
> closes; under a cap of 2 and a 500 ms header timeout, a silent peer and one trickling its head are
> closed and a message behind them is delivered after that timeout, not before; a body trickled
> 100 ms apart over about 1 s is accepted under a 300 ms idle timeout, while one that stalls is
> answered `408`; two pipelined requests get one answer and one queued message; bodies that do not
> parse, or are empty, are answered `400`; invalid configs and targets are refused; connectivity is
> reported against a live node and not against a closed port. That `receive_raw` hands each message
> out once, that `stop()` answers a waiting request `503`, that every non-2xx answer (`500`, `404`,
> `302`) is an error, and that `https://` uses TLS are shown by unit tests in
> `src/transport/http_unified.rs`. Nothing here was run across machines.
>
> **Known gaps, not fixed in Task 9 (follow-ups):** each send to a peer costs two HTTP exchanges
> through the manager, because adaptive selection calls `estimate_metrics`, which probes; the
> server speaks plain HTTP only (no TLS server), so `capabilities()` reports `encrypted: false`;
> `TransportCapabilities::http()` in `abstraction.rs` still advertises 10 MB (the transport reports
> its own capabilities and does not use it); a `503` from a busy peer is a `TransportError`, which
> the manager counts against HTTP; if the `2xx` is lost after the message is queued, the sender sees
> an error for a delivered message (a resend is then dropped by the replay record); and TCP's
> `estimate_metrics` still reports an invented 1,000,000 bytes/s of bandwidth.

⚠️ **So Synapse can carry a message today, over UDP, and the two transports have opposite and
undocumented construction requirements.** That single fact matters more for planning than everything
else in this document.

✅ **Added 2026-09-17, fixed 2026-09-18: until PR #41, "encrypted" messages on `main` could be read by
anyone who had the bytes.** `encrypt_message` stored the AES key inside its own output. This was never
in a published release (§2.2). **Fixed by PR #41, on `main` as `63d4945`:** `encrypt_message`,
`encrypt_with_aes` and `decrypt_message` are gone from `src/` at `origin/main` 4df9e36.

---

## 1. What was blocking the build

### 1.1 Three dependency features that have never existed

`Cargo.toml` requested five features from `auth-framework`; three of them do not exist:

```
requested: oauth-device-flows  enhanced-device-flow  config-management  enterprise-features  token-to-profile
exists:    yes                 yes                   NO                 NO                   NO
```

Checked against `index.crates.io/au/th/auth-framework` — **every published version**: `0.1.1`,
`0.2.0`, `0.3.0`, `0.4.0`, `0.4.1`, `0.4.2`, `0.5.0-rc1`, `0.5.0-rc18`, `0.5.0-rc19`.
`config-management`, `enterprise-features`, `token-to-profile` are absent from all nine.
**Positive control:** the same query reports `enhanced-device-flow` PRESENT in 0.3.0 onward, and
`oauth-device-flows` resolves as the implicit feature of auth-framework's optional dependency of the
same name. The query discriminates. Independently confirmed absent in auth-framework's unpublished
`main` (rc24) by the auth-framework lane, using its own control set.

**Cargo validates a dependency's requested feature names at RESOLUTION time, whether or not the
optional dependency is enabled.** So this single line broke configurations that do not use auth at
all. Measured, all ten feature sets, identical first error:

```
minimal core crypto networking nat_traversal email database auth wasm native
  -> 10 of 10 EXIT=101, zero lines compiled

error: failed to select a version for `auth-framework`.
package `synapse` depends on `auth-framework` with feature `config-management`
but `auth-framework` does not have that feature.
```

Note cargo names only the *first* missing feature, so the error message undercounts by two.

**Provenance — the breakage is isolated to one commit.** Measured with
`git show <ref>:Cargo.toml` across the release history (bisect contributed by the Claim Auditor lane,
verified here independently):

```
7b80ca4  (v1.1.0 release)   oauth-device-flows  enhanced-device-flow
7775f19                     oauth-device-flows  enhanced-device-flow
c06ad4a                     oauth-device-flows  enhanced-device-flow
f0f570c  (HEAD, checkpoint) oauth-device-flows  enhanced-device-flow
                            + config-management + enterprise-features + token-to-profile
```

**Every tagged/release commit requests only the two features that exist. `f0f570c` — "Checkpoint:
commit all local work before machine wipe" — introduced all three phantom names.** So the repo was
resolvable through v1.1.0 and was broken by the emergency checkpoint, which is also the commit that
renamed the trust-system test to `.disabled` (§4) and published
`AUTH_FRAMEWORK_INTEGRATION_SUMMARY.md` (§6.1). ⚠️ **One commit, made under time pressure, carries
the build break, the disabled test, and the document asserting the work was complete.**

**Fix applied:** removed the three names. This is deleting a statement that was never true, not a
version migration. The `^0.3.0` pin is untouched — crates.io serves `0.4.2` stable and `0.5.0-rc19`,
and for a 0.x crate `^0.3.0` excludes both, but that upgrade is a merge decision and is left open.

### 1.2 A forced linker that is not installed

`.cargo/config.toml` (added in `f0f570c` itself) set `linker = "lld-link"` unconditionally. `lld-link`
ships with LLVM, not with Rust. Without LLVM installed, every build died before compiling:

```
error: linker `lld-link` not found
```

**Fix applied:** commented out, with the reasoning preserved in the file. Measured: the default MSVC
linker links the library and all 11 integration-test binaries with no LNK1318. The problem the
override was added for did not reproduce.

---

## 2. Verified working — measured by execution

`cargo test` on the default (`native`) feature set. **106 tests, 105 passed, 1 failed, 0 ignored**,
across 21 test binaries.

⚠️ **And as of PR #18 + #24 this is CI-verified, not only local.** Until 2026-09-10 no test had ever
executed in this repository's CI — the pipeline died at a style check before reaching `Run tests`
(§2.4). It now runs, and **CI's result is identical to the local one, checked figure by figure
rather than by conclusion:**

```
                binaries  passed  failed  total   failing test              assertion
local                 21     105       1    106   test_transport_error_..   "Should fail with invalid email"
CI (run 34517609451)  21     105       1    106   test_transport_error_..   "Should fail with invalid email"
```

**Same count, same test, same assertion.** ⚠️ Worth stating explicitly because a local run and a
containerised CI run differ in ways that can produce genuinely different failures under the same
test name — **agreement on the name is not agreement on the failure**, so the message was compared
too.

| target | tests | result |
|---|---:|---|
| `--lib` (unit tests) | 62 | all pass |
| `basic_integration_test` | 4 | all pass |
| `concurrent_registry_access_test` | 4 | all pass |
| `edge_case_test` | 8 | all pass |
| `high_load_test` | 2 | all pass |
| `integration_test` | 3 | all pass |
| `multi_transport_integration` | 4 | all pass |
| `network_partition_test` | 3 | all pass |
| `registry_integration_test` | 1 | all pass |
| `security_test` | 8 | all pass |
| `transport_error_handling_test` | 3 | **2 pass, 1 FAIL** |

**Nothing is `#[ignore]`d.** Count is 0 across every test file — this is a real zero, not an absent
query: the same scan returns 53 host test attributes plus 7 `#[wasm_bindgen_test]` in `tests/` (§7).

### 2.1 The one real test failure — a genuine behavioural defect

```
thread 'test_transport_error_handling' panicked at tests\transport_error_handling_test.rs:45:21:
Should fail with invalid email
```

The transport **accepted an invalid email address that the test asserts must be rejected**. This is
not an infrastructure problem; it is the test doing its job. It took 8.08s, which suggests a network
timeout path is involved. **Deliberately not fixed** — it is a behaviour question, and the code that
owns it may not survive the merge.

> **Status, 2026-09-18: fixed in PR A of the transport contract (PR #44, on `main` as `b6a1904`).** `email_simple.rs` had three
> disagreeing address checks; `test_connectivity` required only an `@`, so `invalid@` passed as
> `connected: true`. One validator (`valid_address`) now serves all three, and the transport, which
> touches no network, refuses to send, receive or report a connection for a well-formed address
> ("not implemented yet; it arrives in the email slice") instead of faking one.
> `transport_error_handling_test` passes; the full run at `593f1c9`, a commit of PR #44 before its squash, shows 0 failures.

> **Status, 2026-09-25, the email-transport slice (branch `feat/email-transport`, not yet on
> `main`):** the "arrives in the email slice" placeholder above is this slice. `TransportType::Email`'s
> factory now constructs a real `EmailTransportImpl` (Direct/RelayOut/External modes: real SMTP
> send via `lettre`, real IMAP-polling receive via `async-imap`) instead of `SimpleEmailTransport`'s
> permanent refusal. `tests/transport_repairs.rs`'s
> `email_direct_mode_carries_a_verified_message_end_to_end` and
> `email_relay_out_mode_receives_via_imap_polling` measure a real round trip over loopback, the same
> standard applied to WebSocket/HTTP (PR B) and QUIC (the QUIC slice) above.

### 2.2 ⚠️ END-TO-END ROUND TRIP: MEASURED, AND IT FAILS WHILE REPORTING SUCCESS

**No test in the suite sends a message between two endpoints over a real socket, so I ran one.** This
is the most consequential measurement in this document.

**Probe A — Synapse to Synapse over TCP, one process, two `TcpTransportImpl` instances.** Receiver
bound to port 47811; sender given the receiver's address:

```
[probe] receiver.start() OK -> status Running
[probe] PORT 47811 IS ACCEPTING (raw TcpStream::connect succeeded)
[probe] send_message OK -> DeliveryReceipt { transport_used: Tcp, delivery_time: 1.19ms,
                             target_reached: "127.0.0.1:47811", confirmation: Sent }
[probe] attempt 1..5: receive_messages -> 0 message(s)
[probe] RESULT: NO MESSAGE ARRIVED
```

⚠️ **`send_message` returns `Ok` with `confirmation: Sent` and a delivery time, for a message that is
never delivered.** A caller has no way to detect the failure from the API.

**Cause — established, not inferred.** `TcpTransportImpl::new` binds `self.listener` on the port.
Then `start_server()` spawns a task that binds a **second** `TcpListener` on **the same address**:

```rust
let local_addr = listener.local_addr()?;         // self.listener already owns this port
tokio::spawn(async move {
    if let Ok(listener) = TcpListener::bind(local_addr).await {   // <-- FAILS, port in use
        loop { match listener.accept().await { ... } }            // <-- never runs
    } else {
        error!("Failed to create TCP listener for server task");  // <-- swallowed
    }
});
```

**Confirmed by turning the swallowed log on** (`RUST_LOG=synapse=debug`), which is the discriminating
test — the error fires *between* `start()` returning `Ok` and the send "succeeding":

```
INFO  TCP transport listening on port 47812        <- self.listener binds
INFO  TCP transport started successfully           <- start() returns Ok, status Running
ERROR Failed to create TCP listener for server task  <- the accept loop never starts
INFO  TCP message sent to 127.0.0.1:47812 in 1.01ms  <- reported success
      receive_messages -> 0 message(s)  x5
```

**So the port accepts connections — `self.listener`'s backlog absorbs them — but nothing ever calls
`accept()` on it.** Bytes are written into a socket no one reads. `start()` returns `Ok(())` and
`status()` reports `Running` regardless.

#### ✅ Independently confirmed, by a different method, and the fix is verified

The Fuel 1 lane replicated this at the portfolio PM's request, deliberately **without** my probe, my
instrument, or my diagnosis — they were given the symptom only, plus a frozen base and a
pre-registered prediction. They reached the **same cause by reading**, and then went further than I
did:

```
their observation:  send Ok / confirmation=Sent / 1.35ms, receive_messages -> 0
                    then -> 1 AFTER THEIR FIX
their cause:        the double-bind, same lines (:57 bind, :101 re-bind, :128 swallowed else)
their fix:          make self.listener an Arc<TcpListener>, clone the Arc into the accept
                    loop, delete the second bind
```

⚠️ **Two independent methods converged on one cause, and the fix is verified rather than plausible.**
I had recorded this as "looks small — someone should confirm that before believing it." It is now
confirmed: **a message arrives after the change.** Filed as
[`ciresnave/synapse#9`](https://github.com/ciresnave/synapse/issues/9) with the patch, marked
UNAPPLIED because `push=false`.

⚠️ **And they resolved a gap I had flagged in my own experiment.** I had noted that I only ever set an
explicit `listen_port` and never tested `listen_port = 0` / absent. Their answer: that is a
**separate state, not this bug** — with port 0 the constructor binds no listener at all,
`start_server` is a no-op, and there is no address to receive on. **So there are two distinct ways to
get a deaf TCP transport: "never a server" (port unset) and "port owned but never served" (port set).
Both report `Running`.** The measured symptom above is the second.

**Probe B — the wire format, captured by a RAW `tokio::net::TcpListener` with no Synapse on the
receiving side.** This direction *works*:

```
[probe] raw listener accepted from 127.0.0.1:52059
[probe] ===== 364 BYTES ON THE WIRE =====
{"message_id":"a3ca0312-...","to_global_id":"bob@synapse.local",
 "from_global_id":"alice@synapse.local","encrypted_content":[82,79,85,78,...],
 "signature":[1,2,3,4],"timestamp":"2026-09-09T14:13:31.517436100Z",
 "security_level":"public","routing_path":[],"metadata":{"probe":"wire-format"}}
[probe] PARSES AS JSON.
```

**The wire format is one self-describing JSON object per TCP connection**, framed by connection
close. Not bincode, not a Rust-specific encoding. `encrypted_content` and `signature` are JSON arrays
of byte integers rather than base64 (verbose, but trivial to implement).

#### ✅ PROBE C — UDP DELIVERS END TO END. THERE IS A WORKING TRANSPORT TODAY.

**This is the most useful result in this document.** Same shape of probe, UDP instead of TCP,
receiver built through `UdpTransportFactory` with `bind_port` set:

```
INFO  UDP transport bound to 0.0.0.0:47901
[udp] sending...
DEBUG Sending UDP message to 127.0.0.1:47901
DEBUG Received 321 bytes via UDP from 127.0.0.1:57249
DEBUG Queued UDP message, total: 1
[udp] attempt 1: 1 message(s)
[udp] ***** DELIVERED ***** from=alice@synapse.local payload=UDP_PROBE_PAYLOAD
[udp] RESULT: UDP ROUND TRIP SUCCEEDED
```

**A `SecureMessage` was serialised, sent over a real loopback socket, received, queued, and returned
by `receive_messages()` with its payload intact, in about 1 ms.**

⚠️ **BUT ONLY VIA THE FACTORY, AND THE LIFECYCLE CONTRACT DIFFERS FROM TCP'S.** This is the part that
would cost someone a day:

| | what starts the receive loop |
|---|---|
| `tcp_unified` | `Transport::start()` calls `self.start_server()` — so `new()` + `start()` is the right path |
| `udp_unified` | ⚠️ **`Transport::start()` does NOT call `start_server()`.** Only `UdpTransportFactory::create_transport` does, and **only if `bind_port` is present and > 0** |

`UdpTransportImpl::new()` leaves `socket: None`, and `start()` merely logs:

```rust
// Note: We need mutable access to self to start the server
// This is a limitation of the current design - we'll work around it
info!("UDP transport ready (server will start on first use)");
```

⚠️ **"server will start on first use" is false — nothing starts it on first use.** Construct a UDP
transport the way you construct a TCP one and you get a permanently deaf transport that reports
`Running`. **The two transports have opposite construction requirements and neither is documented.**

Two further observations, recorded because they mislead:
- `receiver.status()` returned **`Stopped`** immediately after the factory had already bound the
  socket and started the loop. Status does not track the server.
- `start()` then logged *"server will start on first use"* on a transport whose server was **already
  running**. The log describes the code path, not the state.

**Limits: single process, loopback, one message, one direction.** UDP is also inherently lossy and
capped at 65507 bytes (`max_message_size` default). **This is a working link, not a reliable one.**

#### ✅ UNTIL PR #38, EVERY DELIVERY CONFIRMATION SYNAPSE PRODUCED WAS SENDER-SIDE

> **Fixed by PR #38 (P2 slice b), on `main` as `71388eb`: a receiver-derived acknowledgement.** The
> receiving application sends a signed ack after processing. The sender reaches `Acknowledged` only on a
> verified, matching ack, and the unused `Received` variant is removed. Design:
> `docs/superpowers/specs/2026-09-17-receiver-acknowledgement-design.md`. What follows describes
> `main` before #38.

Checked because the FAM lane, whose fabric is being rewritten into Synapse, handed over a measured
requirement — *"the ack must belong to the receiver"* — after their own system marked a message
delivered on the **pushing** side and a client silently destroyed its own backlog. **Synapse has the
same defect, and one detail makes it worse.**

`DeliveryConfirmation` declares four variants. Only two are ever constructed:

```
DeliveryConfirmation::Sent          14 occurrences
DeliveryConfirmation::Delivered      4
DeliveryConfirmation::Received       0   <- never constructed, anywhere
DeliveryConfirmation::Acknowledged   0   <- never constructed, anywhere
```

**Control:** the same query finds `Delivered` at `mdns_enhanced.rs:576`, `providers.rs:270`,
`quic_unified.rs:415`, so it discriminates. `Received` and `Acknowledged` appear **nowhere in
`src/`, `tests/` or `examples/` outside the enum definition itself.**

⚠️ **The two variants that would mean "the recipient got it" exist in the public type and are never
produced.** A caller matching on `DeliveryConfirmation::Received` has written a branch that can
never be taken, and nothing — not the compiler, not a test, not the docs — says so. **The type
advertises a guarantee the implementation has never been able to make.**

**And no confirmation is derived from the far end.** Every one is constructed immediately after a
local write:

```rust
tcp_unified.rs:270   confirmation: DeliveryConfirmation::Sent,
udp_unified.rs:207   confirmation: DeliveryConfirmation::Sent,   // UDP is best-effort
```

⚠️ **This is exactly what made the TCP silent drop unobservable (§2.2): `send_message` returned
`Ok(confirmation: Sent)` with a sub-millisecond delivery time for a message that never arrived,
because `Sent` only ever meant "written to a socket".** The receipt was accurate; the reader's
interpretation of it could not be.

⚠️ **And the strongest delivery claim in the codebase is made by the transport that does no
networking at all.** `quic_unified.rs:415` constructs `Delivered` — a stronger assertion than TCP's
`Sent` — with the comment *"QUIC provides delivery confirmation"*, in a module that binds nothing and
fabricates its connections (§2.2). **The simulation out-claims every real transport.**

> **Status, 2026-09-18, PR A of the transport contract (PR #44, on `main` as `b6a1904`):** `quic_unified.rs` is **deleted** and QUIC refuses to
> construct. The other `Delivered` claims named in the control above are gone too:
> `mdns_enhanced.rs`'s send refuses, and `providers.rs`'s is the test mock, marked as a
> test double. `tests/delivery_claims.rs` now scans `src/transport/` so every `Delivered`
> construction names its protocol event and only the manager constructs `Acknowledged` or `Expired`
> (all in PR #44).

> **Status, 2026-09-23, the QUIC slice (branch `design/quic-transport`, not yet on `main`):** the
> real `quic_unified.rs` this slice adds claims `Sent` only, never `Delivered` (spec §4) — it does
> not repeat the deleted simulation's overclaim.

**Not fixed here.** A receiver-derived acknowledgement is a protocol addition, not a repair, and it
is precisely the kind of decision the pending merge should make deliberately. **Recorded because it
is cheap to design in now and, in the FAM lane's words from having lived it, unfixable later.**

#### ⚠️ `receive_messages` IS 26 DIFFERENT FUNCTIONS WITH FOUR RETURN TYPES AND THREE SEMANTICS

Found because the FAM lane tried to verify a claim of mine — *"`receive_messages()` drains"* — and
**could not**, correctly. Their first hit was `src/email.rs:157`, an IMAP simulation whose body is a
comment describing what a real implementation would do. **Same name, different module, different
thing.** My claim was true of the one I had read and unverifiable as stated.

```
26 definitions across 25 files.  Return types:
    Vec<IncomingMessage>      the Transport trait's
    Vec<SecureMessage>        transport/mod.rs, providers.rs, tcp_enhanced.rs, udp.rs
    Vec<SimpleMessage>        router.rs
    Vec<SynapseEmailMessage>  email.rs (x2)
```

**And the semantics differ between implementations of the same trait method:**

| behaviour | implementations |
|---|---|
| **DRAINS** (destructive — a second caller gets nothing) | `tcp_unified`, `udp_unified`, `http_unified` |
| **clones** (non-destructive) | `production_http`, `quic_unified` |
| **always returns empty** | `discovery`; also `tcp_simple` until transport contract PR B, Task 7 deleted it (branch `feat/transport-contract-b`) |

⚠️ **`tcp_simple::receive_messages` returned `Ok(vec![])` unconditionally, and said so** (quoted as
of this audit; the file is deleted in transport contract PR B, Task 7):

```rust
// For this simple implementation, we don't maintain persistent listeners
// This would typically be implemented with a background task
Ok(vec![])
```

**That transport could never receive anything.** It was not broken by a bug — it had no receive path
at all. ⚠️ **And it was the transport `unified_transport_demo` actually started** ("TCP Simple
transport started" was the last line before that demo hung, §2.2), because the public
`TcpTransportFactory` built it. Both the file and that factory are deleted in transport contract PR B, Task 7.

`discovery` also returns empty unconditionally, but legitimately: it is a service-discovery
transport, not a message transport, and its comment says so. **Same code shape, opposite
significance — which is the point.**

**Why this matters to a caller:** two implementations of one trait method, both typed
`Result<Vec<IncomingMessage>>`, where one is destructive and one is not, and a third could never
return anything (`tcp_simple`, until transport contract PR B, Task 7 deleted it). **A caller who reads `receive_messages`
once and assumes it forever will be right about one transport and wrong about the others**, and the type signature is identical in every case.

⚠️ **METHOD CAVEAT, AND IT IS A CORRECTION AGAINST MY OWN CLASSIFIER.** I generated the table above
by reading the 12 lines following each definition and pattern-matching for `drain(` / `.clone()` /
`Ok(vec![])`. **It produced a false positive: it classified `websocket_unified` as "always returns
empty" because the first `Ok(Vec::new())` in its body is a circuit-breaker early return.** Reading
the whole function showed it did call `receive_websocket_messages()` and had a real path -- one
that put back everything it drained, so each message repeated on every poll, until transport
contract PR B, Task 8 made it drain.
`websocket_unified` is **excluded** from the table above rather than reclassified, because I have not
read every remaining implementation in full. **The rows shown are the ones I read; the others are
unmeasured, not "other".** A window is not a function, and a heuristic over a window will confidently
mis-read an early return as the whole body.

> **Status, 2026-09-18: fixed for transports in PR A of the transport contract (PR #44, on `main` as `b6a1904`).** The old `Transport` trait and
> the files that never compiled are deleted, and a transport's receive is now one
> signature, `TransportReceive::receive_raw(&self, &mut RawInbox)`, which only the manager can call
> (all in PR #44). `git grep -nE 'fn receive_messages\b' -- '*.rs'` finds 25 definitions in
> 23 files at `origin/main` `624c62d` and 3 at `593f1c9` (a commit of PR #44 before its squash): `TransportManager::receive_messages`
> (`manager.rs:653`), and the unrelated `email.rs:162` and `router.rs:109`, which are not transports.
> Of the semantics above, the two cloning implementations (`production_http`, `quic_unified`) are
> deleted; `discovery` still adds nothing, `email_simple` now refuses, and `tcp_simple` added nothing
> until transport contract PR B, Task 7 deleted it (below). **Status, 2026-09-25:** `email_simple`'s
> refusal is itself superseded by the email-transport slice's real `EmailTransportImpl` -- see the
> "email-transport slice" status notes under §2.1 above and "Still unmeasured end-to-end" below.

> **Status, 2026-09-18, PR B Task 7 (branch `feat/transport-contract-b`, not yet on `main`):**
> `tcp_simple.rs` is deleted, with the shadowing `TcpTransportFactory` that built it; the public
> factory is now `tcp_unified`'s, whose receive drains a real listener's queue.

#### ✅ UNTIL PR #37, NO MESSAGE'S SENDER WAS AUTHENTICATED, AND THE TYPE SAID OTHERWISE

> **Fixed by PR #37 (P2 slice a), on `main` as `ee1bf8c`.** It added a mandatory `sender_proof`,
> a pinned `TrustStore`, and receiver-computed verdicts from `TransportManager::receive_messages`.
> The design is `docs/superpowers/specs/2026-09-17-sender-authentication-design.md`. The
> measurements below describe `main` before #37.

> **Replay suppression and bounded inbound state merged as PR #42 (P2 slice e), on `main` as
> `5ddcb07`.** Unverified senders are denied by default at the transport, with an opt-in setting to
> accept them and a bounded record of who was refused. This is not sender authentication: it
> decides whether to admit a message from a sender the transport could not verify, not whether the
> sender is who it claims to be. Stated plainly, not as a caveat to bury: the router's email path
> (`SynapseRouter`) remains unauthenticated, because it holds no trust store (`TrustStore` has no
> hit in `src/router.rs` at `origin/main` `4df9e36`; the same query finds 9 in
> `src/transport/manager.rs`).

> **Account keys and agent certificates merged as PR #43 (P2 slice f1), on `main` as
> `bbd4bf0`.** An account holder's key signs
> certificates for the agents it runs, so a receiver pins **one** account key instead of every
> agent's own key. `TrustStore::verify_at` accepts a certificate chain rooted in a pinned account
> key as an alternative to pinning the agent directly, checks the chain's validity window,
> permissions and delegation budget, and enforces the one permission Synapse itself acts on: a
> validated leaf without `Permission::Send` is `Unverifiable { NoSendPermission }`, whatever else
> the chain grants it. Revocations relayed in a verified sender's own message metadata are
> accepted into the trust store only when signed by a pinned account key -- a relay can deliver a
> revocation but never forge one. **Direct per-agent pinning still works unchanged and is removed
> in slice f2**, which is scoped to that removal plus the delegation and identity work this slice
> deferred. The router's email path remains unauthenticated, because `SynapseRouter` holds no
> trust store.

Checked because the OverMind lane — which drives non-Claude models through MCP tools behind a
refusal gate — asked directly whether Synapse carries a sender identity a recipient can verify
without trusting the relay. **It does not, and the shape of the "no" matters.**

**`SecureMessage.signature: Vec<u8>` is written in exactly one place and read in none.**

```
writes:  router.rs:88   secure_msg.signature = signature;
         every other construction sets it empty --
         email.rs:66 · smtp_server.rs:387 · router.rs:67,211 · router_enhanced.rs:676,700
reads:   NONE.  `.signature` appears nowhere in src/transport/ at all.
```

**Control:** the same query finds `.signature` read and verified 12 times in
`src/synapse/blockchain/` — `consensus.rs:284` calls `public_key.verify(...)` on a vote, and
`verification.rs:387` on a block. **The crate verifies signatures. It has never verified a
message's.**

**`from_global_id` is an unauthenticated string.** Across `src/transport/` it is only ever logged
(`email_simple.rs:78`), embedded in a header (`email_unified.rs:189`), or copied
(`nat_traversal.rs:585`, one site as of PR B Task 10, was two before it collapsed the hand-built
envelope into a direct `SecureMessage` deserialization). Nothing compares it to anything.

⚠️ **Measured, not inferred.** Probe D (above) sent `"signature": []` and
`"from_global_id": "python-agent@openai.example"` from a Python process with no credentials of any
kind. **The message was delivered and the claimed identity accepted verbatim.**

##### The capability exists and is unwired — and the one function that looks like the answer isn't

`CryptoManager::verify_signature` at `crypto.rs:197` is real, Ed25519, and correct-looking: it
resolves the sender's public key by `sender_global_id` and calls `public_key.verify(...)`. **Its only
caller in the entire crate is its own unit test at `crypto.rs:293`.**

And `auth_integration.rs:668` declares exactly what a reader would hope for:

```rust
pub async fn verify_message_sender(&self, message: &SecureMessage) -> Result<bool>
```

⚠️ **Two things are wrong with reaching for it.** First, `src/auth_integration.rs` is **orphaned** —
no `mod` declaration names it (§5.3) — though the **published** crate declared it at `lib.rs:264`,
so this is another capability the `f0f570c` checkpoint took out of the build.

**Second, and more important: it does not verify anything.** Its body fetches the profile for the
**claimed** `from_global_id` and returns whether *that profile* is `Verified | Trusted`. It never
touches `message.signature`. **It asks "is the party this message claims to be from trustworthy?" —
which is an authorisation check performed on an unauthenticated claim.** An attacker sets
`from_global_id` to a trusted entity's id and passes.

⚠️ **So even restoring the orphaned module would not give Synapse sender authentication. The function
whose name promises it is the most dangerous artifact in this area**, because it is exactly what a
future implementer will find, wire up, and believe.

##### What a consumer needs, recorded from the lane that needs it

Their requirement, which Synapse satisfies none of: a per-message assertion of the sender that a
recipient can verify **without asking the relay**; **three** distinguishable outcomes rather than two
— verified / could-not-verify / verified-and-contradicted; and **failure that is never silent** — a
message that could not be verified must arrive marked unverifiable, not arrive looking ordinary.

**Synapse currently produces a fourth state that lane's spec did not enumerate until this
measurement: not verified, not marked, indistinguishable from verified.** FAM at least reports
`sender_vouched: false`; Synapse carries no such field, **so a consumer cannot fail closed on its
absence without already knowing to look for something that was never there.** It is the only one of
the four that cannot be detected by reading the message.

That is safe today only because no policy anywhere is per-sender. **The first per-sender
authorisation rule anyone writes turns `from_global_id` from metadata into an authorisation input,
and there is no local check that recovers what the transport never carried.**

##### The requirement, stated so it is checkable

Contributed by that lane after this measurement, and worth recording verbatim because it is a design
constraint rather than a wish: **a recipient must be able to compute, from the message alone plus
keys obtained independently of the relay, exactly one of — `VERIFIED` / `UNVERIFIABLE` /
`CONTRADICTED`.**

⚠️ **And the fourth state is eliminated by the field being MANDATORY in the wire format, not
optional.** A message without it must **fail to parse** rather than arrive looking ordinary. **A
field a sender may omit is a field a consumer cannot rely on** — an optional `sender_vouched` would
reproduce precisely the state measured above, because the absence and the negative are then
indistinguishable at the receiver.

This bears directly on §2.2's finding that the wire format is plain self-describing JSON: **adding
an optional identity field would be the cheap change and the wrong one.**

**Not fixed here** — signing and verifying messages is a protocol addition and a merge decision, and
FAM (being rewritten into Synapse) already has a voucher-chain design for it. Recorded so the merge
inherits the measurement rather than the type's implication.

#### ✅ UNTIL PR #41, ENCRYPTION ON `main` WAS NOT CONFIDENTIAL — the key travelled inside the ciphertext

*Added 2026-09-17. Measured at `8edce9c1`. Fixed by PR #41, on `main` as `63d4945`; everything in
this section up to "Status" describes `main` before #41.*

`CryptoManager::encrypt_message` (`crypto.rs:121`) never used the recipient's key; it only checked
that one was on file. `encrypt_with_aes` generated a random AES-256-GCM key and returned
`key(32) ‖ nonce(12) ‖ ciphertext`. `decrypt_message` (`crypto.rs:161`) read the key back out of
those bytes and never touched a private key.

**Measured by running it.** A throwaway test (not committed) did three things:
- created a sender and a recipient;
- encrypted `"the secret"` for the recipient;
- decrypted the result with a `CryptoManager::new()` that holds **no keys at all**.

It returned `Ok("the secret")`. **Control:** the ciphertext does not contain the plaintext bytes, so
the result is not a plaintext passthrough.

⚠️ **So, before #41, `SecurityLevel::Secure` gave no confidentiality.** Anyone who could read the
bytes (a relay, a mail server, a packet capture) could read the message. The router encrypted this
way on its send path (`router.rs:79`) and in `convert_to_secure_message` (`router.rs:223`).

**When it arrived:** `git log -S` finds the key-in-output line was introduced by `f0f570c` (the
2026-06-12 checkpoint). That commit replaced RSA with Ed25519, which can only sign and cannot
encrypt. **The published 1.1.0 crate never had this flaw:** its `crypto.rs`, read from the
registry copy and from `7b80ca4`, encrypts to the recipient's RSA public key with PKCS#1 v1.5.
That older scheme carries its own advisory, RUSTSEC-2023-0071 (already in the audit list). **No
crates.io consumer has ever received the self-decrypting version.**

**Status: fixed by PR #41 (P2 slice d), on `main` as `63d4945`.** It removes `encrypt_message`, `encrypt_with_aes` and `decrypt_message`. In their place it
seals the body to the recipient's pinned X25519 key with HPKE (RFC 9180 base mode). The sealing key
is generated on its own and is **never** derived from an Ed25519 key; that derivation produces
ciphertext the recipient cannot open (OverMind MEASUREMENTS §20). An independent Python RFC 9180
implementation opened a Rust-sealed message. Design:
`docs/superpowers/specs/2026-09-17-sealing-design.md`. The sealing block on publishing 2.0.0 (recorded 2026-09-17) ended when #41 merged; publishing still
waits on the rest of the 2.0 set and on CireSnave's approval.

#### What this means for a non-Rust agent runtime

> **An MCP stdio surface: PR #39 (P2 slice c), on `main` as `a9dd1d1`.**
> It is the `synapse-mcp` binary, in its own crate `crates/synapse-mcp-server` (package `synapse-mcp-server`; renamed from `synapse-mcp`, whose crates.io name belongs to another project) since M0 (the core crate has no MCP code). Any MCP client, in any language, can `send`, `poll`, `list` and
> `ack` through synapse, and gets sender verdicts and receiver acknowledgement. Keys and peers can
> only be changed in the config file. **Superseded in rc.24 (M6b):** that UDP backend is gone; the same binary now speaks to `synapsed` as one role (tools `send`, `fetch`, `ack`, `list`, `set_summary`, `whoami`; see `docs/API_REFERENCE.md`). Design: `docs/superpowers/specs/2026-09-17-mcp-surface-design.md`.
> Before #39, `main` had no agent-facing surface.

| direction | status |
|---|---|
| **Synapse → foreign process (TCP)** | ✅ **WORKS — measured.** A Python/Node/Go process opening a TCP listener receives clean parseable JSON. No Rust linkage required. |
| **foreign process → Synapse (TCP)** | 🔴 **BROKEN — measured.** Synapse's TCP listener never accepts. |
| **Synapse ↔ Synapse (UDP)** | ✅ **WORKS — measured, both directions of the round trip.** Via the factory path with `bind_port` set. |
| **foreign process → Synapse (UDP)** | ✅ **WORKS — MEASURED.** See Probe D below. |

#### ✅ PROBE D — A PYTHON PROCESS DELIVERED INTO SYNAPSE. NO RUST ANYWHERE ON THE SENDING SIDE.

This is the measurement that closes the multi-provider question, and it was the last row in this
table that was **inferred rather than measured**. It is now measured.

**Sender:** plain CPython 3, standard library only (`json`, `socket`, `uuid`, `datetime`). No Rust,
no bindings, no generated code, no `synapse` crate — the message was hand-constructed from the wire
format observed off a raw socket in Probe B. **Receiver:** Synapse, UDP, via
`UdpTransportFactory` with `bind_port` set.

```
[python]  sending 473 bytes of JSON to 127.0.0.1:47950
[inbound] ***** DELIVERED FROM A NON-RUST PROCESS *****
          from=python-agent@openai.example  to=synapse-node@local
          payload="HELLO-FROM-PYTHON-NO-RUST-LINKAGE"  security=Public
[inbound] RESULT: FOREIGN -> SYNAPSE SUCCEEDED
```

**Payload, sender identity, recipient and security level all survived the crossing.**

##### ⚠️ The encoding detail a foreign client author will get wrong first

Stated as a finding rather than left as an implementation detail of the probe, because **it is
invisible from the Rust side and it is the first thing an independent client implementation would get
wrong.**

**`encrypted_content` and `signature` are JSON ARRAYS OF BYTE INTEGERS, not base64 strings.**

```json
"encrypted_content": [72, 69, 76, 76, 79, 45, 70, 82, 79, 77, ...]   // correct
"encrypted_content": "SEVMTE8tRlJPTS4uLg=="                          // WRONG -- will not deserialise
```

**Why it is invisible from inside the crate:** `SecureMessage` declares these fields as `Vec<u8>` and
serde's default JSON representation of `Vec<u8>` is an array of numbers. Nobody chose it; nobody
wrote it down; it does not appear in any type signature a reader would consult. **A Rust author
reading `Vec<u8>` and a Python author reaching for `base64.b64encode()` will produce incompatible
wire formats and neither will see anything wrong in their own code.**

⚠️ **It is also the expensive convention on the wire, and here the measured numbers differ from the
obvious estimate — so these are measured, not reasoned:**

```
payload  1024 bytes -> json-array  4695   base64  1368     4.58x raw   3.43x base64
payload  8192 bytes -> json-array 37508   base64 10924     4.58x raw   3.43x base64
```

**The array form is ~4.6× raw and ~3.4× base64**, stable across sizes. **Against UDP's 65507-byte
datagram cap, the largest payload whose encoded form alone fits is 14,328 bytes of random data
(14.0 KB) — 15,291 bytes (14.9 KB) for ASCII text**, measured by binary search, and that is *before*
the rest of the envelope (ids, addresses, timestamp, metadata).

⚠️ **So the practical maximum message payload over UDP is about 14 KB, not the 65 KB the
`max_message_size` default (65507) implies.** That is an operational limit produced entirely by an
unrecorded serialisation default, and `max_message_size` measures the wrong thing — it bounds the
datagram, not the payload a caller can pass.

*(I first wrote "roughly 4× larger than base64" here from intuition. Measured, it is 3.43× base64 and
4.58× raw, and the cap is 14 KB rather than the 16 KB I estimated. Corrected in place.)*

**Neither of these is a defect to fix in this pass** — changing the encoding is a wire-compatibility
decision, and the crate is published. They are recorded because **an implementer needs both, and
neither is discoverable from the source without doing what this probe did: reading the bytes off a
live socket.**

⚠️ **What this establishes, precisely:** a process written in any language, running under any model
provider, can both **send to** and **receive from** this fabric using nothing but a UDP socket and a
JSON encoder. **`src/types.rs::SecureMessage` is the de facto schema.** There is still no published
specification and no client library — but neither is required, and the absence of one is now a
documentation gap rather than an architectural blocker.

**Limits, so this is not over-read:** loopback, one message, UDP only. UDP remains lossy and capped
at 65507 bytes, and TCP inbound is still broken (fixed in PR #11, not yet merged). **This is a
working link, not a reliable transport.** Nothing here was tested across machines or through a NAT.

**There is no published wire specification, no schema, and no client library in any language** — but
the format is simple enough to implement from the capture above, and `src/types.rs::SecureMessage` is
its de facto schema. **The blocking defect is the receive path, not the protocol.**

#### The other transports — read, not run, and the speculation I first published was wrong

⚠️ **I originally wrote that `udp_unified`, `quic_unified` and `websocket_unified` "follow the same
`bind-then-spawn-and-bind-again` shape." I had not checked. One of the three does; the other two do
not, and one of them does something worse.** Corrected by reading each `start_server`. The rows
were read at different times, so each says when: **2026-09-09** is the original reading, at #10
(`9f63707`); later rows or updates name their own date and ref.

| transport | as of | server side | verdict |
|---|---|---|---|
| `tcp_unified` | 2026-09-09 at `9f63707`; fixed by #11 (`6e8d058`, 2026-09-09, on `main`) | bound, then re-bound inside `tokio::spawn`, until #11 made it serve the constructor's listener | 🔴 **defect MEASURED end-to-end** (above) at the time; fixed by #11 |
| `websocket_unified` | current: 2026-09-19, branch `feat/transport-contract-b` (PR B, Task 8), not yet on `main` | bound, stored it, then re-bound the same port inside the spawn, until PR B, Task 8 made `start()` bind once and serve that listener | ✅ **fixed; delivers end-to-end over loopback** (PR B, Task 8) |
| `udp_unified` | 2026-09-09 at `9f63707` (the bind is at :77 on 2026-09-19) | binds once at :72, stores `Arc<UdpSocket>`, receive path uses `self.socket` | ✅ **structurally sound** — my speculation was wrong |
| `quic_unified` | 2026-09-09 at `9f63707`; deleted 2026-09-18 by PR A (#44, `b6a1904`) | **did not bind anything** | 🔴 **was a simulation — see below** |
| `http_unified` | current: 2026-09-19, branch `feat/transport-contract-b` (PR B, Task 9), not yet on `main` | had no bind call until PR B, Task 9 made `start()` bind once and serve that listener with `axum` | ✅ **fixed; delivers end-to-end over loopback** (PR B, Task 9) |
| `tcp_simple` | 2026-09-19: deleted in PR B, Task 7 | had no bind call | had no server side |

⚠️ **`websocket_unified` had the same bug, more silently than the TCP one, until transport contract
PR B, Task 8 fixed it.** It stored the real listener, then in the spawned task bound a second one on
the same port and swallowed the failure with `.ok()` — so unlike `tcp_unified` there was **no error
log at all**, and the code comments admitted it:

```rust
tokio::spawn(async move {
    let listener = {
        // We need to move the listener out to avoid borrowing issues
        // In a real implementation, we'd keep the listener in the task
        TcpListener::bind(format!("0.0.0.0:{}", actual_port)).await.ok()   // <-- port in use
    };
    if let Some(listener) = listener { ... while let Ok(..) = listener.accept().await ... }
});
```

⚠️ **`quic_unified` performs no networking whatsoever. It is a simulation that reports success.**
`start_server()` binds nothing and returns `Ok` after logging **`"QUIC server started on {addr}"`** at
INFO. `connect_to_server()` sleeps 50 ms to "simulate connection establishment", fabricates a
`QuicConnection` with a hardcoded `rtt: Some(20ms)`, and stores it. **The file contains no reference
to `quinn` or any QUIC library** — control: `grep -n quinn src/transport/quic_unified.rs` returns
nothing, while `quinn` is present in `Cargo.lock`. Its own comments say so:

```
// In real implementation, this would:
//   1. Configure QUIC server with certificates and crypto  2. Bind to local address ...
// For simulation, just log
```

**So an operator enabling QUIC sees `QUIC transport started` in the logs and has no QUIC.** The
orphaned `src/transport/quic.rs` (740 lines, §5.3) *does* contain a real `endpoint.accept()` loop —
**the working-looking implementation is the one excluded from the build.**

> **Status, 2026-09-18, PR A of the transport contract (PR #44, on `main` as `b6a1904`):** `quic_unified` — **deleted**, and QUIC refuses to
> construct. `websocket_unified`'s double bind — **fixed in PR B, Task 8**, which also added the real
> handshake, send and draining receive; PR A only made its send refuse. The orphaned `quic.rs` is deleted too.

**Still unmeasured end-to-end:** UDP, ~~QUIC~~, ~~email~~. (WebSocket and HTTP are measured over loopback by
`tests/transport_repairs.rs` since transport contract PR B, Tasks 8 and 9.) The table above is a reading of
`start_server` in each, not a round trip. **`udp_unified` being structurally sound is not a claim that
it delivers.**

> **Status, 2026-09-25, the email-transport slice:** email is now measured end-to-end too --
> `tests/transport_repairs.rs`'s `email_direct_mode_carries_a_verified_message_end_to_end` and
> `email_relay_out_mode_receives_via_imap_polling` cover Direct-mode SMTP send/receive and
> RelayOut-mode IMAP polling round trips, plus size limits, backpressure and honest
> capabilities/metrics (`email_refuses_at_send_a_message_over_its_limit`,
> `email_metrics_counts_real_sends`). `async-imap` and `lettre` are non-optional dependencies now
> (no longer gated behind the `email` Cargo feature).
>
> **New finding, recorded rather than fixed here (out of scope for this slice, flagged for the
> project owner):** the wire-format-hand-picking bug class (a component building a `SecureMessage`
> by hand-picking a field into `encrypted_content` instead of parsing/serializing the whole
> structure) was swept across the codebase in parallel with this slice's Task 4. Of 4 instances
> found, 3 are fixed in this slice's commits (NAT traversal, `smtp_server.rs`'s `store_message`,
> `imap_server.rs`); the 4th, `src/email.rs`'s `create_email_message` (reachable via the public
> `SynapseRouter` in `src/router.rs`, which still constructs the legacy `EmailTransport` from
> `src/email.rs`, not `EmailTransportImpl`), is explicitly **out of scope** for this slice and
> pending the project owner's decision -- not fixed, not silently ignored.
>
> **`TransportMetrics::active_connections` for email is a verified `0`, not a default standing in
> for one:** this transport holds no persistent connection or pool in any mode (the SMTP client and
> IMAP session are both constructed fresh per call), so `active_connections: 0` is measured, not
> guessed. But `capabilities().unmeasured_metrics` being empty for this transport does **not** mean
> every `TransportMetrics` field is measured in general: `UnmeasuredMetric` (`abstraction.rs`) has
> only two variants, `AverageLatency` and `ReliabilityScore`, so a transport with a real gap in a
> field outside those two (this one doesn't have one, but the enum itself can't express one if a
> future transport does) would still read `unmeasured_metrics: []`. This is an asserted, documented
> limitation of the honesty-contract enum, not a silent absence.
>
> **`poll_imap_inbox`'s RelayOut/External receive always full-scans (`FETCH "1:*"`) rather than using
> `SEARCH UNSEEN`, and this is correct behaviour today, not a shortcut taken.** Its trigger, stated
> precisely rather than left as a general to-do: this slice's own `SynapseImapServer` (the loopback
> stand-in every test in this slice runs against, per the "no live external provider" constraint) has
> no `SEARCH`/`STORE` support at all, so there is nothing narrower to ask it for — client-side
> dedup (`imap_seen_ids`) is the only option against that server. **The behaviour becomes wrong, not
> merely inefficient, only when External mode is pointed at a real provider** (Gmail, Outlook, etc.)
> that does support `SEARCH UNSEEN`/`STORE +FLAGS`: at that point this full-scan-and-dedup approach
> should be replaced with a real `CAPABILITY` negotiation and narrower fetches. Not fixed here because
> the trigger condition (a real external provider in the loop) does not exist yet in this slice's own
> scope.

> **Status, 2026-09-27, sizing pass (not implemented — banked deliberately, see below):**
>
> ⚠️ **The decision that must be made before this is built, stated first because it is the thing that
> makes this bankable rather than a quick fix: WHEN a fetched message gets marked `\Seen` on the
> server.** Both wrong branches are real:
> - **Too early** (immediately after `FETCH`, before the message is actually handed to the router):
>   a failure between fetch and delivery **silently loses the message** — it will never be fetched
>   again, and nothing else re-delivers it. This is the more dangerous branch.
> - **Too late, or never**: every future `SEARCH UNSEEN` keeps returning the same messages forever,
>   and the optimisation this whole change exists for does nothing.
>
> No answer is proposed here. Naming the decision, and both failure modes, is the deliverable — it is
> not a design call to make mechanically while wiring a protocol change, and it should not be made at
> the end of a long session.
>
> **A framing correction to the entry above, checked rather than assumed**: the entry above frames a
> future fix as needing "a real `CAPABILITY` negotiation." Re-checked against RFC 3501 §6.4.4:
> **`SEARCH` is a MANDATORY IMAP4rev1 command, not an optional extension a server might lack.** Any
> RFC-compliant real provider supports `SEARCH UNSEEN` unconditionally — there is nothing to
> negotiate. The earlier framing was more cautious than the protocol actually requires; correcting it
> here rather than letting it stand as a phantom requirement for whoever eventually builds this.
>
> **Confirmed at no cost**: `async-imap` 0.11 (already the pinned dependency,
> `Cargo.toml`: `async-imap = "0.11"`) already provides `Session::search`, `Session::store`, and
> `Session::fetch` — the client-side library needs nothing added.
>
> **Sizing, read from the code rather than guessed:**
> - `SynapseImapServer` (`src/email_server/imap_server.rs`) has **no `\Seen`-flag concept anywhere
>   today** — `FETCH`'s own `FLAGS` response is hardcoded to always return `FLAGS ()`. Needs: a
>   per-message Seen bit (new field), a new `SEARCH` match arm (minimally parsing the literal
>   `"UNSEEN"`), a new `STORE` match arm (minimally parsing `"+FLAGS (\Seen)"`).
> - **A concrete blocker, not an estimate**: `FETCH`'s sequence-set parser handles only the literal
>   `"1:*"` or a single bare number — a targeted `FETCH` of the specific sequence numbers a `SEARCH`
>   would return **does not parse today** and needs a real upgrade (comma-separated lists at minimum).
> - `poll_imap_inbox` (`src/transport/email_unified.rs`) needs rewriting from one `FETCH "1:*"` call
>   into three steps: `SEARCH UNSEEN` → format the returned sequence numbers into a targeted `FETCH`
>   → `STORE +FLAGS (\Seen)` on each successfully-processed message (timing per the decision above).
>   Whether the existing client-side `imap_seen_ids` in-memory dedup stays as defense-in-depth or is
>   replaced is part of the same decision.
> - At least two new integration tests with real assertions (unseen-only delivery; a second poll
>   after marking confirms nothing re-delivers), not vacuous ones.
> - Rough total: **~300–400 lines including tests** — comparable in scope to a normal single-task PR
>   in this repo, not a quick fix, and not free of a genuine design decision.
>
> **Why banked rather than built now**: this is an optimisation, not a bug fix — `FETCH "1:*"` is
> slow but *correct* today, and stays correct until External mode targets a real provider (the
> trigger already named above). A design decision whose wrong branch silently loses messages is worth
> making deliberately, with time to reason about it, not mechanically at the tail of an unrelated
> session. Slow-and-correct is a better place to sit than fast-and-occasionally-lossy.

> **Status, 2026-09-23, the QUIC slice (branch `design/quic-transport`, not yet on `main`):** QUIC
> is now measured end-to-end too — `quic_carries_a_verified_message_end_to_end` and 12 further tests
> in `tests/transport_repairs.rs` cover the round trip, connection pooling/reuse, size limits, the
> per-stream timeout, and honest capabilities/metrics. Real `quinn` finally in the build:
> `grep -n quinn Cargo.toml` now finds the direct dependency, not just a transitive one.
>
> **New finding from this slice, recorded rather than fixed here (out of scope for QUIC, flagged by
> the PM):** adding `quinn`/`rcgen` surfaced that this crate's dependency graph already carries
> *both* `ring` and `aws-lc-rs` as compiled-in rustls crypto-provider backends (via other,
> pre-existing dependencies) — two backends, two audit surfaces, extra build time and binary size,
> with no single place that decides which one the process actually uses at runtime unless a
> component asks for a specific one explicitly (as the QUIC transport's `quic_tls.rs` now does, via
> `builder_with_provider`, precisely because relying on `CryptoProvider::install_default()`'s
> process-wide, order-dependent behavior would have been silently non-deterministic). Worth a
> dedicated pass to converge the whole crate on one backend; not attempted here.

**Reproducing:** the two probes are ~70 lines each and are not committed (adding a build target is
outside this pass's charter). Probe A: construct two `TcpTransportImpl` via
`TcpTransportImpl::new(&HashMap)` with `listen_port` set on one, `start()` both, `send_message` to
`127.0.0.1:<port>`, then poll `receive_messages()`. Probe B: replace the receiver with a raw
`tokio::net::TcpListener` and `read_to_end`. Run with `RUST_LOG=synapse=debug` — **without it the
causal error is invisible.**

#### Update 2026-09-17: listeners bind loopback unless configured otherwise

*Measured with the Windows Firewall event log. Event 2097 (by `svchost`, "Query User") is written when
a prompt is **raised**; event 2099 (by `dllhost`) is written when someone answers it.*

- **Before the fix:** synapse test runs raised **64 prompts** between 2026-09-17 03:46Z and 06:41Z.
  - 44 came from doc-test `rust_out.exe` binaries. Each doc-test gets a fresh temp path, so every run
    prompted again.
  - The other 20 came from test binaries.
- **The cause:** every listener bound `0.0.0.0`. This affected the UDP, TCP and WebSocket transports,
  NAT traversal, mDNS, and the SMTP and IMAP servers. The email connectivity detector did the same.
  The doc-tests reached these through `EnhancedSynapseRouter::new`.
- **The fix:** `src/network_scope.rs` makes `BindScope::Loopback` the default, and listening on all
  interfaces must be configured (see README, "Network exposure").
  `tests/loopback_by_default.rs` guards the source.
- **Acceptance:** a full `cargo test --no-fail-fast` in a fresh target directory (0 prompts raised between 09:13:34Z and 09:34:37Z at 002f762e, a commit of PR #40, on `main` as squash `05eee3c`; the same query finds 128 prompt events (64 prompts) in the pre-fix window).

### 2.3 What "verified" does and does not mean here

102 passing tests over a 44,562-line crate is thin, and the distribution is skewed: `security_test`
carries 44 assertions across 8 tests, while `multi_transport_integration` has 4 tests and **1**
assertion total, and `registry_integration_test` is 1 test with 1 assertion. Assertion density per file is recorded in §7. **Test count is not coverage** and no coverage run was performed.

---

## 2.4 ⚠️ CI HAS NEVER COMPILED THIS REPOSITORY — NOT ONCE, IN ITS ENTIRE HISTORY

This is the structural explanation for how everything else in this document survived unnoticed.

**The repository has had exactly three GitHub Actions runs, ever:**

```
34368757423  2026-09-09  pull_request  repair/buildable-and-inventory  failure   <- this pass
27432430342  2026-06-12  dynamic       main                            success
27432424608  2026-06-12  push          main                            failure   <- the only real run on main
```

**The only push-triggered run on `main` — at `f0f570c`, the checkpoint commit — failed at step 8 of
16, and everything that matters was skipped:**

```
 6 Install stable toolchain      success
 7 Install wasm-pack             success
 8 Check formatting              FAILURE      <- cargo fmt -- --check
 9 Clippy                        skipped
10 Build                         skipped
11 Run tests                     skipped
12 Build WebAssembly package     skipped
```

⚠️ **`Build`, `Run tests`, `Clippy` and the WASM build have never executed on this repository.** The
run on my own branch (2026-09-09) fails identically, at the same step, with the same four skips —
**two runs, three months apart, same shape.**

**Why the formatting check fails — and ⚠️ MY FIRST ANSWER WAS AN ARTIFACT OF THE INSTRUMENT.**

I originally recorded: *"`cargo fmt -- --check` flags 23 files, all in `examples/` and `tests/`, none
in `src/`."* The set was byte-identical at `f0f570c` and on the repair branch, so the red was
correctly identified as pre-existing. **But "none in `src/`" was false, and so was the portfolio
PM's independently-measured version of the same claim.** When I ran `cargo fmt` to fix it, it did not
format — it **errored**:

```
Error writing files: failed to resolve mod `wasm`: file for module found at both
  "C:\Projects\synapse\src\wasm.rs" and "C:\Projects\synapse\src\wasm\mod.rs"
```

⚠️ **`src/wasm.rs` is 0 bytes and has been since the initial release commit `33f3448` — it has never
held content at any ref** (`git cat-file -s <ref>:src/wasm.rs` → `0` at `33f3448`, `7b80ca4`,
`f0f570c`; it is 0 bytes in the published 1.1.0 crate too). **`src/wasm/mod.rs` is the real module.**
The collision made the module tree unresolvable, **so rustfmt bailed out before it ever reached
`src/`.**

**Two people measured "no `src/` files affected" and both were reading the shape of a crash.** After
deleting the empty file, `cargo fmt` touched **18 `src/` files that have never been formatted in this
repository's history** — including `config.rs`, `router.rs`, `transport/manager.rs`, and the whole of
`synapse/telemetry/`. The true figure is **44 files** (26 under `examples/`+`tests/`, 18 under
`src/`), not 23.

⚠️ **The general shape, which is the transferable part: a tool that fails early reports a SMALLER
population than the truth, and the smaller number looks like good news.** "The formatting problems
are confined to examples and tests" was a more comfortable finding than "the formatter has never
run", and nothing in the output announced the difference. This document previously recorded the
comfortable version. **The `src/wasm.rs` collision was already documented in §5.4 as a predicted
`wasm32` failure — it was in fact breaking the build pipeline on every platform, on every run, and I
did not connect the two until the formatter refused to run.**

⚠️ **The consequence is the important part. `cargo fmt` does not need dependency resolution — it
parses sources and never consults the lockfile — so it runs fine at `f0f570c`, where `cargo build`
cannot resolve at all (§1.1).** The pipeline therefore fails on *formatting* and short-circuits
before it can discover that **the crate does not build**. **The most serious defect in the repository
was invisible to CI because a cosmetic check ran first and failed.**

**This also means every "the build is green" claim in the root status documents (§6) was
uncheckable**: there has never been a CI run that got as far as compiling, and at `f0f570c` a local
build could not resolve either. ⚠️ **Nobody was ignoring a red build signal. There was no build
signal.**

#### Update after the formatting fix: the pipeline advanced one step, and stopped again

Run `34371759050`, head `54c2596` (a commit of PR #10, on `main` as squash `9f63707`), after `src/wasm.rs` was removed and `cargo fmt` applied:

```
 8  Check formatting          SUCCESS   <- first time in this repository's history
 9  Clippy                    FAILURE   <- the new blocker
10  Build                     skipped
11  Run tests                 skipped
12  Build WebAssembly package skipped
```

⚠️ **`Build` and `Run tests` have STILL never executed here.** The heading of this section remains
literally true.

CI runs `cargo clippy -- -D warnings`, so **31 ordinary style and dead-code lints become hard
errors** — 6 × "this `if` statement can be collapsed", 3 × "this operation has no effect", 2 ×
"`map_or` can be simplified", plus unused imports, unused variables and never-read fields.

**They are not introduced by this pass.** Clippy at `7579b56` (PR #10's first commit, before the `cargo fmt` commit) and at
`HEAD` both report *"could not compile `synapse` (lib) due to 31 previous errors"*, and a diff of the
two lint-kind sets is **empty**. `cargo fmt` introduced zero lints.

**They are also not fixed here, for a specific reason:** 8 of the 31 are in
`src/transport/tcp_unified.rs`, the entire subject of the stacked PR #11. Fixing clippy in this
branch would rewrite another author's file under their open PR. Clippy belongs in its own PR once
that file has one owner again.

⚠️ **The structural observation is worth more than the fix: a pipeline that refuses to compile
because an `if` could be collapsed has never told anyone whether the code compiles.** Step 8 was
crashing outright from the first release commit (above) and step 9 gates `Build` behind style. **This
repository has had a CI configuration capable of reporting on everything except the thing it exists
to report on.** That is a CI-design question, not a code question, and it is deliberately left open.

**Remedy is not in this pass's scope** (it changes CI behaviour, and the 23 files are examples and
tests whose fate the merge decides), but the shape is small: the formatting failures are whitespace
and import-order drift, and moving `Check formatting` after `Build`/`Run tests` — or fixing the 23
files — would make the pipeline able to report on the thing it exists to report on.

#### Update 2026-09-17: `Run tests` stopped at the first failing test binary

*Measured locally at `337f7df5` plus the `TransportManager::start` deadlock fix, with
`cargo test --no-fail-fast`.*

- CI ran `cargo test --verbose`. That command stops after the first test **binary** that fails, and
  the known failure is in `transport_error_handling_test`. So every target that sorts after it had
  never run in CI:
  - `transport_manager_starts`, the regression test added with the deadlock fix;
  - `webrtc_transport_integration_test`, which had 0 tests (the empty file was removed 2026-11-26);
  - **all 25 doc-tests**. They pass locally and take about 72 s.
- With `--no-fail-fast` the failing set is unchanged, `{test_transport_error_handling}`. 108 named
  tests and the 25 doc-tests pass.
- ⚠️ **The earlier "107 tests run in CI" was a count of what ran before the stop, not of the
  suite.** A new test file named after `transport_error_handling_test` would have been silently
  skipped in CI.
- CI now runs `cargo test --verbose --no-fail-fast`.

---

## 3. ⚠️ The feature system is decorative — `native` is the only configuration that can compile

**Of the 17 declared features, exactly ONE gates any compiled code.**

Counted over `*.rs` only (`src/synapse/services/registry.rs.bak2` and `registry.rs.fixed` are
tracked in git but are not modules and compile in no configuration; they were inflating my first
count and are excluded):

| feature | `#[cfg(feature = …)]` sites in compiled code |
|---|---:|
| `mdns` | 9 (`transport/discovery.rs`, `transport/mod.rs`) |
| `wasm-logger` | 1 |
| `console_error_panic_hook` | 1 |
| `cache` `database` `email` `crypto` `auth` `http` `networking` `nat_traversal` `wasm` `telemetry` `minimal` `core` `std` `auto_discovery` | **0 each** |

**No module declaration anywhere in the crate carries a feature gate.** The only `cfg` on a `mod` is
`#[cfg(target_arch = "wasm32")] pub mod wasm;`. So `--features minimal` compiles exactly the same
source as `--features native` — it just removes the dependencies that source needs.

Positive control: `src/synapse/storage/mod.rs:4` is a bare `pub mod database;`, and
`src/synapse/storage/database.rs:6` is an unconditional `use sqlx::{PgPool, Row};`. Consequently
`--features minimal` produced 118 compile errors, 103 of them E0432/E0433 "unresolved import / crate
not linked", concentrated in `storage/database.rs` (42), `synapse/auth/mod.rs` (17),
`transport/llm_discovery.rs` (12), `synapse/auth/utils.rs` (12).

**Implication for the merge:** the published feature matrix is fiction. Anyone who does
`synapse = { version = "1.1", default-features = false, features = ["minimal"] }` gets a crate that
cannot compile. The subsystem boundaries the features imply do not exist in the code.

---

## 4. Compiles but unexercised

Everything in this section builds under `native` and has **no test that executes it**. Judged by
absence of any reference from `tests/` — control: `security_test.rs` and `edge_case_test.rs` do
reference the crate's public API, so the query finds tests when they exist.

- **`src/synapse/blockchain/` and `services/trust_manager.rs`** — 7 modules, 3,772 lines, 64 public
  functions. **Split, not uniform.** See the retraction immediately below before quoting anything
  about this subsystem.

#### ⚠️ RETRACTION: I claimed this subsystem had "zero executing coverage." That is FALSE.

I wrote that the trust/staking path "has no executing test at all," and elsewhere that it is "a
consensus and staking implementation that has never executed — not once, in any test, on any path."
**Both statements are wrong**, and I repeated them to three other lanes and to the project owner
before the FAM lane measured it and pushed back. Corrected measurement:

```
module                       own #[test]   exercised by tests/          status
blockchain/staking.rs             9        (self)                       TESTED -- and they RUN
blockchain/block.rs               0        security_test.rs sign_block  PARTIAL
blockchain/consensus.rs           0        none                         0 of 9 pub fns
blockchain/verification.rs        0        none                         0 of 5 pub fns
blockchain/mod.rs                 0        none                         0 of 7 pub fns
services/trust_manager.rs         0        none                         0 of 15 pub fns
```

`staking.rs` has **nine unit tests that execute and pass** — stake, unstake, slash,
validator-selection-by-weight, minimum/maximum/balance rejection. Verified by name in the runner, not
inferred:

```
$ cargo test --lib -- --list | grep staking
synapse::blockchain::staking::tests::test_slash_stake_security_validation: test
synapse::blockchain::staking::tests::test_validator_selection_by_stake_weight: test
... 9 total
```

⚠️ **How I got it wrong: I looked only at `tests/` and never decomposed the 62 lib unit tests by
module.** I reported "62 passing" in §2 and then reasoned about subsystem coverage from the
integration-test directory alone, as though the two were the same population. **A test count you
report but never break down is a number you cannot reason with.** The 9 staking tests were inside my
own headline figure the whole time.

**What survives, and it is still the finding that matters for the merge:** `consensus.rs`,
`verification.rs`, `blockchain/mod.rs` and `trust_manager.rs` — **36 public functions — have no
executing test.** `TrustManager` is referenced only in `end_to_end_integration_test.rs`, which **does
not compile** (§5.5), and there only via `::new()`. ⚠️ **Constructing a type is not exercising it**;
a search for `new(` matches every type in every test and was what produced FAM's own first, inflated
pass. And `security_test.rs:232` explicitly defers the other half of `block.rs`:
`// Test verification requires proper implementation of verify_block_signature` — **signing is
exercised, verification is not.**

For that 36-function remainder the tier point stands: type-checking constrains shape, not agreement,
liveness or safety, which are the only properties a consensus mechanism exists to provide. It is not
"less verified than the transports" but "unverified in a category where the compiler cannot help."

#### ⚠️ RETIER: consensus and verification are not untested — they are UNWIRED

This is a stronger and more specific finding than "no coverage," raised by the FAM lane and verified
here independently. **A textual caller scan across all of `src/`, `tests/` and `examples/` finds 19
public functions with no call site anywhere in the repository:**

```
blockchain/verification.rs   4 of 4   verify_block, verify_transaction,
                                      quick_validate_transaction, batch_verify_transactions
blockchain/consensus.rs      8 of 8   add_validator, remove_validator, start_consensus_round,
                                      process_vote, get_consensus_state,
                                      update_validator_trust_scores,
                                      get_active_validator_count, has_minimum_validators
services/trust_manager.rs    6 of 14
blockchain/mod.rs            1 of 6
```

Positive control: `send_message` matches in 22 files, `unstake_points` in 2, `sign_block` in 1. The
scan finds callers where they exist.

**And the wiring itself confirms it.** Both engines are constructed, stored on the `Blockchain`
struct, and **never read again** — each name appears exactly three times in the whole crate:

```
consensus_engine     mod.rs:79 field decl · :91 construction · :105 struct literal   NEVER READ
verification_engine  mod.rs:82 field decl · :98 construction · :107 struct literal   NEVER READ
control: staking_manager -> 11 occurrences in the same file (a field that IS used)
```

**What actually runs when `start_consensus()` is called** is a `tokio::spawn` timer loop calling
`process_next_block`, which selects a validator by **round robin on the block number**:

```rust
// Select a validator (in production this would use consensus algorithm)
let validator_idx = previous_block.number as usize % validators.len();
```

⚠️ **The source says so itself.** There is no voting, no quorum, no validator set management — the
`ConsensusEngine` that implements those is built and never consulted.

**Be precise about the verification half, because the obvious overclaim is wrong:** blocks *are*
verified. `process_next_block` calls `new_block.verify(Some(&previous_block))` and errors out on
failure. What is unwired is the **`VerificationEngine`** — its four public functions, including
batch and transaction verification, have no caller. So verification is *present inline* and the
dedicated engine is dead.

**Consequence for this document's own scheme: `consensus.rs` and `verification.rs` do not belong in
§4 "compiles but unexercised" — they belong in §5, aspirational.** "Unexercised" implies a wired
component nobody has pointed a test at. These are unreachable from any entry point, so no test
*could* exercise them without new wiring being written first. That is a different problem with a
different cost, and it is the single most important structural fact about this subsystem.

⚠️ **Caveat, stated because it bounds the claim: the caller scan is TEXTUAL.** Dispatch through a
trait object, a macro, or reflection would not match. It is strong evidence, not proof. The
`consensus_engine` / `verification_engine` field evidence is independent of it and points the same
way.

#### The instrument exists and was switched off

`tests/trust_system_integration_test.rs.disabled` — 174 lines, 3 test functions — exercises **exactly
the uncovered surface**: `register_entity_with_stake`, `submit_trust_report`, `calculate_trust_score`,
`get_stake_info`, `start_decay_process`, `stop_decay_process`. Git history (measured by the FAM lane):
it shipped as an **active** test in `33f3448` (v1.0.0) and `7b80ca4` (v1.1.0), and was renamed to
`.disabled` in `f0f570c`, the "commit all local work before machine wipe" checkpoint.

⚠️ **So this is not a capability gap and not an instrument that was never aimed. It was aimed, it
shipped in two releases, and it was switched off during an emergency dump.** The remedy is
correspondingly small: re-enable one file and fix whatever it reports. **Deliberately not done here**
— re-enabling a test changes what the suite asserts, and I was asked to add nothing — but it is the
highest-value single action available in this subsystem.

⚠️ **One caveat that keeps this honest: on `main` NOTHING in the crate executes, because the crate
does not build there (§1). All coverage statements in this document are measured on the repaired
branch. "Zero executing coverage on main" is true of every module in Synapse and is a BUILD fact, not
a coverage fact** — quoting it about the trust layer specifically would make it look uniquely bad
when it was merely part of a crate that did not compile.

**For the merge:** FAM brings a trust model (vouchers and revocations, sequence-based
order-independent resolution) that is tested and mutation-proven. The two models cannot both survive,
and the choice should be made on their merits — **not settled by which repository supplies the
project's name.**
- **`src/synapse/storage/database.rs` / `cache.rs` / `migrations.rs`** — compiles against `sqlx` and
  `redis`. No test connects to Postgres or Redis; `dev-dependencies` pull in `sqlx` with `sqlite`,
  which no test file uses.
- **`src/email_server/`** — `smtp_server.rs`, `imap_server.rs`, `auth.rs`, `connectivity.rs`.
  Compiles. `email_server_demo` example compiles. No test binds a port or speaks SMTP/IMAP.
- **`src/transport/nat_traversal.rs`** — compiles (STUN/UPnP via `stun_codec`, `igd`). Exercised only
  by `examples/real_nat_traversal_test.rs`, which **does not compile** (see §5).
- **`src/synapse/api/`** — `participant_api.rs`, `trust_api.rs`, `discovery_api.rs`. No test.
- **`src/streaming.rs`, `src/monitoring.rs`, `src/circuit_breaker.rs`** — compile; `circuit_breaker`
  has a demo example but no test target.

#### ⚠️ The discovery TXT key `version` means two different things

*Added 2026-09-17, read at `1e6898bd`. Nothing was run.*

- `transport/discovery.rs:133` advertises the **crate** version under `version`. It said `1.1.0`
  until 2.0.0 and now reads `CARGO_PKG_VERSION`.
- `transport/mdns_enhanced.rs:456` and `:1456` advertise `1.0` under the same key, and `:1494` reads
  that key back as `protocol_version`.
- So an `mdns_enhanced` reader that sees a `discovery.rs` advertisement would record a crate version
  as a protocol version. **Nothing compares `protocol_version` today.** Its three hits in `src/` are
  the field, the read and the struct literal. Control: the same query also matches
  `with_protocol_versions` in `quic.rs`. The mix-up is harmless until someone adds a compatibility
  check that reads it.
- It only goes one way: `discovery.rs` never reads TXT records back (`txt_records: HashMap::new()`).
  Not fixed here. The merge decides what the key should mean.

> **Status, 2026-09-18: fixed in PR A of the transport contract (PR #44, on `main` as `b6a1904`).** No `version` key is advertised any more: `discovery.rs` and both
> `mdns_enhanced` advertisements carry `synapse_protocol=1` (the signed wire `protocol_version`), and
> `mdns_enhanced`'s reader reads that key. The crate version is no longer advertised.

---

## 5. Aspirational — does not compile, is unreachable, or is not in the build at all

⚠️ **Also in this tier, documented in §4 where the evidence sits:** `blockchain/consensus.rs` (8 of 8
public functions) and `blockchain/verification.rs` (4 of 4) are **unwired** — no call site anywhere,
and their engines are constructed and never read. They are not "untested"; they are unreachable from
any entry point, so no test could exercise them without new wiring being written first.


### 5.1 `src/auth_integration_enhanced.rs` — written against an API that has never existed

828 lines. Now gated behind `enhanced-auth` (previously compiled unconditionally, which is what made
the *default* build fail). **`--features enhanced-auth` does not compile.** Its `use auth_framework::{…}`
block imports nine items that exist in no published auth-framework:

```
OAuthTokenResponse · TokenToProfile · audit::{AuditEvent, AuditLogger}
compliance::{ComplianceLevel, ComplianceReporter} · config::{AuthFrameworkConfigManager, ConfigManager}
device_flow::{DeviceFlowConfig, DeviceFlowManager} · methods::AuthMethodEnum · storage::PostgreSqlStorage
```

plus four API-shape errors past the imports (`AuthConfig::enable_audit_logging` — no such method;
`&Vec<String>` vs `Vec<String>`; `AuthToken` vs `Box<AuthToken>`; `Credential::enhanced_device_flow` —
no such variant).

⚠️ **The three phantom feature names in §1.1 map one-to-one onto these phantom imports**
(`config-management` → `config::ConfigManager`, `enterprise-features` → `audit`/`compliance`,
`token-to-profile` → `TokenToProfile`). The manifest and the module were written against the same
anticipated auth-framework, and that API was never published. This is the single measurement that
best characterises the project's documentation-to-code gap.

**Not deleted.** Left in-tree, gated, for the merge to dispose of.

#### ⚠️ What the published crate proves about when this happened

I pulled the real `synapse-1.1.0.crate` from `static.crates.io` and extracted it. The published
artifact and this git tree are **different artifacts under one version string**, and the difference
is exactly this module:

| | published `synapse 1.1.0` | git tree @ `f0f570c` |
|---|---|---|
| `src/auth_integration_enhanced.rs` | **not shipped — file absent** | present, 828 lines, live |
| `src/auth_integration.rs` (715 lines) | **live**: `lib.rs:264 pub mod auth_integration;` | **orphaned** — no `mod` declares it |
| `auth-framework` features requested | 2 (`oauth-device-flows`, `enhanced-device-flow`) | 5 (3 of them phantom) |
| `cargo tree --features auth` | **resolves, EXIT 0** | **EXIT 101** |

So the sequence is legible: at publish time the crate used `auth_integration.rs` and asked for two
features that exist. **Afterwards**, `auth_integration.rs` was dropped from `lib.rs` (not deleted —
just unreferenced), `auth_integration_enhanced.rs` was written against an anticipated
auth-framework, and three matching phantom feature names were added to the manifest. The regression
is post-publish, and `cargo publish` never validated the tree that is on `main`.

**Correction to a claim in circulation:** it is *not* the case that the published version also fails
to resolve, nor that `oauth-device-flows` is missing from auth-framework 0.3.0. Measured:
`oauth-device-flows` **is** available in 0.3.0 as the implicit feature of auth-framework's optional
dependency of that name — `cargo` lists it, and the published tree resolves with it, exit 0. It is
also not the case that `auth` is a non-default feature: `default = ["native"]` and `native` includes
`auth`, so the broken path was the default one. (Reading the index's `features` map alone hides
implicit optional-dependency features; that is the trap here.)

**Still unmeasured:** whether the published `auth_integration.rs` *compiles* against auth-framework
0.3.0. The published tree's `--features auth` build fails first in `redis 0.24.0` (§9), a transitive
dependency, before reaching any Synapse code. So "the published auth worked" is **not** established
either — only that it resolved.

### 5.2 The `enhanced-auth` feature gated nothing, while a README told users to enable it

`Cargo.toml` declared `enhanced-auth = []` — empty, referenced by no `cfg` anywhere — while
`src/synapse/auth/README.md:21` instructs `cargo build --features enhanced-auth`. That command was a
no-op. It is now wired to §5.1 and documented as known-broken.

### 5.3 17 source files — 8,062 lines — are in no configuration's module tree

Not orphaned "modules"; **files that no `mod` declaration ever names**, so they compile never.
Control: `mod tcp_unified;`, `mod udp_unified;`, `mod websocket_unified;`, `mod crypto;` each return
exactly 1 declaration; the files below return 0.

| file | lines | note |
|---|---:|---|
| `src/transport/nat_traversal_clean.rs` | 1159 | |
| `src/transport/quic.rs` | 740 | **QUIC transport — no QUIC in any build** |
| `src/auth_integration.rs` | 715 | ⚠️ **see note below — this is the file that shipped** |
| `src/transport/email_unified.rs` | 710 | |
| `src/transport/websocket.rs` | 588 | |
| `src/wasm/storage.rs` | 572 | |
| `src/wasm/websocket.rs` | 450 | |
| `src/wasm/webrtc.rs` | 443 | |
| `src/wasm/browser.rs` | 442 | |
| `src/transport/tcp.rs` | 434 | |
| `src/wasm/crypto.rs` | 396 | |
| `src/wasm/worker.rs` | 389 | |
| `src/transport/tcp_enhanced.rs` | 334 | imported by a demo that therefore fails — §5.5 |
| `src/transport/udp.rs` | 320 | |
| `src/transport/email_enhanced.rs` | 313 | imported by a demo that therefore fails — §5.5 |
| `src/transport/discovery_test.rs` | 57 | |
| `src/types_new.rs` | 0 | empty; removed 2026-11-26 |

⚠️ **`src/auth_integration.rs` is not just another orphan, and the reason is a selection criterion
worth stating explicitly because it is easy to lose.** It is the module the **published** crate
declares (`lib.rs:264`), so it is **the only Synapse auth code that plausibly ever compiled against a
real auth-framework.** The currently-imported module, `auth_integration_enhanced.rs`, never did (§5.1).
So if auth survives the merge, *this* is the file to map forward to a current auth-framework —
**"the file that actually shipped" is a better selection criterion than "the file that is currently
imported,"** and the two point at different files here. Retrieve with
`git show f0f570c:src/auth_integration.rs`.

### 5.4 WASM is a 26-line stub, and would not compile on `wasm32` if attempted

`src/wasm/mod.rs` is 26 lines: it declares `pub mod simple;` (109 lines) and a non-WASM `stub` module
whose `WasmSynapseNode::new()` returns `Err("WebAssembly support only available in WASM builds")`.
The six real WASM implementation files (2,692 lines — browser, crypto, storage, webrtc, websocket,
worker) are in §5.3: unreachable.

⚠️ Additionally **`src/wasm.rs` (0 bytes) and `src/wasm/mod.rs` both exist.** That is a hard rustc
error (`file for module 'wasm' found at both …`) on any `wasm32` target — **and, discovered later,
it also broke `cargo fmt` on EVERY platform, which is why CI never reached its build step (§2.4).
`src/wasm.rs` is removed on this branch.** I recorded this defect as a *prediction about wasm32*
before realising it was already causing a *measured* failure on the host, in the pipeline, on every
run. **A defect scoped to a platform nobody builds for was the one blocking the platform everybody
builds on.** `Cargo.toml` declares
`crate-type = ["cdylib", "rlib"]` (as of this pass; `cdylib` was dropped in M2, synapse#66, because on Windows it collided with the `synapse` CLI binary's `synapse.pdb` and the root wasm-pack path it served was not working), a `wasm` feature, `Cargo-wasm.toml`, `build-wasm.sh` and
`build-wasm.bat`. **No wasm32 build was attempted in this pass** — recorded as unmeasured, not as
working.

### 5.5 Targets that do not build

- `examples/multi_transport_circuit_breaker_demo.rs` — imports
  `synapse::transport::{EnhancedTcpTransport, EmailEnhancedTransport}`, which live in the
  **unreachable** files `tcp_enhanced.rs` / `email_enhanced.rs`. 6 errors.
- `examples/real_nat_traversal_test.rs` — `TransportTarget` has no field `metadata`. 2 errors.
  (Not declared in `Cargo.toml`; only reached via `--examples`.)
- `tests/comprehensive_feature_test.rs` — **137 errors** (`SimpleMessage`, `MessageType`,
  `SecurityLevel` not in scope). 12 tests, 31 assertions, none of which have ever run.
- `tests/end_to_end_integration_test.rs` — 44 errors (unresolved `synapse::identity::{Identity,
  KeyPair}`, `synapse::transport::{TransportError, TransportResult, MessageDeliveryStatus}`; and
  `get_id`/`send` declared as members of trait `Transport` that the trait does not have).
- `tests/browser_compatibility_test.rs` — 23 errors. It is a **wasm32-only** file (7
  `#[wasm_bindgen_test]`) that is not gated to `cfg(target_arch = "wasm32")`, so the host test run
  tries to compile it. See §7.

### 5.6 Empty and disabled files that read as coverage

Four test files were **0 bytes** (removed 2026-11-26, when the SUP-016 licence gate made headerless files fail CI) — they appeared in `ls tests/` and in any file-count, and contained
nothing:
`high_load_test_new.rs`, `multi_transport_integration_new.rs`, `registry_integration_test_new.rs`,
`webrtc_transport_integration_test.rs`.

Two are renamed out of the build: `trust_system_integration_test.rs.disabled` (the only
trust-system test) and `webrtc_transport_integration_test.rs.disabled`.

Also 0 bytes at repo root: `WINDOWS_LINKER_WORKAROUND.md` (which the README links to as a "detailed
guide"), `build-debug.ps1`, `test-build.ps1`.

`examples/` holds 33 `.rs` files; `Cargo.toml` declares 15. The other 18 are built only by
`--examples` and are unmeasured.

---

## 6. The README asserts properties the code does not have

Not a stylistic complaint — these are specific, checkable claims:

| README claim | measured |
|---|---|
| `auth_manager.authenticate_ai_agent_webauthn(...)` (§"AI-Native Authentication") | **no such symbol in the crate.** Control: `EnhancedSynapseRouter` returns 4 hits. |
| `auth_manager.authenticate_saml_enterprise(...)`, "SAML 2.0 Corporate SSO" | **no such symbol.** No SAML implementation exists. |
| "🔐 WebAuthn Passwordless: AI agents authenticate using hardware security keys" | no WebAuthn code, no WebAuthn dependency in `Cargo.toml`. |
| "📋 Advanced Audit Trails: Complete compliance logging for GDPR, HIPAA, SOX" | the only `audit`/`compliance` references are the **phantom imports** of §5.1. |
| "The first and only authentication system designed specifically for AI agents" | the auth integration module does not compile. |
| Windows §: "This **has been resolved** using LLVM's `lld-link`" | that config is what made the repo unbuildable on a stock toolchain (§1.2). Links to `docs/WINDOWS_LINKER_WORKAROUND.md`; the root copy is **0 bytes**. |

Eight root-level `*_COMPLETE.md` / `*_AUDIT_*.md` / `*_FINAL.md` / `*_SUMMARY.md` reports assert
completion of work that, at `f0f570c`, could not be compiled. **No claim in any of them was treated
as evidence for this inventory.**

### 6.1 ⚠️ `AUTH_FRAMEWORK_INTEGRATION_SUMMARY.md` — a success frame around the change that broke the build

This distinction matters for the remedy: a document that was true and drifted deserves a supersession
banner; one that was never true is a different and worse defect. This one is the latter, and it can
be shown rather than argued.

The document is titled **"🚀 Integration Complete"** and states, as accomplished work:

> *"Updated from auth-framework v0.3 to v0.3.0 with latest features. Added new feature flags:
> `config-management`, `enterprise-features`, `token-to-profile`"*

**Those three feature flags have never existed in any published version of auth-framework** (§1.1 —
all nine versions, 0.1.1 through 0.5.0-rc19; and absent from the crate's unpublished `main` at rc24
per the auth-framework lane's own check with controls).

⚠️ **Precision matters here, and my first wording overreached.** I originally wrote "there is no
point in time at which this paragraph was true." That is wrong as stated: the sentence *"Added new
feature flags: config-management, enterprise-features, token-to-profile"* is **literally accurate** —
those three names really were added to `Cargo.toml`. **The document describes the edit correctly.
What is false is the frame: that the edit constitutes an "Integration Complete", an upgrade "to
latest version with latest features", and a working state.** The edit it accurately reports is
precisely the edit that made the crate unresolvable in every configuration (§1.1). Credit to the
Claim Auditor lane for the distinction — *the change is described faithfully and the change is what
breaks the build* is a sharper and more defensible finding than "the document is false."

So the defect is not a false report of an action; it is **a success frame wrapped around an action
that failed**, published in the same commit as the breakage.

Two further internal tells, independent of anything outside the file:

- *"Updated **from auth-framework v0.3 to v0.3.0**"* — those are the same requirement. The document's
  own headline upgrade is a non-event.
- Its "Next Steps" instructs `cargo run --example auth_framework_v3_demo --features auth,core`.
  **That command could never have run**, for the same reason: `--features auth` did not resolve.

It also lists `src/auth_integration_enhanced.rs` under "Files Created" — the module that has never
compiled (§5.1). **The document, the module, and the three phantom feature names are one artifact
written against an imagined API**, and the document asserts all three as finished.

The remaining seven root reports were not individually adjudicated; this one was, because §1.1 gave
it a decisive test. **Do not generalise this verdict to the others** — they may well be the ordinary
historical kind.

---

## 7. Assertion density (for the merge's triage)

Host tests (`#[test]` / `#[tokio::test]`, including attribute forms with arguments), WASM tests
(`#[wasm_bindgen_test]`), and `assert*!` count per file:

```
FILE                                 host  wasm  asserts   status
security_test.rs                        8     0       44   runs, all pass
comprehensive_feature_test.rs          12     0       31   DOES NOT COMPILE
end_to_end_integration_test.rs          1     0       13   DOES NOT COMPILE
edge_case_test.rs                       8     0       10   runs, all pass
basic_integration_test.rs               4     0        7   runs, all pass
browser_compatibility_test.rs           0     7        7   DOES NOT COMPILE (host) -- see below
transport_error_handling_test.rs        3     0        5   runs, 1 FAILING
concurrent_registry_access_test.rs      4     0        4   runs, all pass
high_load_test.rs                       2     0        4   runs, all pass
network_partition_test.rs               3     0        2   runs, all pass
multi_transport_integration.rs          4     0        1   runs, all pass
integration_test.rs                     3     0        1   runs, all pass
registry_integration_test.rs            1     0        1   runs, all pass
                                     ----  ----
                                       53     7
```

`browser_compatibility_test.rs` is a **wasm32-only** test file: its 7 tests are
`#[wasm_bindgen_test]` and it uses `#[wasm_bindgen]`. It is not gated to `cfg(target_arch =
"wasm32")` and carries no `wasm-bindgen-test` import path that resolves on the host, so `cargo test`
on this machine tries to compile it and fails with 23 errors (`cannot find attribute
wasm_bindgen_test in this scope`). **Its 7 tests have never run here and would need a wasm32 test
runner.** That is a target-gating defect, not broken logic.

⚠️ **A correction to my own first pass, recorded because the wrong version is the more alarming
one.** I initially counted test attributes with a regex that required `#[test]`/`#[tokio::test]` to
be followed by `]`, which silently missed the argument form. It reported `high_load_test.rs` as
having *4 assertions and zero test attributes* — i.e. a file that can never fail. **That was false.**
`high_load_test.rs` has two real tests:

```
tests/high_load_test.rs:9   #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
tests/high_load_test.rs:87  #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
```

which is exactly the "running 2 tests" `cargo test` reported for that target. The tell that something
was wrong was the mismatch between my static count (0) and the runtime count (2); a static count with
no runtime number beside it would have shipped the false claim. **Prefer `cargo test`'s own per-target
counts over any grep.**

---

## 8. Changes made in this pass

Four edits, all narrow, none adding a feature or changing behaviour:

1. `Cargo.toml` — removed 3 never-existent `auth-framework` features. **Unblocked all 10 configs.**
2. `.cargo/config.toml` — commented out the forced `lld-link`, reasoning preserved in-file.
3. `src/lib.rs` + `Cargo.toml` — gated `auth_integration_enhanced` behind the pre-existing (and
   previously inert) `enhanced-auth` feature; marked it known-broken in the manifest.
4. `src/auth_integration_enhanced.rs` — header rewritten to state, with the measurement, that it has
   never compiled against a real auth-framework. **No code changed.**

Deliberately **not** done, because the merge decides: the `auth-framework` 0.3 → 0.4/0.5 upgrade; the
failing `test_transport_error_handling`; the 17 unreachable files; the 3 non-compiling test targets;
the WASM double-module; the README's claims; the `.bak2`/`.fixed` files tracked in `src/`.

---

## 9. Known-unmeasured

Stated so nobody reads silence as a pass:

- No `wasm32-unknown-unknown` build attempted (§5.4 predicts a hard failure).
- No coverage instrumentation. No clippy run. No `cargo audit` / advisory scan.
- The 18 undeclared files in `examples/` were not compiled.
- `cargo doc` not run; the crate-level doctests in `src/lib.rs` were exercised only insofar as
  `cargo test --lib` ran them — the large doc examples there are mostly commented out internally.
- No behaviour was verified against a live network, SMTP/IMAP server, Postgres, or Redis.
- Transitive-dependency health: `net2 v0.2.39` is flagged future-incompatible by cargo.

- ⚠️ **`redis 0.24.0` vs `0.24.1` — a one-patch-version difference decides whether the auth path
  builds, and my first explanation of it was wrong.** `auth-framework 0.3.0` has
  `default = ["redis-storage"]` and Synapse does not pass `default-features = false`, so enabling
  `auth` pulls a `redis ^0.24` **in addition to** the `redis 0.32.x` that the `cache` feature
  selects — the ranges are disjoint, so cargo builds *both*. Measured:

  ```
  git tree @ f0f570c, --features native : redis v0.24.1  +  redis v0.32.7   -> COMPILES (lib EXIT 0)
  published synapse 1.1.0, --features auth : redis v0.24.0                  -> FAILS
      redis-0.24.0/src/script.rs:{150,176}  4x error[E0277] `!: FromRedisValue`  (never-type fallback)
  ```

  **`0.24.0` does not compile on rustc 1.100.0-nightly; `0.24.1` does.** The published crate ships a
  `Cargo.lock` pinning `0.24.0`, which is why the published tree fails there and this tree does not.

  I earlier recorded the cause as "`redis 0.32.4` is selected via the `cache` feature." **That was an
  inference and it was wrong** — both versions are in the graph, so the `cache` feature does not
  displace anything. The FAM lane flagged the discrepancy; the actual discriminator is the patch
  version in the lockfile.

  ⚠️ **And the failure is UNREACHABLE FOR DEPENDENTS, which is stronger than "lockfile-aged."**
  Measured by the FAM lane on a scratch crate depending on `synapse = "1.1.0"`: `cargo tree -i redis`
  reports `redis@0.24.1` + `redis@0.32.7` — not `0.24.0`. Control: `cargo tree -i auth-framework`
  resolves the chain `auth-framework 0.3.0 -> synapse 1.1.0 -> probe`. **A crate's bundled
  `Cargo.lock` is authoritative only when it is the top-level package; as a dependency it is
  ignored.** So `0.24.0` is reachable only by extracting the `.crate` and building it standalone —
  which is what I did. **No consumer of synapse 1.1.0 has ever seen this failure**, and it is not
  evidence against auth-framework 0.3.0 at all.

  **Isolated control**, built by the auth-framework lane on a two-file scratch crate — no Synapse
  tree involved, same toolchain, same features auth-framework 0.3.0 requests (`aio`, `tokio-comp`),
  only the version requirement differing:

  ```
  redis = { version = "0.24",   features = ["aio","tokio-comp"] }  -> resolves 0.24.1  EXIT 0
  redis = { version = "=0.24.0", features = ["aio","tokio-comp"] } -> 4x E0277         EXIT 101
  ```

  The control fires under one hypothesis and not the other, and the error signature matches the one
  seen here exactly. auth-framework 0.3.0 declares `redis = "^0.24"`, which admits `0.24.1`.

  **The transferable rule: "does the published artifact build?" is two questions, not one, and the
  answers can disagree.** Built standalone, its bundled lock decides; built as a dependency, the
  top-level resolve decides and its lock is discarded. Testing a published crate by extracting and
  building it measures a configuration that exists only in the tester's directory.
