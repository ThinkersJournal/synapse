# The agent-facing MCP adapter in Synapse's first public release (design note)

**Status:** DRAFT for PM review. Docs only; no code. Nothing here is built by this PR.
**Ruling (CireSnave 2026-10-12, verbatim, relayed by the PM):** *"The agent-facing MCP adapter ships in
Synapse's first public release."* Pure Rust (EXPECTATIONS 5.1b).
**Read at:** `ciresnave/synapse` `origin/main@3b58babe` (6.0.0-rc.34); FAM `origin/main@5111f2b`
(`DESIGN-SYNAPSE-HANDOVER.md`, itself measured on 2026-09-09 at FAM `7978588`); claude-peers
`c1210c6` (2026-08-20, its working tree on this box). Anything not read at those refs is marked
**UNVERIFIED**.

## 0. Summary

1. **The adapter is not a new build; most of it exists.** `synapse-mcp-server` (generic tools),
   `synapse-claude-channel` (push) and `synapse-client` are on main and the channel push has run live
   (M1, c7, soak phase 1). This note is about the gap between that and "ships in the public release".
2. **Four things stand between rc.34 and a public release of the adapter**, in the order they bite:
   1. **`synapse-client` cannot be published under that name.** crates.io `synapse-client` is owned by
      another user (`krypticmouse`, "Rust client SDK for Synapse memory runtime", 0.1.0). Both adapters
      depend on it, so neither can be published until it is renamed (§5.1).
   2. **FAM's trap 4a is partly inherited.** The adapter acks on bounded delivery attempts, which is a
      sender-side ack of a notification nobody confirmed (§3, row 4a). This was a measured, PM-ruled
      trade for Claude Code (rc.33) and is right for that client; it is **not** a safe default for a
      client that has no handler at all (§4.2).
   3. **The push loop and the ack policy live in the Claude-specific crate.** A second renderer today
      means copying them (§2, §5.3).
   4. **No client other than an rmcp one has ever talked to the adapter.** FAM's trap 4b says that is
      the instrument that finds sibling-branch divergence (§3, row 4b).
3. **The FAM "above the seam" list (sealing, identity resolution, replay suppression, vouched chain) is
   not on the local mailbox path** and does not need to be for a loopback daemon. It must be wired
   before any cross-machine delivery ships, and the public release must not imply otherwise (§3, row 3).
4. **Estimate:** 5 PRs of mine for the adapter, about 4-5 lane-days, plus the cut-over PRs that are not
   mine (§7). These are estimates, not measurements.

## 1. What exists today (read at 3b58babe)

| Piece | Where | What it is |
|---|---|---|
| Core | `src/` (`synapse`) | `keystore`, `roles`, `mailbox` (+ `RedbStore`), `certificate`, `sender_auth`, `replay`, `sealing`. No rmcp, no MCP types; guarded by the model-agnostic job |
| Daemon | `crates/synapsed` | One per user per machine, loopback HTTP `/v1/{claim,send,fetch,ack,heartbeat,list,stats}`, session token per claimed role |
| Client | `crates/synapse-client` | Blocking `Daemon::connect` (announce file, HMAC health proof, auto-start), claim, session cache, role lock |
| Generic MCP adapter | `crates/synapse-mcp-server`, bin `synapse-mcp` | stdio MCP server, tools `send`, `fetch`, `ack`, `list`, `set_summary`, `whoami`; every tool description carries the untrusted-text wording |
| Claude Code adapter | `crates/synapse-claude-channel`, bin `synapse-claude-channel` | Wraps the same tool router, declares `experimental."claude/channel"` **and** `tools`, caps protocol at 2025-11-25, and runs a 1 Hz lease/push loop |
| Public HTTP endpoint | designed, not built | `2026-10-07-public-mcp-endpoint-design.md`; shares the mailbox, adds a network listener. Separate from this note |

Facts I read that the design below leans on:

- `synapse-claude-channel/src/lib.rs`: the push loop (`push_once`), `PushLedger`, `should_ack`,
  `channel_params`, `escape`, `CHANNEL_METHOD`, `MAX_PROTOCOL`, `INSTRUCTIONS`, and the `Notifier`
  trait all sit in the Claude crate. `Notifier::notify(params: Value)` is the only seam.
- `synapse-mcp-server/src/lib.rs`: `SynapseMcpServer::pull` and `confirm` exist **for** the push
  adapter ("For adapters that push instead of waiting for the model to poll").
- `synapsed` `send`: the envelope is `{message_id, to, from, body}`; `from` is the session's role, a
  client-supplied `from` is refused. `fetch` returns `{message_id, from, body_b64, enqueued_at,
  lease_until, attempts}`. There is no signature, `sealed` flag or verdict in that payload.
- A grep of `src` and `crates` for `sealing::` and `seal(` finds `src/sealing.rs`, `router_merged.rs`,
  `transport/*`, `crypto.rs`, `keystore.rs` and `sender_auth.rs`, and **nothing** in `mailbox.rs`,
  `synapsed` or `synapse-client`. The positive control is that the same grep finds `src/sealing.rs`.
- A grep for `claude|anthropic` in `crates/synapsed`, `synapse-client` and `synapse-mcp-server` finds
  one hit, a doc comment in `synapsed` ("claude-peers replacement plan"). The agnostic guard holds.

## 2. Layer boundary

```
 agent runtime (Claude Code, any MCP client, a Python script ...)       <- NOT ours
        ▲ MCP over stdio: tools (pull) + one declared push capability (push)
 ┌──────┴─────────────────────────────────────────────────────────────┐
 │ INJECTION ADAPTER   synapse-mcp-server (+ one renderer crate each) │
 │   tools, untrusted-text framing, push loop, ack policy, rendering  │
 └──────▲─────────────────────────────────────────────────────────────┘
        │ synapse-client (blocking, proves the daemon, one session per role)
 ┌──────┴─────────────────────────────────────────────────────────────┐
 │ TRANSPORT CORE      synapsed + synapse (lib)                       │
 │   identity, roles/epochs, signing, mailbox, lease/ack, presence    │
 └────────────────────────────────────────────────────────────────────┘
```

**The boundary is the daemon's HTTP API, and the adapter holds no key.** That is already true
(`synapse-mcp-server` header: "The adapter holds no key"). Rules that keep it true:

- The core never learns what rendered its message. No field, route or counter names a client product.
- The adapter never makes a delivery decision the daemon could make. It may *choose when to ack*
  (below) but the ack, lease, epoch and dedupe are the daemon's.
- A wire format is portable; its **method name and rendering are the client's behaviour** (the
  FAM handover, section 1: *"Any runtime can receive it; whether it does anything with it is the
  runtime's problem"*). So the adapter treats `notifications/claude/channel` as one **renderer**:

```rust
// In synapse-mcp-server (no product names). Sketch, not final.
pub trait Renderer: Send + Sync + 'static {
    /// Declared at `initialize`: `experimental.<key>` (e.g. "claude/channel").
    fn capability_key(&self) -> &str;
    /// The notification method, derived from the key the way FAM's Python client does:
    /// `"notifications/" + key` unless the client's behaviour differs.
    fn method(&self) -> &str;
    /// Highest protocol revision this renderer can be delivered on (M1: 2025-11-25 for Claude Code).
    fn protocol_cap(&self) -> ProtocolVersion;
    /// Server `instructions` text (trusted; says what repeats mean and how to ack).
    fn instructions(&self) -> &str;
    /// One message in, notification params out. Receives the SAME view the `fetch` tool shows.
    fn render(&self, message: &MessageView) -> serde_json::Value;
    fn ack_policy(&self) -> AckPolicy;
}
pub enum AckPolicy {
    /// Only the receiver's `ack` removes a message; the adapter never does (FAM 4a, the default).
    ReceiverOnly,
    /// rc.33 for Claude Code: the adapter acks after a successful write once the daemon's
    /// `attempts >= max` AND this process wrote it at least twice. Bounded ATTEMPTS, not delivery.
    BoundedAttempts { max: u32 },
}
```

`synapse-claude-channel` then shrinks to a `ClaudeChannel: Renderer` (the method name, the `meta`
shaping, the `<channel>` entity escaping, the 2025-11-25 cap, its instructions) and a 30-line `main`.
`PushLedger`, `should_ack`, `push_once`, the tick loop and `Notifier` move to `synapse-mcp-server`
under a `push` module. **The existing `tests/channel.rs` is the proof of "no behaviour change":
it must pass unchanged.**

## 3. FAM's measured traps against the Rust adapter

Status is at 3b58babe. "Met" means I read the code that does it; it does not mean a foreign client
confirmed it.

| FAM item | What the rewrite must do | Status | Evidence / what is missing |
|---|---|---|---|
| §1 injection is the runtime's job | Say so; do not claim delivery to the model | **Met** (docs) | `synapse-claude-channel` header: "Claude Code gives no confirmation that an event was shown"; soak result check 7 (p1-0003 acked, no event in the transcript, n=1) |
| §2 capability negotiated, not a private method name | Declare at `initialize` | **Met** | `get_info`: `enable_experimental_with({"claude/channel": {}})` + `enable_tools()`; pinned by `tests/channel.rs` (init result asserts both) |
| §2 Python SDK fixes bindings at construction, so discovery needs a reconnect | Advertise out of band too; keep a pull floor | **Partly** | Pull floor exists (`fetch` tool). Nothing advertises the push method outside `initialize`. Proposed: `whoami` reports `push: {capability_key, method}` and the instructions name it |
| §2 SDKs disagree on unknown notifications (Python drops at DEBUG) | Do not let a silent drop destroy mail | **NOT met** | See row 4a. A Python-style client with no binding gets 3 pushes, then the adapter's ack. **UNVERIFIED by a live run**; derived from `should_ack` + `push_once` |
| §3 three callbacks + one payload; name the payload for the message, not the pipe | A message type independent of transport | **Mostly** | `Envelope` / daemon `fetch` JSON name no socket. But the push payload is built from the JSON `Value` with string keys (`message["from"]`, `message["body"]`), not a type, which is the drift hazard FAM recorded at `types/index.ts:388`. Proposed: `MessageView` struct, §5.2 |
| §3 above-the-seam list: sealing, identity resolution, replay, vouched chain | Carry, or say plainly it is not carried | **Not on this path** | Core has `sealing`, `sender_auth`, `replay`, `certificate`; the daemon path does not call them. Loopback trust is "the daemon's word": `from` = the session's role, tokens are kept as SHA-256 hashes, `Host` is checked, claims need a certificate chain. That is the local boundary and is stated in the plan §3. **Before any cross-machine delivery, sealing and sender verdicts must be wired**; until then no adapter text may say `verified` or `sealed` about a message. The pushed frame today says only "UNTRUSTED message from {from}", which is accurate |
| §3 "re-earning this layer will not announce itself" | A test that fails if a message flows without the layer | **Missing** | Proposed: a guard test that the adapter's rendered text never contains the words `verified`/`sealed` unless the daemon payload carries the field |
| §4a the ack belongs to the receiver | The receiver acks; the transport gives it something to ack with | **PARTLY INHERITED** | The `ack` tool and `meta.message_id` give the receiver the means. But `push_once` calls `source.confirm(id)` after a *successful write*; `Notifier::notify` returns `Ok` when `send_notification` returns, which is "written to the pipe" and nothing more (FAM's exact wording). That is the sender-side ack FAM measured destroying a backlog, bounded to ≥ 2 local pushes and daemon `attempts >= 3`. Measured reason: 0 of 5 unprimed Claude trials called `ack` (rc.33 amendment). Right for Claude Code; **wrong default for an unknown client** (§4.2) |
| §4b a guard on one branch, not its sibling | One method both paths call; a foreign client from the start | **Partly** | Both paths start from `synapse_client::inbox_line`. They then diverge: the `fetch` tool uses `message_view`/`safe_text` (keeps `body_b64`, all daemon fields, leaves `<`/`>`), the push uses `channel_params`/`escape` (drops `enqueued_at` and `attempts`, entity-escapes `<`/`>`). The `<`/`>` difference is deliberate (the push is inside a tag). Nothing pinned that both agree on id, sender and body for the same input (rc.36: `MessageView` and `tests/message_paths.rs` now do). Every test client is rmcp, the same SDK as the server: FAM's "native client's habits hide the divergence" |
| §5 config dir and data store differ by a suffix | Do not | **Met** | One home (`SYNAPSE_HOME`, else `%LOCALAPPDATA%\synapse`, else XDG) holds the keystore and `mailbox.redb`; `Daemon::connect` refuses a squatter. No schema or version marker in `src/mailbox.rs` (grep `version|schema`: 0 hits; the same grep finds 1 in `src/keystore.rs`). **UNVERIFIED:** what happens when an older rc's `mailbox.redb` is opened by a newer layout |
| §6 first-run traps | A fresh box works from the docs | **UNVERIFIED** | The binary is `synapse` (crate `synapsectl`); error text says `synapse id` / `synapse claim`, which matches. I have not run a cold first-run from the README on a clean home. Task in §5.5 |
| §7 not demonstrated: an agent | Say what was and was not shown | **Open** | Soak phase 1: n=5 Claude trials, one model, one wording. Untested (HANDOFF): a model acting once on a real request, a missing `message_id`, a refused adapter ack (#119-#121) |

## 4. Decisions this note asks for

### 4.1 Rename `synapse-client` (blocks publishing)

- **Measured 2026-10-12:** `GET https://crates.io/api/v1/crates/synapse-client` returns 200, owner
  `krypticmouse`, description "Rust client SDK for Synapse memory runtime", repository
  `krypticmouse/synapse`. Positive control: `serde` 200. Same query: `synapse-mcp-server`,
  `synapse-claude-channel`, `synapsed`, `synapsectl`, `synapse-security` all 404 (available).
  `synapse` is ours (1.1.0, owner `ciresnave`).
- **Recommendation:** rename to **`synapsed-client`** (404 on 2026-10-12; it is the client *of
  `synapsed`*, which is what its Cargo description already says). Other 404 candidates:
  `synapse-daemon-client`, `synapse-mailbox-client`. The directory, the `use synapse_client` imports
  and the path deps change; the bump places go from fourteen to the same number.
- A free name can be taken before publish; whether to reserve the final names early is CireSnave's
  call, not this note's. *Blocks the public release; does not block anything else.*

### 4.2 What the adapter does when the client never acks

rc.33 is a PM ruling on a measured Claude Code behaviour and **this note does not reopen it for
Claude Code.** The question is only what the *generic* renderer does, which has no measurement.

- **Recommended:** `AckPolicy::ReceiverOnly` is the default; `BoundedAttempts` is opted into by the
  Claude renderer, which carries the measurement. For a receiver-only client the adapter stops
  *pushing* after `max` attempts (push-count in the ledger), and the message stays pending, still
  returned by the `fetch` tool. Loss is then impossible by the adapter's hand; the cost is a message
  that sits until the client's `fetch` or `ack`. **Complication:** the push loop leases to read a
  message (`pull`), so a message it has stopped pushing is still re-leased every tick and hidden from
  the model's own `fetch` for `lease_secs`; PR 4 needs either a daemon-side non-leasing peek or a
  parked state, which makes PR 4 a daemon change too (§7). That is the rc.32 behaviour, whose problem (every new
  Claude session re-pushed unacked mail, n=5) is specific to a model that never acks.
- **Alternative:** one policy for all renderers (today). Simplest; keeps FAM's measured loss for any
  client that registers no handler.
- *Blocks the generic renderer's contract (PR 4), not the refactor (PR 3).*

### 4.3 Where "channel" semantics end

FAM's `channel` (a named group room) and `onInvitation` are not what `notifications/claude/channel`
means; the Claude name is the client's word for "unsolicited push". Synapse mail is point-to-role.
Group channels and invitations are **not** in this adapter. Whether they are needed for lane
messaging is **UNVERIFIED**: which lanes use FAM today, and for what, is not in the handover.
Per the FAM scope ruling, message-path parity only; new FAM ideas go to Synapse.

## 5. Crate and module placement, and the public API

Publish order (path deps already carry `version`): `synapse` -> `synapse-security` ->
`synapsed-client` (renamed) -> `synapse-mcp-server` -> `synapse-claude-channel`; `synapsed` and
`synapsectl` after `synapse-security`. **UNVERIFIED:** `cargo publish --dry-run` for each; the root
`exclude` list and `*.md` excludes were read, a dry run was not.

### 5.1 PR 1: rename `synapse-client`
Mechanical. `tests/cli.rs` and `tests/mail.rs` pass unchanged. 14-place bump as usual.

### 5.2 PR 2: one message view, and a foreign client
- `MessageView { message_id, from, to?, enqueued_at, attempts, body: Body }` built once from the
  daemon JSON by one function. The `fetch` tool and every renderer read it; neither indexes a
  `Value` by string.
- A corpus test: for N inputs (plain text, control characters, `<channel>` forgery, non-UTF-8, empty,
  max length) both paths agree on id, sender and body, up to their documented escaping.
- A **raw JSON-RPC stdio client written in Rust** (no rmcp) that does `server/discover` ->
  `-32022`, `initialize`, `notifications/initialized`, `tools/list`, a `send`, then reads the push
  frame by hand. This is the second client; it adds no dependency. A stock Python `mcp` client run is
  documented as an `#[ignore]`d, manual check, since "no new non-Rust deps" (board 104) covers test
  tooling until the PM says otherwise.

### 5.3 PR 3: extract the push loop (no behaviour change)
`synapse-mcp-server` gains `pub mod push` with `Renderer`, `AckPolicy`, `PushConfig` (today's
`ChannelConfig`), `PushLedger`, `should_ack`, `push_once`, `run_push_loop`. The server's
`ServerHandler` impl moves too, parameterised by a `Renderer`, so a renderer crate is a few dozen lines:

```rust
// synapse-claude-channel/src/main.rs, after the change (sketch)
let server = PushServer::start(McpConfig { role, home }, PushConfig::default(), ClaudeChannel).await?;
```

Public API additions to `synapse-mcp-server`: `Renderer`, `AckPolicy`, `MessageView`, `PushConfig`,
`PushServer`. Removals/renames from `synapse-claude-channel`: `ChannelConfig`, `ChannelServer`,
`push_once`, `PushLedger` become re-exports or move (a breaking change to a crate nobody outside this
repo can depend on yet, because it is unpublished: PM decides whether to re-export).

### 5.4 PR 4: ack policy per renderer (needs 4.2)
Implements `AckPolicy::ReceiverOnly`, makes it the default, opts the Claude renderer into
`BoundedAttempts`, adds the "stop pushing after `max`, leave pending" ledger state, and `whoami`'s
`push` field. Tests: a renderer whose `notify` always succeeds and whose client never acks leaves the
message pending and returned by `fetch` (mutation: restore the adapter ack => it fails).

### 5.5 PR 5: release readiness
README + `API_REFERENCE.md` sections for both binaries; a cold first-run on a clean home from the
README alone (the FAM §6 lesson), recorded in the PR; `cargo publish --dry-run` per crate in the
order above; CHANGELOG. Alert delivery is still only a seam (`AlertTransport` has no implementation,
board 131); the release notes must say so.

## 6. What claude-peers and FAM do today, and what replaces it

### claude-peers (read at `c1210c6`, 2026-08-20; tools `list_peers`, `send_message`, `set_summary`,
### `check_messages`; broker on 7899)

| Today | Replacement | Status at 3b58babe |
|---|---|---|
| 8-char peer id minted per register | `role@account`, takeover by epoch | **Done** (M3) |
| `/poll-messages` marks delivered on return | lease, receiver/adapter ack, redelivery | **Done** (M4); ack policy per §4.2 |
| Mail to a dead peer stranded | mailbox belongs to the role | **Done** (M4) |
| `from_id` unchecked | session's verified role, token per claim | **Done** (M5a, loopback boundary) |
| Presence = pid alive | heartbeat lease, offline roles stay listed | **Done** (`list`, `ONLINE_WINDOW`) |
| `notifications/claude/channel` at 1 Hz | `synapse-claude-channel` | **Done**, live-tested n=1 (c7 PASS on rc.33); cut-over NOT approved |
| broker auto-spawn | `Daemon::connect` auto-start | **Done** |
| lane-restart `notify.rs` posts to 7899 | outbox relayed under role `agentlife-launcher` (M8 as built, agentlife #123; amended 2026-10-22, was `lane-restart@<account>`) | built, **not run** against a daemon |
| auto-summary via OpenAI model | dropped; client sets its own | **Done** (`set_summary`) |
| `server:claude-peers` approval records | `server:synapse` and the side-by-side pair | OverMind/PM; **UNVERIFIED** whether recorded |

### FAM (handover at `5111f2b`)

| FAM does | In the adapter | Note |
|---|---|---|
| WebSocket push + `notifications/claude/channel` | yes (pull-based over the daemon) | same wire method, different transport |
| Sealed E2E, vouched identity, replay store | **no** (core has them, daemon path does not use them) | needed only before cross-machine |
| Group channels, invitations, `refs` | **no** | §4.3; **UNVERIFIED** whether lanes need them |
| Directory/entity registry | roles + account key + certificates | different model |
| Undelivered replay | durable mailbox | **Done** |

### Cut-over order (lane messaging)

1. PR 1 (rename) and PR 2/3 (single view, foreign client, renderer seam): no behaviour change, so
   they do not restart the clock on anything already measured.
2. **PM ruling on §4.2**, then PR 4. If PR 4 lands after a soak begins the soak's subject changes;
   so PR 4 first if a ruling is available, otherwise the soak runs the rc.33 behaviour and says so.
3. **The soak is CireSnave's test** (board 175: go, canary rate, keep or restart the daemon). This
   note does not start it and does not assume its result.
4. OverMind M8 (lane-restart on the daemon API), then M9 side by side per the parent plan §5.
5. Drop `server:claude-peers` from launch flags, retire the broker. claude-peers is not modified.
6. FAM message path last; FAM stays in the Synapse merge per CireSnave's 2026-09-09 ruling.

## 7. Size (estimates in PRs and lane-days, not measurements)

| PR | What | Size | Gate |
|---|---|---|---|
| 1 | Rename `synapse-client` -> `synapsed-client` | 1 PR, 0.25 d | naming ruling §4.1 |
| 2 | `MessageView`, corpus test, raw JSON-RPC foreign client | 1 PR, 1 d | none |
| 3 | `Renderer` seam, push loop into `synapse-mcp-server` | 1 PR, 1 d | none; `tests/channel.rs` unchanged |
| 4 | `AckPolicy`, receiver-only default, `whoami` push info | 1 PR, 1 d | ruling §4.2 |
| 5 | Release readiness: docs, cold first-run, publish dry runs | 1 PR, 0.75 d | none |
| - | OverMind M8; M9 soak; retire claude-peers | not mine: 1-2 + 1-2 PRs | board 175 |

**Total mine: 5 PRs, about 4 lane-days.** What would make it wrong: a stock Python client showing
a divergence PR 2's Rust client misses (adds a PR); the daemon needing a per-message "parked" state
instead of a ledger-only one (PR 4 grows a daemon change); a cold first-run that finds a FAM-§6-style
trap (PR 5 grows).

## 8. Not verified, in one place

- A live push to a non-Claude client of any kind. Nothing has been run.
- The effect of a client with no binding on mail (row 4a): derived from code, not exercised.
- `cargo publish --dry-run` of any crate; crate name availability beyond 2026-10-12.
- Whether a redb file from an older rc is migrated silently.
- A cold first-run from the README on a clean home.
- Which lanes use FAM, and for which features; lane-restart's current port to the daemon (M8).
- Whether Claude Code declares any client capability in `initialize` (the probe's fake client sends
  `{}`; the real client's `initialize` is in the `tee_mcp` log, not read for this note).
