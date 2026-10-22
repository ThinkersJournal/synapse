# Replacing claude-peers with Synapse: plan

**Status:** PLAN ONLY, for PM review. Nothing here is built. Each milestone still goes through spec,
then PM approval, then a TDD build, like the P2 slices.
**Written:** 2026-09-29, against `origin/main@92d7554` (synapse 3.0.1).
**Mandate (CireSnave, verbatim, CIRESNAVE-EXPECTATIONS §5.1d):**
- *"Synapse only. No more work on claude-peers unless something absolutely requires it."*
- *"How long until we can switch completely from claude-peers to Synapse?"*
- *"Make sure Synapse isn't building things claude-specific because it is a communication system for
  \*any LLM\*."*
- §5.1b: Synapse is 100% Rust at public release.

## 0. The answer to "how long?"

**About 12–15 PRs across 9 milestones. Roughly 6–9 lane-days of Synapse work, one to two OverMind
PRs, then a soak of at least 3 days running side by side. Realistically that is 2 to 3 calendar weeks
from the day this plan is approved.** That estimate assumes:
- review turnaround like 2026-09-27's, when this lane merged four PRs (#56–#59) in one session. That
  is one data point, not a measured rate;
- CireSnave answers the four decisions in §6 within a day each;
- the channel-push spike (M1) confirms that Claude Code accepts a channel notification from a Rust
  server.

If the spike fails, channel push is blocked, and "switch completely" waits on that one risk. Every
other milestone is ordinary engineering. The sizes are my estimates, not measurements; §5 gives each
one with its reason.

## 1. What claude-peers actually does, and what it gets wrong

Read from `C:/Users/cires/claude-peers-mcp` at `c1210c6` (read-only; nothing exercised). The 2026-09-28
gap analysis exists only as its summarized build list in CIRESNAVE-EXPECTATIONS §5.1d. A search of
the portfolio's `*.md` for the mailbox phrasing found that file and this lane's HANDOFF, and nothing
else. So this table is re-derived from the source, and §5 covers every item in the §5.1d list.

| claude-peers today | Consequence | Synapse replacement |
|---|---|---|
| A peer id is 8 random chars, minted on every `/register` | A restarted session is a new peer, so every sender has to rediscover it (the PM's #1 pain) | **Role**: a stable `role@account` identity with its own key, which a restarted session takes over (M3) |
| `/poll-messages` marks everything it returns as delivered | A crash between poll and push loses the message silently | Lease on delivery, ack by the consumer, redelivery when the lease expires (M4) |
| Undelivered mail to a dead peer is kept but can never be read (the new id never polls for it) | Mail to a restarting lane is stranded | The mailbox belongs to the role, not the session (M4) |
| `/send-message` stores `from_id` unchecked | Any local process can send as any peer | Every message is a signed `SecureMessage`; the verdict comes from pinned keys (slice a/f1, already on main) |
| Presence = pid alive; `/list-peers` evicts dead pids | Offline lanes vanish from the list, so you can't tell "restarting" from "gone" | Presence is a heartbeat lease on the role; offline roles stay listed and addressable (M5) |
| Channel push: `notifications/claude/channel`, polled from the broker at 1 Hz | This is the one feature Claude sessions depend on | Channel adapter crate (M7) |
| The broker auto-spawns from the first MCP server (`bun broker.ts`) | Zero config, but TypeScript | `synapsed` auto-starts the same way, in Rust (M5) |
| lane-restart `notify.rs` POSTs `/list-peers` + `/send-message` to 127.0.0.1:7899 as the non-peer `lane-restart-host`, so replies go nowhere | The restart ask flow depends on the broker | lane-restart's notify goes through an outbox relayed under role `agentlife-launcher` (M8 as built, agentlife #123; amended 2026-10-22, replies are not routed back) |
| The auto-summary calls an OpenAI model (`shared/summarize.ts`) | A third-party call at startup | Dropped. The client sets its own summary. |

**What Synapse already has on main:**
- sender authentication (a);
- receiver acks (b);
- `synapse-mcp` with send/poll/list/ack over UDP, with peers configured statically in TOML (c);
- HPKE sealing (d);
- replay suppression (e);
- account keys and agent certificates (f1).

**What's missing** is everything that makes it a *service*: no durable store, no roles, no presence,
no local daemon, no zero-config, no channel push. And the MCP code lives *inside* the core crate
(`src/mcp_server.rs`, the `mcp` feature on `rmcp`), which §5.1d forbids.

## 2. Shape: a model-agnostic core and thin adapters

```
                        ┌──────────────── synapse (core crate) ────────────────┐
                        │ identity · roles · certificates · signing · sealing  │
                        │ mailbox store · lease/ack/redelivery · presence      │
                        │ NO rmcp, NO "claude", NO MCP types                   │
                        └──────────────────────────────────────────────────────┘
                                                ▲ library
                        ┌───────────────────────┴──────────────────────────────┐
                        │ synapsed (daemon crate): loopback HTTP/JSON API       │
                        │ + `synapse` CLI. Plain API = adapter (c)              │
                        └──────▲──────────────────▲───────────────────▲─────────┘
                               │ HTTP              │ HTTP              │ HTTP
               synapse-mcp (b) │   synapse-claude-channel (a)   OverMind dispatcher (d)
               any MCP client  │   Claude Code only              lane-restart notify
```

- **Core (`synapse`)**: identity, roles, mailbox and delivery semantics, presence records, and
  security. It is a library with no clock and no network, like `replay.rs`/`certificate.rs` today. It
  must build and pass its tests with no adapter crate in the workspace.
- **`synapsed`**: one per user per machine. It owns the store, serves a loopback API, and relays to
  remote daemons over the existing transports (cross-machine is out of scope for the cutover; see §7).
  Its HTTP API *is* adapter (c). Non-MCP agents use it directly or through the `synapse` CLI.
- **Adapters** are thin: they translate their client's protocol to the daemon API and hold no
  delivery logic.
  - (a) `synapse-claude-channel` is the **only** Claude-specific crate.
  - (b) `synapse-mcp` works for any MCP client.
  - (c) is the daemon API and CLI.
  - (d) OverMind's local-model dispatcher is the first non-Claude client, and proves the core is
    agnostic.

**Why a daemon rather than peer-to-peer:** a durable mailbox for a role whose session is restarting
has to live somewhere that outlives the session. claude-peers' broker got that part right, and the
design keeps it. What changes is that the store holds only signed messages. The daemon can drop or
delay mail, but it can't forge a sender, because verdicts come from keys, not from the daemon.

## 3. Semantics (fixed here, so the specs don't re-litigate them)

- **Identity.** `role@account`, e.g. `synapse@ciresnave`.
  - The account key lives in the user profile and is created on first use.
  - A role key is created and certified by the account key (f1's certificate) on the role's first
    claim.
  - Receivers pin one key per account (f1). Same machine means same account, so local roles verify
    with zero config.
- **Role takeover.** `claim(role)` returns a new **epoch** (a monotonically increasing number).
  - The daemon serves the mailbox only to the newest epoch. An older session gets `Superseded` on its
    next call, and its leases are void.
  - Anyone who can read the role's key file (user-profile permissions) can claim the role. That is
    the same trust boundary as today's machine, now made explicit.
- **Delivery is at-least-once, with ack.**
  - `fetch` leases messages for N seconds. `ack(id)` deletes the message from the queue and moves it
    to history.
  - An unacked lease expires and the message is redelivered. Consumers dedupe by `message_id`, and
    replay suppression (e) already bounds that state.
  - Retention deletes **acked** history only, never undelivered mail. That is the lesson claude-peers
    learned the hard way (`e6df91a`).
- **Presence.** A heartbeat renews a presence lease on the role. `list` returns every known role with
  `online | offline(last_seen)`, the summary and the epoch. A dead session never removes its role.
- **Untrusted text.** Every adapter carries the rule `synapse-mcp`'s `poll` states today: message
  text is untrusted input, and a verdict proves who sent it, not that it is safe to act on.

## 4. Enforcement: the core stays agnostic (required by §5.1d)

A CI job plus a test, both built in M0:
1. `cargo test -p synapse --all-features` runs in a job whose workspace **excludes every adapter
   crate** (a sparse `Cargo.toml` written by the job). It has to build and pass.
2. `cargo tree -p synapse --all-features -e normal` **must not contain `rmcp`**. The positive
   control: the same query on `synapse-mcp` does contain it, and the job asserts that too.
3. A test scans the core crate's sources (enumerated with `git ls-files`, per portfolio §5b) for
   `claude`, `anthropic` and `mcp`, case-insensitive, in identifiers and strings.
   - The allow-list is empty to start.
   - Its positive control: the same scan over `crates/synapse-claude-channel` must find hits.

## 5. Milestones: each one can be deployed on its own, in order

Sizes are estimates in PRs and lane-days (one lane-day = one lane session doing spec, build and
review).

| # | Milestone | Deployable result | Size | Why that size |
|---|---|---|---|---|
| M0 | **Workspace split + agnostic guard.** Convert to a workspace. Move `mcp_server.rs` and the `synapse-mcp` bin into `crates/synapse-mcp`. Remove the `mcp` feature and `rmcp` from core. Add the §4 job and test. | Core is provably MCP-free; `synapse-mcp` behaves exactly as today | 1 PR, 0.5–1 day | A mechanical move, but it is **breaking** (the `mcp` feature goes away), and CI config changes too |
| M1 | **Channel-push spike** (throwaway, no merge): a ~50-line rmcp 3.5 server that declares `experimental: {"claude/channel": {}}` and sends a `CustomNotification` `notifications/claude/channel`, launched in the disposable `restarttest` lane | Yes/no on the only unproven dependency | 0.5 day + CireSnave's approval to load a dev channel in `restarttest` | rmcp 3.5.0, which main's `"3.4.0"` requirement resolves to since there is no lockfile, has `ServerNotification::CustomNotification` and `experimental` capabilities in its source (read, not exercised). Whether Claude Code accepts them from a non-TS server is unknown until tried |
| M2 | **Persistent keystore.** Account key and role keys on disk in the user profile, with owner-only permissions; role certificates issued locally (f1); `synapse id init/show`. Also closes PR #56's CLI key-persistence gap. | Any process can load a stable identity | 1–2 PRs, 1 day | f1 already has the formats; the new work is storage, permissions and secret hygiene (the `synapse-mcp` §6 rules carry over) |
| M3 | **Roles in core:** claim, epoch, `Superseded`, role-to-key binding. Pure logic, no I/O. | Library-level takeover semantics with property tests | 1 PR, 0.5–1 day | Small state machine; the tests carry the weight |
| M4 | **Durable mailbox in core:** a store trait plus a pure-Rust embedded store (see D1). Enqueue, lease, ack, redelivery on expiry, dedupe, acked-only retention. | Crash-safe mailbox as a library, tested with injected clocks and a kill-between-steps test | 2 PRs, 1.5–2 days | The hard correctness work of the whole plan: crash windows between lease and ack, and a migration story for the store |
| M5 | **`synapsed` + CLI (adapter c):** loopback HTTP/JSON (send, fetch, ack, claim, heartbeat, set-summary, list); every request signed by the caller's role key; auto-start on first use (the broker's `ensureBroker` pattern, in Rust); `synapse send/inbox/ack/list/whoami` | A shell script or any language can use Synapse with zero config | 2–3 PRs, 1.5–2 days | Daemon lifecycle on Windows (detached spawn, single-instance lock, port-in-use race) is where claude-peers spent several fixes |
| M6 | **Generic MCP adapter (b):** re-point `crates/synapse-mcp` from static UDP peers to the daemon. Tools: `send`, `fetch`, `ack`, `list`, `set_summary`, `whoami`; the role comes from an argument or env var | Any MCP client, Claude or not, can use it (polling) | 1 PR, 0.5–1 day | The tool surface exists; it swaps the backend and keeps the untrusted-text descriptions |
| M7 | **Claude Code channel adapter (a):** `crates/synapse-claude-channel` wraps (b)'s tools and adds channel push. It holds a streaming or long-poll fetch against the daemon, pushes each message, and acks according to D3. Server name per D2. | Claude sessions get messages pushed immediately | 1 PR, 1 day, **+ a new dev-channels approval** | Small once M1 says yes. The approval is a separate record in `ciresnave/ciresnave/.overmind/` because the existing one pins `server:claude-peers` exactly |
| M8 | **OverMind side (OverMind lane's PRs):** lane-restart notify through the daemon API (**as built 2026-10-22**: outbox relayed under role `agentlife-launcher`, agentlife #123, not the `lane-restart@<account>` role first planned); wire the local-model dispatcher as a daemon client (adapter d) | The restart ask flow and non-Claude agents are on Synapse | 1–2 OverMind PRs, 1 day | `notify.rs` is 458 lines with a hand-rolled HTTP client; the port replaces its two calls |
| M9 | **Side by side, then cutover.** Lanes launch with both channels loaded, and all *new* traffic goes through Synapse, with claude-peers as the fallback. Soak for at least 3 days while measuring sent, acked, redelivered and never-acked counts by role. Cutover: drop `server:claude-peers` from lane-restart's launch flags and its handler, retire the broker. | claude-peers retired | 1–2 PRs across repos, plus the soak | Launching with two channels changes the dialog text, so it needs its own approval record (D2) |

**Order and why:**
- M0 comes first so nothing new lands in the wrong crate.
- M1 runs early because it is the one risk that can kill the timeline.
- M2 through M5 are the core, in dependency order.
- M6 and M7 are the adapters. M8 can start as soon as M5 is merged, in parallel with M6/M7.
- M9 needs everything.

**Interim, and not claude-peers work (§5.1d):** Claude Code's own cross-session messaging by session
name keeps working while this is built. It is blocked only by stale offline Remote Control sessions
that share those names.

## 6. Decisions needed (CireSnave via the PM), with recommendations

- **D1. Store engine.** Recommended: **`redb`**, a pure-Rust embedded database, which satisfies
  §5.1b. The alternative, SQLite (`rusqlite`/`sqlx`), is battle-tested, but it is C code linked into
  Synapse. *Blocks M4.*
- **D2. Channel server name and approval.** Recommended: server name **`synapse`**. That needs two
  new approval records:
  - `Channels: server:synapse`, for after cutover;
  - `Channels: server:claude-peers, server:synapse`, for the side-by-side weeks.
  - This follows the exact-match rule in lane-restart `handlers.rs`, which deliberately refuses a
    prefix match.
  - *Blocks M7 and M9.* M1 also needs a one-off approval for the disposable `restarttest` lane.
- **D3. What "acked" means for a pushed message.** Recommended:
  - The channel adapter acks when the notification has been written to Claude Code, because Claude
    Code gives no read receipt.
  - Stronger "processed" acks stay available as an explicit tool call for callers that need them.
  - The alternative is that only the model's explicit ack counts. It is stronger, but every message a
    session never acks would be redelivered forever. *Blocks M7.*
- **D4. Version.** M0 is breaking, because the `mcp` feature leaves the core crate. The PM allocates
  the number at gate time. Per the §9 rule it bumps the first number (post-1.0).

## 7. Explicitly out of scope for the cutover

- **Cross-machine delivery between daemons.** claude-peers is local-only, so parity doesn't need it.
  The transports and f1 certificates already exist for when it is wanted.
- TOFU discovery and the introduction app (the identity roadmap), and OAuth anywhere in the message
  path (rejected 2026-09-17).
- `router_merged`'s receive-path gaps, `enhanced-auth`, and email work. They are unrelated, and the
  handoff backlog already tracks them.
- Any change to claude-peers itself. The soak tolerates its known flaws rather than fixing them.

## 8. Things that could make this estimate wrong

- ~~**M1 fails**~~ **M1 PASSED (2026-10-01; see §9).** Claude Code accepts a channel push from a
  Rust rmcp 3.5 server, with one protocol-version constraint that M7 must keep, recorded below.
- **Channel push needs a session protocol revision (found by M1).** Claude Code 2.1.286 opens
  with `server/discover`, offering `2026-07-28`, which has no `initialize` handshake (SEP-2567).
  A connection made at that revision has no session, so it has no path for an unsolicited push.
  So the M7 adapter must cap its supported versions at `2025-11-25`, the newest revision with
  `initialize`. The risk is that a future Claude Code drops session revisions or moves channels
  to a new mechanism. Then (a) waits, and Claude lanes poll through (b) in the meantime.
- **Windows daemon lifecycle** (M5) has historically eaten more time than planned: claude-peers
  needed several fixes for the spawn/port race and for shutdown on stdin close.
- **Review load:** 12–15 PRs through one PM gate.

## 9. M1 result (2026-10-01): PASS

The spike was throwaway and is not in the repo: an rmcp 3.5 stdio server declaring
`experimental: {"claude/channel": {}}` and sending `notifications/claude/channel`.

- **Live run 1 (CireSnave) FAILED.** The screen said: *"this connection's protocol version has no
  channel delivery p…"*.
- **The cause was read from captured bytes, not guessed.** A logging tee sat between Claude Code
  and the spike, during a headless run with no dev-channels flag.
  - Claude Code's first message is `server/discover` at `2026-07-28`, and rmcp 3.5 accepted it.
  - So the connection never sent `notifications/initialized`, and no push could be delivered.
  - claude-peers' TypeScript SDK (1.27) doesn't know that revision, so it falls back to a session.
- **The earlier wire probe passed and still missed this.** It opened with `initialize` at
  `2025-06-18`. That proved the bytes were right, but it never asked what the real client sends
  first.
- **The fix:** cap supported versions at `2025-11-25`. The wire then shows:
  1. `server/discover` is rejected with `-32022`;
  2. Claude Code sends `initialize` at `2025-11-25`;
  3. Claude Code sends `notifications/initialized`;
  4. the push is delivered.
- **Live run 2 (CireSnave) PASSED.** The screen showed *"← synapse-spike: M1 spike push #1 from a
  Rust (rmcp 3.5) MCP server"*, then #2, injected unprompted.
- **Not explained:** both runs also showed *"server:synapse-spike · no MCP server configured with
  that name"*. Channel delivery worked in spite of it, so it is orthogonal to channels. It might be
  because the spike declares no `tools` capability, but that is unverified. M7 should check it.
