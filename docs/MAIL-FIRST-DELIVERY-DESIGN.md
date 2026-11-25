<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Mail first-delivery loss: hold or redeliver, and a launcher-only peek (ROADMAP row 56)

Design only, no code. Brief: agentlife `docs/MAIL-BEFORE-FIRST-TURN.md` @cdcd26f (measurement: 312 mail-started
transcripts to 2026-11-25 01:18Z; first channel event at about 120 s in 151 of 237 sessions that saw one, under 30 s in
1). PM rulings 2026-11-25 (via pm-platform): yes to hold-until-accepted or a `redeliver`; yes to a launcher-only `peek`.
Read at `origin/main` fd00ea68.

## 1. Where the first lease is taken

1. `PushServer::on_initialized` (`crates/synapse-mcp-server/src/push.rs`) spawns the push loop when the MCP
   `initialized` notification arrives. `tokio::time::interval` fires its first tick at once, so the first look at the
   mailbox is within a poll of the MCP handshake.
2. That look is `pull_views_excluding`, a `POST /v1/fetch` (`fetch` in `crates/synapsed/src/lib.rs`), which leases the
   message in the mailbox (`fetch_excluding`): `attempts` becomes 1 and the message is hidden until the next
   `delivery.gaps_secs` step (default 2, 4, 8, 16 minutes). That hidden time is the 120 s agentlife measured. The
   request's `lease_secs` (30 in `PushConfig::default`) is not what decides it; to be confirmed against the mailbox
   crate before code, because the 120 s reading depends on it.
3. The adapter then writes the `notifications/claude/channel` notification. A successful write means the bytes left
   the process, not that Claude Code showed the event (`push.rs` header). With `AckPolicy::Never` (the channel
   renderer) the adapter keeps the lease and never re-writes until the daemon hands the message out again.
4. `should_ack`'s comment already names the cause class ("the first push can precede the client's registration: the
   c7 case"). So the loss is a known shape; what is unmeasured is only which of (a) the dev-channels dialog or (b)
   an uninitialised session is the moment it is dropped.

The fault is therefore: the lease and the one write happen at MCP `initialized`, and nothing later re-writes until the
gap ends.

## 2. Does hold-until-accepted need a handshake? Yes

MCP gives the server no signal that the client accepted the channel (the dev-channels dialog is Claude Code UI, not
protocol). `initialized` is all the adapter sees, and it is exactly the event that is too early. So "hold until
accepted" needs a signal from outside the adapter:

- **H1, host-called `redeliver` (agentlife's B(2), recommended as the precise fix).** After the host answers the
  dialog it calls a local control on the adapter (or the daemon, `POST /v1/redeliver`, own-role only): re-write every
  message this session holds leased with `attempts` equal to 1, without a new lease and without bumping `attempts`.
  Authority: the call is made by the role's own adapter process (a stdio or loopback control the host can reach), so
  the launcher never acts as the role.
- **H2, adapter early re-push (no handshake, small, recommended as the first step).** The ledger already remembers
  every id this process wrote. For a message still leased and unacked, re-write the same notification at +10 s and
  +30 s after the first write (then leave it to the daemon's gap). It takes no new lease and does not touch
  `attempts`, so the daemon's accounting and the 2/4/8/16 schedule are unchanged. Receivers already ignore a repeat of
  a `message_id` (server instructions). Cost: at most two duplicate notifications per message; benefit: delivery
  within about 10 to 30 s of any dialog or init delay shorter than 30 s, with no host change.
- **H3, hold the first lease** (do not pull until a ready signal). Rejected: it needs the same external signal as H1
  and delays mail for a session that never signals; H1 and H2 do not.

Recommendation: H2 now (adapter-only, one PR, a test that a leased unacked message is written again at the configured
offsets and not after an ack), H1 after the probe shows whether 30 s covers the dialog. agentlife's C (wait about 2
minutes) stays as the floor.

Failure modes: a session that never connects holds nothing (H2 acts only on messages this process leased); a repeat
cannot be told from a first delivery except by `message_id`, as today.

## 3. Launcher-only `peek`

`GET`-style `POST /v1/peek`, authenticated as the launcher identity only (a daemon-side grant, not a role name check
in the client):

- Returns, per pending message for a named role: `message_id`, sender role, `enqueued_at`, `attempts`, `lease_until`,
  and the L1 header line (the first line, at most 200 bytes, escaped). **Never a note body.**
- Never leases, never changes `attempts`, never moves a message: a read of mailbox rows.
- Every call is audited (caller, target role, count returned) on the same trail as `fetch`.
- Limits: at most 20 messages per call; a role with no grant gets 403, not an empty list.
- The launcher puts the result in the start prompt as UNTRUSTED text; it never goes in HANDOFF.

Open: whether `peek` may name any role or only roles the launcher started (recommend the latter, one grant field).

## 4. Probe (agentlife, launchtest; PM schedules)

One start with one mail queued, three timestamps: the daemon's lease (`/v1/fetch` log, `attempts` 1), the host's
answer to the dev-channels dialog, the first channel entry in the transcript. Lease before the answer means (a), and
H1/H2 apply; if the lease is after the answer and the event is still lost, the loss is elsewhere and neither fixes it.

## 5. Decisions wanted from the PM

1. H2 first, then H1 (recommended), or H1 only?
2. `peek` scoped to roles the launcher started (recommended)?
3. Who runs the probe and when (agentlife on launchtest)?

— lane: synapse
