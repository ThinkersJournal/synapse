# Design: claude-peers cutover, wake-on-mail, and lane launch on message

**Status:** DESIGN ONLY, for PM and OverMind review. Nothing here is built; each code PR in section 7 goes
through its own plan and gate.
**Written:** 2026-10-15 against `origin/main@d1afc09` (6.0.0-rc.73).
**Mandate (CireSnave, 2026-10-15, relayed by the PM, verbatim):** *"Claude-peers is going away. Synapse is
its replacement."* This is a decision, not a pending question. ROADMAP's "separate question to CireSnave"
wording was stale and is corrected in this PR.
**Earlier mandate that still binds:** Synapse is a communication system for *any LLM*; the only
Claude-specific crate is `synapse-claude-channel` (`docs/superpowers/plans/2026-09-29-claude-peers-replacement.md`).

Three parts: (A) wake-on-mail and push as the default, (B) the cutover plan with the gaps found, (C) launching
a lane when mail waits for a role that has no live session.

## A. Wake-on-mail and channel push as the default

### What exists on main (read, not assumed)

- The channel adapter (`crates/synapse-claude-channel`) leases mail every `poll_every` (1 s default),
  sends each message as `notifications/claude/channel`, and leaves it leased; the model's `ack` removes it;
  after `max_pushes` (3) the adapter acks it itself. A channel event is what wakes an idle Claude Code
  session, so "wake-on-mail" for a live session is the push loop, already built.
- `GET /v1/list` returns, per role: `online` (heard from within `ONLINE_WINDOW` = 90 s), `last_seen`,
  `summary`, `epoch` and `pending` `{queued, leased, dead, oldest_enqueued_at}`. That is the per-role
  waiting count.
- `GET /v1/stats` has cumulative `sent/acked/redelivered/expired` per role since the daemon started.

### What "default" still lacks

1. **Launch flags.** A lane gets push only if it was launched with `--dangerously-load-development-channels
   server:synapse` (or the combined side-by-side value). OverMind's handler
   `claude-peers-dev-channels.json` approves `Channels: server:claude-peers` by exact match, deliberately
   not a prefix. So today a lane launched for `server:synapse` stops at the dialog. The plan's D2 records
   (`server:synapse`, and `server:claude-peers,server:synapse` for the overlap) are **not yet approved**:
   they need CireSnave's verbatim approval, scoped to the same roles as the existing record. Nothing in
   this PR creates one.
2. **Push needs a role and a home.** `synapse-claude-channel --role <role>` takes the role from an argument
   or `SYNAPSE_ROLE`. The lane launcher must pass it. A lane with no role argument fails at startup with
   exit 2, which is the right failure but is invisible unless the launcher reads it.
3. **No push without a live session.** The loop dies with the session. That is part C.

### Decision for this part

"Default" means: lane-launch always passes the synapse channel and role, and the dev-channels approval
record exists. It does **not** mean a daemon-side push to a non-Claude agent: other agents use the same
fetch/ack API through `synapse-mcp-server` or the CLI, and long-poll (section C, `wait`) gives them the same
latency without a Claude-specific path.

## B. Cutover plan

Order is by dependency. Each row is one PR unless stated; owner in brackets.

| # | Step | Needs | Done when |
|---|---|---|---|
| 1 | Approval record for `Channels: server:synapse` (and the overlap value) in OverMind's handlers, scoped to the lane roles in the existing record | CireSnave's verbatim yes [PM asks] | handler tests pin the exact-match and the no-prefix cases, like the claude-peers record's |
| 2 | Lane launch passes `--role` and the synapse channel (OverMind `lane-restart` and AgentLife launcher) | 1 | a restarted test lane shows a pushed event |
| 3 | `notify.rs` becomes an outbox relayed under role `agentlife-launcher` (agentlife #123; **amended 2026-10-22**, was role `lane-restart@<account>`; replies are not routed back to lane-restart) [OverMind/agentlife] | daemon API (on main) | the restart ask gets its reply |
| 4 | Peer lookup by cwd and summary on the daemon (gap G1) | PR in section 7 | a lane finds another by cwd without claude-peers |
| 5 | Channel meta carries sender summary and cwd (gap G2) | 4 | event shows who sent it by lane, not only role |
| 6 | Side by side: both channels loaded, new traffic over Synapse, soak 3 days on `/v1/stats` (`redelivered`, never-acked) | 1-3 | soak counters read; board 175's soak is the model |
| 7 | Cut: drop `server:claude-peers` from lane launch and the handler, stop the broker on 7899, delete `claude-peers-mcp` use from every `CLAUDE.md` that names it (`KISS/CLAUDE.md`, `fam/CLAUDE.md`, the portfolio `C:\Projects\CLAUDE.md` section 8 and 10 wording) | 6 + PM go | `list_peers` is not in any lane's tool list |

### Gaps: what lanes use claude-peers for that Synapse does not yet give

| # | Use today | Synapse today | Gap and proposal |
|---|---|---|---|
| G1 | `list_peers` by `scope` machine/directory/repo, showing `cwd`, `repo`, `summary` | `/v1/list` has role, online, summary, epoch, pending; no cwd or repo | Add `cwd` and `repo` as optional self-reported presence fields set on heartbeat (untrusted, display only), and `?cwd=` / `?repo=` filters |
| G2 | A received message shows `from_id`, `from_summary`, `from_cwd` | Channel `meta` is `{sender, message_id}` | Add the sender's presence `summary` (escaped like the body: it is untrusted) to `meta`; cwd with G1 |
| G3 | `set_summary` | `set_summary` tool exists in M6 (`summary` in list) | None; check the tool is in the channel server's tool set |
| G4 | Peer ids rotate on every restart; senders rediscover | Roles are stable; mail to an offline role is kept | An improvement, not a gap. CLAUDE.md section 8 ("peer IDs rotate") becomes obsolete |
| G5 | Dev-channels dialog approval for `server:claude-peers` | No record for `server:synapse` | Step 1; CireSnave's decision |
| G6 | `lane-restart` notify posts to 127.0.0.1:7899 as non-peer `lane-restart-host`; replies go nowhere | Amended 2026-10-22: the `agentlife-launcher` relay sends it; no reply path needed | Step 3 |
| G7 | Auto-start broker on first MCP use | `synapsed` is started by hand or by the soak scripts; the adapter fails if it is down | Decide who starts `synapsed` at login (OverMind at boot is the natural owner); until then lane launch must check `/v1/health` and name the failure |
| G8 | Broadcast to all peers | None | Only if a lane still needs it; the PM's `[NOTICE]` goes to ~20 lanes today by hand. Out of scope unless asked |
| G9 | The HTTP broker accepted any local process as any peer | Daemon verifies keys | Not a gap; a security improvement (the broker never checked `from_id`) |

Open question for the PM: is cross-machine delivery needed at cutover? The earlier plan said no
(claude-peers is local-only), and this design keeps that.

## C. Lane launch on message

**Scenario.** A lane shuts down while waiting (CLAUDE.md "restart whenever you are not mid-task"). Mail
arrives for its role. Synapse tells OverMind; OverMind decides; AgentLife launches the lane; the lane
claims its role and Synapse completes delivery from the same durable mailbox.

### Split of responsibility (PM ruling, restated; OverMind constraints adopted)

| Part | Owns | Does not |
|---|---|---|
| **Synapse** | Detecting "mail waiting, role has no live session"; the signal; the signal's identity and retry; the mailbox | Choosing whether to launch, the model, the terminal |
| **OverMind** | The decision: policy, dedupe, model pin, the named error back | Mail contents, keys |
| **AgentLife** | The mechanism: start the lane by role, idempotent no-op if already running | Deciding |

### C1. The condition

A role is **launchable** when all hold at one daemon read:
- `pending.queued > 0` (mail waits that a session could fetch);
- `online == false` (no heartbeat within `ONLINE_WINDOW`, 90 s);
- the oldest queued message has waited at least `launch_grace` (default 5 s). The 90 s `ONLINE_WINDOW`
  already covers a lane that heartbeated recently and is mid-restart; the grace matters mainly for a role
  that has never heartbeated;
- the role **has claimed before** (it has a role record). Role names are chosen by the sender, so mail
  addressed to a string no one ever claimed must not become a launch. (A send to a never-claimed role is
  already refused in the adapter tests as an unknown recipient; this condition keeps the rule in the daemon
  and does not depend on that.) OverMind additionally allowlists roles and rate-caps launches per role,
  answering `refused` with `reason=policy`; `refused` stays terminal.

- the daemon has been up at least the online window. Presence is in memory, so right after a daemon
  restart every role looks offline; without this a restart would signal every role that has mail.

Dead-set mail (`pending.dead`) never triggers a launch.

### C2. The signal (level-triggered, so no event is lost)

`GET /v1/waiting` returns the launchable roles:

```json
{ "roles": [ { "role": "synapse", "signal_id": "synapse:<oldest pending enqueue time>",
               "count": 3, "oldest_enqueued_at": "...", "attempt": 1,
               "epoch": "<daemon start>.<n>" } ] }
```

- **Level, not edge.** The daemon does not remember "I told OverMind". It answers from current state, so a
  daemon restart, an OverMind restart or a lost response loses nothing: the next read shows the same role
  again. This is what makes delivery of the signal at-least-once without a second durable queue.
- **Latency.** `?wait=<seconds>` (max 30) holds the request until a role becomes launchable, so OverMind
  long-polls and acts within about a second of the grace window. Plain polling also works.
- **Contents.** Role, signal id, count and timestamps only. **No mail body, no sender, no token, no model,
  no key material** (OverMind constraints 1 and 3). The signal id is `<role>:<enqueue time of the oldest
  pending message, RFC 3339 to microseconds>` (as built in rc.78; the mailbox exposes the time, not the
  id, and the time is already in `/v1/list`). It is stable while that message stays pending, so a repeat
  is recognisably the same signal (constraint 2). When the oldest message is acked the id moves on, which
  is correct: a new launch need.
- **Not a mail endpoint.** It never returns, leases or acks a message. Reading it changes nothing.

### C2a. Who runs the poller, and bootstrap

The poller must not be a lane session: a lane is told to restart at every task boundary, and the role
`overmind` can itself be the role that is down, so a lane-hosted poller launches nothing exactly when it is
needed. Requirements, owned by OverMind and AgentLife:
- a **service** (AgentLife or Task Scheduler), not a lane, holds a session for a poller role and long-polls
  `/v1/waiting`;
- the role `overmind` (the lane) is launched by that service, never by itself;
- until that service exists the feature is **off**, not best-effort: no role is launched, and `launcher_roles`
  stays empty. This design does not claim wake-on-mail works before then.

### C3. Who may read it (auth)

The claim flow is not new and is not specified here: `POST /v1/claim` (no bearer) with `{audience, chain_pem,
nonce_hex, signed_at, signature_b64}`, signed by the role key; built by `synapse::sign_claim_for` and verified
per `docs/superpowers/specs/2026-10-02-m5-synapsed-design.md` and the header of `crates/synapsed/src/lib.rs`.
Keys live under `$SYNAPSE_HOME` (else `%LOCALAPPDATA%\synapse`), managed by `src/keystore.rs`; a client
library (`synapsed-client`) already performs the claim, so OverMind/AgentLife should use it rather than
re-implement signing.

`/v1/waiting` and `/v1/launch-result` need a bearer session like every route, **and** the session's role must
be in the daemon's `launcher_roles` (config, default empty, so the feature is off until set; recommended
value: `agentlife-launcher`, the launch service's own role, distinct from `overmind` so it never takes OverMind's session). A role in that list can learn *that* mail waits and *how much*, never what. Any other
role gets 403. The session comes from the same claim flow as any role, so the trust root is the launcher role's
key, not a shared secret.

### C4. The launch result (named errors, never a silent drop: constraint 5)

OverMind answers every signal it acts on with `POST /v1/launch-result`, echoing the `epoch` and `attempt` it was given
(the dedupe key is `(signal_id, epoch, attempt)`):

```json
{ "signal_id": "...", "epoch": "...", "attempt": 1, "role": "...", "outcome": "started" | "already-running" | "refused" | "failed",
  "reason": "<short code, e.g. model-not-pinned, policy, spawn-failed, restore-lock-held>" }
```

The four `outcome` strings are the whole vocabulary; anything else is `malformed`. `launching` and
`unreachable` are Synapse's own `launch.state` values, never sent. A launcher's dry run launched
nothing, so it sends no answer (the signal stays open and re-signals after `launch_wait`). Pinned by
`launch::tests::only_the_four_spec_outcomes_parse`, `synapsectl/tests/mail.rs` (real daemon) and
`synapsed_client::LaunchOutcome`.

Synapse records it per role as `launch: {state, reason, since, attempts}` and shows it in `/v1/list`, so a
**sender can see why its mail is not being read** (see C6).

| Outcome | Synapse does |
|---|---|
| `started` | Mark `launching`; stop re-signalling that id for `launch_wait` (default 120 s). If the role has not claimed by then, the signal reappears with `attempt+1` |
| `already-running` | Mark `launching`; same wait. (AgentLife's lane-start reports the role as running and OverMind relays it; Synapse has not heard a heartbeat: a heartbeat gap, not a launch need) |
| `refused` | Terminal for that signal id: `launch.state = refused`, reason shown. No retry until the oldest message changes or it is cleared (C4a). Policy said no; asking again is noise |
| `failed` | Retry with backoff: re-signal after 30 s, 2 min, 10 min: **one signal and three retries, four attempts in all** (the
retry count is the length of the configured backoff list), then `launch.state = unreachable`, reason shown, and a security-event/alert row is written (board 131's alert path is still a seam: until it is wired the row is the log line and the `/v1/list` field) |
| no answer at all | Treated as `failed(reason=no-answer)` after `launch_wait`, same backoff. A `launching` role that has not claimed after `launch_wait` is `failed(reason=no-claim)` and is re-signalled at once (the launch was believed, so no backoff), still counting the attempt |

The bounds are config, not code constants. Mail is **never** dropped or expired by any of this.

**Dedupe key is `(signal_id, epoch, attempt)`.** `epoch` is an opaque string: the daemon's start time plus a
counter that `launch-clear` bumps. Launch state is in memory (section 7), so a daemon restart or a clear
starts a new epoch and `attempt` begins again at 1; without `epoch` a replayed `(signal_id, 1)` after either
would be indistinguishable from the old one. A clear after a transient refusal therefore re-signals the same
`signal_id` as attempt 1 of a new epoch.

Earlier wording, kept for the reasoning: the key was `(signal_id, attempt)`. The signal id is stable while the oldest message stays queued, and
`attempt` rises on every re-signal (a `failed` backoff or a `launch_wait` expiry). OverMind records the
outcome per `(signal_id, epoch, attempt)`: a repeat of the same triple is a no-op, a higher attempt within the
same epoch, or any attempt in a new epoch, is a new launch request. Without the attempt in the key the backoff would never launch.

### C4a. Clearing `refused` and `unreachable`

Two mechanisms, both named: (1) **automatic** on the role's next successful claim (the lane is up, so the
state is stale), and (2) **explicit** `POST /v1/launch-clear {role}` (CLI `synapsectl launch-clear <role>`),
allowed only to `launcher_roles`. Clearing resets `attempts` and lets the next read re-signal.

### C4b. Alive but stuck is not unreachable

A lane whose session is alive but stopped at a dialog (the development-channels dialog, for example) is
OverMind's to alarm on (launch-stalled). Synapse sees only a role that has not heartbeated, so it reports
`launching` then `unreachable` by the C4 table; it never knows why. The stalled-launch alarm is not a
Synapse state.

`GET /v1/list` already returns every known role with `online` and `pending` in one response and needs only
a valid bearer session of any role (`authed`, no role check), so OverMind's reads of presence need no extra
permission. `pending` is `null` when the daemon could not count depths; treat that as unknown, not zero.

### C5. Guarantees

- **Mail:** unchanged: at-least-once with lease and ack, in the durable redb mailbox; the role's next claim
  receives everything queued while it was down, in order.
- **Signal:** at-least-once (level-triggered). **Launch effect:** at most one per role per signal id,
  because OverMind dedupes on `signal_id` and AgentLife's start is a no-op when the role runs
  (constraint 2). Two daemons are out of scope (single local daemon).
- **Ordering:** none promised across roles.
- **Launch never changes identity:** the launched lane claims its role through the normal claim; Synapse
  gains no new path to create a session.

### C6. What a role that never comes up looks like to the sender

The sender's `send` succeeds (it is queued durably; that has always been the contract). Then:
- `list` shows the role `online: false`, `pending.queued > 0`, and `launch: {state: "unreachable" |
  "refused" | "launching", reason, since}`;
- nothing is lost: the first claim after any recovery delivers the lot;
- there is no sender-side "undeliverable" error, deliberately: an offline lane is a normal state, and
  failing the send would reintroduce claude-peers' stranding in the other direction.

### C7. Constraints from OverMind, and where each is met

| OverMind constraint | Met by |
|---|---|
| 1. Always `--model sonnet`; signal carries no model | C2: no model field exists; launch is OverMind/AgentLife's, which pin the model. Synapse must never grow one |
| 2. One launch per role; stable idempotent signal id | C2 signal id, C4 `already-running`, C5 |
| 3. No secret, token or body in the signal | C2 contents |
| 4. Launch path never runs `gh auth switch` / acts as ciresnave | Out of Synapse's hands entirely: it only sends the signal; stated here so the PR review can check no Synapse code launches anything |
| 5. Named error, with Synapse's retry bound/backoff/alert | C4 |
| Delivery guarantee; who sends the signal; what a never-up role looks like | C5; C3; C6 |

Synapse itself launches nothing and holds no AgentLife or OverMind dependency (portfolio rule: no
cross-repo path deps; OverMind is a client of the HTTP API).

## 7. Code PRs that follow (each its own plan, PM allocates the number)

1. **Presence fields and filters (G1, G2):** `cwd`/`repo` on heartbeat, `?cwd`/`?repo` on list, summary in
   channel `meta`. Breaking only if a field is renamed; additive otherwise.
2. **`GET /v1/waiting`, `POST /v1/launch-result` and `POST /v1/launch-clear`** with `launcher_roles`, `launch` state in `/v1/list`,
   the backoff table, in-memory launch state (a daemon restart resets attempts: acceptable because the
   condition is re-read from the durable mailbox; say so in the PR).
3. **`synapsectl waiting`, `launch-result` and `launch-clear <role>`** for operators and for OverMind's tests.
4. **Docs:** CLAUDE.md wording, and the lane onboarding line "launch passes `--role`".

OverMind's PRs (handler record, lane-restart on the daemon API, a `/v1/waiting` poller) and AgentLife's
(lane-start by role) are theirs; this design only fixes the interface they code against.

## 8. Open decisions

- **CireSnave:** approve the `server:synapse` dev-channels record (step 1), and the cutover date after the
  3-day soak.
- **PM:** who starts `synapsed` at login (G7); whether broadcast (G8) is needed.
- **OverMind (answered 2026-10-15):** `launcher_roles`: OverMind agreed in principle, conditional on C2a; the launcher role is **`agentlife-launcher`** (AgentLife's service, PM 2026-10-15; a distinct role, since one session per (home,role) would knock OverMind off). The default stays empty; `launch_grace` 5 s
  yes; `launch_wait` 120 s accepted as a default but **unmeasured**: AgentLife should report a measured
  lane-start-to-claim time before it is relied on.
- **OverMind/AgentLife:** who builds the poller service (C2a).

## 9. What was not measured

Nothing here was run. The facts about main come from reading `crates/synapsed/src/lib.rs`,
`crates/synapse-claude-channel/src/lib.rs` and the two earlier plans at `d1afc09`; the AgentLife and
OverMind facts come from `agentlife/docs/LAUNCHER.md` and `OverMind/crates/lane-restart` as checked out
on 2026-10-15 (read-only), which may differ from their `origin/main`.
