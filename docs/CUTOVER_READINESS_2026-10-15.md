# Cutover readiness assessment: claude-peers to Synapse (board 217)

**Written:** 2026-10-15 by the synapse lane, at `origin/main@7d2df10` (6.0.0-rc.81).
**Asked by:** PM TASK 2026-10-15, for CireSnave's *"If you and the Synapse lane agree we're ready to cut over to Synapse, do it!"*
**Verdict: NOT READY.** Section 5 is the shortest list to ready. The cutover was not started.

Facts here come from reading `origin/main`, the 2026-10-09 phase-1 result, the soak procedure, and
OverMind's `docs/SOAK-RESTARTTEST-END-REPORT.md` (read at its `origin/main`). Nothing was run for this
document. Where I did not check a fact, it says so.

## 1. Gaps G1-G9 at main

Gap numbers and wording are the table in `superpowers/specs/2026-10-15-cutover-and-lane-launch.md` section B.

| # | Gap | Status at main | PR / owner |
|---|---|---|---|
| G1 | `list_peers` with cwd, repo, summary and filters | **Closed on the HTTP API**: heartbeat carries `cwd`/`repo`, `GET /v1/list` shows them and filters `?cwd=` `?repo=`. **Not exposed to a lane**: the MCP `list` tool takes no arguments (it returns every role, with the fields, so a lane filters client-side), and the CLI has no `--cwd/--repo` flags | #176 (rc.79); flags: synapse lane follow-up, unscheduled |
| G2 | Received message shows sender summary and cwd | **Closed**: `/v1/fetch` has `from_summary`/`from_cwd`; channel `meta.sender_summary`/`sender_cwd` (escaped) | #176 |
| G3 | `set_summary` | **Closed**: tool in `synapse-mcp-server` (`set_summary`, with `send`, `fetch`, `ack`, `list`, `whoami`) | M6, on main before rc.73 |
| G4 | Peer ids rotate | Not a gap: roles are stable, mail to an offline role is kept | n/a |
| G5 | Dev-channels dialog approval for `server:synapse` | **OPEN. CireSnave's verbatim yes is the blocker.** I have not read OverMind's handler file at its current `main`; last known state is "no record" | PM asks CireSnave; OverMind writes the record |
| G6 | `lane-restart` notify uses claude-peers' port and replies go nowhere | **BUILT, NOT RUN** (amended 2026-10-22): outbox relayed under role `agentlife-launcher` (agentlife #123), not `lane-restart@<account>`; one real send on a scratch home is owed before `notify_transport` is flipped; no Synapse change needed | OverMind |
| G7 | Who starts `synapsed` at login | **OPEN.** Today it is started by hand (the soak daemon is this lane's, pid 28280). The adapter fails if it is down | PM decision; OverMind is the natural owner |
| G8 | Broadcast to all peers | **OPEN, unrequested.** No broadcast in Synapse; the PM's `[NOTICE]` to ~20 lanes would be 20 sends | PM: needed or not |
| G9 | Broker accepted any local process as any peer | Not a gap: the daemon verifies keys | n/a |

Lane launch on message (spec part C) is separate and **not needed for cutover**: server side is built
(`/v1/waiting`, `/v1/launch-result`, `/v1/launch-clear`: #175 rc.78; client methods #177 rc.80), feature
off by default (`launcher_roles` empty). The poller service (AgentLife's `agentlife-launcher`) is not built.
Without it, mail for a role with no live session waits in the durable mailbox and is delivered at that
role's next claim; nobody is woken. That is no worse than claude-peers, where a message to an absent peer
had nowhere to wait.

## 2. What lanes use claude-peers for, and what Synapse covers

Sixteen peers were listed on this machine at 2026-10-15T21:17Z (`list_peers`, scope machine):
ThinkersFoundation, Unpopped, HumboldtUnifiedKidTracker (a worktree), ThinkersJournal-Community, SafeImage,
PersistAnt, KISS, baracuda, fuel, the portfolio PM (`C:\Projects`), lightbulb, coderipper, auth-framework,
OverMind, agentlife, unisql. Four had no summary set.

| Use today | Synapse today | Verdict |
|---|---|---|
| `list_peers` (cwd, repo, summary) | `list` tool: every role with `online`, `last_seen`, `summary`, `cwd`, `repo`, `pending`; no tool-level filter | Covered; filter is client-side |
| `send_message(to_id)` | `send(to, ...)` by **role name**, durable, idempotent by `--id` | Covered, but a sender must know the role name, not read a peer id. A role-name table per lane is not written down anywhere I have seen |
| Receive pushed message, `from_*` header | Channel event, untrusted frame, `meta.sender`, `sender_summary`, `sender_cwd`, `message_id` | Covered |
| `set_summary` | `set_summary` | Covered |
| `check_messages` | `fetch` | Covered |
| Wake an idle session on mail | Channel push loop, 1 s poll, `notifications/claude/channel` | Covered, **with the delivery caveat in section 3** |
| Dev-channels dialog | Exact-match approval record per channel string | **Not covered** (G5) |
| Broadcast | none | **Not covered** (G8) |
| Auto-start broker | none (G7) | **Not covered** |
| Reply-less non-peer notify from `lane-restart` | role `agentlife-launcher` relaying the outbox (amended 2026-10-22; was `lane-restart@<account>`) | Built, never run against a daemon (G6) |

## 3. Soak evidence and what it did not test

**Run:** OverMind's restarttest soak, 2026-10-12T18:25Z to 2026-10-15T18:52Z (72.5 h), one message per
10 minutes from role `soak-probe` to one Sonnet session, against **synapsed 6.0.0-rc.33**.

| Measure | Reading (OverMind report, read at its `origin/main`) |
|---|---|
| Sent / unique / seen in the transcript | 435 / 435 / 435 |
| Max shows of one id | 3 (the expected bound; readings to 18:49Z, soak-0435 unwatched) |
| Model `tool_use` blocks | 0 |
| Daemon | one pid, `started_at` unchanged across 73 hourly readings |
| Turns / usage to 18:49Z | 1303 turns, cache_read 170.6M (about 2.35M/hour), output 54.3k |

Caveats the report itself states: one `auth_failure` line (this lane's own curl, not independently
confirmed); compaction untested (0); weekly-limit delta unmeasured. It is not a clean soak and says so.

**What it did not test.** Each item is a gap in the evidence, not a known failure.

1. **One receiving session.** Cutover is 16-20 lanes sending to each other. No many-to-many traffic, no two
   senders racing, no lane receiving from several roles at once.
2. **A synthetic sender.** 435 identical-shaped probes. No real lane-to-lane messages, reply chains,
   `[READY]`-style bursts or large bodies.
3. **The model never acted.** 0 `tool_use`: the session ignored every message by design. The path "message
   arrives, model reads it, model replies with `send`" was never exercised over time (phase-1 check 6 was
   "NOT RUN"). The model also never called `ack` in the rc.32 trials (0 of 5).
4. **Delivery is not at-least-once.** From rc.33 the adapter acks a message itself after a bounded number of
   push attempts, because the model does not ack. A message whose every push Claude Code drops is lost, and
   a daemon-side `acked` proves nothing about display. Phase-1 check 7 lost one message (n=1, rc.29: queued
   while the session was down, acked, never shown). rc.33 is a mitigation. The soak saw no loss in 435,
   which bounds the loss rate only weakly (about 0.7% at 95% confidence by the rule of three, one session,
   one cadence). Whether the c7 case (queued while the session was down) occurred during the 72.5 h I
   cannot tell from the report.
5. **Daemon version.** The soak ran rc.33. Main is rc.81: 48 releases later, including the dead set,
   requeue, launch signals, presence fields, and changes to the `list` shape. The soak validates the push
   path as of rc.33 only.
6. **No compaction**, no daemon restart under load, no machine reboot. The session was restarted at
   CireSnave's instruction; I have not seen how many restart cycles the window covered.
7. **Cost.** 1303 turns for 435 messages is roughly three turns per message (inference from the counts: one
   turn per push, bounded at 3). Whether claude-peers costs the same per message is **unmeasured**. Given
   CireSnave's cost constraint, that comparison should exist before 20 lanes carry routine traffic.
8. **Windows only, one account, loopback only.**

## 4. Side by side, then cutover, with rollback

Principle: claude-peers stays fully working until the last step, so a lane that cannot receive on Synapse
is still reachable the old way.

**Phase A: prerequisites (no lane changes).** G5 approval record; G7 owner decided; `lane-restart` launch
passes `--role <role>` and the Synapse channel (spec B step 2); a written role-name table (lane cwd to
role name); a fresh daemon at current main.

**Phase B: side by side (3 days, spec step 6).** Every lane launches with both channels
(`server:claude-peers,server:synapse`). Senders send over Synapse **and** claude-peers on day one, then
Synapse first with claude-peers as fallback. Counters (`/v1/list`, `/v1/stats`) are read hourly, and the
loss test is the transcript (soak stop condition 1), not the daemon. Exit when: zero lost, no lane stuck at
a dialog, `pending.oldest_enqueued_at` under 5 minutes for every online role, and cost per message measured
against claude-peers.

**Phase C: cutover (spec step 7).** Launch without `server:claude-peers`, drop the handler record, stop
the broker on 7899, remove `list_peers` wording from the `CLAUDE.md` files.

**Rollback if a lane cannot receive mail:**

- *During phase B:* the lane still has claude-peers loaded, so it still receives. Record the failure and
  stop sending that lane Synapse-only.
- *Detecting a deaf lane:* `list` shows `online: true` with `pending.oldest_enqueued_at` older than 5
  minutes, or `online: false` for a lane that is running. Either means it is not draining. The sender
  resends the same body over claude-peers.
- *After phase C:* relaunch the lane with `--dangerously-load-development-channels server:claude-peers`
  and start the broker again. The broker's start command and the handler record are OverMind's and **I have
  not verified a restore procedure**, so phase C must not start until OverMind has run that restore once.
  Mail already in Synapse's mailbox is not lost by a rollback: the role keeps it and delivers it at its
  next Synapse claim.
- *Order:* do not delete the old handler record or the broker's start script until phase C has held for a
  week.

## 5. Verdict and the shortest list to ready

**Not ready.** Sending, receiving, presence and lane identity are built, and were shown to work for one
session over 72.5 h on rc.33. It is not ready to cut over today because of what has not been decided or
exercised, not because endpoints are missing:

1. **CireSnave approves the `server:synapse` dev-channels record (G5).** Without it a relaunched lane stops
   at the dialog. Hard blocker.
2. **An owner starts `synapsed` at login (G7)**, decided and done. Hard blocker: with no daemon every
   lane's adapter fails.
3. **Lane launch passes `--role` and the channel** (OverMind/AgentLife, spec step 2), and a role-name table
   exists for every lane.
4. **A side-by-side soak on current main with real lane traffic** (Phase B): many senders, replies, at
   least one daemon restart, several lane restarts, one measured cost comparison. This replaces the rc.33
   evidence for section 3 items 1-7.
5. **A recorded decision that bounded-attempt delivery is acceptable** (section 3 item 4): CireSnave or the
   PM accepts that a push Claude Code drops can lose a message, because the model does not ack. If it is
   not acceptable, the fix is a protocol change (a reply the model reliably gives), not more soak.
6. **A tested restore for claude-peers** (rollback, third bullet).

Not required for cutover: the launch-on-message poller (part C), broadcast (G8, unless a lane needs it),
`list --cwd/--repo` flags.

Ready means 1-6 hold and the Phase B exit conditions are met; the earliest that can be is 3 days after
items 1-3 are done.

## 6. Update 2026-10-30 (at `origin/main@42bb441`, rc.191): items 1-6 re-read

The text above is the 2026-10-15 reading and is not rewritten. What moved, with the evidence:

| Item | State | Evidence |
|---|---|---|
| 1 G5, dev-channels approval | **Closed** | `ciresnave/ciresnave` PR #13 (every lane, two channels) merged 2026-10-26 and PR #14 (Synapse only, every lane, no expiry) merged 2026-10-28. Live: the host log of the synapse lane's `lane-restart host --role synapse` launch of 2026-10-30T03:18Z shows `synapse-dev-channel-any-lane matched=true` |
| 2 G7, daemon at login | **Closed** | scheduled task `\synapsed-cires`, at logon, interactive-only; it started the daemon (pid 15536) at 2026-10-29 20:11:24 after the reboot. Limit: it needs `cires` logged in |
| 3 launch with `--role` and the channel; role-name table | **In progress** | a real `lane-restart host --role synapse` launch with the Synapse channel ran on 2026-10-30 (G6 launch half: yes). G6 notify half is **not** flipped (`notify_transport` unset, default broker). The PM ran `synapse id provision --apply` from the account home on CireSnave's instruction (2026-10-30): 19 role homes created, 0 refused, under `C:\Users\cires\AppData\Local\synapse-lanes\<role>`. The role list, `C:\Projects\.lane-state\roles-soak.txt`, **is the role-name table**: role = lane name, cwd `C:\Projects\<lane dir>`. No key was read for this record |
| 4 side-by-side soak on current main | **Open** | none since the rc.33 soak; the PM's three-day Phase B starts after the switch-and-back test |
| 5 bounded-attempt delivery | **Closed** | CireSnave, 2026-10-30, verbatim as relayed by the PM from the PM session: *"Message loss, although not ideal, is acceptable."* The soak's zero-lost stays a **measurement**, not a gate |
| 6 claude-peers restore test | **Open** | no record that one was run; OverMind asked to run it once on a scratch broker port. Needed before Phase C, not Phase B |

**Acked is not displayed.** `/v1/stats` counts, per recipient role, `sent`, `acked`, `redelivered`, `expired` (in memory, zeroed at each daemon start, until rc.195). The adapter acks a message itself after a bounded number of push attempts, so `acked` says nothing about whether Claude Code showed it. Loss is measured end to end: numbered canary mails to a sample of lanes with a one-line reply, compared with transcripts. Since rc.195 the counters also carry a per-sender `submitted` and survive a daemon restart (`stats.json`); `acked` still proves nothing about display.

**Found by the first soak lanes (2026-10-30), both fixed or explained:**

1. A role-only home from `id provision` holds no `synapsed.json`, so an adapter in it exited at start. Fix: `SYNAPSE_DAEMON_HOME` (#298, rc.191); until a lane carries it, the PM's `tools/synapse-announce-sync.sh` copies the announce file in, and goes stale at every daemon start.
2. `synapse-claude-channel` exited at its first start with "the identity store refused". Cause, reproduced with the installed binary on a fresh provision (a current build starts on the same home): the installed adapter was the 2026-10-23 build, older than the role-only keystore (rc.134), so it looked for an account key. The CLI's `list` creating `sessions/<role>.json` made the old adapter skip the claim, which is why seeding worked. Fix: install a current adapter. #299 makes the error name the keystore's reason.
