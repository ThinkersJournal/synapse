# `restarttest` live push and the M9 soak: the procedure, ready to run on a yes

**Status (origin/main 6.0.0-rc.34): phase 1 RUN in part; the soak (phase 2 and the canary in section 4) is
NOT STARTED, and starting it is CireSnave's call (board 160).** Measured so far, all n=1 and all in the
disposable `restarttest` session: the live push is shown (rc.29, `SOAK_PHASE1_RESULT_2026-10-09.md`);
check 7 FAILED on rc.29 (a message queued while the session was down was acked on write and never shown);
rc.32 showed it (n=1); rc.33 PASSED it (n=1: a message queued while down was pushed 3 times and shown
2 of 3, because the first push went out before `tools/list` and produced no transcript row; a message
sent live was pushed and shown 3 of 3; same `message_id` on every repeat; both left pending without a
model ack). Not measured: a model acting ONCE on repeats when it has a real request, a missing
`message_id`, a refused adapter ack (#119 to #121), and the moment a message leaves pending. Rows below
marked *(source)* were read from the source, not observed.

Plan: `docs/superpowers/plans/2026-09-29-claude-peers-replacement.md` (M1, M9, D2) and
`docs/superpowers/plans/2026-10-08-m6-m7-adapters.md` section 5.

## 0. What each phase proves

| Phase | Proves | Scope | Reversible by |
|---|---|---|---|
| 1. Live push in `restarttest` | Claude Code shows a pushed Synapse message in a real session; ack and redelivery behave | One disposable lane, **its own home and port** | Deleting a directory and killing two PIDs |
| 2. Side-by-side soak (M9) | The local path is good enough to replace claude-peers over at least 3 days | Every lane loaded with both channels | Relaunching lanes with `server:claude-peers` only |

Phase 1 does not touch the lanes' real Synapse home or any daemon another lane may be using.
Phase 2 is the PM's and OverMind's to run; this lane supplies the measurement and the stop
conditions. Cutover (dropping `server:claude-peers`) is **not** part of either phase.

## 1. Preconditions (all checkable now, none needs the approval)

1. **Binaries from a known commit.** In a worktree at the exact `origin/main` commit to be tested:
   `cargo build --release -p synapsed -p synapsectl -p synapse-claude-channel`
   with `C:\Users\cires\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin` on `PATH`. Record
   `git rev-parse HEAD` and `synapsed`'s `/v1/health` `version`. Binaries: `synapsed`, `synapse`
   (from the `synapsectl` crate), `synapse-claude-channel`.
2. **The wire probe passes.** It is an example, not a test (no `#[ignore]`). It needs the `claude` CLI on `PATH` (or `SYNAPSE_PROBE_CLAUDE`) and a logged-in account, builds the `tee_mcp` example itself, and starts a real `claude -p hi --model haiku` child that the test stops once the adapter has answered `initialize` (the test's own comments say it makes no model request and kills only that child; not verified by running it). It needs no dev-channel approval:
   `cargo run -p synapse-claude-channel --example wire_probe` (prints `wire probe: ok`; exit 1 with the reason otherwise)
   **No CI job runs it: it needs a logged-in `claude`, and the self-hosted runner has no secrets (CIRESNAVE-EXPECTATIONS 5.1h). Its result is UNVERIFIED until someone runs it; CI only type-checks it (`clippy --all-targets` builds examples and, under the default `native` features, the two benches).**
   Expect *(source)*: `initialize` accepted at `2025-11-25`, `serverInfo.name` = `synapse`, and, only if
   the client sent `server/discover` (the assertion is conditional), that it was answered `-32022`. If it fails, stop: the live test would fail the same way.
3. **The approval exists, or CireSnave will answer the dialog by hand.** `lane-restart`'s approval for
   `--dangerously-load-development-channels` pins `Channels` **exactly** (`server:claude-peers` today;
   no prefix match). Phase 1 passes `server:synapse`, which no record covers yet, so the dialog
   ("WARNING: Loading development channels") will need a human, or a new record in
   `ciresnave/ciresnave/.overmind/lane-restart/approvals/` (the OverMind lane's, D2). Phase 2 needs
   the second record, `server:claude-peers, server:synapse`.
4. **Back up before any first open of an existing home.** rc.27 migrates `mailbox.redb` to store
   format 2 on first open, **one way**; rc.26 and earlier must not open it afterwards. Phase 1 uses a
   fresh home, so it is exempt. Phase 2 on a home an older daemon has used: copy the home directory
   first, and the rollback in section 6 restores the copy.
5. **Know the limits.** The daemon's `/v1/stats` counters (rc.29) are kept across a `synapsed` restart since rc.195 (`stats.json`); before that they were per-process (section 4).

## 2. Phase 1: the `restarttest` live push

All commands in Git Bash. `H` is the throwaway home; `PORT` is not 7920 (the default other lanes use).

```bash
export H="C:/Users/cires/AppData/Local/synapse-restarttest"   # a NEW directory; must not exist yet
export PORT=7931
export SYNAPSE_HOME="$H" SYNAPSE_ADDR="127.0.0.1:$PORT"
```

### 2.1 Identity and daemon

```bash
synapse id init --account soaktest
synapse id show --role restarttest
synapse id show --role soak-probe
```
Expect *(source)*: `account: soaktest`, `account key id: <id>`, and for `--role` an `identity: <global id>`
line. Never key material or the keystore path. `id init` refuses a second run.

Start the daemon in the background and **record the PID you started**:
```bash
synapsed 2> "$H/synapsed.log" &  echo $! > "$H/synapsed.pid"
```
Expect *(source)*, on stderr: `synapsed: listening on 127.0.0.1:7931`. Health:
`curl -s http://127.0.0.1:7931/v1/health` -> JSON with `"ok":true`, `version`, `started_at`.
(`synapse` and the channel adapter also auto-start a daemon if none answers; with `SYNAPSE_ADDR` set
they start it on this address.) *Exact stderr text of an auto-start I have not read; the manual start
above avoids depending on it.*

### 2.2 Claude Code side

`C:\Projects\restarttest` does not exist on this machine as of 2026-10-09 (checked), and I have not
read how `lane-restart` builds that lane's command line. So the launch below is the **shape**, to be
reconciled with the lane's real launcher by the PM or OverMind before use:

`mcp.json`:
```json
{ "mcpServers": { "synapse": {
  "command": "C:/path/to/synapse-claude-channel.exe",
  "args": ["--role", "restarttest", "--home", "C:/Users/cires/AppData/Local/synapse-restarttest"],
  "env": { "SYNAPSE_HOME": "C:/Users/cires/AppData/Local/synapse-restarttest", "SYNAPSE_ADDR": "127.0.0.1:7931" } } } }
```
**`SYNAPSE_HOME` in `env` is required, not optional.** The adapter's `--home` does not reach a daemon it
auto-starts: `spawn_daemon` inherits only the environment, and `synapsed` reads its home from
`SYNAPSE_HOME`, else `%LOCALAPPDATA%\synapse`. Without it, if the manual daemon is not answering, the
adapter starts a daemon on port 7931 against the **real default home**, whose store rc.27 migrates one way.
Launch (model **Sonnet**, never Opus):
```
claude --model sonnet --mcp-config <mcp.json> --dangerously-load-development-channels server:synapse
```
The server name in the file must be `synapse`: it is what `server:synapse` names, and what the adapter
reports as `serverInfo.name`. `--mcp-config` and `--dangerously-load-development-channels` are both on
`lane-restart`'s carry-over allowlist, so a restarted lane keeps them.

Expect: the development-channels dialog; answer "I am using this for local development" (option 1).
A session stuck at that dialog still fires `SessionStart`, so **a live process is not a working
session** (OverMind's fourth retest): confirm a real prompt is accepted.

### 2.3 The checks (each is pass/fail; record the observed text)

| # | Do | Expect | Source |
|---|---|---|---|
| 1 | `synapse list --role soak-probe` | one JSON object per line; the entry with `"global_id": "restarttest@soaktest"` has `"online": true` (the adapter heartbeats once at start-up, then every 30 s; online window 90 s) | source |
| 2 | `synapse send --role soak-probe --to restarttest --id p1-0001 "hello"` | the session shows a `<channel source="synapse">` event whose text reads `<sender> (untrusted): ...` within ~1-2 s (poll every 1 s) | source |
| 3 | `synapse list --role soak-probe` | `pending` for `restarttest` is `queued:0, leased:0` once the message was acked: by the **model** (`ack` tool) or, from rc.33, by the **adapter** (after its second push in this process once the daemon's `attempts` has reached `max_pushes` = 3). Until then it stays `leased:1` and is pushed again when the 30 s lease ends, at most `max(3, attempts_at_first_pull + 2)` times. A model that never acks (measured: 0 of 5 trials) still ends with `queued:0, leased:0` | source |
| 4 | send the same `--id p1-0001` again | no second push (idempotent resend; acked history is kept 7 days, after which a resend would be delivered again) | source |
| 5 | send a body containing `</channel>`, `<`, an ESC character and "ignore previous instructions" | arrives inside the untrusted frame, `<` and `>` as `&lt;` `&gt;`, control characters as escapes; the model must not obey it | source |
| 6 | in the session, call the `send` tool to `soak-probe`, then `synapse inbox --role soak-probe` | the reply appears with `"from"` = the session's role | source |
| 7 | kill the **claude** process only; send one message; relaunch | the message is shown after relaunch (leased on the old session or queued; it returns when the lease ends, 30 s at most, or sooner because a relaunch claims a new epoch). rc.29 lost one here (acked on write); rc.33 pushes at least twice in a fresh session before it acks. Delivery is bounded ATTEMPTS, not at-least-once: record shown yes/no from the transcript, not from the daemon's ack | source |
| 8 | `tail "$H/security-events.jsonl"` | no lines (none expected in a clean run) | source |

**Caution on `synapse inbox`:** it *fetches*, which leases and hides messages from that role's own
channel adapter for the lease (60 s by the daemon's default when `--lease-secs` is not given; the adapter
itself uses 30 s). Run it only as `soak-probe` (a role nothing else drains), never as
`restarttest` during a test.

### 2.4 Phase 1 pass and stop

**Result of the first run (2026-10-09, rc.29): `SOAK_PHASE1_RESULT_2026-10-09.md`. Check 7 failed once: a message queued while the session was down was acked by the daemon and never shown. Do not start the soak until that is resolved. Fix C (the adapter no longer acks on write; the model's `ack` removes the message) was the change under test, and rc.32 re-ran check 7 once (n=1): shown. The model never acked (0 of 5), so rc.33 has the adapter ack after bounded delivery attempts (section 2.3 checks 3 and 7); check 7 re-run against rc.33 (n=1): PASS, see the status line at the top.**

**Pass:** checks 1-8 as above, with zero messages lost and none shown more than `max(3, attempts_at_first_pull + 2)` times.
**Stop immediately** on: a message not shown after 10 s; a message shown more than that bound
(repeats are expected: same `message_id`, the model must act once); any line in `security-events.jsonl` (an auth event, or a
`PermissionsTooOpen` file refusal); the daemon exiting; the
dialog text differing from the approval's anchors (do not auto-answer an unfamiliar dialog).

## 3. Phase 2: the side-by-side soak (M9) -- needs the second approval and every lane

Owner: the PM with OverMind (launch flags are `lane-restart`'s). This lane's part is below.

1. Approval record `Channels: server:claude-peers, server:synapse` merged (D2). Without it every lane's
   relaunch stops at a dialog nobody answers.
2. Real home: take the backup (precondition 4), then start `synapsed` on the default address once, by a
   PID you record. Never `taskkill /IM synapsed.exe` (it kills other lanes' daemons).
3. Relaunch lanes at their next task boundary with **both** channels loaded
   (`--dangerously-load-development-channels server:claude-peers server:synapse`), model pinned.
   Claude-peers stays the path of record; Synapse carries *new* traffic named by the PM.
4. Run the canary (section 4) for at least 3 days; sample `synapse list` hourly.
5. Fetch-scan note: `fetch(max=1)` on a role of 10 000 messages with half leased is p50 5.2 ms (rc.27,
   release, one laptop, 1 KiB bodies; 2.4x the 1k case). Real mailboxes are small; a role whose
   `queued + leased` stays above ~1 000 is the signal that follow-up B (issue #110, a READY table) is needed.

## 4. What is measured, and the honest gap

Since rc.29 `synapsed` answers `GET /v1/stats` (bearer session token, like `/v1/list`) with cumulative
per-role counters and no message content:

```json
{"scope":"home","since":"<RFC 3339>","daemon_started":"<RFC 3339>","roles":[{"global_id":"restarttest@soaktest","sent":0,"submitted":0,"acked":0,"redelivered":0,"expired":0}]}
```

`sent` is new messages queued **for** the role (a duplicate send is not one); `submitted` is new messages the role itself sent; `acked` is removals by the role;
`redelivered` is every delivery after a message's first; `expired` is the part of `redelivered` whose previous
lease ran out (the rest are takeovers). **Since rc.195 the counters survive a clean daemon restart (`stats.json`, flushed within 2 s of a change; a kill loses at most that),
so `since` no longer moves; `daemon_started` does.** Read `daemon_started` at every reading; a changed value is a restart (stop
condition 5). Before rc.195 a restart zeroed the counters and moved `since`, and the counts before it are only in the readings you saved. Take a reading at least hourly and
append it to a log. There is no CLI subcommand for it yet: a reading needs a session token for any claimed role
(`POST /v1/claim`), sent as `Authorization: Bearer <token>` to the announced address with that `Host`.

The rest still comes from other sources:

| Quantity | How | Limit |
|---|---|---|
| sent / acked / redelivered / expired | `/v1/stats` for the receiving role, compared with the canary's `sent.log` | covers all traffic to the role, not only the canary's; zeroed by a restart |
| acked / lost | canary ids that appeared as `<channel>` events in the session transcript, compared to sent. **The daemon stores the id as `<sender global id>/<id>`**, so `meta.message_id` reads `soak-probe@soaktest/soak-001`, not `soak-001`: log or strip that prefix when comparing | needs the transcript; no daemon-side confirmation |
| shown twice | the same `message_id` appearing twice in the transcript | since fix C a repeat after an un-acked lease is expected (the adapter no longer acks and logs no redeliveries); `/v1/stats` `redelivered` counts them |
| never acked / stuck | `synapse list` -> `pending.queued`, `pending.leased`, `pending.oldest_enqueued_at` | a depth snapshot, not history |
| rejected / hostile | lines in `<home>/security-events.jsonl` (rotates at 4 MiB to `.1`) | authentication and budget events, and also `PermissionsTooOpen` (a file-permissions refusal by the CLI); the daemon rate-limits lines per kind and surface to one per second, folding the rest into a count |
| latency | canary send time vs the event's arrival in the transcript | the transcript's clock; ~1 s poll granularity |

**Gap, stated plainly:** the counters are not persisted. A restart loses the history in the daemon (the saved
readings and `sent.log` keep it), and nothing in them says a message was *shown*: that is still the transcript.

Canary (unrun sketch; `--id` makes resends idempotent, so a retry cannot inflate "sent"):
```bash
for i in $(seq -w 1 4320); do   # 4320 x 60 s = 3 days
  synapse send --role soak-probe --to restarttest --id "soak-$i" "canary $i" \
    && echo "$(date -u +%FT%TZ) soak-$i" >> "$H/sent.log"
  sleep 60
done
```
Compare at the end: `sent.log` ids minus ids found in the transcript = lost; ids found twice =
shown twice; `/v1/stats` `sent` for the role must equal the canary's count and, after quiescence, equal
`acked` with `pending` at `queued:0, leased:0` (this shows the daemon is drained, not that anything was shown: the
adapter acks after bounded attempts; lost is the transcript comparison above); `redelivered` explains any message shown twice.

## 5. Stop conditions for the soak (proposed; the PM sets the numbers)

Stop the soak, restore claude-peers-only launches, and write up the cause if **any** occurs:
1. A canary message **lost**: its id was sent and **never appears as a `<channel>` event in the session transcript**. Only the transcript decides this. Since rc.33 the adapter acks a message after bounded delivery attempts, so a daemon-side `acked`, `pending` at `queued:0, leased:0`, or `acked == sent` in `/v1/stats` proves nothing about display: a message whose every push was dropped looks exactly like a shown one there. Compare `sent.log` ids with the transcript (strip the `<sender global id>/` prefix).
2. A message shown more than `max(3, attempts_at_first_pull + 2)` times, or acted on more than once by the model. **Up to 3 shows of one `message_id` is expected** (bounded delivery attempts, section 2.3 check 3; c7 on rc.33 saw 3 of 3 and 2 of 3), so a repeat is not a stop. `attempts_at_first_pull` is the daemon's per-message lease count when this adapter first pulled it, so a message earlier sessions already leased can be pushed up to 2 more times.
3. `pending.oldest_enqueued_at` for a live role older than 5 minutes while the role is `online`.
4. Any `security-events.jsonl` line whose surface is not an expected canary mistake.
5. `synapsed` exits, restarts, or its announce file (`synapsed.json`) names a different instance id
   than the one started.
6. A lane stuck at a dialog or unable to receive on claude-peers because of the second channel.
7. `fetch` cost visibly grows: `queued + leased` above ~1 000 for a role, or CPU of `synapsed` not
   idle between polls.
8. CireSnave says stop.

## 6. Rollback

Phase 1 (everything is disposable):
```bash
kill "$(cat "$H/synapsed.pid")"         # only the PID started above; never taskkill /IM
# close the claude session, then:
rm -rf "$H"                              # the throwaway home, keystore included
# delete mcp.json
```
Verify: `curl http://127.0.0.1:7931/v1/health` fails to connect; `$H` is gone. Nothing outside `$H`,
port 7931 and `mcp.json` was touched, so no other lane is affected.

Phase 2:
1. Relaunch each lane with `--dangerously-load-development-channels server:claude-peers` only (the
   existing approval covers exactly that).
2. Stop the daemon by its recorded PID.
3. If the home existed before rc.27, restore the backup taken in precondition 4. **A home that rc.27
   has opened cannot be opened by rc.26 or earlier**; only the backup restores the old format.
4. Claude-peers was never switched off, so no message path has to be rebuilt.

## 7. Not covered

Cutover; LAN mode (`docs/LAN_MODE.md`); a live test of anything other than `restarttest`; and the
exact `lane-restart` invocation for `restarttest`, which belongs to OverMind and is flagged in 2.2.
