# Cutover step 4: a plan, not a run (2026-11-06)

Proposal only. Nothing here was run; the PM runs it, each step on the PM's go (and CireSnave's where marked).
Step 4 is the last item of `agentlife/docs/SYNAPSE-ONLY-CUTOVER.md` "Order": strip `claude-peers` from user scope,
flip `notify_transport`, retire the old approval records. Rulings behind it: CireSnave 2026-10-28, *"Any lane should
be able to run with Synapse and Synapse only."* (same doc, line 3-5).

## Read today (names and counts only, 2026-11-06)

| fact | reading | control |
|---|---|---|
| user-scope MCP servers in `~/.claude.json` | `['claude-peers']` only | key list is non-empty |
| `notify_transport` in `~/.overmind/lane-restart.json` | key absent, so the default `broker` (`ctx.rs` `transport()`) | the file's only key is `approvals` |
| `.lane-state/*.launch.json` | 48 specs; 40 contain `server:claude-peers`; 0 lack `server:synapse` | 48 files counted; grep -L finds none |
| approval records (ciresnave/ciresnave `.overmind/lane-restart/approvals`) | 8 files, listed under Records | `gh api` listing |
| Phase B soak exit | not in this lane's view; `SYNAPSE-SOAK.md` exit: zero unexplained lost canaries, no lane at a dialog, oldest pending < 5 min, cost measured | |

So step 4's precondition is not met by specs: 40 of 48 still launch with claude-peers named.

## Preconditions (all must hold; each has its check)

1. **Every spec is Synapse-only**: `grep -l "server:claude-peers" .lane-state/*.launch.json` prints nothing, and every lane has restarted under its new spec and sent and received one message (`synapse inbox`).
2. **Phase B exit conditions met** and CireSnave's go for Phase C (`CUTOVER_READINESS_2026-10-15.md` section 4).
3. **claude-peers restore proven for the lane-relaunch half** (SYNAPSE-SOAK.md line 22: OverMind#175 proved broker and server only). Readiness gate 6 was open.
4. **G6 notify half run once**: one real send through the `synapse` notify transport on a scratch home (`agentlife-launcher` relay), recorded. Readiness G6 said "built, not run".
5. **`agentlife status --peers` and `restore` join**: the doc's "unverified" line 45: read `main.rs` call sites to confirm the Synapse `list` join is wired for every caller before the flip.
6. **Snapshot taken** (see Rollback).

## Order of operations (each reversible until the last)

| # | action | who | check after | undo |
|---|---|---|---|---|
| 4a | **Flip `notify_transport` to `synapse`** in `~/.overmind/lane-restart.json` (add `"notify_transport": "synapse"`). Smallest blast radius first: it only moves `lane-restart` notices, `down` wrap-ups and stall alarms. | PM | send one notice to a test lane: it arrives via the outbox + `agentlife launcher` relay; `lane-restart status --peers` prints the "moved" line; `agentlife status --peers` lists roles | set the key back to `broker` (default) |
| 4b | Watch one launcher cycle (the relay must be running: `agentlife launcher`). A refused message stays queued in `.lane-state/notify-outbox/`, junk becomes `*.bad`. | PM | outbox empty, no `*.bad` | as 4a |
| 4c | **Strip `claude-peers` from user scope**: `claude mcp remove -s user claude-peers`. This is a CireSnave-level change by his words (same doc, step 4 of "What a Synapse-only lane needs"), executed by the PM; it also removes it from CireSnave's and the PM's own sessions. Back up `~/.claude.json` first. | PM, CireSnave's go | `~/.claude.json` `mcpServers` has no `claude-peers`; restart one lane: tools list shows `synapse` only; it sends and receives | `claude mcp add -s user claude-peers ...` with the exact entry saved in the snapshot |
| 4d | **Retire approval records** (see Records), by PR to ciresnave/ciresnave, after 4c. | PM | `lane-restart` with a Synapse-only spec still answers its dialog (the any-lane record) | revert the PR |
| 4e | Stop the broker on 7899 (Phase C, not step 4 proper). Only after 4a-4d have run a full day. | PM | no listener on 7899; canary round passes | restart the broker; relaunch a lane with `--dangerously-load-development-channels server:claude-peers` (readiness section 4) |

Order rationale: 4a before 4c, because 4c removes the broker client from the PM's own session, and `lane-restart`
must already be on Synapse by then. 4d last, because a record removed early stops a lane that still names
claude-peers at the dialog.

## Records: the four that name `server:claude-peers` (PM ruling 2026-11-06: use the measured four)

Measured 2026-11-06 over `.lane-state/*.launch.json` (48 specs; Channels value from `launch_args`): 40 specs name
`server:claude-peers,server:synapse`, 8 name `server:synapse` only, 0 name `server:claude-peers` only (8+40=48).
"Last spec write" is `written_at` of the spec, the nearest record of a launch (`written_by` launch, restart,
both-channels or stop); the dialog answers themselves are not logged anywhere I read.

| # | record | answers `Channels` | scope (roles) | specs that match it today | latest spec write among them | expires |
|---|---|---|---|---|---|---|
| 1 | claude-peers-dev-channels | `server:claude-peers` only | all (`*`) | **0** | none | 2027-03-19 |
| 2 | claude-peers-synapse-dev-channels-any-lane | `server:claude-peers, server:synapse` | all (`*`) | **40** (lanes below) | 2026-11-06 (mlmf, restart); by date: 11-01 x11, 11-03 x2, 11-04 x23, 11-05 x3, 11-06 x1 | 2027-04-25 |
| 3 | claude-peers-synapse-dev-channels-pilot | both | synapse, agentlife, overmind | **0** (all three are synapse-only now) | agentlife 2026-11-06, synapse 2026-11-06, overmind 2026-11-01 (their current specs no longer match) | 2026-10-31, expired |
| 4 | claude-peers-synapse-dev-channels-restarttest | both | restarttest, restarttest2 | **0** (`restarttest` is synapse-only; `restarttest2` has no spec) | restarttest 2026-10-14 (import) | 2026-11-09 |

Kept: `synapse-dev-channel-any-lane` (`server:synapse`, all roles, no expiry) answers every Synapse-only lane after
cutover. Not touched: `trust-folder-prefix`. Left to expire or retire as clutter (PM's call): `synapse-dev-channel-pilot`
(expired 2026-10-31) and `synapse-dev-channel-restarttest` (2026-11-09).

Lanes that depend on row 2 today (40): alarmant antspawn auth-framework baracuda bitman bonefish capant coderipper
commy-sdk-rust commy configurant cpufish dirty-ranges fmp-rs fuel httpant humboldt json-mcp-server kiss lightbulb
ml-convertant mlmf openclownfish persistant pm-assist pm releaseant rockfish rust-analyzer-mcp-server safeimage sageant
sortant surfaceant thinkersfoundation thinkersjournal-community unisql unpopped vulkane wasm-sandbox webhostant.
By spec `state` at reading: 14 running, 26 suspended.

Reading: rows 1, 3 and 4 answer no current spec and could be retired now with no lane stopping at a dialog (row 3 is
already expired). **Row 2 is the one that matters: retire it only after precondition 1 holds** (no spec names
claude-peers), or the 40 lanes above stop at the dialog on their next launch. Order within 4d: rows 1, 3, 4 first, row 2 last.

## Rollback and snapshot

Before 4a: copy `~/.overmind/lane-restart.json` and `~/.claude.json` aside; record `git rev-parse origin/main` of
ciresnave/ciresnave; note the `claude-peers` user-scope entry verbatim (command, args, env names only). Rollback of any
step is its "undo" column. Mail sent over Synapse in the window stays in the daemon's mailboxes; claude-peers loses
messages in flight (accepted by CireSnave, archive item 326, quoted in `SYNAPSE-SOAK.md`).

## Not decided / not read

- Which three records (above). Whether CireSnave's go for 4c exists as a written ruling, or must be asked.
- I did not read `agentlife` `main.rs` call sites (precondition 5) or run any lane-restart command.
- Soak results: the canary tally (`.lane-state/soak/canary.tsv`) was not read.
- `lane-restart.json` was read for key names only; its `approvals` object holds repo and path.
