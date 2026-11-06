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

## Records ("retire 3 old records" needs a ruling on which)

| record | `Channels` it answers | scope | expires |
|---|---|---|---|
| claude-peers-dev-channels | `server:claude-peers` | all roles | 2027-03-19 |
| claude-peers-synapse-dev-channels-any-lane | `server:claude-peers, server:synapse` | all roles | 2027-04-25 |
| claude-peers-synapse-dev-channels-pilot | both | synapse, agentlife, overmind | 2026-10-31 (already expired) |
| claude-peers-synapse-dev-channels-restarttest | both | restarttest, restarttest2 | 2026-11-09 |
| synapse-dev-channel-any-lane | `server:synapse` | all roles | none (keep: this is the one that answers a Synapse-only lane) |
| synapse-dev-channel-pilot | `server:synapse` | three roles | 2026-10-31 (already expired) |
| synapse-dev-channel-restarttest | `server:synapse` | restarttest | 2026-11-09 |
| trust-folder-prefix | (not a channels record) | | not touched |

Four records name `server:claude-peers` (rows 1-4). The agentlife doc says "the first three are dead letters" once every
spec is Synapse-only; by the table, that matches rows 1, 2 and 4 or rows 1-3 depending on what "first three" counted.
**The PM should name the three**, and rule on row 4 and on the two expired synapse-only rows (retire as clutter or leave
to expire). Do not retire row 2 before precondition 1 holds: it answers every lane that still lists both channels.

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
