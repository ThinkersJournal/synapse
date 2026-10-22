<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Pilot T-0 runbook (PM runs this, in order)

Spec: `docs/superpowers/specs/2026-10-15-daemon-contract-and-pilot.md` (section 3 = measures).
Written 2026-10-16 against `origin/main@993abf3` (6.0.0-rc.94). **Rehearsed 2026-10-17 at `bb84636` (6.0.0-rc.102)**
in a throwaway home on port 7961 with two stand-in MCP clients driving `synapse-claude-channel`: sections 2 and 4
below are corrected to what that run printed. Not rehearsed (they touch lane config or the scheduler): `-Register`,
`schtasks /Run`, section 3, the G5 dialog. "Expect" lines in those say so where they are a guess.
Subject: lanes `synapse`, `agentlife`, `overmind`. Pilot home: `C:\Users\cires\AppData\Local\synapse-pilot`
(exists, empty as of 2026-10-16; the default `%LOCALAPPDATA%\synapse` does not exist). Address `127.0.0.1:7920`.

## 0. Read first

- **The Claude Code adapter is `synapse-claude-channel`, not `synapse-mcp-server`.** `server:synapse` needs the
  `claude/channel` capability, which only `synapse-claude-channel` declares. `synapse-mcp-server` (bin
  `synapse-mcp`) is the generic MCP adapter: it would load, never push. Install the channel crate.
- `synapsectl`'s binary is `synapse.exe`. agentlife's `-Exe` help text says "beside synapsectl.exe and
  synapse-mcp-server.exe": wrong names, harmless (only the file path matters), fix in agentlife.
- Blockers that are not mine: **G5** (CireSnave's yes + OverMind's approval record for the channel string
  `server:claude-peers, server:synapse`; without it every relaunch stops at a dialog nobody answers) and a
  decision on the **account name** (`<ACCT>` below).

## 1. Install rc.123 and stop the rc.33 daemon

```powershell
cargo install synapsed --version 6.0.0-rc.123 --locked --features sqlite-store
cargo install synapsectl synapse-claude-channel --version 6.0.0-rc.123 --locked
```
Two commands: `--features` applies to every package named in one `cargo install`, and only `synapsed` has `sqlite-store`. Board 237 (CireSnave, "Decision 237: yes") puts the pilot on the SQLite mailbox store; a `synapsed` built without the feature refuses `SYNAPSE_MAILBOX_STORE=sqlite` and the pilot would not start.
Needs the MSVC toolchain env your shell already has. Prerelease: `--version` must be exact.
Expect: `Installed package ... synapsed`, `... synapsectl`, `... synapse-claude-channel`; in `C:\Users\cires\.cargo\bin`:
`synapsed.exe`, `synapse.exe`, `synapse-claude-channel.exe` (side by side: the client looks next to its own exe).
Check: neither `synapsed` nor `synapse` has a `--version` flag; `Get-Item` the exe, and the daemon's `version` is in neither (`synapse list` has no version field); the adapter's MCP `serverInfo.version` shows the installed build. `synapsed --help` does not print help: it starts a daemon on the default home, so never run it bare.
Rollback: `cargo uninstall synapsed synapsectl synapse-claude-channel`.

Stop the old daemon (restarttest, rc.33, **pid 28280**, `...\synapse-restarttest-bin\synapsed.exe`, port 7931,
started 2026-10-12):
```powershell
$p = Get-CimInstance Win32_Process -Filter "ProcessId=28280"
$p.ExecutablePath    # must be ...\synapse-restarttest-bin\synapsed.exe, else STOP: the pid was reused
Stop-Process -Id 28280
Get-NetTCPConnection -State Listen -LocalPort 7931 -ErrorAction SilentlyContinue   # expect: nothing
```
Never `taskkill /IM synapsed.exe` (kills the new daemon too). Breaks: only the disposable restarttest home on
7931 (`...\synapse-restarttest`, kept on disk, nothing else uses it; no `restarttest` lane runs). rc.33 does not
touch the pilot home or port. In-memory counters and presence die with it (expected).
Rollback: `Start-Process "C:\Users\cires\AppData\Local\synapse-restarttest-bin\synapsed.exe"` with
`SYNAPSE_HOME=...\synapse-restarttest` and `SYNAPSE_ADDR=127.0.0.1:7931` set first.

## 2. Identity, then the scheduled task (agentlife `scripts/synapsed-task.ps1`)

```powershell
$env:SYNAPSE_HOME = "C:\Users\cires\AppData\Local\synapse-pilot"; $env:SYNAPSE_ADDR = "127.0.0.1:7920"
synapse id init --account <ACCT>
synapse id show --role synapse; synapse id show --role agentlife; synapse id show --role overmind
```
Expect (rehearsed): `account: <ACCT>` and `account key id: ...` from `id init`; `id show` adds `identity: <role>@<ACCT>`,
`signing key id`, `sealing key id`, `certificate valid: <now> to <now+24h>` and `permissions: ack, request-ack, send`; never key
material. The 24 h certificate does not end the pilot: the keystore reissues it once under 12 h remain
(`RENEW_BELOW`, `src/keystore.rs`). The home must be owner-only: a home under `C:\s` inherited Authenticated Users and
`id init` refused it (`permissions_too_open ... account directory`, exit 2); a home under `%LOCALAPPDATA%` works.
`id init` refuses a second run (`error: an account already exists`, exit 2). Rollback: delete the pilot home (step 5).

**Server stores are not the pilot's store** (Decision 237 is SQLite). If a later pilot uses PostgreSQL/MySQL, `synapse storage use <id> --url-env VAR` records the variable name and the wrapper must set `VAR` itself; one daemon per database is enforced by a lease (a restart after a hard kill can be refused for up to 20 s). Detail: `docs/MAILBOX_STORES.md`.

**The store choice must reach the daemon, and the task wrapper does not carry it.** `scripts/synapsed-task.ps1` (agentlife) SETs only `SYNAPSE_HOME`, `SYNAPSE_ADDR` and `SYNAPSE_LAUNCHER_ROLES`; a lane's environment never reaches the daemon. The pilot home is fresh, so a daemon started without `SYNAPSE_MAILBOX_STORE=sqlite` would open the default store (redb, `mailbox.redb`) there, and the pilot would not be the SQLite pilot Decision 237 ruled. Before `-Register`, the agentlife script needs a `set "SYNAPSE_MAILBOX_STORE=sqlite"` line in the wrapper (a `-MailboxStore` parameter, validated like `-LauncherRoles`). Until that lands, do not register. After registering, read the wrapper (`%SYNAPSE_HOME%\task\synapsed-run-*.cmd`) for that line and, after the first start, confirm that `mailbox.sqlite` (not `mailbox.redb`) is the file that appears in the pilot home (`StoreKind::file_name`, `crates/synapsed/src/lib.rs`).

Dry run (prints the wrapper and the task XML, changes nothing), then register:
```powershell
cd C:\Projects\agentlife
.\scripts\synapsed-task.ps1 -Exe C:\Users\cires\.cargo\bin\synapsed.exe -SynapseHome $env:SYNAPSE_HOME -Addr 127.0.0.1:7920
.\scripts\synapsed-task.ps1 -Exe C:\Users\cires\.cargo\bin\synapsed.exe -SynapseHome $env:SYNAPSE_HOME -Addr 127.0.0.1:7920 -Register
schtasks /Run /TN synapsed-cires
synapse list --role synapse
```
Expect: dry run starts `DRY RUN (nothing written...`; register ends `registered task synapsed-cires (read back: logon
trigger, restart-on-failure, wrapper ...)`. The dry run printed task `synapsed-cires` (rehearsed). **`synapse list` requires `--role`** (a bare `synapse list`
exits 2) and acting as a role makes that role present, so the output is never empty: it is one JSON line per role the
daemon knows, the caller `online: true`. No error means the daemon answered and proved its instance id.
**The CLI starts a `synapsed` itself when none answers** (`synapse: started synapsed (pid N)`): after any stop by pid,
the next `synapse` or adapter call resurrects a daemon, from the caller's environment, outside the task. Log: `%SYNAPSE_HOME%\task\synapsed.log`.
Exit 2 from `synapsed` is a config or lock problem; the wrapper reports it and does not restart.
Rollback: `.\scripts\synapsed-task.ps1 -Remove` (leaves logs and home), then
`Stop-Process -Id (Get-Content "$env:SYNAPSE_HOME\synapsed.json" | ConvertFrom-Json).pid`
(rehearsed: `synapsed.json` is `{"addr","instance_id","pid"}` and stays after the stop; confirm with
`Get-NetTCPConnection -LocalPort 7920`). Stop the lanes' adapters first or re-check the port, then confirm the pid's
`ExecutablePath` before a second stop.

## 3. Per-lane config

Same for all three lanes; only `--role` differs. Role = the lane's name: `synapse`, `agentlife`, `overmind`.

**a. `C:\Projects\.lane-state\<role>.mcp.json`** (new file; server name MUST be `synapse`):
```json
{ "mcpServers": { "synapse": {
  "command": "C:/Users/cires/.cargo/bin/synapse-claude-channel.exe",
  "args": ["--role", "<role>", "--home", "C:/Users/cires/AppData/Local/synapse-pilot"],
  "env": { "SYNAPSE_HOME": "C:/Users/cires/AppData/Local/synapse-pilot", "SYNAPSE_ADDR": "127.0.0.1:7920" } } } }
```
`SYNAPSE_HOME` in `env` is required: `--home` does not reach a daemon the adapter auto-starts (soak procedure 2.2).

**b. `C:\Projects\.lane-state\<role>.launch.json`**, field `launch_args` (today
`["--dangerously-load-development-channels","server:claude-peers"]`) becomes:
```json
"launch_args": ["--dangerously-load-development-channels","server:claude-peers","server:synapse",
                "--mcp-config","C:\\Projects\\.lane-state\\<role>.mcp.json"]
```
Both flags are on `lane-restart`'s carry-over allowlist. **Editing this spec alone does not survive a restart**
(measured by OverMind from `agentlife@e609da5` code, not run: `docs/PILOT-OVERMIND-LANE-CONFIG.md` in the OverMind
repo, section 3). A restart launches from the state file `.lane-state/<role>.json` (the original launch's full
argv), then overwrites `<role>.launch.json` from it. So **the hand launch below is required**: it is what puts the
new flags in the state file. After it, read back `<role>.json` and `<role>.launch.json`: both must hold the new
flags, and only then does a normal restart carry them. Editing the spec first only matters for stop-then-`start`.

First launch of each lane (hand, in the lane's cwd; Sonnet only):
```
claude --model sonnet --mcp-config C:\Projects\.lane-state\<role>.mcp.json --dangerously-load-development-channels server:claude-peers server:synapse
```
Answer the dialog "I am using this for local development" (option 1) **only if** its text matches the G5 record;
an unfamiliar dialog = STOP. A session at the dialog still fires `SessionStart`: confirm a real prompt is accepted.
Cwds: synapse `C:\Projects\synapse`, agentlife `C:\Projects\agentlife`, overmind `C:\Projects\OverMind`.
Rollback per lane: restoring the spec and restarting reverts nothing (a restart rebuilds from the state file).
Hand-launch once with the old flags (`claude --model sonnet --dangerously-load-development-channels server:claude-peers`)
so `SessionStart` re-records them, confirm `<role>.json` and `<role>.launch.json` show the two-element form, delete
`<role>.mcp.json`, then restart normally and confirm a prompt.

## 3c. Non-lane senders: AgentLife M8 (`agentlife-launcher`, `agentlife-cli`)

Added at rc.105 from AgentLife's account of its M8 (reported by the agentlife lane 2026-10-17; their code was not read
for this note). These are **senders, not Claude lanes**: no session, no `claude-peers` channel, no adapter, so the
three-lane config in section 3 does not apply to them. Both need the `send` permission (the default role certificate
carries `ack`, `request-ack`, `send`).

| Role | What it sends | Target | When it claims |
|---|---|---|---|
| `agentlife-launcher` | waiting and launch-result notices, alarms, relayed host ASKs | `pm` | while the launcher service runs |
| `agentlife-cli` | `agentlife down` wrap-up requests (PM-run) | the lane's role | once per `agentlife down` run |

**Address the recipient qualified: `pm@ciresnave`, never bare `pm`.** `/v1/send` to a bare role is 404 `unknown_recipient`
(measured by the agentlife lane against a scratch `synapsed` rc.101; the code requires `role@account` with this daemon's
account, `crates/synapsed/src/lib.rs` "Review I2"). `synapsectl` qualifies a bare name for its own callers; a library
caller such as AgentLife's must send the qualified form. The account is `ciresnave` per the PM (the `<ACCT>` of section 2).

**Order matters.** `/v1/send` answers 404 `unknown_recipient` unless the recipient is in the daemon's account **and has
claimed at least once on this daemon** (`crates/synapsed/src/lib.rs`, "Review I2"). So at T-0:
1. `pm` claims first (a `synapse list --role pm` is enough; or the PM's own adapter session). A role that has claimed
   once stays known, even when no session is connected: mail then waits in its durable queue.
2. Then the lane roles (`synapse`, `agentlife`, `overmind`) claim, as section 3.
3. Only then may `agentlife-launcher` start, and `agentlife-cli` on its first run. A launcher started earlier gets 404s;
   repeated 404s from one sender are counted and, over budget, written to `security-events.jsonl`
   (`unknown_recipient`), which measure 6 would then have to classify.
Each role needs its own keys in the pilot home (created when the role first claims through `synapse`; whether the
`synapsed-client` library path AgentLife uses creates them was **not rehearsed**, rehearse it in a scratch home first,
as in section 4).

What the 24 h pilot measures for them (spec section 3, by measure number):
- **1 Loss by id and 2 wake latency:** AgentLife's sender log lists every send as `<id> <to-role> <utc>`, with ids
  `pilot-agentlife-launcher-<n>` and `pilot-agentlife-cli-<n>`. A loss can only be decided where a **session reads
  the message**: for a lane target, its transcript; for `pm`, only if the PM's session runs the adapter. If `pm` has no
  adapter session, those sends are measured by `synapse stats` (`sent` against `acked`) and `synapse dead pm` instead,
  and the report says that measure 1 could not be decided for them.
- **3 Shows per id:** only for targets that have an adapter.
- **4 Queue age:** applies to `online` roles. `pm` without a session is not `online`, so its queue is expected to
  age; do not read that as a breach (read it as undelivered mail, and say so).
- **5 Dead set and 6 Security events:** `synapse dead pm` and every line naming `agentlife-launcher` or
  `agentlife-cli` (failed claims, `unknown_recipient`, bad bearer) are classified. The launcher's claims after the
  deliberate daemon restart (measure 7/10) are a normal re-claim, not an event to explain.
- **Not measured for them:** 8 (they have no dialog), 9 (no model turns, no cache-read).
- A sender whose daemon restarted must re-claim; AgentLife's behaviour on a 401 is **not covered** by this pilot
  unless the deliberate restart is done while the launcher is sending.

## 4. First message and the measures

```powershell
synapse list --role synapse   # one line per role that has connected, "online": true (heartbeat every 30 s; window 90 s)
synapse send --role overmind --to synapse --id pilot-overmind-0001 "smoke"
```
Expect: the synapse session shows a `<channel source="synapse">` event, text starting `UNTRUSTED message from`,
within ~1-2 s. Then `synapse list` shows `pending` for `synapse` at `queued:0, leased:0` after the adapter's bounded
attempts (up to 3 shows, ~30 s apart; same `message_id`; act once).
Rehearsed: `send` prints `message id: overmind@rehearsal/pilot-overmind-0001` and `outcome: queued` (the id is prefixed
with the sender's identity: match on the suffix); the event arrived at +0.7 s, +31 s, +61 s, with `meta.message_id`,
`sender`, `sender_cwd`. `pending` read `leased:1` at +15 s and +60 s and `queued:0, leased:0` by +120 s. `synapse stats`
then read `sent:1, acked:1, redelivered:2, expired:2` for that one message: **`expired` and `redelivered` count each
unacknowledged show, so 2 per message is normal, not loss** (measure it as `sent` vs `acked` plus `synapse dead`, which
was empty).
Record at T-0 in the pilot log: `git rev-parse` of the rc.123 tag/commit (crates.io rc.123 = the commit it was
published from), `synapse list --role <r>` output, the task XML, and each lane's `--role`. Then start the 10 measures
(spec section 3, table): sender log lines `<id> <to-role> <utc>` with ids `pilot-<role>-<n>`; `synapse list --role <r>` every 5 min;
`security-events.jsonl` and `synapse dead <role>` at the end. Do not `curl` the port without a session
(it writes `security-events.jsonl` lines).

## 5. STOP, and rollback to claude-peers-only

STOP on any of: a lost id (sent, never in the receiver's transcript); a lane stuck at a dialog or unable to
receive on claude-peers; `pending.oldest_enqueued_at` > 5 min for an `online` role that does not clear on the
next sample; an unexplained `security-events.jsonl` line; `synapsed` exits or its pid/`started_at` changes
(other than the deliberate restart); CireSnave says stop.

Rollback (nothing on claude-peers was ever switched off, so no path needs rebuilding):
1. Per lane: hand-launch once with the old flags (`claude --model sonnet --dangerously-load-development-channels
   server:claude-peers`) so the state file records them (restoring `launch_args` in the spec and restarting is
   overwritten: section 3b), confirm `<role>.json` and `<role>.launch.json` show the two-element form, delete
   `<role>.mcp.json`, then restart normally (`lane-restart --role <role>`). Confirm each reaches a prompt.
2. `.\scripts\synapsed-task.ps1 -Remove`, then stop the daemon by pid (step 2 rollback). Never by image name.
3. Keep `$env:SYNAPSE_HOME` until the pilot report is written (the mailbox and `security-events.jsonl` are the
   evidence). Then `Remove-Item -Recurse "C:\Users\cires\AppData\Local\synapse-pilot"` (keystore included).
4. `cargo uninstall synapsed synapsectl synapse-claude-channel` if rc.123 should leave the machine too.
