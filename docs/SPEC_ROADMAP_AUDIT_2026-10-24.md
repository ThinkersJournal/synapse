# Spec to roadmap audit

Read 2026-10-24 against `origin/main` fee84b7 (6.0.0-rc.156), at the PM's request: every unmet or deferred
condition in `docs/superpowers/specs/` gets a ROADMAP row or an issue, and done ones say where.

**Method.** All 26 files were searched for deferral words (deferred, not yet, unmet, follow-up, out of scope,
later slice, open question, future, TODO) and the 35 hits read in context; the two long status tables in
`2026-10-12-agent-facing-mcp-adapter.md` and the gap table in `2026-10-15-cutover-and-lane-launch.md` were read
whole. A spec with no hit was not read line by line, so "no hit" is not "nothing owed". Each disposition below was
checked against `origin/main` with the command or file named, unless it says *not re-verified*.

## Open: now ROADMAP rows 32-35

| Spec | Item | Evidence it is open | Row |
|---|---|---|---|
| `2026-10-07-public-mcp-endpoint-design.md` | The public MCP endpoint is "designed, not built"; its section 9 has four open questions (what "Muse" is, which SMTP relay, which hostname, who does the G3 independent review) | `2026-10-12-agent-facing-mcp-adapter.md:43` says "designed, not built"; no listener code beyond the loopback daemon | 32 |
| `2026-09-17-agent-certificates-design.md`, `2026-09-17-replay-suppression-design.md` | Trust-on-first-use peer discovery, then the introduction app | Both specs name it as the follow-up; ROADMAP had a row only for the app | 33 |
| `2026-10-10-channel-ack-and-gate.md` | The readiness gate (its section 4) is deferred, to be built only if a re-test shows an event racing registration | `git grep -i readiness` in the two adapter crates: 0 hits | 34 |
| `2026-10-12-agent-facing-mcp-adapter.md` | Rows still marked NOT met, Missing or UNVERIFIED: a guard test that rendered text never says "verified" or "sealed" unless the daemon payload carries it; a Python-style client that drops unknown notifications (3 pushes, then the adapter acks), never run live; an agent acting once on a real request | No such guard test in `crates/synapse-claude-channel/tests` (grep: 0). The other two were not re-run | 35 |

## Open, already tracked

| Spec | Item | Where |
|---|---|---|
| `2026-09-22-quic-transport-design.md` condition 3 | Pool eviction on verification failure | Row 20, #49, design `2026-10-24-quic-pool-eviction-design.md` (#252) |
| `2026-10-07-brute-force-hardening-design.md` section 6 | Deleting the old `synapse::api`, `blockchain`, `services` trees is "the FAM/Synapse merge's call" | Row 28, #20 (FAM-merge checklist) |
| `2026-10-09-fetch-scan.md` | Follow-up B, the READY table | Row 24, #110 (conditional on the soak) |
| `2026-10-23-shared-state-design.md` | Q1 to Q5 are ruled and S1 to S4b shipped (#241, #243, #244, #245, #246, #247) | Row 30 |

## Closed or answered since the spec

| Spec | Item | Evidence |
|---|---|---|
| `2026-09-17-sealing-design.md` section 9 | Bump `aes-gcm` 0.10 to 0.11 | `Cargo.toml` has `aes-gcm = "0.11"` |
| `2026-09-25-router-merge-design.md` | The merged router's type name | `pub struct SynapseRouter` in `src/router_merged.rs` |
| `2026-10-15-cutover-and-lane-launch.md` G1, G2 | `cwd` and `repo` presence, sender summary in channel `meta` | `list_entries` carries them; `channel_meta` adds `sender_summary` and `sender_cwd` |
| same, G7 | Who starts `synapsed` | `2026-10-15-daemon-contract-and-pilot.md`: AgentLife, from Task Scheduler (task `synapsed-cires`) |
| `2026-10-12-agent-facing-mcp-adapter.md` section 6 | Cold first run from the README | Row 5, done at rc.48 (#146) |
| same, publish dry run | `cargo publish --dry-run` in dependency order | Row 4 |
| same, section 4a / #119, #120, #121 | Refused ack, always-failing writes, missing `message_id` tests | #165, #119 and #120 closed 2026-10-24 |
| `2026-10-01-m3-roles-design.md` section 3.3 | Leases, mailbox, presence, the daemon API, persistence | Shipped (M4, M5): `src/mailbox.rs`, `crates/synapsed` (*not re-verified item by item*) |

## Recorded, not planned (the spec says so; no row needed)

Metadata encryption and forward secrecy beyond HPKE's (sealing section 9); keystore encryption at rest and
limiter state across restarts (brute-force section 6); a process running as the same OS user (M5c); a compromised
account key (agent-certificates item 10); broadcast to all peers (cutover G8, "unless asked"); cross-machine delivery
(cutover: "this design keeps that" local-only; LAN mode is a separate document); group channels and invitations
(FAM scope ruling: message-path parity only); retransmission on a lossy transport (receiver-acknowledgement); two
daemons (cutover); WASM for the QUIC transport ("its own slice after 2.0").

## Found while auditing

- ROADMAP's "After the flip" list sends the reader to "deferred minors listed in HANDOFF (M5a/M5b/M6b)". The
  HANDOFF is current state and lists none. Whoever owns that list must say where it went; this audit could not find it.
