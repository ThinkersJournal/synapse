# Synapse roadmap

Written 2026-10-14 against `origin/main` f506140 (6.0.0-rc.47); rows 4, 11 and 18 refreshed 2026-10-16 at 2e92b03 (rc.97). Current state, not history: delete what is done, move what
is worth keeping to its home. Priorities across projects live in the portfolio roadmap; this file is Synapse's own path.

**The public flip is CireSnave's decision**, not this file's. Everything below is "ready so he can say go", and nothing here
publishes anything.

## What Synapse is

A provider-agnostic agent-to-agent transport: authenticated messages between processes (TCP/UDP/QUIC/email), a local daemon
(`synapsed`) with an at-least-once mailbox (redb), a CLI (`synapsectl`), an MCP server, and a Claude Code channel adapter.
It moves bytes between processes; it does not put them into an agent (that is each agent's client or an adapter).

## Release path to the public flip (ordered)

| # | Item | State at f506140 | Blocks flip? |
|---|------|------------------|--------------|
| 1 | CI green and protected: required checks, `--locked`, Cargo.lock tracked, actions on newest majors | done (rc.43-rc.46) | no |
| 2 | Docker image push to `ghcr.io/thinkersjournal/synapse` | moved from Docker Hub in rc.131 (one secret store: `GITHUB_TOKEN`); first GHCR push not yet read back | no |
| 3 | Coverage upload | done (org-level `CODECOV_TOKEN`, 2026-10-12) | no |
| 4 | **`cargo publish --dry-run` in dependency order**: `synapse` (root) -> `synapse-security` -> `synapsed-client` -> `synapse-mcp-server` -> `synapse-claude-channel`; `synapsed` and `synapsectl` after `synapsed-client` | **DONE**: the PM published the family at 6.0.0-rc.97 on 2026-10-16 (PM notice: 7 crates, none yanked; `synapse` 6.0.0-rc.97 read back from the crates.io API as `max_version`). The other six were not re-read by this lane | no |
| 5 | **Cold first run from the README** | done at rc.48 (#146): CLI sequence runs end to end; README no longer names `message_routing_system`/`register_peer` | no |
| 6 | `docker-compose.yml` matches the daemon | done: one loopback-only daemon service with a volume, run against `ghcr.io/thinkersjournal/synapse:main` (the old `:latest` tag never existed). `ci_cd.yml` deploy jobs still `docker-compose pull/up` over ssh: unchanged, not exercised | no |
| 7 | `whoami` push advertisement | done in rc.52: `push: {capability_key, method}` on the channel adapter, `null` on the generic one | no |
| 8 | Soak ends with `sent.log` matching the transcript | running (rc.33 daemon, 1 msg/10 min since 2026-10-12T18:31Z) | no (evidence) |
| 9 | Alert delivery: `AlertTransport` had no implementation (board 131); alerts were logged only | **DONE as an internal transport in rc.101 (PM-ruled 2026-10-17)**: `SYNAPSE_ALERT_ROLES` names the roles that receive alerts as mail from `daemon:alerts@<account>`; unset, nothing changes. **Which external channel carries an alert to a person stays board 131 (CireSnave's)** | no |
| 10 | Dependency currency: `auth-framework` `0.6.0-rc42` -> `0.6.0-rc55` | done in rc.63 (#159; item 15) | no |
| 11 | crates.io names: `synapse` is at 1.1.0 there (ours is 6.0.0-rc.47, higher); the six other names are `0.0.0` placeholders. Ownership/permission was the open question; the rc.97 publish (row 4) went through, so it is settled for the seven published names | done |
| 12 | `docs/` staleness pass | measured and bannered in rc.55 (`python .github/docs_staleness.py`): 12 pages at 0.69-0.99 unknown-method rate carry an unverified banner; **not rewritten** (per-page decisions: rewrite to the daemon surface, or delete). README Advanced Features sections are 0.47 and unbannered. rc.57: `API_REFERENCE.md` cut to the daemon/CLI/MCP surface, the empty files deleted, the eight root reports archived to `docs/archive/`; **rc.100 (PM-approved, 2026-10-17): five pages for retired features deleted** (`OAUTH_AUTHENTICATION`, `SYNAPSE_COMPLETE_ARCHITECTURE`, `UNKNOWN_NAME_HANDLING_COOKBOOK`, `IDENTITY_RESOLUTION_TROUBLESHOOTING`, `ADVANCED_MONITORING`: the types their samples use are absent from the code), **three rewritten to the daemon surface** (`TROUBLESHOOTING`, `CONFIGURATION_GUIDE`, `DEVELOPER_GUIDE`); `NEW_FEATURES`, `LLM_DISCOVERY_GUIDE` and `CIRCUIT_BREAKER_SYSTEM` stay (their modules exist) with their banners | no |
| 13 | **Daemon start failures name their cause** (DONE in rc.51, #148): `synapse claim` on a refused home prints only "synapsed exited (exit code: 2) and no daemon answered"; `synapsed` itself prints the reason (`permissions_too_open` + path, or `no account`) on its stderr, which the CLI's on-demand start drops. Fix: surface the daemon's stderr (or its last line) in the CLI error, with a test per cause | open (PM 2026-10-14) | no, but the first thing a new user hits |
| 14 | `src/lib.rs:185` doc named `message_routing_system` | done in rc.56 (a commented-out `register_peer` at `src/lib.rs:70` remains) | no |

Each item is its own PR with a version bump (PM allocates the number). Items 4-6 go first: they are mechanical and each one
can fail the first public user.

## What Synapse gives and takes

| Project | Synapse takes | Synapse gives | State |
|---------|---------------|---------------|-------|
| **auth-framework** | Account-holder auth, OAuth, JWT, credential stores, behind the optional `auth` feature (`auth-framework = 0.6.0-rc42`) | Real usage as a consumer; findings (e.g. the lettre `tokio1`/native-tls compile_error, the aws-lc-rs C dependency the owner accepted) | live; currency gap in item 10 |
| **OverMind** | Orchestration: choosing sessions, spawning, restart tooling; the 17-paper AI-to-AI literature summaries that `DESIGN_AI_TO_AI_COMMUNICATION.md` cites | Messaging between modules and lanes (OverMind's layer spec says messaging is Synapse's, not OverMind's); a Synapse plug-in point (`on_message_in`); the soak host (OverMind owns the restarttest session) | design agreed in OverMind's `ARCHITECTURE-LAYERS-SPEC.md`; OverMind's `dispatch.py` was built against FAM, not Synapse (its DESIGN-PROPOSAL, possibly dated) |
| **PersistAnt** | Nothing yet. Its `DESIGN-KINDS.md` proposes shared blob/kv/lock/rel kinds and lists Synapse's mailbox (redb), keystore, locks and the legacy Postgres layer as inputs and as a later migration (rows 2 and 6) | The measured requirements: one atomic multi-key transaction with ordered composite-key scan, 0600 files, no-clobber publish by hard link, OS file lock | proposal on PersistAnt's side; nothing adopted. Synapse stays on redb until it exists and passes the mailbox contract tests |
| **KISS** | Nothing | Nothing | **no relationship today**: `git grep -i synapse origin/main` in KISS finds 0 files, and KISS standardises ML kernel interfaces. Do not invent one |
| **Trust vouching** (to be spun out) | Optional trust-hook trait implementation, published on crates.io | `TrustSource` (`src/synapse/services/trust_source.rs`), the seam a vouching crate would implement | spin-out not scheduled (CireSnave 2026-10-08) |
| **Introduction app** (not started) | Account-owner introductions, so Synapse never authenticates account owners itself | Agent certificates (slice f) are the cryptographic side | waits for a lane to state requirements |

**Unverified until its first CI run:** `the_daemon_start_file_is_owner_only` (rc.54, `cfg(unix)`) asserts the `0600` mode of `synapsed-start.err`; it compiles to nothing on the Windows box it was written on, so it was not seen red or green locally and `Build and Test` on ubuntu is its first execution.

## Next slice: what Synapse consumes and owes (measured 2026-10-14 at main 704fa34, rc.57)

Built from the portfolio roadmap's entries for auth-framework, PersistAnt and UniSQL, checked against each repo's `origin/main`
and crates.io. Nothing here is started; each item is its own PR.

| # | Item | Measured | Owner / decision |
|---|------|----------|------------------|
| 15 | **Dependency currency** (CireSnave: newest versions at all times) | `redb` 4.3.0 -> 4.4.0 (the mailbox store; DONE in rc.59 with a forward and rollback file proof); `sqlx` 0.8.6 -> 0.9.0 (DONE in rc.61, compile-checked only: no test reaches PostgreSQL); `redis` 0.32.4 -> 1.7.1 (a major; DONE in rc.62, compile-checked only: no test reaches Redis); `auth-framework` 0.6.0-rc42 -> 0.6.0-rc55 (crates.io; DONE in rc.63, guard re-run: `enhanced-auth` still broken). redb first: it holds the on-disk mailbox, so check the file-format stamp before and after | Synapse lane |
| 16 | **Default features compile layers the daemon does not use** | **DONE rc.83 (board 199, CireSnave: "Retire database and cache features.")**: `database` and `cache` and their modules (`storage`, `services::{discovery,privacy_manager,registry}`, `api::{discovery_api,participant_api}`) are removed; `sqlx` and `redis` leave the tree | done |
| 17 | **auth-framework: consumed but not used** | **DONE rc.83 (board 200, CireSnave: "Retire the auth-framework feature.")**: `auth`, `enhanced-auth`, the `auth-framework` dependency, `src/auth_integration_enhanced.rs` and the CI guard are removed | done |
| 18 | **PersistAnt: owed a store contract, consumes nothing** | `persistant` 0.4.28 is on crates.io. Its `DESIGN-KINDS.md` takes Synapse's mailbox (atomic multi-key transaction, ordered `(role, seq)` scan) as a requirement. Synapse already has the contract as `src/mailbox/conformance.rs` (it began as `tests/mailbox_suite/mod.rs`), run against the memory and redb `MailStore`s. The suite is now reusable: `synapse::mailbox::conformance::run_all` (DONE in rc.65, #162). **Spike 2026-10-16 (outside the repo, `C:/s/spike-kvmail`; PersistAnt 0.6.2 at git `cdb29ab`, Synapse rc.97):** a `MailStore` over `KvOnRelational` passes `contract::check` (7 leaves), all 21 conformance cases and `run_all` on SQLite 3.51.3, PostgreSQL 16.15 and MySQL 8.4.11, and an 8-thread duplicate-`seq` test shows none with the `Require` guard (65-70 of 80 duplicated without it). **Defect found, routed to PersistAnt:** on PostgreSQL and MySQL, racing batches whose first op is `Require(key, absent)` can return a `deadlock detected` error instead of `Ok(false)`; rerun the spike when it is fixed. Not measured: batch crash safety, power loss. Still owed before any adoption: a decision to leave redb, a migration, and the crash measurements. Consumed later, only if PersistAnt offers them: `blob.replace_atomic` for the three atomic-replace sites. Stays native: `create_exclusive_atomic` (hard link) and `file_mode` (0600), which OpenDAL does not offer. **Synapse stays on redb until a PersistAnt backend passes the suite**; any on-disk change needs a migration | Synapse lane (suite); PersistAnt lane (backend) |
| 19 | **UniSQL: a corpus, if the SQL survives** | `unisql` is `0.0.0` on crates.io; its `DESIGN.md` names Synapse's Postgres use as one input. Synapse owes nothing and consumes nothing now. If item 16 keeps the legacy relational layer, its SQL (24 `sqlx::` references in `database.rs` and `migrations.rs`) is a sample corpus for dialect translation and would be consumed through PersistAnt's relational kind; if it is retired, there is nothing to offer | Contingent on 16 |

## Open issues, scheduled (verified 2026-10-23 at origin/main a2e98e2, rc.133)

Each row is its own PR with a version bump (PM allocates the number). "Verified" means the cited file or command was read at that ref.

| # | Issue | Verified state | Plan |
|---|-------|----------------|------|
| 20 | #49 QUIC pool eviction on verification failure | Still unmet: `QuicTransportImpl::evict` (`src/transport/quic_unified.rs:372`) has no production caller; `TransportManager` holds `Box<dyn Transport>`. Robustness, not security (sealing/signing already rule out spoofing). | Slice: a `Transport`/`TransportReceive` contract change touching every transport (the spec's deferred condition 3), red-first test that a verification failure evicts and the next send reopens. After the cutover work. |
| 21 | #61 unused dependencies | 9 remain, each with 0 uses in src, tests, examples and crates: `ahash`, `async-smtp`, `blake3`, `config` (only the crate's own `config` module), `igd`, `rustls-native-certs`, `stun_codec`, `syn`, `sysinfo` (2 hits, both comments in `src/monitoring.rs`). `rsa` is already gone (CI guards its absence). | One PR removing them and the features that name them; stable has no `unused_dependencies` lint, so check with nightly `cargo clippy --all-targets` before and after, and keep `cargo metadata --locked` green. Mechanical; first. |
| 22 | #105 MCP adapter has no reconnect after a daemon restart | **Fixed in rc.130 (#234)**: `reattach` in `crates/synapse-mcp-server/src/lib.rs`, test `an_adapter_re_attaches_to_a_restarted_daemon_and_not_after_a_takeover` (`tests/adapter.rs:448`). | Close with that evidence. |
| 23 | #106 bidi control characters unescaped in tool output | Open: `escape` (`crates/synapse-claude-channel/src/lib.rs`) and `safe_text` (`crates/synapse-mcp-server/src/lib.rs`) escape only `char::is_control` (Cc). U+202A-202E and U+2066-2069 are Cf, so they pass through (`tests/message_paths.rs:41` sends U+202E and asserts only on Cc). | Red-first test with U+202E and U+2066, then escape the Cf bidi set in both functions. Small. |
| 24 | #110 READY table for O(max) fetch | Conditional: do only if the M9 soak shows a need. Measured at rc.27: `fetch(max=1)` 5.2 ms at a 10k role (5k leased) against 2.1 ms at 1k. | Decide from the soak numbers; no work until then. |
| 25 | #120 always-failing writes re-lease forever | Open. #119 (a refused ack re-pushes every lease) is fixed: the id is parked for the process (`push.rs`, tests in `tests/push.rs`), as is #121 (tests landed in #165). What remains is a write that always fails: `should_ack` counts only successful pushes. Needs a decision, not code. | Decision first (cap/backoff in the adapter or a failure count in the daemon), recorded on the issue; then one PR. |
| 27 | #5 root documents assert a clean `--all-features` build | The premise is stale: `cargo check --all-features --all-targets` exits 0 at a2e98e2 (4m02s cold, 0 errors, run 2026-10-23), and the four reports now live in `docs/archive/` under a README that calls them history. The remaining half holds: no CI step runs that command (`.github/workflows/ci_cd.yml` runs `--all-features` only for `cargo tree`). | One PR adding `cargo check --locked --all-features --all-targets` to CI so the claim cannot rot; then close #5. |
| 28 | #20 what a FAM rewrite loses silently above the transport seam | Synapse side: sealing keys and `CryptoManager`, replay suppression (`src/replay.rs`), account-signed agent certificates (keystore, `src/certificate.rs`) all exist. FAM is not yet merged in. | Keep open as the FAM-merge checklist: when the merge is scheduled, test each of the four rows (sealing, identity resolution, replay, vouched chain) on the Synapse path, one test each. No work before then. |
| 29 | #21 a push channel must be a declared capability; #22 config dir and data store differing by a suffix | #21: done as ROADMAP row 7 (rc.52): `whoami` advertises `push: {capability_key, method}`, covered by `tests/foreign_client.rs:264`. #22 concerns FAM's `~/.fam` / `~/.fam.db`; Synapse keeps its keystore, mailbox and announce file under one home directory. | Close #21 and #22 with this evidence (#22: FAM's to fix before the merge, not ours). |
| 30 | Shared state between lanes (CireSnave 2026-10-23: *"Synapse should have the ability to store shared stated between lanes. Commy will likely eventually become one of Synapse's communication interfaces."*) | Design: `docs/superpowers/specs/2026-10-23-shared-state-design.md` (records with compare-and-set revisions and hash-chained history; ids-only notifications; forge facts derived by a checker role from a closed registry, never typed; a transport-neutral `StateStore` trait). Nothing built. | Seven slices S1-S7 after the design merges; S4 (the checker and derived facts) is the one that fixes the stale-copy incidents. Order: S1-S3, S4, #106, S5-S7; ahead of the unstarted rows 20-29 except #61. Does not touch `mailbox.redb` or the soak. |

## After the flip (unordered, not tasked)

- **claude-peers cutover, wake-on-mail and lane launch on message** (CireSnave, 2026-10-15: *"Claude-peers is going away. Synapse is its replacement."*, a decision, not a question). Design: `docs/superpowers/specs/2026-10-15-cutover-and-lane-launch.md`; code PRs follow it.
- Deferred minors listed in HANDOFF (M5a/M5b/M6b), and issues #48, #55, #56. (#1 was closed as obsolete; #5, #20-22, #49 and the rest are the open-issue rows above.)
- The 6.0.0 final cut (rc series -> 6.0.0) once items 4-6 and 11 are done.
