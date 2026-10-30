# Synapse Changelog

All notable changes to the Synapse project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 6.0.0 release-candidate series

### Refactor (rc.197): one store-selection path (ROADMAP row 42, slice B)

`synapsed::select_store` is now the only place the mailbox store is chosen, and `Daemon::open_selected` the only open `main` calls (`named_choice` and the second `StoreKind` match are gone). Behaviour unchanged, each case now has a test (`crates/synapsed/tests/select.rs`): a pin wins (the `SYNAPSE_MAILBOX_STORE` deprecation line still prints); else the recorded `mailbox-store.json`; else a home holding `mailbox.redb` or `mailbox.sqlite` keeps that store; else a fresh home is given and records the first file provider. Redb→SQLite migration and the both-files-no-marker refusal are untouched (`migration::prepare`).

**Planned (slice C), not a promise date (PM ruling 2026-10-30): the `redb` mailbox variant (`StoreKind::Redb`, `SYNAPSE_MAILBOX_STORE=redb`) is removed no earlier than 2026-11-30, and only after (a) the live daemon's home is migrated to SQLite by a tested path and (b) the 3-day Phase B soak is closed and Phase C decided; `redb` stays for the daemon's state engine. Migration window: `migration::prepare` copies and verifies `mailbox.redb` while no daemon holds it, so mail accepted before the stop is carried; sends during the gap from stop to the new daemon's first start get the no-daemon answer and are not queued, and going back to redb after the move loses every message accepted since (message loss on the migration is acceptable: CireSnave 2026-10-30, archive 326). Slice C gets its own ROADMAP row then.

### Feature (rc.196): SQLite store in the default build (ROADMAP row 42, slice A)

`synapsed` now has `default = ["sqlite-store"]`: a home with no mailbox file starts on PersistAnt SQLite; a home that already holds a redb mailbox stays on it. `--no-default-features` builds the redb-only daemon. Measured (release, cold target dir, Windows, `-p synapsed`): `synapsed.exe` 8,150,016 to 31,259,136 bytes; build 357 s to 417 s. The size is sqlx with sqlite, postgres and mysql, accepted for now; a PersistAnt ask to split the registry features is a ROADMAP row.

### Feature (rc.195): `/v1/stats` counts per sender and keeps its counters across a restart

New `submitted` per role (messages that role itself sent; `sent` stays mail queued for the role). The counters are written to `stats.json` in the home when they change (at most every 2 s) and at a clean shutdown, and read back at start, so a daemon restart no longer zeroes them: `since` is when counting began, the new `daemon_started` is this run, and `scope` is now `home` (was `process`). A kill loses at most the last 2 s; an unreadable file starts from zero and says so on stderr. Message counts only, never content. Test `stats_count_per_sender_and_survive_a_restart` restarts a daemon on the same home (sabotage: not loading the file fails it). `acked` still does not show a message was displayed (readiness doc section 6).

### Chore (rc.194): `persistant`, `persistant-sqlx` and `persistant-kv` 0.9 to 0.12.3 (ROADMAP row 42, slice 0)

The three were declared at 0.9.x while 0.12.3 is current (latest-deps rule). `synapse-mailbox-persistant`, `synapsed --features sqlite-store` and `synapsectl --features storage` compile unchanged against 0.12.3; the persistant crate's tests and the whole `synapsed` suite with `sqlite-store` pass. `Cargo.lock` moves the persistant family 0.9.10 to 0.12.3, the `unisql` crates 0.24.17 to 0.27.10, and adds `capant` 0.0.7 (a dependency of `persistant-core`, from crates.io). No git or path dependencies.

### Docs (rc.193): cutover readiness update 2026-10-30 and the runbook's first-soak notes

`docs/CUTOVER_READINESS_2026-10-15.md` section 6 re-reads items 1-6 at `42bb441` (G5 and G7 closed, bounded-attempt delivery accepted by CireSnave, role-name table = the provisioned role list, acked is not displayed) without rewriting the 10-15 text; `docs/CUTOVER_RUNBOOK.md` section 6 records the two first-start findings. No code changes.

### Fixed (rc.192): the adapter's startup failure says what the identity store refused

`describe` turned every keystore error into "the identity store refused: check the role and home", so a lane whose adapter exited at its first start (soak, 2026-10-30, capant and pm-assist) gave the operator nothing to act on. It now appends the keystore's own text, which names the problem (no role certificate, expired certificate, a too-open item) and never a path. **The cause of that first-start exit was a stale installed adapter** (the `~/.cargo/bin` build of 2026-10-23 predates the role-only keystore of rc.134, so it looked for an account key in a role-only home); reproduced with that binary on a fresh provision, and a current build starts on the same home. The fix is to install a current adapter; this change only makes the next such exit name its keystore error.

### Fixed (rc.191): a provisioned lane home reaches the daemon without an announce copy (`SYNAPSE_DAEMON_HOME`)

A role-only home from `id provision` holds keys and no `synapsed.json`, and the client read the announce file only from its own home, so a lane's MCP adapter exited at start (`CONNECTION_CLOSED`); the cutover runbook had never been run end to end. `SYNAPSE_DAEMON_HOME`, when set, is where the announce file is read from; keys and sessions stay in `SYNAPSE_HOME`, and setting it also keeps the CLI from starting a daemon. "No daemon answered" now names the announce file it read: a missing one, or a stale copy that no longer names a running daemon, or a listener that failed the proof. Test `a_provisioned_lane_home_reaches_the_daemon_through_synapse_daemon_home` (no copy in the lane home; control without the variable; stale file after the daemon dies), sabotage-checked. `docs/CUTOVER_RUNBOOK.md` section 2 carries the variable and the stopgap.

### Fixed (rc.190): the SQLite store's cold-start lines carry their own clock

Each `synapse: mail store <path>: <step>` line printed while `SqliteMailStore::open` runs now ends in the wall clock it was written at (UTC, to the millisecond), the time since the previous step and the time since the open began, so a start that fails (the `pool timed out` exits of 2026-10-22, 10-24 and 10-29) shows which step was slow and when. Only the log text changes. The row 42 design note drops the WAL-checkpoint slice: a read-only copy of the live store showed the WAL at exactly 1000 frames, the default `wal_autocheckpoint`, so it is steady state, and the earlier claim that an oversized WAL caused the timeouts is retracted. The cause of the timeouts and who held `mailbox.sqlite` at the time are not established.

### Chore (rc.189): the five unwaived gitleaks hits are triaged and waived with reasons

The CodeRipper portfolio job's SEC-002 scan (gitleaks 8.30.1) reported 7 hits on `main` at `6b63312`; 2 were already waived. The other 5 are not credentials, and each now has a line-scoped `[[allow]]` entry in `.coderipper.toml` with its reason: a 14-character event name in `crates/synapsed/tests/api.rs`; two `format!` PEM templates in `src/auth_integration.rs` and `src/auth_integration_enhanced.rs` (history only, both files since deleted); the jwt.io documentation sample token in `tests/security_test.rs`; and the RFC 6455 sample nonce in `tests/transport_repairs.rs` (the last two by sha256 against the public values). No value is printed anywhere. Waivers are by line, not by file, so a new secret in those files is still reported.

### Chore (rc.188): the CodeRipper portfolio caller is pinned to coderipper#182

`ci_cd.yml` calls `ciresnave/coderipper/.github/workflows/portfolio.yml` at `b45eb41` (was `30e012b`). That revision frees runner disk before the sweep (#290's sweep ran out of disk, so three members did not build and the secrets scan never ran) and names a failed check or tool install. It also moves CodeRipper itself from 0.9.6 to the current release, so more rules run; the job stays advisory and is not a required check. Workflow only.

### Docs (rc.187): design note for the mailbox store through PersistAnt `choose` (ROADMAP row 42)

`docs/superpowers/specs/2026-10-30-mailbox-store-choose.md`. Reading the code first: selection through `choose` already exists behind `sqlite-store`, so the work left is SQLite in the default build, one selection path, the redb decision, and WAL handling, with the WAL item held until the cause of the pool timeouts is captured (a checkpoint runs after the connect that timed out). Finds the `persistant` crates three minor lines behind (0.9 declared, 0.12.3 current), proposed as slice 0. No code changes.

### Docs (rc.186): cutover runbook (`docs/CUTOVER_RUNBOOK.md`)

The settings a cutover depends on and the check that proves each took: the daemon wrapper's environment (`SYNAPSE_MAILBOX_STORE=sqlite`, `SYNAPSE_LAUNCHER_ROLES`, `SYNAPSE_LAUNCH_SENDERS` and its fail-closed rule), the lane's (`SYNAPSE_NO_AUTOSTART`), the weekly `synapse id provision` and why the schedule must be shorter than `--renew-below-days`, the home decision (promote the pilot home; redb to SQLite migrates on first start), and what to read after a restart. No code changes; it starts no task and touches no key.

### Feature (rc.185): `SYNAPSE_NO_AUTOSTART` stops the CLI starting a daemon

With `SYNAPSE_NO_AUTOSTART` set (not empty, not `0`), `Daemon::connect` behaves as `connect_existing`: it finds the daemon its owner runs, with the owner's store and address, and fails with `no daemon answered` rather than start one with the wrong environment. The MCP adapter already never started one. Unlike `SYNAPSE_REMOTE_DAEMON` it leaves the announced-pid liveness check alone.

### Changed (rc.184): configurant 0.2.34 to 0.5.22

`synapsed` takes the latest ConfigurAnt (published 2026-10-30). The 0.5 line is a breaking release of that crate, but the daemon's use of it (`Loader`, `Origin`, `Schema` in `settings.rs`) compiles unchanged and the `synapsed` tests pass; no behaviour change.

### Fixed (rc.183): `--help` and `-h` work in all four binaries, `--version` in the two adapters

`synapsed`, `synapse-mcp`, `synapse-agent` and `synapse-claude-channel` now answer `--help`/`-h` (usage on stdout) and `--version`/`-V` with exit 0 before opening any home, keystore, store or port. Before, `synapsed` and `synapse-mcp` looked up the keystore first, and the two adapters had neither flag (CodeRipper OPS-011). An unknown argument now exits 2 with `unknown argument` on stderr and starts nothing; before, `synapsed --bogus` started a daemon. Also adds `SECURITY.md` with the supported-versions policy: the latest line gets security fixes, an older line only when the backport is small, and no support period is promised.

### Added (rc.182): `synapse stats --daemon` shows `launch_senders_set`

`synapse stats --role <role> --daemon` prints one JSON object about the daemon: `scope`, `since` and `launch_senders_set`, whether `SYNAPSE_LAUNCH_SENDERS` lists anyone (false means launch signals are off). Reads the `/v1/stats` field added in rc.178, so no curl is needed to confirm the allowlist is active. Without `--daemon`, `stats` is unchanged.

### Added (rc.181): `synapse id provision`, a role-only home per lane

`synapse id provision --roles-file F --lane-home-root DIR [--apply] [--days 30] [--renew-below-days 14]`, run with the account key, gives each role in F (one name per line, `#` comments) its own home `DIR/<role>` holding that role's keys and a current certificate and NOT the account key. A dry run unless `--apply` (it writes nothing, not even `DIR`). Idempotent: a role with a current certificate is `ok` and untouched; one near expiry, expired, or no longer carrying its grants is `renewed`. Prints `<role> <ok|created|renewed|would-create|would-renew|refused: ...>` and never a key, certificate or path; exit 2 if any role was refused, and the rest are still done. The account home is refused as a role home. A bad or repeated name refuses the whole file before anything is written. Library: `Keystore::provision_role`, `keystore::Provision`. **Not isolation:** lanes run as one OS user, so any lane can read any role's home; this keeps the account key out of lanes and keys out of output, nothing more. Certificates last at most 30 days and lanes cannot renew them, so run this on a schedule shorter than `--renew-below-days`.

### Docs (rc.180): ROADMAP row 42, mailbox store via PersistAnt `choose`

Scheduled after the cutover items: SQLite in the default build, backend chosen through persistant's `choose`/registry from a declared need, a keep-or-retire decision for redb, and WAL handling at startup. No code changes.

### Added (rc.179): `--version` / `-V` on `synapsed`, `synapse` and `synapse-mcp`

Each prints `<bin> <crate version>` and exits 0 before opening any home, store or port. `synapsed --version` used to try to start a daemon. Tests run each binary with no `SYNAPSE_HOME` in an empty directory and check that nothing was created. Lets a cutover read which build is installed.

### Added (rc.178): `SYNAPSE_LAUNCH_SENDERS`, an allowlist of whose mail may raise a launch signal

`GET /v1/waiting` now counts only pending mail whose authenticated sender is listed in `SYNAPSE_LAUNCH_SENDERS` (or `launch.senders` in `synapsed.toml`; entries are `role`, meaning this account, or `role@account`). `count`, `oldest_enqueued_at` and `signal_id` are computed over the allowed mail only, so a role whose pending mail is all from other senders gets no signal; the signal's shape is unchanged and still carries no sender or body. **Fail closed:** with launcher roles set and this list empty, no signal is raised (never "anyone"), so existing launch setups must set it. The list is held live: `synapsed` re-reads the file every 5 s and the next poll sees a change; a bad file keeps the last good list. Dead-set mail never counted. `GET /v1/stats` gains `launch_senders_set` (bool) so a doctor can refuse to enable wake without it. A sender cannot borrow a listed role's name: the sender is always the key-proven session role (`a_forged_from_is_refused`, `a_claim_without_key_proof_issues_no_token`). Relayed from AgentLife's M5 wake slice 3.

### Fixed (rc.177): `DiscoveryTransport` expires discovered services nobody has seen for three scan intervals (Closes #282)

A scanned service stayed in `discovered_services` forever, so a peer that left, or whose address another host reused, stayed "reachable". Each scan now drops entries whose `last_seen` is older than `3 x scan_interval` (`SynapseDiscoveryConfig::expiry`, no new setting), and `can_reach`, `test_connectivity`, `find_service_by_name`, `find_services_by_type` and `get_discovered_services` ignore an expired entry even between scans.

### Fixed (rc.176): QUIC evicts the pooled connection when a message from that address fails verification (slice 2; Part of #49)

`QuicTransportImpl` implements `Transport::on_verification_failure`: the source is parsed as a socket address (anything else is ignored) and the pooled connection to it is evicted, at most once per address per 5 s (`DEFAULT_EVICT_COOLDOWN_MS`, `with_evict_cooldown`), so a peer sending bad messages cannot make us reconnect in a loop. The next send reopens a connection. This closes the gap in the QUIC spec's condition 3: `evict` was tested but called by nothing.

### Added (rc.175): `Transport::on_verification_failure` (QUIC pool eviction, slice 1; Part of #49)

A new `Transport` method, default no-op, so no implementor breaks, and a `#[non_exhaustive]` `VerificationFailure { Rejected, Unopenable }`. `TransportManager::receive_messages` records `(transport, source, kind)` where it already records a knock or an unopenable message, and calls the hook after its locks are dropped. A sender nobody pinned (`UnknownSender`, `UnknownIssuer`) is not reported: it says the trust store lacks them, nothing about the connection. No transport implements the hook yet; QUIC follows in slice 2.

### Docs (rc.174): patent sweep of the 6.0.0-rc line (`docs/PATENT-SWEEP.md`)

CireSnave's pre-release patent sweep (board 286), run on `main` e657ecd. 17 mechanism ideas, 13 documented queries, independent claims of 9 patents read, 14 more located but unread. One `needs-review` (US12711207B1, idea I17, which is design only); the rest are `clear` or `design-around`. Due diligence, not legal advice. No code changes.

### Chore (rc.173): `rand` 0.9 -> 0.10 (Dependabot #268)

The `rand` dependency is `0.10.3`. Its three call sites (`rand::random` in `src/transport/mdns_enhanced.rs`, `src/synapse/transport/error_recovery.rs` and `tests/edge_case_test.rs`) compile unchanged against 0.10, so no code moves. `Cargo.lock` only re-points the root package at `rand 0.10.3`, which was already in the lock for another crate.

### Chore (rc.172): four more unused dependencies removed instead of bumped (Dependabot #265, #266, #267)

`bytecodec` (was 0.4, Dependabot #265 proposed 0.5), `hmac` (0.12; #266 proposed 0.13), `parking_lot` (0.12; #267 proposed 0.13) and `bytes` have no use in `src`, `tests`, `examples`, `benches` or `crates` (`hmac` appears only as `ring::hmac`; `bytecodec` and `bytes` were the companions of the `stun_codec` removed in rc.157). They are gone from `Cargo.toml` and from the `core`, `nat_traversal` and `native-base` feature lists; no feature name changed. Bumping a crate nothing uses would have been code churn for no reader. Rand 0.10 (#268) is a real bump and follows separately.

### Chore (rc.171): the clean dependency bumps (Dependabot #263, #264)

`rmcp` and `rmcp-macros` 3.5.1 -> 3.7.0 (Dependabot proposed 3.6.0 for `rmcp`; 3.7.0 was the newest) and `tokio` 1.53.3 -> 1.54.1 in `Cargo.lock` (minor and patch, no code change), and `actions/download-artifact` v8.0.1 -> v8.0.2 in the CI workflow (the new SHA matches the upstream tag). Taken over from Dependabot because the gate refuses a PR without a version line (CireSnave: newest dependencies at all times). The breaking bumps (bytecodec 0.5, hmac 0.13, parking_lot 0.13, rand 0.10) follow one PR each.

### Test (rc.170): the adapter's heartbeat is tested (ROADMAP row 39)

`SynapseMcpServer::start_with_heartbeat(config, every)` is new; `start(config)` is `start_with_heartbeat(config, 30 s)`, so nothing changes for callers. `an_adapter_heartbeats_on_its_own_at_its_interval` starts one adapter on a 150 ms interval and one on the default, and checks the daemon's `last_seen` for the first keeps moving with no tool call while the second's does not. Observed to fail when the loop ignores the interval. The last item of the deferred minors recovered into ROADMAP rows 37-40.

### Tooling and measurement (rc.169): `synapsed` latency under load (ROADMAP row 37d)

New `crates/synapsed/examples/latency_probe.rs` and `docs/SYNAPSED_LATENCY_2026-10-25.md`: `send`/`fetch`/`ack` from 0 to 32 concurrent roles against an in-process daemon (redb and sqlite) while a probe times a `heartbeat` and a `list`. Finding: the mailbox lock queues even cheap calls behind synchronous store commits (heartbeat p50 0.4 ms idle, about 22 ms with 8 writers, about 99 ms with 32), at roughly 100 writes a second whatever the concurrency; the real fleet sends about 6 messages a minute, so nothing changes. No code in the daemon is touched.

### Fix (rc.168): sessions expire after 24 hours of disuse (ROADMAP row 37b)

**Breaking (behaviour):** a session token no longer lives for as long as its role's epoch. One unused for `[session] ttl_hours` in `synapsed.toml` (default 24, at least 1) answers **401 `session_expired`** and must be claimed again; every authenticated call renews the window (sliding). A session that was superseded still answers 409 `superseded` first, so a holder that lost the role is told so and does not claim it back; an expiry is not counted as a bearer failure and raises no security event. `synapsed_client::Daemon::call` claims again once, under the role lock, on `session_expired` (and only on it, so a 401 `unauthorized` or a 409 is still reported); a client that talks to the HTTP API directly must do the same. New: `Daemon::with_session_ttl` and `with_session_ttl_hours`. Tests: `an_idle_session_expires_and_use_slides_the_window` (daemon), `an_expired_session_is_claimed_again_and_a_used_one_is_not` (the real client against an in-process daemon), and the settings tests.

### Fix (rc.167): an IMAP poll costs what is new, and the seen-id set is bounded (ROADMAP row 40)

`EmailTransportImpl`'s RelayOut/External poll fetched the whole mailbox on every poll (`FETCH 1:*`) and remembered every delivered `message_id` forever, so a long-running daemon's polls grew with its mailbox and its memory with its history. It now keeps the mailbox's `UIDVALIDITY` and next UID and sends `UID FETCH <next>:*` (a poll with nothing new fetches nothing; a changed `UIDVALIDITY` starts over; a server that reports no `UIDNEXT` is polled the old way), and the de-duplication set is capped at 10,000 ids, oldest forgotten first. `SynapseImapServer` gains real `UIDNEXT`, `UID FETCH` and message-number sets (`a:b`, `a:*`, comma lists), plus `fetch_counter()` for tests. Proven by `an_imap_poll_costs_what_is_new_not_what_is_in_the_mailbox` (25 messages: 25 moved, then 0 for three empty polls, then exactly the 2 new ones; it failed before with 100) and a unit test of the bounded set.

### Chore (rc.166): the httpbin example is dropped (ROADMAP row 40)

`examples/http_transport_demo.rs` is removed, with its `[[example]]` entry and its line in `examples/README.md`. It sent real requests to httpbin.org, jsonplaceholder.typicode.com and api.github.com (a third-party dependency in an example, PM ruling 2026-10-25) and its `localhost:8443` demo had no server. The HTTP transport itself is unchanged and covered by its own tests. No library change.

### Fix and tests (rc.165): deferred minors verified (ROADMAP rows 37-40)

**Breaking (behaviour of a public function, noted as Breaking per the pre-release policy):** `KeyManager::verify` with a 33-byte public key now returns an `Err` ("compressed P-256 public keys (33 bytes) are not supported") instead of `Ok(false)`: ring parses only the uncompressed point, so the old answer rejected a valid signature silently (the legacy `synapse::synapse::auth` tree; nothing forged was ever accepted). Tests, no behaviour change: `an_unauthenticated_body_is_bounded_before_auth` (axum's 2 MiB default limit bounds a body read before auth; observed to fail with the limit disabled) and `describe_keeps_paths_out_of_keystore_and_io_failures` (observed to fail when the I/O arm echoes the error). ROADMAP rows 37-40 now say what is done, what is by design, and what is open.

### Feature (rc.164): `/v1/health` reports the mailbox's state in a separate field

`GET /v1/health` keeps `"ok": true` (a non-ok reply reads as a squat to clients, which start another daemon) and gains `"mailbox": "ok" | "poisoned" | "unavailable" | "busy"`: `poisoned` after a failed write left memory and store disagreeing (every call refuses until a restart), `unavailable` when the lock itself is poisoned, `busy` when a handler holds it (the probe never waits). New: `Mailbox::is_poisoned`. ROADMAP row 37(c), recovered from the deferred M5a minors.

### Docs and tooling (rc.163): P0 of the AI-to-AI plan, what lane traffic costs in tokens

`.github/ai2ai_p0_tokens.py` counts tokens per message type from a copy of the claude-peers database with the tokenizers it is given and writes numbers only (self-test: `--self-test`; the real run needs `pip install tokenizers tiktoken`, not a repo dependency). `docs/AI_TO_AI_P0_MEASUREMENT_2026-10-25.md` holds the numbers for cl100k_base, Qwen3-0.6B and TinyLlama-1.1B: no message text. No code change in the daemon.

### Docs (rc.162): plan for efficient AI-to-AI communication (ROADMAP row 41, slice one)

`docs/AI_TO_AI_COMMUNICATION_PLAN_2026-10-25.md`: an ordered plan (measure the lane traffic first; a program decoder for `MESSAGE-FORMATS` v1; a mode and negotiation on the wire; a spec registry; token-saving schemas; latent left to Fuel) with, for each item, what it leans on and how that is verified. OverMind's summary file is treated as UNVERIFIED throughout: its checks prove a quote exists in a paper, not that it supports the claim, and paper #3's journal version was never fetched. No code.

### Feature (rc.161): `synapsed` reads its settings through ConfigurAnt; `<home>/synapsed.toml`

`synapsed` now takes `SYNAPSE_ADDR`, `SYNAPSE_MAILBOX_STORE`, `SYNAPSE_LAUNCHER_ROLES` and `SYNAPSE_ALERT_ROLES` through `configurant` 0.2.34 (new dependency, by crates.io version; `Cargo.lock` gains `configurant`, `toml`, `toml_datetime`, `toml_edit`). The environment works exactly as before, and the same four values can be set in an optional `<home>/synapsed.toml` (`[listen] addr`, `[launch] roles`, `[alert] roles`, `[storage] id`); the environment wins. An unknown key or an unparsable file exits 2 naming it. New: `synapsed::settings` (pure, tested without a process) and `crates/synapsed/synapsed.schema.toml`, derived from configurant's `examples/synapsed.toml` without `home.dir` (the file lives in the home), without the `persistant` provider on `storage.id` (it would refuse `sqlite`, which the running pilot pins) and without `storage.endpoint` (nothing reads it). The empty `SYNAPSE_MAILBOX_STORE` is still no pin. The role-retirement ttl, a 30-day constant since L1, is now `[liveness] role_ttl_days` (file only, at least 1; `Daemon::with_role_ttl_days`). The error text for a bad address now reads `listen.addr "..." is not an address (set SYNAPSE_ADDR, or listen.addr in synapsed.toml)`. ROADMAP row 36; new ROADMAP row 41 (efficient AI-to-AI communication, plan first).

### Test (rc.160): the channel push never claims a message is verified or sealed

A guard test in `synapse-claude-channel`: the text built from a daemon payload that carries no verification or sealing field must not contain either word (ROADMAP row 35, from the 2026-10-12 FAM-vs-adapter note). Observed to fail when the word is injected into the rendered text. No behaviour change.

### Docs (rc.159): the deferred minors M5a/M5b/M6b are ROADMAP rows again

ROADMAP pointed at a list in HANDOFF that no longer exists (HANDOFF is never tracked in git). The list was recovered from earlier session transcripts and is now rows 37-40 with what is still true on main. Row 29 (#21, #22) is removed: both issues were closed 2026-10-23. No code.

### Docs (rc.158): spec to roadmap audit

`docs/SPEC_ROADMAP_AUDIT_2026-10-24.md`: every unmet or deferred item in `docs/superpowers/specs/` is now a ROADMAP row (new rows 32-35, plus row 36 for the ConfigurAnt adoption), points to an existing row or issue, or is recorded as not planned. No code.

### Chore (rc.157): nine unused dependencies removed (#61)

`ahash`, `async-smtp`, `blake3`, `config`, `igd`, `rustls-native-certs`, `stun_codec`, `syn` and `sysinfo` had no use in `src`, `tests`, `examples` or `crates` (`sysinfo` appeared only in two comments). They are gone from `Cargo.toml` and from the `minimal`, `core`, `crypto`, `nat_traversal`, `email` and `native-base` feature lists; no feature name changed. `Cargo.lock` drops 50 packages and adds none. `cargo check -p synapse --no-default-features --features core` already failed before this change (it needs `axum`), unchanged.

### Feature (rc.156): role liveness L3, a send to a retired role is refused

`POST /v1/send` to a retired role is 410 `recipient_retired` (nothing queued, no abuse budget charged); mail queued before the retirement is kept and is delivered when the role claims again. `unknown_recipient` (404) now names the recipient in its message (truncated and escaped). The daemon still takes only a qualified `role@account`; the CLI and MCP tool qualify a bare name with the sender's account, so a name matches one role. Slice L3 of `docs/ROLE_LIVENESS_DESIGN.md`.

### Feature (rc.155): role liveness L2, `role-admin`, `synapse retire` and `synapse revive`

A new grant, `role-admin` (`Permission::RoleAdmin`; `synapse id grant --role pm role-admin`), lets a role retire and revive others: `POST /v1/roles/retire` and `/v1/roles/revive` with `{"role": "<name>"}`, and `synapse retire|revive <name>`. Without the grant the answer is 403, a role that never claimed is 404, retiring twice succeeds. Retiring leaves the epoch and queued mail; revive clears `retired_at` and restarts the idle clock; a claim by the role itself also revives it. **Breaking:** `Permission` has a new variant. New: `Roles::retire`, `Roles::revive`, `Mailbox::set_role_retired`. Slice L2 of `docs/ROLE_LIVENESS_DESIGN.md`.

### Feature (rc.154): role liveness L1, idle roles are retired and hidden from `list`

**Breaking:** `synapse::roles::RoleRecord` has two new public fields, `last_seen` and `retired_at` (both default when absent, so stored state loads unchanged). A role whose last activity (`last_seen`, else `claimed_at`) is more than 30 days old is retired by the daemon's sweep: `retired_at` is set, and `list` leaves it out unless asked (`GET /v1/list?include_retired=true`, `synapse list --include-retired`). Nothing is deleted: the epoch and queued mail stay, and a valid claim revives the role. Sightings are written at most hourly per role, because presence is in memory and a restart would otherwise make every role look idle since its claim. `Roles::note_seen`, `Roles::retire_idle` and `Mailbox::maintain_roles` are new. The ttl is a daemon constant (30 days) until the daemon has a config file. Design: `docs/ROLE_LIVENESS_DESIGN.md` (slice L1 of three).

### Docs (rc.153): QUIC pool eviction design; #120 closed

`docs/superpowers/specs/2026-10-24-quic-pool-eviction-design.md` (#49, no code). ROADMAP row 25 removed: #119 is fixed (parked) and #120 is bounded by the daemon's `max_deliveries` (default 10), so it was closed.

### Docs (rc.152): role liveness design

`docs/ROLE_LIVENESS_DESIGN.md` and ROADMAP row 31: retiring a role that never returns (TTL, explicit retire/revive, typed send error). No code.

### Fix (rc.151): bidi formatting characters are escaped in tool output and channel pushes

The embeddings and overrides (U+202A-202E), the isolates (U+2066-2069) and the marks U+200E, U+200F and U+061C are format characters, not control characters, so a sender could use them to reorder how a body or a `meta` value is displayed (#106). `synapse_mcp_server::needs_escape` now names the set and both `safe_text` and the channel adapter's `escape` use it. No behaviour change for any other text.

### Fix (rc.150): the SQLite mailbox open is retried after a pool timeout

One first start after a reboot (2026-10-22) exited 2 with `open sqlite: database unavailable: pool timed out while waiting for an open connection`: the file stayed locked for the whole 30 s busy wait. `SqliteMailStore::open` now repeats the open at most twice after exactly that error, printing a warning with the path and the wait each time; any other error, and the third timeout, is returned unchanged. The holder of the lock that time is not known.

The open also prints one line per cold-start step (permissions checked, lock taken, runtime started, sqlite and key-value layer open) with the time since it began, so the next start that hangs shows which step it was in; on 2026-10-24 the same error came back on several starts and nothing in the files explained it.

### Feature (rc.149): shared state, slice S4b: the checker process (`synapse state check`)

The process that answers forge facts: it reads `GET /v1/state/wanted`, looks each fact up (`crate_version` = crates.io `max_version`; `pr_state` merged/open/closed; `ref_sha`; `check_state` failure/pending/success over all check runs, not only the required ones; `file_at_ref` blob SHA or absent), and posts `POST /v1/state/facts`. Rate limits and 5xx are `failed`, never `absent`. The credential is a `TokenSource` asked per request (today an environment variable; a GitHub App installation token fits the same seam), sent only over HTTPS or to loopback and never to crates.io. `synapsectl` names reqwest's `rustls` feature: the TLS stack (rustls with aws-lc-rs, board 104's tracked exception) was already in its tree through `synapse`, and `Cargo.lock` gains one dependency line and no crate.

### Fix (rc.148): synapsed survives an empty redb beside the SQLite store

After an unclean shutdown a stray CLI spawn can leave a content-free `mailbox.redb` next to the real `mailbox.sqlite`; `synapsed` refused to start (exit 2) because it could not tell which held the mail. A redb that dumps to nothing (no mail, acked history or roles, sequence 0) is now renamed to `mailbox.redb.empty-<n>` (never deleted) and the daemon starts on SQLite. If the redb holds anything, it is still refused.

### Feature (rc.146): shared state, slice S4a: derived facts, staleness, unblocked

A fact the forge can answer is never typed by a lane: the checker role (`state-derive`) reports what it looked up (`POST /v1/state/facts`; `GET /v1/state/wanted` lists what to look up), and `get` and `list` carry a `derived` object beside each record, computed at read time: per condition `observed`, `observed_by`, `satisfied` (semver for `ge`; unknown when never looked up or when the newest look failed, so a failed lookup never satisfies `absent`), and per record `last_verified` (the OLDEST observation) with who made it, `stale` (a condition unobserved or past its kind's limit, 6 h by default) and `unblocked` (blocked, and every blocker cleared). A daemon pass (each minute and after each report) mails the parties once per change (`facts`, `stale`, `unblocked`; `derived: true`, ids and field names only). The store takes a baseline when a record is written, so the first change after that notifies. **Breaking:** `state::Caller` gains `derive`; `Notice` gains `derived`. `semver` becomes a direct dependency. CI: the portfolio job is repinned to coderipper 30e012b.

### Feature (rc.145): shared state, slice S3: change notices, ids only

Every accepted state write leaves one `Notice` per party but the writer, in the same redb transaction as the write (`pending_notices`, `notice_delivered` on `StateStore`). A daemon task, woken by each write and retrying every 5 s, hands each to the mailbox as mail from `daemon:state@<account>` and then marks it delivered; the message id `state:<id>:<revision>:<role>` makes a crash between the two steps a duplicate, not a second message. The body is `{"kind":"state","id","revision","changed_by","fields"}`: no title, note or value reaches a channel, and a party whose access is withdrawn learns nothing readable. A notice that cannot be queued waits and does not hold up the others.

### Feature (rc.144): shared state, slice S2b: `/v1/state/*` and `synapse state`

The daemon opens `state.redb` beside the mailbox and serves `create`, `get`, `list`, `patch` and `history` under `/v1/state/` behind the usual session auth. The caller is built from the session's verified certificate (`state-write`, `state-read-all`, `state-admin`), never from the request; access, compare-and-set and validation are the store's. A stale `patch` is `409 stale_revision` carrying `current` and the winner's `record`; a record the caller may not see is `404` on `get`; a refusal is a new `state_denied` security event. CLI: `synapse state` with `new`, `show`, `list`, `set` and `history`. A claim never derives from the account key: `load_role` reads the identity through the public view and opens the key only when the role has no usable certificate (none, expired, within 12 h of expiry, or not carrying the account holder's grants), and the identity is read from the role's files without the account name (the certificate's own subject is its id; the daemon checks the account at claim); a test corrupts the account key and shows `claim` and the state commands still work. CI: the portfolio job is repinned to coderipper a48fc6c (it now sweeps workspace members, so expect new advisory findings).

### Feature (rc.143): shared state, slice S2a: `state-*` permissions and `id grant`

`Permission` gains `state-write` (now in every role's default grants, so certificates re-issue on the next load), `state-read-all`, `state-admin` and `state-derive`. The last three are granted by the account holder: `synapse id grant --role <role> <permission>` / `ungrant`, stored in `roles/<role>/grants`, applied when the certificate is next made (a full home renews on load; `id issue` uses them for a role-only home). A corrupt grants file is refused, never skipped. **Breaking for a parser from before this change:** `Permission::parse` rejects a name it does not know, so it cannot read a certificate that carries the new ones. The design doc is amended (decisions Q1-Q5; four permissions, `state-read` dropped); S2 is split into S2a (this) and S2b (daemon `/v1/state` + `synapse state`). CI: the portfolio job is repinned to coderipper 789b0122 (Windows fix).

### Feature (rc.142): shared state between lanes, slice S1 (the store)

`synapse::state`: a `Record` per cross-lane thread (`T-<n>` ids, reserved `uid` for a later ULID), written by compare-and-set on its revision (`StateError::StaleRevision` carries the current record), with an append-only history hash-chained over each entry (`verify_chain`, `fold`). Access by party: `Caller { write, admin, read_all }` (a party with `write` patches; `read_all` reads everything and writes nothing, for the PM and the export role; `admin` does both and may patch terminal records); only the owner or an admin changes parties or owner. `FactSpec` parses the closed fact registry (`crate_version`, `pr_state`, `ref_sha`, `check_state`, `file_at_ref`); free text is bounded and control-character-free. `StateStore` is the transport-neutral trait; `StateEngine` over a `Backend` holds all the logic; `MemoryBackend` and (with `mailbox-redb`) `RedbBackend` (`state.redb`, owner-only, format-stamped) store rows. No daemon, CLI, permission or notification yet (S2-S4). Design: `docs/superpowers/specs/2026-10-23-shared-state-design.md` (#240).

### CI (rc.141): advisory CodeRipper portfolio check

CireSnave 2026-10-23: "Roll out advisory-only, non-blocking CodeRipper checks everywhere." A `portfolio` job in `ci_cd.yml` calls `ciresnave/coderipper`'s reusable workflow, pinned to commit c665210. It is not a required check and silences no rule.

### Docs (rc.139): design for shared state between lanes

`docs/superpowers/specs/2026-10-23-shared-state-design.md` and ROADMAP row 30. No code change.

### Fix (rc.138): a daemon renamed aside by an upgrade is still found; no daemon is started onto a held port

On Windows the client treated an announced pid as stale unless its image was named exactly `synapsed.exe`. An in-place upgrade renames the running `synapsed.exe` aside (`synapsed.exe.<tag>.bak`), so every fresh client and reconnect said "no daemon answered" until the daemon restarted. The image name is no longer checked: the HMAC health proof decides. Separately, `Daemon::connect` no longer starts `synapsed` when the announced port is held by something that fails the proof AND the daemon would bind that same address (`SYNAPSE_ADDR`, else the default 127.0.0.1:7920); it reports the failed proof (the spawned daemon could only exit "address in use" and leave a stray `mailbox.redb`). On a free-port configuration (`:0`) a daemon still starts and takes over, as before.

### Feature (rc.137): a role-only keystore (`id init-role`, `id issue`, `id install-cert`)

For a sandbox (the WSL pilot) that must not hold the account key, which could mint any role. The role's keys are made where they are used (`synapse id init-role`, which prints their public halves); the account holder certifies them (`synapse id issue --days N`, 1 to 30) and the certificate, which is public, is installed with `synapse id install-cert`. `Keystore::open_role_only` refuses a home that holds an account key; a role-only home never creates keys or certificates and never renews, so an expired certificate is an error that says to ask for a re-issue. `synapse`, `synapsed-client` and the adapters load roles through `keystore::load_role`, which uses the full keystore when the account key is present and the role-only one otherwise. The daemon is unchanged.

### Docs (rc.136): ROADMAP rows for the open issues

Rows 20-29 schedule or close #5, #20, #21, #22, #49, #61, #105, #106, #110 and #119-#121, each checked at `origin/main` a2e98e2. No code change.

### Feature (rc.133): `SYNAPSE_REMOTE_DAEMON` for a daemon on the other side of a boundary

A client in a WSL guest reaching the Windows daemon through a relay reads an announce file naming a Windows pid, which `kill(pid, 0)` can never find, so every announce looked stale. With `SYNAPSE_REMOTE_DAEMON` set (not empty, not `0`) the client skips only that pid check; the HMAC health proof still decides, and `Daemon::connect` behaves as `connect_existing` (it never starts a second daemon with its own store).

### CI (rc.131): Docker image moves from Docker Hub to GHCR

CireSnave 2026-10-23: all projects' Docker images move from Docker Hub to GHCR "so we don't have secrets stored in two places." `publish-docker` now logs in to `ghcr.io` with the job's `GITHUB_TOKEN` (job permissions `contents: read`, `packages: write`) and pushes `ghcr.io/thinkersjournal/synapse`; no `DOCKERHUB_*` secret is referenced any more. `docker-compose.yml` defaults to `ghcr.io/thinkersjournal/synapse:main`. Not verified: the first GHCR push (it runs only on push to main), and that the package is public (a new GHCR package starts private; visibility is a one-time setting on the package page). The old Docker Hub images are untouched.

### Fix (rc.130): the MCP adapter never starts a daemon, and re-attaches after a daemon restart

Pilot gates 5 and 6. `synapse-mcp-server` (and so `synapse-claude-channel` and `synapse-agent`) attached with `Daemon::connect`, which starts `synapsed` when nothing answers; the daemon it started inherited the adapter's environment, not the owner's, and ran on the default redb store (seen 2026-10-22: a stray `mailbox.redb` appeared beside the live sqlite store). It now uses the new `Daemon::connect_existing`, which never spawns and fails with "synapsed is not running". After the daemon restarts, the adapter's calls and heartbeat find (new `Daemon::instance_gone`) that the instance it proved is gone, attach to the new one (the same implicit claim startup makes; the call that noticed still reports its failure, the next succeeds). A refusal from the same instance (`superseded`, ...) is still never recovered: taking a role back stays a human `synapse claim`. Breaking for no one: `Daemon::connect` is unchanged. Tests: `the_adapter_never_starts_a_daemon`, `an_adapter_re_attaches_to_a_restarted_daemon_and_not_after_a_takeover` (fails with re-attach disabled).

### CI (rc.129): no repository secret in any pull-request job

CireSnave 2026-10-22: "Don't give pull-request-triggered jobs on a public repo any repository secrets." `coverage` no longer references `CODECOV_TOKEN`: a pull request uploads tokenless (a refusal does not fail the signal), and the new `coverage-upload` job (push only, downloads the `lcov` artifact) holds the token. `build-docker` builds without login or push on every event; the new `publish-docker` (push only) holds `DOCKERHUB_*`, and the deploy jobs now follow it. The top-level `permissions: contents: read` was already present. No code change.

### Docs (rc.128): cutover docs say how G6 was built

The readiness doc, the cutover spec, the replacement plan and the adapter spec named role `lane-restart@<account>` for lane-restart's notify. agentlife built it as an outbox relayed under role `agentlife-launcher` (#123); replies are not routed back, and one real send on a scratch home is owed before `notify_transport` is flipped. Evidence: OverMind#157. No code change.

### Docs (rc.127): `docs/MAILBOX_STORES.md`

How to list and record a mailbox store (`synapse storage list|use`), the store order the daemon follows, and what server stores (PostgreSQL/MySQL/MariaDB) need: the URL variable in the daemon's own environment, one daemon per database by lease, and what is not covered. A line in the pilot runbook points to it. No code change.

### Added (rc.126): server-backed mailbox stores (PostgreSQL, MySQL, MariaDB) and one daemon per database

`synapse storage use <id> --url-env VAR` records a server provider; `VAR` names the environment variable that holds the connection URL, which is read when the store opens and never written to `mailbox-store.json`, printed or logged. `StoreChoice` is now a file or a URL variable (older files with only `id` and `file` still read). `RegistryMailStore::open_named_url`/`open_choice`; `persistant` features `registry-postgres`/`-mysql`. A server has no file to lock, so the store holds a **lease** in itself (`PersistantMailStore::hold_lease`: a key with a 20 s time to live, renewed every 5 s, deleted on a clean stop, using only `put_if_absent`/`compare_and_swap`/`compare_and_delete`): a second daemon on the same database is refused ("another process holds this mail store"), a daemon killed without a clean stop frees it 20 s later, and a holder that cannot renew for 20 s errors every `write` rather than serve alongside another. File stores keep the file lock. Fix: the store crate's runtime now enables I/O (`enable_all`), which a network backend needs and SQLite never did. Tests: `tests/lease.rs` (SQLite; includes the known-bad control, two openers without a lease both succeed) and `tests/servers.rs` (conformance suite, listing and two-daemon refusal on PostgreSQL 16 and MySQL 8.4; skip without `SYNAPSE_TEST_DATABASE_URL`/`SYNAPSE_TEST_MYSQL_URL` unless `SYNAPSE_REQUIRE_DATABASE`/`SYNAPSE_REQUIRE_MYSQL`=1, which the new `server-postgres`/`server-mysql` CI jobs set). Not covered: MariaDB (listed by PersistAnt, not in CI here), TLS URLs, migrating an existing store onto a server.

### Added (rc.125): the mailbox store is chosen through PersistAnt 0.9.10, not named in Synapse

`synapse-mailbox-persistant::needs`: `provider_needs(&MailboxNeeds)` (capability ids incl. `kv.bounded_call`, durability Machine), `listing()` (= `persistant::registry::providers`), `RegistryMailStore::open_named(id, path, needs, call_bound)` (`open_named_with` + `Handle::into_kv`; owner-only file and one-process lock as for the SQLite store) and `StoreChoice` (`<home>/mailbox-store.json`: provider id + file). `synapsed` serves the recorded choice (`Daemon::open_named`); on a fresh home in a `sqlite-store` build it records the first provider PersistAnt lists. `synapse storage list` prints the list with PersistAnt's reasons; `synapse storage use <id> [--file F]` records one (feature `storage`, default on in `synapsectl`). `SYNAPSE_MAILBOX_STORE` still works and wins, but is deprecated (the daemon says so). Existing homes keep their store: a home with `mailbox.redb` or `mailbox.sqlite` and no recorded choice opens as before. No Synapse code names a backend id; a Postgres/MySQL provider needs a URL endpoint and is not wired here. `persistant` 0.9.10 (kv/sqlx 0.9.4 -> 0.9.10).

### Added (rc.124): `MailboxNeeds`, the mailbox's needs stated without naming a store; PersistAnt 0.9.4

`synapse::mailbox::MailboxNeeds` (`MailboxNeeds::MAILBOX`): minimum durability (`REQUIRED_DURABILITY`, Machine), atomic batch, ordered scan, lease/TTL, bounded calls, one field per row of `docs/MAILBOX_STORE_NEEDS.md`. It names no backend. Nothing consumes it yet: CireSnave ruled (2026-10-21) that PersistAnt takes the needs and returns the stores that can provide them, so Synapse neither keeps a backend registry nor builds candidates; the daemon will call PersistAnt's API when it exists. `persistant-kv` and `persistant-sqlx` 0.9.0 -> 0.9.4 (lock: also persistant-core, -blob, -relational). No behaviour change: `SYNAPSE_MAILBOX_STORE` and the stores are untouched.

### Changed (rc.123): pilot T-0 runbook installs the SQLite build

`docs/PILOT_T0_RUNBOOK.md` installs rc.123 (was rc.97) with `cargo install synapsed --features sqlite-store`, and says the agentlife task wrapper must set `SYNAPSE_MAILBOX_STORE=sqlite` before `-Register` (the wrapper carries only `SYNAPSE_HOME`, `SYNAPSE_ADDR`, `SYNAPSE_LAUNCHER_ROLES`). Docs only; no code change.

### Security (rc.122): lock-only update of `rustls-webpki` and `webpki-root-certs`

`cargo update -p rustls-webpki -p webpki-root-certs`: rustls-webpki 0.103.15 -> 0.103.16 (RUSTSEC-2026-0382) and webpki-root-certs 1.0.9 -> 1.0.10 (RUSTSEC-2026-0383). Only `Cargo.lock` and the version change; no source change.

### Changed (rc.120): `synapse-agent` live-smoke fixes (first live Gemini run, 2026-10-20)

The PM's live run (Google AI Studio free tier, `gemini-3.8-flash`, reply `PONG`, attempts 1) passed and found two faults outside the transport. The smoke scripts move into the repo (`crates/synapse-agent/smoke/`): `smoke.sh` converts its bin dir with `cygpath` (a `C:/...` path split `PATH` at the colon) and takes the model from `SMOKE_MODEL` (default `gemini-3.8-flash`; `gemini-2.5-flash` now answers 404 "no longer available to new users"). The agent logs an HTTP 404/410 from the provider as "model ... is retired or unavailable to this key: pick another model" (test: a mock that answers 404, and a 500 that must not be called retired).

### Added (rc.119): `synapse-agent` gives the model a `send_message` tool, bound to an allow-list (roadmap step 6, slice 2)

`--allow-send ops,boss` (`GenaiResponder::with_send_tool`): the model may call `send_message(to, body)` for roles on the list only; anything else is refused and the model is told. At most 3 sends and 4 model turns per message; tool sends use ids derived from the message's, so a retried message deduplicates. `Responder::reply` now takes the message id. Tests (mock model, real `synapsed`): an allowed send arrives and an off-list one does not; a model that never stops calling a tool it was not given is cut off after 4 turns and the message stays leased. Not covered: a live provider; a model that returns several tool calls in one turn (handled in order, untested); tools other than send.

### Added (rc.118): `synapse-agent`, a non-Claude model driven as an agent on a role (roadmap step 6, slice 1)

New crate `synapse-agent` (binary `synapse-agent`): leases a role's mail through `synapse-mcp-server`, asks a model through `genai` 0.7.0 (Gemini by model name, or any OpenAI-compatible endpoint such as OpenRouter or NVIDIA NIM with `--endpoint` and `--key-env`), sends the text back to the sender and then acks. The reply goes out under an id derived from the message's, so a crash between send and ack is deduplicated by the daemon. A message that fails 3 times is acked unanswered (each retry costs a model call). The model has no tools and is told the mail is untrusted. `SynapseMcpServer::deliver` is new (the `send` tool now shares its code). Proved against a real `synapsed` and a local OpenAI-compatible mock (3 tests: answer + ack, retry after a model failure, drop after 3). Not covered: a live provider (no key on this box), tools, conversation memory, a notice to the sender when a message is dropped.

### Changed (rc.117): CI cargo commands take `--locked` (CodeRipper SUP-001)

The two `cargo tree` rmcp checks and the two `cargo metadata` calls in `.github/workflows/ci_cd.yml` ran without `--locked`, so they could resolve against a lock the build jobs had not used. All now pass `--locked`. `cargo test -p synapse` in the core-only job stays unlocked on purpose: the step before it deletes `crates/`, so the lock cannot match (a first attempt to lock it failed that required job). A `.coderipper.toml` waiver records the exception. No source change.

### Changed (rc.116): PersistAnt 0.9 (dependency rule: latest)

`synapse-mailbox-persistant` takes `persistant-kv` and `persistant-sqlx` 0.9.0 (was 0.8.20; a 0.8 requirement cannot resolve 0.9). The lock also moves the transitive `unisql` crates 0.24.11 -> 0.24.17. No source change. Found by the publish-order dry-run: the existing crates on crates.io top out at rc.105, and only `synapse` can be dry-run until it is published.

### Fixed (rc.115): opening a mailbox, and `depths`, no longer write

PersistAnt's power-cut run (synapse 0feebc78) showed `mailbox_vm check` failing on a full volume with "mail store: batch: ... database or disk is full": `Mailbox::open` read the role state through `MailStore::write`, which commits a batch even when nothing changed, so a full disk hid the mail already acknowledged on it. `MailStore` gains `read` (default: `write`, so redb and memory are unchanged); `Mailbox::open_volatile` and `Mailbox::depths` use it, and the SQLite adapter overrides it to read through the same overlay and commit nothing. `DaemonStore` forwards it. Test: `opening_and_depths_need_no_room_to_write` (a store whose every write fails; red before the change with "database or disk is full"). Not covered: a real full volume (PersistAnt's run, with ballast, is the check), and redb still opens through a write transaction.

### Added (rc.114): moving a redb mailbox to the SQLite store, copied and proved (adoption-fit gap 5)

`synapse::mailbox::migrate` (`dump`, `restore`, `copy_verified`) reads a mailbox's whole state out of one `MailStore`, writes it to another in one transaction and reads it back; the two reads must be equal or the copy is refused naming the first difference. Four `MailTxn` methods support it (`queue_roles`, `all_acked`, `seq_counter`, `set_seq_counter`), with defaults that refuse so no other store breaks; memory, redb and the PersistAnt store implement them. `synapsed --features sqlite-store` with `SYNAPSE_MAILBOX_STORE=sqlite` does it at start: `mailbox.redb` present and `mailbox.sqlite` absent copies, verifies and writes `mailbox.sqlite.migrated`; both present with no marker is refused without changing anything, because only the operator knows which holds the mail; redb is only read and never deleted. Copied and checked equal: every queue (leases and attempts, mail for roles that never claimed, the dead sets), the acked history, the role epochs and the sequence counter. Tested in the adapter crate with a mailbox that has three epochs, two leased messages, an acked one, mail for an unclaimed role and a dead-lettered message; afterwards the SQLite mailbox is opened as `Machine`, a re-claim gets the next epoch, a leased message is redeliverable after the takeover, a resend of an acked message is a duplicate and the next sequence number follows the copied one; a destination that loses acked history fails verification (and the honest one passes the same check); and in `synapsed` the first start copies, the second does not and keeps mail accepted after the move, and the two-stores case is refused. `docs/MAILBOX_MIGRATION_REDB_TO_SQLITE.md` has the table and what is not covered: a power cut during the copy (atomic by the single transaction, not tested), timing on a pilot-sized mailbox, and going back (possible, loses everything since the move). **Nothing was run against the pilot's mailbox.** CI: the non-required SQLite job runs the new `synapsed` test.

### Changed (rc.113): the SQLite adapter's `fetch` and `depths` read only what they need

Two indexes beside the queue, `f/<role>/<seq>` (a marker per message with no lease) and `l/<role>/<seq>` (the `Lease` of each message that has one), kept by `put` and `remove`; `fetch` merges them by seq and reads a message's metadata and body only once chosen, and a new `MailTxn::queue_depth` (default: through `scan_leases`, so redb and memory are unchanged) lets `Mailbox::depths` count leased messages from the lease index and the total from the per-role count, instead of reading every message. This answers PersistAnt's finding that a backend scan is not linear (`limit 1` is 0.9 ms at 10k rows): the cost was ours, paging the whole prefix. Same bench, same laptop, one run each, SQLite vs the redb control in the same run. **A handful of leased messages (`BENCH_LEASED=10`, the usual case)**: `fetch(1)` p50 6.7 ms and `depths` p50 4.6 ms at 10k messages, flat from 1k (redb 2.2 and 18 ms). **Half the queue leased and older than everything free (a stuck consumer, the old default)**: `fetch(1)` p50 104 ms at 10k (was 145; redb 6.1) because the merge must read every leased entry that sorts before the first free message, and `depths` 42 ms (was 243; redb 21). Not done: skipping leased entries by expiry or epoch (an index keyed by `until`), which would fix the stuck-consumer fetch; I did not measure how often a daemon is in that state. `depths` takes the oldest arrival from the lowest-seq row, which equals the minimum when enqueue times do not decrease with seq (the daemon passes the wall clock). Key namespace `mail.v3`: files written under `mail.v2` (rc.111 or rc.112) are not read; nothing is deployed on them.

### Added (rc.112): the guest binary for Synapse's own power-loss test (board 229 stop-line; stacked on #216)

`cargo build --release -p synapse-mailbox-persistant --example mailbox_vm` builds a binary with the command line, output and exit codes of PersistAnt's `machine_vm` (`write`, `check`, `enospc`; backends `sqlite` and `sqlite-off`), so PersistAnt's `scripts/machine-durability/run.ps1` can drive it unchanged: `run.ps1 -Binary <mailbox_vm built on Ubuntu 24.04> -Backends sqlite,sqlite-off`. The layer under test is ours: an acknowledgement is `Mailbox::enqueue` returning `Ok` through the whole mailbox and `SqliteMailStore` (opened through `Mailbox::open`, so it must declare `Machine`), and `check` asks the store for each acknowledged message and compares its body. `sqlite-off` is the known-bad control (`synchronous=OFF`, opened through `open_volatile`): a harness that cannot make it lose a message proves nothing. Verified here without a power cut only, on this Windows laptop: both backends write and `check` reports `held` for everything acknowledged (1,832 and 3,008 messages in 6 s). **Not verified: the power cut itself.** It needs Hyper-V Administrators, the image from `build-image.ps1` and a runner registered for this repository, none of which this lane has; until `run.ps1` has run it on a guest, nothing here shows that mail survives a power loss.

### Changed (rc.111): the SQLite adapter's enqueue no longer scans the queue (adoption-fit gap 2, first measurement)

`benches` in `synapse-mailbox-persistant` (`cargo bench -p synapse-mailbox-persistant --bench mailbox_cost`) runs the root crate's fetch/depth workload (1 KiB bodies, one role of N messages, half leased, 100 samples) against `SqliteMailStore` and, in the same run as the control, `RedbStore`. Measured at `dad2313` (rc.110) on this Windows 11 laptop, one run, not a benchmark of any other machine: SQLite enqueue p50 **39 ms at 1k messages and 112 ms at 3k** (redb 1.9 and 2.6 ms), because every write read and JSON-decoded the whole queue, bodies included, to count it. The adapter now keeps what the redb store keeps: the body apart from the metadata, a per-role (count, bytes) row, and an id-to-seq index, with a zero-padded seq in the key so the backend's key order is the queue's order; `scan_leases` and `scan_free` read metadata only and `scan` stops early. After, same machine, same bench: SQLite enqueue p50 **4.0 ms flat from 1k to 10k** (redb 2.0 to 2.7 ms); a 1k fill takes 4.1 s instead of 38.6 s, and the `synapsed` API suite (38 tests) against SQLite takes 13.7 s of test time instead of 561 s (the same suite against redb took 21 s on an earlier run; one run each). Not fixed, and the number that decides whether redb can go: `fetch(max=1)` past a leased half is still a linear scan, p50 17 / 27 / 145 ms at 1k / 3k / 10k messages (redb 1.9 / 3.3 / 5.8) and `depths` p50 17 / 40 / 243 ms (redb 2.1 / 6.0 / 20.4), about 10 us per row in `ordered_scan_values` (a page size of 5000 was no faster). A leased-message index, as redb's `LEASES` table is, is the next step; `depths` at 243 ms holds the daemon's mailbox lock for that long at a full queue. The key layout changed (namespace `mail.v2`): a SQLite file written by rc.109 to rc.110 is not read; nothing was deployed on it (the feature is off by default). `is_free` is now `pub` for the adapter. The adapter's `synapse` dependency versions, left at rc.107 by an earlier bump, are corrected.

### Added (rc.110): need 9, a stalled backend becomes an error (conformance case, `Bounded` SQLite)

`conformance::a_stalled_backend_returns_an_error_not_a_hang` (with a `Stall` switch the store's backend consults) asserts that a write against a backend that stops answering returns `Err` within a bound, and that after the backend recovers and the sender retries under the same message id the queue holds each message exactly once, whether the stalled write was never applied or was applied and only its answer lost. It is not in `run_all` (which takes no switch); a store that can stall runs it beside `run_all`. `synapse-mailbox-persistant` runs it twice, over a real SQLite key-value backend wrapped to stall before or after the call, and it fails when the bound is longer than `within` (checked: a 12 s store bound against a 10 s limit fails both with "the stalled write took 12.01s"). `SqliteMailStore` now opens PersistAnt 0.8.20's `Bounded` (30 s per call; a timed-out batch is rolled back, a timed-out lone commit has an unknown outcome, which is exactly what the retry case covers) and keeps its own timeout as a backstop 5 s past the backend's bound. `docs/MAILBOX_STORE_NEEDS.md` need 9 is now enforced. Not covered: a real MySQL stall (PersistAnt's own `kv.bounded_call` leaf is the evidence there); there is still no PostgreSQL/MySQL opener in this crate.

### Added (rc.109): `synapsed` can serve the mailbox from PersistAnt SQLite (`sqlite-store`, off by default; board 229)

`synapsed --features sqlite-store` with `SYNAPSE_MAILBOX_STORE=sqlite` serves `<home>/mailbox.sqlite` (WAL, `synchronous=FULL`, declared `Machine`, so `Mailbox::open` accepts it) instead of `mailbox.redb`; anything else keeps redb, and asking for sqlite in a build without the feature exits 2. No migration: a different store is a different file and the other is left untouched. New `StoreKind`, `DaemonStore` (a `MailStore` over either) and `Daemon::open_with`; `Daemon::open` is unchanged. In `synapse-mailbox-persistant` (now publishable; `synapsed` depends on it only under the feature, so it must be published first): `SqliteMailStore::open` creates the file owner-only and refuses a broader one, as the redb store does; takes an exclusive lock on `<file>.lock` so a second process on the same database is refused (SQLite has no equivalent of redb's file lock, and the mailbox keeps role epochs in memory); opens from inside a tokio runtime; and drops without blocking (dropping its runtime inside another panicked, found by the first test of it). `persistant-*` 0.8.19 to 0.8.20. CI gains a separate, non-required job (`SQLite store (signal, not a gate)`, PM ruling 2026-10-20) running clippy, the adapter tests and the `synapsed` HTTP suite (`tests/api.rs`, 38 tests) against the SQLite store (`SYNAPSE_TEST_STORE=sqlite`); `Build and Test` is untouched. Measured here: 37 of 38 passed on first run, the failure being the second-daemon test that had no lock to hit (now fixed; 38 of 38 on the final code); the whole suite took 561 s against SQLite, with `a_full_mailbox_is_413_mailbox_full` over 60 s alone, while the same 38 tests against redb take 21 s on the same machine, about 26 times faster (one run each, not a benchmark). Performance (adoption-fit gap 2) is the open problem before redb can go. Not done: the benches, our own power-cut test, the redb migration, consuming 0.8.20's `Bounded` call bound (need 9; next PR), PostgreSQL/MySQL openers.

### Added (rc.108): `synapse-mailbox-persistant`, a MailStore over PersistAnt 0.8.19 (adoption-fit step 2; stacked on #212)

New workspace crate (`publish = false`, not linked into `synapsed`; redb remains the daemon's store). `SqliteMailStore::open` opens SQLite with `SqliteBackend::open_durable` (WAL + `synchronous=FULL`); `PersistantMailStore::new` wraps any PersistAnt `KvBackend` with `batch` + `Require`. One write is optimistic (read `m/ver`, run the closure on an overlay, one `batch` that `Require`s `m/ver` unchanged), the algorithm of `C:/s/spike-kvmail`. `MailStore::durability()` is read from PersistAnt's `declared_durability(backend)`, never assumed: the durable open reports `Machine` and is accepted, a plain `SqliteBackend::open` reports `Process` and `Mailbox::open` refuses it (both tested). Every backend call is bounded (default 30 s, `with_timeout`) because MySQL stalls rather than fails on a full disk (PersistAnt run 39325665814); the async work runs on the store's own runtime and the caller waits on a std channel, so `write` is safe inside another tokio runtime (tested). Passes `conformance::run_all` (21 cases), a reopen test with live leases and an ack, and the two durability checks. Not done: the two mailbox benches against it, a crash/power-cut test of our own, the offline redb migration, and wiring it into `synapsed`; the PostgreSQL/MySQL openers are not in this crate. Needs-list item 9 (stall becomes an error) is covered here by a unit test over `run`, not by a conformance case.

### Changed (rc.107): the mailbox refuses a store below Machine durability (board 229)

CireSnave 2026-10-18 ruled option A: mail needs `Machine` (power-loss) durability. `MailStore` gains a required `durability() -> DurabilityClass` (no default, so a new backend cannot be accepted by omission); `Mailbox::open` returns `MailError::DurabilityTooWeak` for a store declaring less than `REQUIRED_DURABILITY`, and `synapsed` maps it to 503 `store_unavailable`. `MemoryStore` declares `Process`; `RedbStore` declares `Machine` (redb's default `Durability::Immediate`, never lowered; a declaration, not a power-cut measurement). `Mailbox::open_volatile` skips the check for tests and throwaway stores; the conformance suite's cases run over it so a `Process` store can still be held to the semantics, with new `declares_the_needed_durability` and `a_store_declaring_less_is_refused`. `docs/MAILBOX_STORE_NEEDS.md` lists the needs the suite enforces (durability, atomic enqueue/ack, ordering, lease, TTL, idempotence, bounds, roles) and the gaps (stall-to-error has no case yet). **Breaking for out-of-tree `MailStore` implementors** (new required method, new error variant). Not done: spike-kvmail on PersistAnt 0.8.19 / `open_durable` (not on crates.io; latest published is 0.8.3).

### Changed (rc.106): dependency bumps (dependabot #205-#210 in one PR)

`async-imap` 0.11 to 0.12, `ed25519-dalek` 2.2 to 3.0, `aes-gcm` 0.10 to 0.11, `gloo-storage` 0.3 to 0.4 (and `gloo-utils` 0.2 to 0.3, which it requires), `actions-rs/toolchain` 1.0.6 to 1.0.7, plus a full `cargo update` (tokio 1.53.3, and the RustCrypto chain `ed25519-dalek` 3 pulls in). No source change was needed: `cargo check --workspace --all-targets --all-features` is clean. `ed25519-dalek` 3 is the only crate with call sites here (certificate, keystore, sender_auth, auth utils); the agent_certificates, sender_authentication, transport_repairs and transport_security_events suites and the lib tests pass unchanged. `aes-gcm` and `gloo-*` are declared but unused by any `.rs` file, so those bumps are manifest-only. Not verified: the `wasm` feature on wasm32 (`ring` build script fails there; the wasm path is already unmeasured).

### Changed (rc.105): T-0 runbook lists AgentLife's M8 sender roles

`docs/PILOT_T0_RUNBOOK.md` section 3c: `agentlife-launcher` and `agentlife-cli` (senders only, both need `send`), the claim order (`pm` and the lane roles claim first, or send is 404 `unknown_recipient`), the qualified recipient form `pm@ciresnave` (a bare role is also 404, measured by agentlife against rc.101), and which of the ten pilot measures apply to them and how a loss to `pm` is decided without an adapter session. Roles and their traffic are as AgentLife's lane reported them; not rehearsed. Docs only; stacked on #203.

### Changed (rc.104): adoption-fit note, auth-framework and PersistAnt

`docs/ADOPTION_FIT_2026-10-17.md` (board 196, EXPECTATIONS 6.14): Synapse's authentication (role-key claim, certificates, session tokens, limiter) against auth-framework, and its stores (redb mailbox, keystore, small files, security log) against PersistAnt, with seven named gaps (durability class, performance, native-fs properties, deployment shape, migration off redb, crash tests, dependencies) and an ordered plan. The mailbox spike (PersistAnt 0.7.0, 21 conformance cases on SQLite, PostgreSQL, MySQL) proves semantics only. Nothing was built; it also records that PersistAnt's inventory still lists a Synapse Postgres/redis layer that no longer exists. Docs only; stacked on #202 (rc.103).

### Changed (rc.103): lint-suppression census, 5.1g

CodeRipper counted 3 lint suppressions in the code; the census at `6b8ad2e` (rc.102) found 6 (4 `expect(dead_code)`, 1 `allow(unused_imports)`, 1 `ignore` doc fence) and removes all 6. No `#[ignore]` attribute exists (0). Removed: four `#[expect(dead_code)]`, each deleting the item (`DiscoveryTransport.last_discovery`, written and never read; `DiscoveryTransport::discover_services`, no caller, since `start()` calls the auto-discovery crate directly; `TcpTransportImpl.listen_port`, the bound `listener` is the source of truth; `TcpTransportImpl.circuit_breaker`, constructed and never consulted). The `#![allow(unused_imports)]` in `tests/mailbox_suite/mod.rs` existed only to re-export the library's conformance suite, so the shim is deleted and the six test and bench files use `synapse::mailbox::conformance` directly. The `ignore` doc fence in `src/mailbox/conformance.rs` is now a compiled, running doctest over `MemoryStore`. Still present and not suppressions of this kind: two `clippy::too_many_arguments` allows (`synapsed-client/src/lib.rs`, `email_server/security.rs`) and one `allow(unused)` inside a string fixture in `tests/delivery_claims.rs`. CodeRipper SUP-001 (one finding per binary crate) stays documented under rc.9x below. No wire change.

### Changed (rc.102): pilot T-0 runbook rehearsed in a scratch home

The runbook was written without running anything. It was rehearsed at `bb84636` (rc.101) with binaries built from that commit into a scratch install root, a throwaway `SYNAPSE_HOME` under `%LOCALAPPDATA%`, port 7961, and two stand-in MCP clients driving `synapse-claude-channel` (no lane config, scheduler or pilot home touched). Corrections: `synapse list` requires `--role` and is never empty; the CLI auto-starts a `synapsed` when none answers, so a stop by pid can be undone by the next call; `synapsed --help` starts a daemon; `id show` prints more than the runbook said and the 24 h certificate renews under 12 h remaining; a home under an ACL-inheriting folder is refused by `id init`; message ids carry the sender's identity prefix; and `expired:2 redelivered:2` per message is the normal three-show cycle, not loss. Docs only; no code change.

### Added (rc.101): security alerts as Synapse mail (`SYNAPSE_ALERT_ROLES`, ROADMAP row 9)

`AlertTransport` had no implementation, so the alert policy's output was dropped and alerts were only logged. `synapsed` now implements it internally: with `SYNAPSE_ALERT_ROLES` set (comma-separated role names), each alert the policy raises is queued into those roles' mailboxes from `daemon:alerts@<account>` (a sender no role can claim, `:` is not valid in a role name). **Off by default**: unset or empty, the daemon behaves exactly as before. The transport only hands the alert to a delivery task through a bounded queue (it never takes the mailbox lock inside the sink); a full queue or a mailbox refusal is recorded as `AlertFailed` in `security-events.jsonl` and never retried through the same path. A role that has not claimed yet receives the alert when it does. The body is untrusted text like any other. The policy fires on a threshold (10 events for one kind, surface and subject in 5 minutes) or a digest, and `synapsed` only emits `AuthFailure` and `RateLimited` events today, so in practice an alert means a flood of bad bearers or claims; the event file's one-line-per-second gate still applies before the policy sees an event. Tests (`crates/synapsed/tests/alerts.rs`): a planted flood reaches the alert role's mailbox; with the variable unset or empty the same flood queues nothing while the event file shows it happened; removing the alert sink from the fanout turns the first test red. **Board 131, which external channel carries an alert to a person, remains CireSnave's decision**; this is the internal transport it would read from.

### Changed (rc.100): docs staleness pass (ROADMAP row 12)

Five pages for retired features are deleted: `OAUTH_AUTHENTICATION` (the `auth` feature went in rc.83), `SYNAPSE_COMPLETE_ARCHITECTURE` and `ADVANCED_MONITORING` (trust, staking, alert manager), `UNKNOWN_NAME_HANDLING_COOKBOOK` and `IDENTITY_RESOLUTION_TROUBLESHOOTING` (approval and contact-lookup API). For each, the CamelCase types in its Rust samples were checked against `src/`, `crates/`, `examples/` and `tests/`: 0.58 to 0.82 of them are absent, and `AlertManager`, `AuditLogger`, `OAuthProvider`, `ContactLookupRequest`, `ApprovalAction`, `ContactHint` and `BlockchainClient` have 0 hits. `TROUBLESHOOTING`, `CONFIGURATION_GUIDE` and `DEVELOPER_GUIDE` are rewritten to the daemon, CLI and MCP surface (each states what it was read from). `NEW_FEATURES`, `LLM_DISCOVERY_GUIDE` and `CIRCUIT_BREAKER_SYSTEM` stay: their modules exist. README doc links to the deleted pages are removed and its Development Setup (a clone URL and example that did not exist) is corrected. Old text: `git show 519bd52:docs/<NAME>.md`. Docs only; no code change.

### Changed (rc.99): pilot runbook s3b/s5 no longer assume a spec edit survives a restart

OverMind#150 (read from `agentlife@e609da5`, not run): `lane-restart` rebuilds from `.lane-state/<role>.json` and overwrites `<role>.launch.json`, so the runbook's "edit `launch_args` and restart" rollback did nothing. Section 3b now requires the hand launch (it records the flags in the state file) and a read-back of both files; section 3 rollback and section 5 step 1 hand-launch once with the old flags. The install version is now rc.97 (what the PM installs; the old text said rc.93). Docs only.

### Changed (rc.98): ROADMAP rows 4, 11, 18 brought up to date

Rows 4 and 11 (publish dry-run, crates.io names) are done: the family is published at 6.0.0-rc.97. Row 18 records the 2026-10-16 spike of a `MailStore` over persistant `KvOnRelational` (all 21 conformance cases pass on SQLite, PostgreSQL 16 and MySQL 8.4; a deadlock defect on PostgreSQL/MySQL batches with `Require(absent)` was reported to PersistAnt). Docs only; no code change.

### Changed (rc.97): no `#[allow(dead_code)]`

CireSnave, 2026-10-16: *"That same general dislike applies to #[allow(dead_code)] as well.  That should also be a last resort."* All 15 are gone, each by deleting, using or gating the item. Deleted (never read): `EmailTransport.smtp_transport` (`new` still calls lettre's `relay` and returns its `SmtpConnection` error, then drops the result; behaviour is unchanged. `relay` accepted all 10 bad hosts tried on 2026-10-16, so that error branch is unreachable in practice and a bad SMTP host is only found at send time: a real check would be a separate hardening change), the SMTP and IMAP session `id`, `connected_at`, `tag`, `SmtpMessage.from`, `ServerMetrics.messages_delivered` (never incremented), and `UdpTransportImpl.circuit_breaker`. Used: `ServerMetrics`' remaining fields are now `pub` (they were written but unreadable behind `get_metrics`). Gated: `generate_subject` is `#[cfg(test)]`. The rest were stale: `MultiTransportRouter.our_entity_id` is read, `RoleLock` holds its file as `_file`, and a test-only unix stub was unneeded. No wire change.

### Changed (rc.96): no test is `#[ignore]`d

CireSnave, 2026-10-16: *"I really dislike #[ignore]d things.  If there is an issue, it should almost always be fixed.  #[ignore] should be a last resort."* The three ignored tests were not tests. `mailbox_depth_cost` and `mailbox_fetch_cost` are measurements: they are now `harness = false` benches (`cargo bench --features mailbox-redb --bench <name>`). `real_claude_code_wire_probe` needs the real `claude` CLI and a login, which CI does not have: it is now the `wire_probe` example (`cargo run -p synapse-claude-channel --example wire_probe`, exit 1 on failure). Docs that cited `--ignored` follow. No library or wire change.

### Added (rc.95): `docs/PILOT_T0_RUNBOOK.md`

The commands the PM runs at pilot T-0, in order, each with its expected output and rollback: install rc.93, stop the rc.33 restarttest daemon by pid, register the `synapsed` scheduled task, per-lane `--mcp-config` and `launch_args`, the first-message smoke test, and the STOP and rollback criteria. Docs only; names the Claude Code adapter as `synapse-claude-channel` (not `synapse-mcp-server`).

### Added (rc.94): `synapse list --cwd <dir> --repo <name>`

The daemon's `/v1/list` already filtered on a role's self-reported cwd and repo; the CLI could not ask. Both flags are exact-match and percent-encoded; a role with no reported presence never matches. Additive, no wire change.

### Added (rc.93): spike 2, a `MailStore` over persistant-kv 0.4.32 `batch`

`docs/spikes/persistant-kv-mailstore-batch.md` and its adapter (not compiled in-tree). `run_all` passes on `MemoryKv` and fails on `KvOnBlob` (no `batch`); 4x25 concurrent `next_seq` writes give 0 duplicates, and 74 of 100 with the `Require`s removed. No durable backend measured. Synapse stays on redb. Docs only.

### Removed (rc.92): the stale `end_to_end_integration_test`

`tests/end_to_end_integration_test.rs` (477 lines, `test = false` since it was found not to compile) is deleted. It imported `synapse::identity::{Identity, KeyPair}`, `synapse::services::trust_manager` and `Database::new_in_memory`, and called `UnifiedTransportManager::new_with_transports` and `TrustManager::trust_participant`; none of these exist at bec9ea5, so repairing it means designing that API, not fixing the test. Nothing else referenced it. Recover with `git show bec9ea5:tests/end_to_end_integration_test.rs`. `comprehensive_feature_test` stays excluded.

### Changed (rc.91): CI guard that `rsa` stays out of the tree

The `Security Audit` job gains a step that fails if `cargo tree --workspace -i rsa` (default and `--all-features`) finds anything. Absence is read only from cargo's "did not match any packages" error, with `-i aws-lc-rs` as the positive control. Checked by pointing the same loop at `ron`, which is present: it prints the tree and fails. CI-only.

### Changed (rc.90): CI no longer starts postgres containers

The `build`, `model-agnostic-core` and `coverage` jobs started a `postgres:13` service and set `DATABASE_URL`; no test reads it (git grep finds no `DATABASE_URL` in any source file), so both are gone. Job names are unchanged, so branch protection is unaffected. CI-only; no code change.

### Changed (rc.89): jsonwebtoken uses the `aws_lc_rs` backend; `rsa` leaves the tree

`jsonwebtoken` (the `jwt` feature, which `native` enables) switches from `rust_crypto` to `aws_lc_rs`. `aws-lc-rs` was already in the tree through rustls, and `rust_crypto` was the only path to `rsa` (RUSTSEC-2023-0071, no fix), so `cargo tree --workspace -i rsa` is now empty and the advisory ignore in `.cargo/audit.toml` is removed along with a net 15 crates (rsa, p256, p384, ecdsa, elliptic-curve, pkcs1, num-bigint-dig, ...). No feature is added, removed or renamed and the JWT API is unchanged, so this is not Breaking; HS256 behaviour is pinned by `tests/jwt_backend.rs`.

### Changed (rc.88): launch-result outcome vocabulary pinned

`synapsed-client` gains `LaunchOutcome` (`started`, `already-running`, `refused`, `failed`) and `Daemon::launch_result` takes it instead of a free string (**breaking** for callers; pre-release). The old doc comment listed `launching` and `unreachable`, which are daemon launch *states*, not outcomes; the daemon always rejected them. Tests pin the vocabulary on the daemon (unit) and client (real daemon) sides, and the spec says a dry run sends no answer.

### Changed (rc.87): CodeQL hygiene, log and assert messages

The email server no longer prints the username when bcrypt verification fails (it still denies access). Three test assert messages (`keystore`, `transport_security_events`) report a discriminant or length instead of a Debug of a result or a secret value; the assertions are unchanged.

### Changed (rc.86): CodeQL hygiene, examples

The three `examples/` programs that passed literal passwords to the Gmail/Outlook config builders now use per-run random ones. Examples only; no library change.

### Changed (rc.85): CodeQL hygiene, config and connectivity tests

`config.rs` tests use per-run random passwords instead of literals. `connectivity.rs`: the `"app_password"` value the builders put in generated configs is now the named constant `PLACEHOLDER_PASSWORD`, `ConnectivityConfigExt` documents that it is a placeholder to be replaced, and a test pins the behaviour. No API change.

### Docs (rc.84): cutover readiness assessment and daemon contract + pilot (board 217)

`docs/CUTOVER_READINESS_2026-10-15.md`: G1-G9 status at rc.81, lane usage of claude-peers against what Synapse covers, what the rc.33 soak did not test, side-by-side and rollback plan, verdict NOT READY with the shortest list to ready. `docs/superpowers/specs/2026-10-15-daemon-contract-and-pilot.md`: the synapsed start contract for AgentLife, the accepted delivery statement, and the 24 h pilot checklist with measures and stop conditions. Docs only.

### Breaking (rc.83): the `database`, `cache`, `auth` and `enhanced-auth` features are retired (board 199, 200)

CireSnave 2026-10-15: *"Retire database and cache features."* and *"Retire the auth-framework feature."*

**Removed features:** `database`, `cache`, `auth`, `enhanced-auth`. **Removed dependencies:** `sqlx`, `redis`, `auth-framework` (and the `sqlx` dev-dependency). **Removed API:** `synapse::storage` (`Cache`, `Database`, migrations), `synapse::services::{DiscoveryService, PrivacyManager, ParticipantRegistry, RegistryService}`, `synapse::api::{DiscoveryAPI, ParticipantAPI}`, `synapse::auth_integration_enhanced`. Kept: `synapse::services::{NoTrustSource, TrustSource, ...}`, `synapse::api::errors`, `synapse::models`, `synapse::synapse::auth::utils` (the key manager, which never used auth-framework). **Removed files:** `examples/auth_framework_v3_demo.rs`, `docs/AUTH_FRAMEWORK_INTEGRATION.md`, the tests that pinned the auth-framework manifest requirement (`auth_framework_is_current`, `integration_summary_matches_manifest`), and the `enhanced-auth` CI guard (`.github/enhanced_auth_guard.py` and its job; it was not a required check). `native` and `native-base` no longer include the removed features. Nothing in the workspace crates used them: `synapsed` stores in redb.

**Measured** (lockfile packages, `Cargo.lock` at rc.82 against this change): 657 to 521, 136 removed, none added or upgraded; `sqlx`, `sqlx-mysql`, `redis`, `auth-framework` and `jsonwebtoken 10.4.0` leave. `rsa` remains only behind the `jwt` feature (default build only).

### Changed (rc.82): `synapsed-client` and `synapse-security` no longer pull `rsa`

`jsonwebtoken` (whose `rust_crypto` backend brings `rsa`, RUSTSEC-2023-0071) moves from `core` to a new `jwt` feature; `native` is now `native-base` + `jwt`, so the default build is unchanged. `synapsed-client` and `synapse-security` depend on `synapse` with `default-features = false, features = ["native-base"]`, so `cargo tree -p synapsed-client -i rsa` is empty. `tests/jwt_backend.rs` requires `jwt`. No API change.

### Changed (rc.81): CodeQL hygiene, tests

Integration tests no longer carry literal passwords: `email_security_events`, `email_server_has_no_default_users` and `basic_integration_test` use per-run random values (`rust/hard-coded-cryptographic-value`). The three historical built-in credentials the no-default-users test asserts are rejected stay literal, since they are the subject of that test.

### Added (rc.80): `synapsed-client` launch methods

`Daemon::waiting(role, wait_secs)`, `Daemon::launch_result(...)` and `Daemon::launch_clear(role, target)` wrap `GET /v1/waiting`, `POST /v1/launch-result` and `POST /v1/launch-clear` for a launcher service. A `waiting` poll is capped at 25 s so it stays under the client's call timeout.

### Added (rc.79): presence `cwd`/`repo`, list filters, sender summary and cwd on fetched mail

A heartbeat may carry `cwd` and `repo` (self-reported, untrusted, at most 500 bytes, no control characters, else 400 `malformed`). `GET /v1/list` shows them and filters on `?cwd=` and `?repo=` (exact match). `/v1/fetch` messages carry `from_summary` and `from_cwd`, the sender's current presence (null when it has no live session), and the Claude Code channel passes them as escaped `meta.sender_summary` and `meta.sender_cwd`. `synapse-mcp-server` heartbeats its working directory and the repository around it. Closes cutover gaps G1 and G2.

### Added (rc.78): launch signals for lane launch on message (`GET /v1/waiting`)

`synapsed` can now tell a launcher which roles have mail and no live session. `GET /v1/waiting[?wait=<=30]` is level-triggered; `POST /v1/launch-result` answers a signal (409 `stale_signal` for a stale id, epoch or attempt); `POST /v1/launch-clear` forgets a role's launch state. `/v1/list` gains a `launch` field. Off unless `SYNAPSE_LAUNCHER_ROLES` names the allowed role(s) (403 otherwise). Defaults: grace 5 s, wait 120 s, backoff 30 s / 2 min / 10 min, one signal plus three retries then `unreachable`. No signals until the daemon has been up for the online window. Spec: `docs/superpowers/specs/2026-10-15-cutover-and-lane-launch.md`.

### Packaging (rc.77): every published crate ships a README and both licence texts

The six sub-crates (`synapse-security`, `synapsed-client`, `synapse-mcp-server`, `synapse-claude-channel`, `synapsed`, `synapsectl`) packaged with no README and no `LICENSE-MIT`/`LICENSE-APACHE`. Each now has a `README.md` (the `readme` key) and byte-identical copies of the root licence files. The workspace has no NOTICE file, so none is shipped

### Fixed (rc.76): `synapsed` api tests claim with a random nonce per claim (CodeQL `rust/hard-coded-cryptographic-value`)

`claim` and `claim_body` in `crates/synapsed/tests/api.rs` no longer take a literal nonce byte; each claim draws a fresh random nonce. Test code only

### Docs (rc.75): design for the claude-peers cutover, wake-on-mail and lane launch on message

`docs/superpowers/specs/2026-10-15-cutover-and-lane-launch.md`: gaps lanes still use claude-peers for, the cutover order, and the `/v1/waiting` signal and launch-result contract OverMind and AgentLife code against. Design only; no behaviour change

### Fixed (rc.74): the MCP adapter test no longer trips CodeQL `rust/hard-coded-cryptographic-value` (alerts 47-48)

The rival-claim helper in `synapse-mcp-server/tests/adapter.rs` draws a random nonce per claim instead of taking a literal byte

### Fixed (rc.73): test and parser code no longer trips CodeQL `rust/hard-coded-cryptographic-value` (alerts 121-140)

Claim nonces and passwords in the tests are random per run (stable per label within a run), and the `unhex` helpers in `synapsed` and `synapsed-client` build their output without a zero-filled literal buffer. No behaviour change in shipped code.

### Added (rc.72): `synapse stats`

`synapse stats --role <role>` prints `GET /v1/stats` one JSON object per role per line (`sent`, `acked`, `redelivered`, `expired`, plus the daemon's `scope` and `since`). The counters are since the daemon started; a restart begins again from zero. CLI only: no daemon or library change.

### Added (rc.71): read and replay the dead set from the daemon and the CLI

`GET /v1/dead` returns the caller's dead set, oldest first, bodies included; `POST /v1/requeue {message_id}` puts one dead message back in the queue with its delivery count reset (`404` if it is not dead; `mailbox_full` and it stays dead if the queue is full). `synapse dead` and `synapse requeue <message_id>` are the CLI. The set stays bounded and visible, never silently dropped; an `ack` still discards a dead message. The push adapter's parked-id behaviour is now pinned by a test. No change to existing routes, no `MailStore` or on-disk change.

### Added (rc.70): the dead set: a delivery cap in the daemon (#119, #120)

A message leased `max_deliveries` times (default 10) and never acked now moves to the role's **dead set**: bounded and visible, never silently dropped. It keeps its body, `from`, attempts and enqueue time. It is stored under the pseudo-role `dead:<role>` in the ordinary queue tables, so no `MailStore` and no on-disk format changes. A full dead set (the queue bounds) leaves the message queued and leased again: nothing is dropped to make room. A resend of a dead id is a duplicate; the receiver's `ack` discards it; the dead set is swept with acked history after `retention`.

- `MailConfig::max_deliveries: u32` (`0` = no cap) and `Depth::dead: usize` are new public fields (**Breaking** for code that builds either by literal). `list` reports `pending.dead`.
- `Mailbox::dead_letters(role, epoch)` and `Mailbox::requeue_dead(role, epoch, id)` read and replay it. (Daemon endpoint and CLI: rc.71.)
- Three conformance cases (`a_message_leased_max_deliveries_times_goes_dead_and_is_kept`, `a_full_dead_set_keeps_the_message_queued`, `a_dead_message_can_be_requeued`) join the stable suite, run against memory and redb.
- The push adapter parks a message whose ack the daemon refused, for the process (#119): it no longer re-pushes it every lease. #120's never-acked failing writes are bounded by the cap.

### Fixed (rc.69): `transport_repairs` ports are free on TCP and UDP (#48)

`free_port()` asked only the TCP table, so two UDP-family transports (QUIC, UDP, NAT traversal) could be handed the same port and the second failed to bind, truncating the run. It now returns only ports free in both namespaces. Tests only.

### Added (rc.68): tests for a refused ack and an id-less message in the push loop (#121)

`a_refused_ack_leaves_the_message_pending_and_the_loop_alive` takes the role over between the lease and the ack and shows the refused ack leaves the message pending, keeps its push count and does not fail the look. `a_message_without_an_id_parses_to_none` pins the total parse the loop's skip rests on; the skip itself is unreachable through a real daemon. No behaviour change. #119/#120 (an unbounded re-push) are ruled to a daemon attempts cap and are not in this change.

### Added (rc.67): conformance case `a_failed_write_changes_nothing`; PersistAnt spike note

A `MailStore` whose write applied changes as they came and never undid them on `Err` passed all 17 cases (measured with a `persistant-kv` adapter, `docs/spikes/persistant-kv-mailstore.md`). The new case holds a store to the atomic multi-key transaction: after a write that returns `Err`, no entry, ack record or sequence number remains. A store from another crate that lacked rollback will now fail `run_all`.

### Changed (rc.66): ROADMAP refresh, no code change

Rows 10 and 18 now say what is done: `auth-framework` currency landed in rc.63; the conformance suite is public (rc.65) and `persistant` is 0.4.28.

### Added (rc.65): `synapse::mailbox::conformance`, the `MailStore` contract as a public suite (ROADMAP item 18)

Behind the new off-by-default feature `mailbox-conformance` (adds the optional `tempfile` dependency). The 17 cases that held
`MemoryStore` and `RedbStore` to the same mailbox semantics moved from `tests/mailbox_suite` into the library, so a `MailStore` in
another crate (PersistAnt's backend, or any store a user brings) can be proved against them:
`synapse::mailbox::conformance::run_all(|| MyStore::fresh())`, or any case on its own. **This is a stable store contract:** a case
is added only when the mailbox gains a guarantee, never to track an implementation detail, and a case is never loosened to let a
store pass. `make` must return a fresh, empty store each call that stays valid after the closure returns. No behaviour change, no
on-disk change; the in-repo suites run unchanged through a re-export (`mailbox` 21 + `mailbox_redb` 26 as before). New: `run_all`
itself is tested against a conforming store and a known-bad one that forgets its writes (it must fail). Synapse stays on redb
until a backend passes the suite.

### Changed (rc.64): portfolio hygiene, no behaviour change (CodeRipper WSP-001, SUP-008, DOC-009)

`.github/CODEOWNERS` (`* @ciresnave`); top-level `permissions: contents: read` in `ci_cd.yml` (no job needs more: Docker Hub and the
deploy hosts use secrets, not the `GITHUB_TOKEN`); the three `postgres:13` CI service-container images carry a waiver comment (PM
ruling 2026-10-14: CI-only, no credential of ours reaches them); `docs/GLOSSARY.md` (80 doc pages, 26 terms, each tied to its source).
Actions were already SHA-pinned (rc.53). No source change.

### Changed (rc.63): `auth-framework` 0.6.0-rc42 -> 0.6.0-rc55 (ROADMAP item 15, last of four; PORTFOLIO drift)

Pinned to the newest rc on crates.io (2026-10-14). Source unchanged: the optional `auth` feature (with `oauth-device-flows` and
`enhanced-device-flow`) compiles on rc55 as it did on rc42. **Proved:** `cargo check --features auth --all-targets`, clippy
`-D warnings`, fmt, SPDX gate, `--locked` pass on Windows; `cargo test --features auth` passes (three QUIC tests in
`tests/transport_repairs.rs` failed once on a busy UDP port, and passed when run alone); the `enhanced-auth` guard
(`.github/enhanced_auth_guard.py`, self-test 6/6) re-run against rc55 still passes, i.e. `enhanced-auth` still fails to compile
with E0308/E0432/E0560/E0599, so that feature's recorded status is unchanged. **Limit:** Synapse's own code uses almost none of
auth-framework (ROADMAP item 17), so the compile is most of what there is to prove; no runtime auth flow is exercised by a test here.

### Changed (rc.62): `redis` 0.32.4 -> 1.7.1 (ROADMAP item 15, third of four)

The legacy `cache` feature's dependency, a major version taken under "newest versions at all times". Source needed **no
change**: `src/synapse/storage/cache.rs` (`Client::open`, `AsyncCommands::{set_ex, get, del, ...}`) compiles unchanged on 1.7.1
and the `tokio-comp` feature still exists. **Proved:** `cargo check --features cache --all-targets`, `cargo test --features
cache`, clippy `-D warnings`, fmt, SPDX gate, `--locked` pass on Windows. **Limit:** no test in this repo talks to a Redis
server, so the runtime behaviour of the cache calls (reply-type conversions changed across redis-rs 1.0) is compile-checked
only, as it was before the bump. The last of the four (`auth-framework`) is a separate PR.

### Changed (rc.61): `sqlx` 0.8.6 -> 0.9.0 (ROADMAP item 15, second of four)

The legacy `database` feature's dependency, taken under "newest versions at all times". sqlx 0.9 split the old
`runtime-tokio-rustls` feature into `runtime-tokio` + `tls-rustls-ring` (same ring backend as before), and made `sqlx::query`
refuse any non-`'static` SQL string unless it is wrapped in `sqlx::AssertSqlSafe`. Four call sites needed that, each stated at the
site: `Database::query_participants` and `query_raw_string` (caller-supplied SQL by design; values still go through `bind`), the
capability search (only `$n` placeholders are formatted in) and the migration runner (embedded SQL). No behaviour change.
**Proved:** `cargo check --features database --all-targets` and `cargo test --features database` pass on Windows (lib 169, all
integration suites). **Limit:** no test in this repo executes a `database` code path against a live PostgreSQL, so the
runtime behaviour of these queries is compile-checked only, as it was before the bump. The remaining two (`redis`,
`auth-framework`) are separate PRs.

### Security (rc.60): `rustls` 0.23.45 -> 0.23.46 in Cargo.lock

Lock-only; no source change. `cargo audit` on rc.59 reported four vulnerabilities in rustls 0.23.45 published 2026-10-14
(RUSTSEC-2026-0346 `Debug` impls expose TLS secrets, -0347 buffered data sent to the outer server after ECH rejection, -0348
Brotli certificate decompression can allocate 1 GiB before authentication, -0349 unauthenticated ServerHello downgrades later
connections); all fixed in 0.23.46 (on crates.io 2026-10-14 09:54Z). Found when the Security Audit job went red on every open PR.

### Changed (rc.59): `redb` 4.3.0 -> 4.4.0 (ROADMAP item 15, first of four)

The mailbox store's dependency, taken under "newest versions at all times". redb's 4.4.0 changelog lists no file-format change
(cursor API, `NonZero` keys, fixes for page-cache growth, `compact()` and `check_integrity()`); that was **proved, not trusted**.
**Forward:** rc.57 binaries (redb 4.3.0) wrote a `mailbox.redb` (573,440 bytes: 6 messages, one acked, one leased on a 900 s
lease, four queued, one with a 60 KB body; the daemon was killed, so open also had to recover). The rc.59 build (4.4.0) opened a
copy: pending counts identical (`leased 1, queued 4`, same `oldest_enqueued_at`), all five unacked messages delivered, the 60 KB
body intact. **Control:** the same step with the rc.57 binary on another copy gave byte-identical output, including `attempts 2`
on the leased message (a new daemon instance releases the previous claim's leases; that is existing behaviour, not redb).
**Header:** magic and the first 20 header bytes unchanged, file size unchanged; only commit-slot bytes differ. **Rollback:** the
rc.57 binary opened the file the 4.4.0 daemon had modified and kept delivering, attempts counted on, and accepted a new send,
so a downgrade needs no migration. Synapse's own `FORMAT` stamp stays 2 (no code change). **Tests on 4.4.0:** `mailbox` 21,
`mailbox_redb` 26, `mailbox_crash` 6, `mailbox_held` 5, `synapsed` 3+36, `synapsed-client`, `synapse-mcp-server` 5+9+4, all pass.
Windows only; not run on Linux locally (CI is). No source file changes: the redb requirement and the lock, plus this version bump. The next three of item 15 (`sqlx`,
`redis`, `auth-framework`) are separate PRs.

### Added (rc.58): ROADMAP.md next slice, items 15-19 (what Synapse consumes and owes)

Docs only. Measured against `origin/main` of PersistAnt, UniSQL and auth-framework and against crates.io on 2026-10-14: four
dependencies behind (`redb`, `sqlx`, `redis`, `auth-framework`), the default `native` feature compiling the legacy
`database`/`cache`/`auth` layers the daemon does not use, `auth-framework` consumed but never compiled against, and the mailbox
contract suite as what Synapse owes PersistAnt. No code changed; nothing started.

### Changed (rc.57): legacy files archived or deleted; `docs/API_REFERENCE.md` cut to the daemon, CLI and MCP surface

At the PM's instruction. **Deleted** (all 0 bytes): root `err.txt`, `WINDOWS_LINKER_WORKAROUND.md` (the real one is
`docs/WINDOWS_LINKER_WORKAROUND.md`), `build-debug.ps1`, `test-build.ps1`, and `docs/STREAMING_SUPPORT.md`; the `err.txt` line in
`.dockerignore` went with it. **Moved with `git mv`** to `docs/archive/` (new `README.md`): the eight root completion, fix and
audit reports. Three of them are read by tests (`empty_test_files_are_named`, `integration_summary_matches_manifest`,
`security_claims_match_the_tree`), which now point at `docs/archive/`; prose naming them in `.github/enhanced_auth_guard.py`, the
`ci_cd.yml` comment and the m0 workspace-split spec was repointed, and `CAPABILITY_INVENTORY.md` (a measurement, not rewritten)
gained a note. The guard's `--self-test` passes. **`docs/API_REFERENCE.md`** was rewritten from about 1,250 lines to the
verified surface (`synapse` commands, `/v1` routes and body fields read from `crates/synapsed/src/lib.rs`, the MCP tools);
the library reference is at `git show 6125f31:docs/API_REFERENCE.md`. The other 11 bannered pages keep their banners.

### Fixed (rc.56): the crate's docs.rs front page named a crate that does not exist

`src/lib.rs` "Getting Started" step 1 told readers to depend on `message_routing_system = "0.1.0"` (the library is
`synapse`; the README was fixed in rc.49). It now gives the git dependency the README gives. A doc comment only; I did not build
it, so CI is the proof. Not changed: the commented-out `register_peer` call at `src/lib.rs:70` (inside an example, not
compiled), and step 2's `cargo run --example email_integration_test` (the file exists in `examples/`; I did not run it).

### Added (rc.55): `.github/docs_staleness.py` and status banners on 12 stale docs (ROADMAP item 12)

The script counts the method names called in each page's ```rust blocks that match no `fn` in the workspace (files from
`git ls-files`; names from external crates count as unknown, so the rate is an upper bound). Measured at c14894b (rc.53), 12 pages
scored 0.69 to 0.99 (`CONFIGURATION_GUIDE.md` 112 of 113 names, `ADVANCED_MONITORING.md` 52 of 55, `API_REFERENCE.md` 73 of 86);
each now carries a banner saying it is unverified, its own numbers, and where the tested surface is. **The pages were not
rewritten**: that needs per-page decisions I did not make. Not covered: prose, CLI flags, config keys, env vars, and the README
sections after Quick Start (README scores 0.47, below the 0.5 banner line). `docs/STREAMING_SUPPORT.md` is 0 bytes. Docs and a
CI-adjacent script only; nothing runs it in CI.

### Added (rc.54): a test reads back the mode of `synapsed-start.err`

`the_daemon_start_file_is_owner_only` (`cfg(unix)`, in `crates/synapsectl/tests/mail.rs`) asserts the file is `0600` after a
healthy start, closing the gap the rc.52 ROADMAP note named. **Not run by me: this machine is Windows, so the test compiles
to nothing here and was not seen red or green locally.** `Build and Test` on ubuntu is its first execution. Test-only.

### Changed (rc.53): every GitHub Action in `ci_cd.yml` pinned to a commit

The PM's pin patch (portfolio `pin-patches-20261014`; the patch's own count is 17 moved and 4 kept, and its diff changes 21 lines). `actions/checkout` v7.0.1,
`actions/cache` v6.1.0 (was v3 and v4), `actions-rs/toolchain` v1.0.6, `actions/upload-artifact` v7.0.2, `codecov/codecov-action`
v7.1.1, `docker/build-push-action` v7.4.0 (was v3), `jetli/wasm-pack-action` v0.4.0, `taiki-e/install-action` (the
`cargo-llvm-cov` tag) and `appleboy/ssh-action` (was `@master`) are SHAs with the tag in a comment. Checked against the forge:
every SHA exists in its repo and, for the tagged ones, is the commit that tag resolves to. The patch pinned `ssh-action` to the
head of `master`; at the PM's ruling it is pinned to its release v1.2.5 (`0ff4204d`, the commit that tag resolves to), because
it is a deploy action that holds secrets. Several moves are
version jumps, not only pins; CI is the proof for the jobs that run on a PR. The staging and production deploy jobs, and the
disabled WASM job, do not run on a PR and were not exercised.

### Added (rc.52): `whoami` advertises the push method

`whoami` now carries `push`: `{"capability_key": "claude/channel", "method": "notifications/claude/channel"}` on the Claude Code
channel adapter and `null` on the generic `synapse-mcp` adapter (the key is always present, so a client can tell "pushes
nothing" from "an older server"). A client that bound its notification handlers before `initialize` can learn the method
without a reconnect (spec 2026-10-12 section 2, the "Partly" row). Additive on the wire; no daemon change. Tests: the channel
foreign-client test pins the object (red on rc.51); the adapter test requires the key present and `null` (the old form of that
assertion passed without the change, because indexing a missing key reads as null, so it was tightened). The server `instructions`
text does not yet name the method.

### Fixed (rc.51): a daemon that cannot start says why

`synapse` started `synapsed` with stderr discarded, so a refusal showed only `synapsed is not running: synapsed exited (exit
code: 2) and no daemon answered`. The CLI now gives the daemon's stderr to a fresh file in the home (`synapsed-start.err`,
created with `create_new`, so a link planted in a home others can write is not followed; read back through the same handle,
not the path) and appends its last two lines, bounded to 512 characters and stripped of control characters, plus the home path,
to both exit errors, for example `synapsed exited (exit code: 2): synapsed: keystore: no account: run synapse id init first
(home <path>)`. `synapsed` also prefixes a refused keystore item with `permissions_too_open:`. A pipe was rejected: a live
daemon holds its write end and blocks when it fills. The file is left in the home (a daemon that started keeps it open). Tests:
no account, a too-open key, and a healthy start that leaks no daemon stderr. Red on rc.50 (the first two fail), green here;
with the file read removed the first two fail again. The CLI still waits out the 5 s deadline after the daemon has exited, as
before.

### Fixed (rc.50): `docker-compose.yml` describes the daemon, not the legacy Postgres service

The file ran `thinkersjournal/synapse:latest` (no such tag on Hub) with Postgres, ports 8080-8082, a config mount, Prometheus
and Grafana, none of which `synapsed` uses. It is now one service with a named volume and no published port (`synapsed` is
loopback only), image `thinkersjournal/synapse:main` overridable with `SYNAPSE_IMAGE`. Run against that image: `id init`,
`up -d`, then `claim`, `send` and `inbox` through `docker compose exec` all worked; before `id init` the daemon restarts in a
loop (exit 2, "no account"), which the header comment says. `monitoring/` is now unreferenced and left in place.
ROADMAP.md: items 4-6 updated, items 13-14 added.

### Fixed (rc.49): README Quick Start named a crate and a method that do not exist

The README told readers to depend on `message_routing_system = "0.1.0"` and `use message_routing_system::*`; the library is
`synapse`. Its Basic Usage example called `register_peer`, which does not exist (`register_peer_key` does, with another
signature). Basic Usage is now the CLI sequence run from a clean home at rc.48 (id init, claim, send, inbox, ack, list); the
Rust example is removed. Docs only. `src/lib.rs:185` still carries the old dependency line, and the README sections after
Quick Start (Real-World Example, Advanced Features) are not checked against the code.

### Added (rc.48): `ROADMAP.md`, the release path to the public flip

Docs only; no code change. Orders the remaining work, and states what Synapse takes from and gives to auth-framework, OverMind,
PersistAnt and KISS (none today for KISS: 0 files mention Synapse). The publish order is read from the manifests; the
`cargo publish --dry-run` itself has not run yet.


### Fixed (rc.47): `free_port()` in `tests/transport_repairs.rs` can no longer hand out the same port twice

`Pair` asserts `alice_port != bob_port`, and `free_port()` bound port 0 and released it, so the kernel could give the same
port to the next bind. That failed the required `Build and Test` job intermittently at `transport_repairs.rs:224`
(`tcp_carries_a_large_verified_message`, `quic_oversize_refusal_does_not_increment_send_failures`,
`quic_times_out_a_stream_that_stalls_mid_message`: three different tests in three runs, each `left == right`). The helper now
remembers the ports it has returned and rebinds until it gets a new one. Test-only; no library change. The new test
`free_port_is_distinct_within_a_process` is a guard, not a reproduction: it did not fail against the old helper on this
Windows machine in 4 runs (8 threads x 250 calls), so only CI over time shows the flake gone.

### Changed (rc.46): five dependencies on their newest majors

Dependabot PRs #137-#141, taken together on one branch (CireSnave's standing rule: newest dependencies at all times):
`base64` 0.22 -> 0.23, `sha2` 0.10 -> 0.11, `getrandom` 0.3 -> 0.4, `stun_codec` 0.3 -> 0.4, `pem` 3 -> 4. One call site needed a
change: sha2 0.11's digest output no longer implements `LowerHex`, so `generate_search_hash` in `services/registry.rs` formats
with the existing `sender_auth::to_hex` (same lowercase two-digit hex, so cache keys are unchanged). Everything else compiled as
is. `base64` 0.22, `getrandom` 0.2/0.3 stay in the lock as other crates' transitive dependencies. `getrandom` is only wired
into the `wasm` feature and no source file calls it, and the `wasm` job does not build a real package (there is no `wasm/`
directory), so that bump is compile-checked only. Verified at this head: `cargo clippy --workspace --all-targets -- -D warnings`
(default and `--features auth`) clean, `cargo check` with `nat_traversal crypto minimal core`, `cargo test --workspace`: one
failure, `tcp_carries_a_large_verified_message`, an existing flake (two `free_port()` calls can return the same port; passes 3 of 3
re-runs alone).

### Changed (rc.45): GitHub Actions on their newest majors

Dependabot PRs #132-#136, taken together (CireSnave's standing rule: newest dependencies at all times). `actions/checkout`
v3/v4 -> v7 (8 steps), `actions/upload-artifact` v4 -> v7, `docker/login-action` v2 -> v4, `docker/metadata-action`
v4 -> v6, `docker/setup-buildx-action` v2 -> v4. Workflow files only; no source change. Still behind: `actions-rs/toolchain@v1`,
`actions/cache@v3`/`@v4`, `docker/build-push-action@v3`, `codecov/codecov-action@v5`, `appleboy/ssh-action@master` (dependabot opens
those as it reaches them). `docker/metadata-action` and `setup-buildx-action` run in the PR image build; `login-action` runs only on a push to `main`, which
still fails with 401 `insufficient scopes` (Docker Hub token), so its new major is untested until that is fixed.
The three docker actions are pinned to full commit SHAs (CodeQL's unpinned-tag finding), each the commit its tag pointed at on 2026-10-13: `setup-buildx-action` f87e5991 (v4), `login-action` dbcb8138 (v4), `metadata-action` dc802804 (v6); `docker/build-push-action@v3` is still a tag.

### Changed (rc.43): `Cargo.lock` is committed and CI builds with `--locked`

CodeRipper SUP-001 (4 medium, one per binary crate: `synapsed`, `synapsectl`, `synapse-mcp-server`, `synapse-claude-channel`):
the workspace ships applications but `Cargo.lock` was untracked. The ignore came from the initial commit's generic
"Dependencies" template block (33f3448, 2025-07-10); no commit message or doc records a reason for it, and no later
change relied on it except comments saying "there is no Cargo.lock". The lock is now tracked, generated with
`cargo generate-lockfile` on 2026-10-13 (`cargo update --dry-run` then locks 0 packages; the 22 entries shown "behind latest"
are held back by this workspace's own version requirements). `ci_cd.yml` passes `--locked` to the build, test, clippy,
coverage and `cargo install cargo-audit` steps (not to the model-agnostic job's `cargo test -p synapse`, which deletes `crates/`
first, so its graph legitimately differs from the lock), and the `Dockerfile` builds `--locked`, so a build can no longer drift from the
commit. Nothing resolves new releases by itself any more: `.github/dependabot.yml` (new here) opens a weekly grouped minor+patch PR for `cargo` and for `github-actions`, a PR each for majors; those PRs do not bump the workspace version, the PM allocates it at gate. Before it, refreshing was a `cargo update`
in a PR. Library consumers are unaffected (cargo ignores a dependency's lockfile). No code changed; running daemons are
unaffected.

### Changed (rc.42): manifests point at `ThinkersJournal/synapse`

The repository moved from `ciresnave/synapse` to `ThinkersJournal/synapse` (transferred 2026-10-12 by the PM). The `repository` and `homepage` lines in the workspace manifest and the six crate manifests (8 lines, 7 files) now name the new location; the old URL only redirects. No code change. Nothing is published.

### Changed (rc.41): the Docker image is `thinkersjournal/synapse`

CireSnave, 2026-10-12, verbatim (via the PM): "Lets ensure Synapse is under ThinkersJournal.  I just created the ThinkersJournal organization on Docker Hub so we should be able to publish docker images as ThinkersJournal/Synapse and such." Board 186 is answered.
The workflow's `images:` and `docker-compose.yml` now name `thinkersjournal/synapse` (Docker Hub names are lowercase) instead of the
nonexistent `synapsenetwork` namespace, which is what made the push fail with 401. Read before the change: the public API
`hub.docker.com/v2/orgs/thinkersjournal` answers 200 (org created 2026-10-12T21:20:50Z) and
`/v2/repositories/thinkersjournal/` lists 0 repositories. Not verified: that `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` may push to that
org (the first push off `main` will say). Nothing is pushed or published by this change. `docker-compose.yml` is still stale in
other ways (postgres, port 8080, a `config` mount; `synapsed` binds loopback only). Alert delivery is still only a seam
(`AlertTransport` has no implementation, board 131).

### Breaking (rc.40): the crate `synapse-client` is now `synapsed-client`

CireSnave (board 183): "synapsed-client". The crates.io name `synapse-client` belongs to another user (owner
`krypticmouse`, "Rust client SDK for Synapse memory runtime"), and both adapters depend on this crate, so it could not be
published. Read on 2026-10-12T19:20Z: `synapsed-client` is on crates.io at 0.0.0, owner `ciresnave`, "Name reserved for
the Synapse project", a placeholder the PM published at 18:34Z under CireSnave's standing order to claim every chosen
name once verified free (control `serde` 200); this PR neither reserves nor publishes anything. The directory is
`crates/synapsed-client`; the library path is `synapsed_client`. Rename only: no code change, and no other dependent
outside this workspace exists (the crate was never published). Historical entries and dated plans/specs keep the old name.
Alert delivery is still only a seam (`AlertTransport` has no implementation, board 131).

### Breaking (rc.39): the generic push default is receiver-only; `/v1/fetch` takes `exclude`

Design: `docs/superpowers/specs/2026-10-12-receiver-only-ack.md`; parent note section 5.4 (PR 4). **Daemon change:**
`POST /v1/fetch` accepts an optional `exclude: [message_id]` (at most 100 ids, each at most 256 bytes, else 400
`malformed`); an excluded message is not leased, its `attempts` does not move and it does not count toward `max`. No
store format change. Core: `Mailbox::fetch_excluding` (`fetch` is unchanged). **Adapter, breaking at runtime:** a `ReceiverOnly` adapter against a daemon older than rc.39 gets 400 on the first look after it parks something; the adapter then clears its parked list and pushes up to the bound again, so push keeps working. Every `Renderer` impl is source-compatible (`ack_policy` gained a default and `AckPolicy` is non-exhaustive), but a renderer that relied on the old required method now gets `ReceiverOnly` only if it deletes its own.
`Renderer::ack_policy` now has a default, `AckPolicy::ReceiverOnly` (new variant): after `max_pushes` writes of a
message by this process the adapter stops pushing it and passes over it with `exclude`, and never acks it, so a client
that never reads a push loses nothing (FAM trap 4a). `ClaudeChannel` keeps `BoundedAttempts`, so Claude Code behaves
as in rc.38 (its push behaviour is unchanged since rc.33) and sends no `exclude`. Known limits: the parked list is in memory, so a new adapter process pushes
a pending message up to the bound again; past 100 parked the oldest is pushed again, so with more than 100 pending messages a `ReceiverOnly` adapter keeps churning through them; a receiver's `ack` does not remove an id from the list (harmless: it excludes nothing). Not in this PR: advertising the
push method in `whoami`. Alert delivery is still only a seam (`AlertTransport` has no implementation, board 131).

### Fixed (rc.38): the Docker image builds

The `Build Docker Image` job failed on `COPY Cargo.toml Cargo.lock` (`Cargo.lock` is gitignored) and its Dockerfile was
stale (rust:1.70, a dummy `src/main.rs` on a workspace, binaries and a `config` directory that no longer exist).
`Dockerfile` now builds `synapsed`, `synapse` (crate `synapsectl`) and `synapse-claude-channel` from the workspace on
`rust:1.95-slim-bookworm` and ships them on `debian:bookworm-slim` as a non-root user with `SYNAPSE_HOME` on a volume;
`.dockerignore` keeps `target` and `.git` out of the context. The workflow now builds the image on pull requests too
(login and push only off pull requests). The image is `synapsenetwork/synapse` (tags `main`, `sha-<short>`, and the
version on a `v*` tag). Note: `synapsed` binds loopback only, so a container is reachable only from inside. Not verified:
that the DockerHub account may push to the `synapsenetwork` namespace. Alert delivery is still only a seam
(`AlertTransport` has no implementation, board 131).

### Changed (rc.37): the push loop moves to `synapse-mcp-server` behind a `Renderer`; Claude Code is one renderer

Design note `docs/superpowers/specs/2026-10-12-agent-facing-mcp-adapter.md` sections 2 and 5.3 (PR 3). New
`synapse_mcp_server::push`: `Renderer` (capability key, method, protocol cap, instructions, `render`, `ack_policy`),
`AckPolicy`, `PushConfig`, `PushServer<R>`, `PushLedger`, `Notifier`, `should_ack`, `push_once_with`. `synapse-claude-channel`
keeps its names (`ChannelServer`, `ChannelConfig`, `push_once`, `PushLedger`, `Notifier`, `CHANNEL_METHOD`) as a
`ClaudeChannel` renderer and aliases, so `tests/channel.rs` passes UNCHANGED. **No behaviour change**; the only visible
difference is the push loop's warning prefix, `synapse push:` instead of `synapse channel:`, and its tracing target
(`synapse_mcp_server::push`, so a `RUST_LOG=synapse_claude_channel=warn` filter no longer matches those warnings). New test
`crates/synapse-mcp-server/tests/push.rs` drives a made-up renderer (its own capability key, method, protocol cap and text)
through a real daemon. Not covered: a second real client product. Alert delivery is still only a seam
(`AlertTransport` has no implementation, board 131).

### Changed (rc.36): one parsed `MessageView` behind the `fetch` tool and the channel push; a raw-wire client test

Design note `docs/superpowers/specs/2026-10-12-agent-facing-mcp-adapter.md` section 5.2 (PR 2). `synapse-mcp-server` gains
`MessageView` (`from_wire`, `message_id`, `from`, `attempts`, `body_text`, `to_tool_json`) and `SynapseMcpServer::pull_views`;
the `fetch` tool and `synapse-claude-channel`'s push both render from it, so the push reads the daemon's JSON only through the view's accessors.
**No behaviour change:** `tests/channel.rs` and `tests/adapter.rs` pass unchanged. **Breaking, unpublished surface:**
`synapse_claude_channel::channel_params` now takes `&MessageView`. New tests: a corpus test that both surfaces agree on id,
sender and body (the push differs only by `<`/`>` entities), and `tests/foreign_client.rs`, a hand-written newline-delimited
JSON-RPC client over the real binary's stdio (`server/discover` -> `-32022`, `initialize`, `tools/list`, the push, `ack`).
Not covered: a stock Python MCP client and a live Claude Code push. Alert delivery is still only a seam
(`AlertTransport` has no implementation, board 131).

### Docs (rc.35): design note for the agent-facing MCP adapter in the first public release

`docs/superpowers/specs/2026-10-12-agent-facing-mcp-adapter.md` (PM task, CireSnave 2026-10-12: the adapter ships
in the first public release). Maps FAM's `DESIGN-SYNAPSE-HANDOVER.md` traps onto the Rust adapter at rc.34, places
a `Renderer` seam, and sizes the work at 5 PRs. **Finding:** the crates.io name `synapse-client` belongs to another
user, so the adapters cannot be published until it is renamed. Also: the rc.33 adapter ack is FAM's trap 4a for a
client with no handler. No code changes. Alert delivery is still only a seam (`AlertTransport` has no
implementation, board 131).

### Docs (rc.34): soak procedure status and stop conditions brought up to rc.33

`docs/RESTARTTEST_SOAK_PROCEDURE.md`: the status line no longer says "PREPARED, NOT RUN" (phase 1 was run, c7 measured
on rc.29 and rc.33, n=1 each; the soak itself is not started). Stop condition 1 now defines "lost" by the session
transcript alone, because since rc.33 a daemon-side ack or an empty `pending` does not mean shown. Stop condition 2
states the `max(3, attempts_at_first_pull + 2)` bound and that up to 3 shows of one `message_id` is expected. No code
changes. Alert delivery is still only a seam (`AlertTransport` has no implementation, board 131).

### Breaking (rc.33): the adapter acks a message itself after bounded delivery attempts

**What this is: bounded delivery ATTEMPTS. Claude Code gives no confirmation that an event was shown,
so this is NOT at-least-once.** Measured on the rc.32 adapter (Claude Code 2.1.296, claude-sonnet-5-5,
n=5 unprimed plain messages, one wording, 2026-10-10): every message was shown and pushed 3 times, the
model called `ack` 0 times, and an unacked message was redelivered to each new session with the adapter's
in-memory push count reset. rc.33 acks after a SUCCESSFUL write when the daemon's per-message `attempts`
is at least `max_pushes` (3) AND this process has pushed that `message_id` at least twice; the `ack` tool
stays as an early removal. Pushes per message across sessions are at most
`max(max_pushes, attempts_at_first_pull + 2)`, not 3. **Loss window:** a message is lost only if every
push in that bound was dropped (~`lease_secs`, 30 s, apart), or if its daemon `attempts` was already spent
by sessions that never wrote it (`attempts` counts leases, not writes; a successful write always
precedes the removal). The c7 case (a push before the client registers the channel, rc.29 lost one, n=1)
is the loss this covers. The same message now arrives up to that many times with the same
`meta.message_id`; the server instructions say to act on it ONCE and ignore repeats. **Breaking:**
`ChannelConfig::max_pushes` now means the daemon-attempt count at which the adapter acks (a message is no
longer left pending past it), the new public `should_ack` is the rule, and the instruction text changed.
Also removed: the batch widening for capped messages and `PushLedger`'s capped count (a message is no
longer left pending past the cap, so nothing lingers to hide newer mail). Known limit: if the daemon
persistently refuses the adapter's ack (it is logged), the message stays pending and is pushed again every
lease, so the stated bound holds only while the ack succeeds; a message whose writes always fail is never
acked and is re-leased. The ack tool and the adapter's ack may both fire; the daemon's ack is idempotent
(`already_acked`). No daemon, wire or store change. Alert delivery is still only a seam
(`AlertTransport` has no implementation, board 131).

### Breaking (rc.32): the channel adapter acks on the model's word, not on the write (fix C)

*Superseded by rc.33 above: models did not ack (0 of 5), and "at-least-once" below is not what ships.*

`synapse-claude-channel` no longer acks a message when the channel notification is written: a write says
the bytes left the adapter, not that Claude Code showed the event (soak check 7: a message was acked and
never shown, cause not established, `docs/SOAK_PHASE1_RESULT_2026-10-09.md`). A pushed message stays leased until the model calls the `ack`
tool with the event's `meta.message_id`; otherwise it is pushed again when the lease ends (at-least-once).
The server instructions now tell the model to ack. **Breaking:** `ChannelConfig` gains `max_pushes`
(default 3; a message pushed that many times stays pending and is no longer pushed, not dropped), and
`push_once` takes a `&PushLedger`. Not done here: the readiness gate of the fix-C spec is DEFERRED. The real-client wire log
(Claude Code 2.1.296 through `tee_mcp`, n=1, rc.29 adapter, 2026-10-10) read: `initialize`, its result,
`notifications/initialized`, `tools/list`, its result, then a channel event that the session showed. That
order does not test the racing case (an event arriving before the client registers the channel), so the gate
is unproven and not shipped; the ack makes a dropped early push recoverable. The c7 re-test (queued while
down, then relaunch) with this adapter decides it. Batching acks is also not done. Alert delivery is still only a seam (`AlertTransport` has no implementation, board 131).

This file was not maintained between 1.1.0 and the 6.0.0 release candidates. The breaking changes of
the earlier candidates are recorded in their pull requests (`ciresnave/synapse`), not here.

### Breaking (rc.31): dependency `auth-framework` 0.5.0-rc26 -> 0.6.0-rc42; minimum Rust 1.89 -> 1.95

`auth-framework` 0.5.0-rc26 and every later 0.5 candidate were yanked on 2026-10-09, so `main` no longer
resolved. `0.6.0-rc42` is the newest published release; the `auth` feature set is unchanged
(`oauth-device-flows`, `enhanced-device-flow`). **Breaking:** that release declares `rust-version = "1.95"`,
so every `synapse*` crate's `rust-version` is now 1.95 (was 1.89); a toolchain older than 1.95 is refused by
cargo for every crate here. No code change was needed: the workspace tests pass (612 passed, 0 failed, 3 ignored,
`--features auth`), as do clippy, fmt and the SPDX gate. No wire or store change.

### Docs (rc.30): soak procedure corrected, phase-1 live-push result

The two-channel development-channels dialog reads `Channels: server:claude-peers, server:synapse` (comma and
space); the procedure and two plans wrote it without the space, and now match. Adds
`docs/SOAK_PHASE1_RESULT_2026-10-09.md`, the measured phase-1 result. No code changes.

### Added (rc.29): `GET /v1/stats`, cumulative per-role mail counters

`synapsed` answers `GET /v1/stats` (session token, like `/v1/list`) with `sent`, `acked`, `redelivered` and
`expired` per claimed role, and `scope: "process"` plus `since`. The counters live in memory: a daemon restart
resets them. No message content, ids or bodies are in the answer. Additive: `mailbox::Delivery` gains
`prior_lease_lapsed` (a public struct, so a literal constructing one needs the field). Nothing else changes on
the wire or in the store. The soak procedure now reads these counters.

### Docs (rc.28): LAN-mode design note, and the `restarttest` live-push and soak procedure

Docs only; no code, wire or store change. `docs/LAN_MODE.md` is a design note (nothing built) on running Synapse
across two machines: why `synapsed` is loopback-only today, a LAN-listening hub (option A) against linked
per-machine daemons (option B), a harness for non-Claude models, and an honest size. `docs/RESTARTTEST_SOAK_PROCEDURE.md`
is the prepared, **not run** procedure for the M7 live push in the disposable `restarttest` lane and the M9
side-by-side soak: commands, rollback, what is measured, and stop conditions. It records that `synapsed` keeps no
cumulative sent/acked/redelivered counters, so the soak measures from a canary and the transcript. Neither
document approves a live test or a cutover.

### Breaking (rc.27): mail store format 2, and `fetch` no longer decodes every held message

`RedbStore` keeps a fixed-width `leases` row per leased message, so `fetch` skips the messages it must
withhold without JSON-decoding their metadata. On a role of 10 000 messages with 5 000 leased, `fetch(max=1)`
fell from p50 9.8 ms to 5.2 ms (release build, one Windows laptop, 1 KiB bodies; `tests/mailbox_fetch_cost.rs`).
**This is not a fix of the cost's growth.** The slice's own bar was "within 2x of the small case", and it is not
met: 5.2 ms is 2.4x the 1k case (2.1 ms), because `fetch` still walks every `META` and `leases` key in the role.
`fetch(max=1)` p50, half the role leased: 1k 2.9 -> 2.1 ms; 5k 6.8 -> 3.5 ms; 10k 9.8 -> 5.2 ms. A `READY` table
would remove the rest; it is tracked as a follow-up, to be done only if the M9 soak shows a need.

**The database file changes and cannot be downgraded.** The first open by this version rebuilds `leases` from the
existing rows and stamps format 2, all in one write transaction (a crash leaves the old file untouched and the next
open starts again). A store stamped with a newer format is refused with an error. rc.26 and earlier do not read the
stamp: opening a migrated file with them would leave `leases` stale, so do not. The wire protocol and the HTTP API
are unchanged.

### Added (rc.25): `synapse-claude-channel`, the Claude Code channel adapter (M7)

New crate and binary `synapse-claude-channel --role <role> [--home <dir>]`. It serves M6b's tools and, once a
second, leases mail from `synapsed` and pushes each message to Claude Code as a `notifications/claude/channel`
event whose text is escaped and framed as untrusted, then acks it. A failed write leaves the lease to run out,
so the message is redelivered. It caps the MCP protocol at 2025-11-25 (`server/discover` is answered `-32022`,
so Claude Code falls back to `initialize`) and declares the `tools` and `experimental: claude/channel`
capabilities. `synapse-mcp-server` gains `SynapseMcpServer::pull` and `confirm`. Not a cutover from
claude-peers; that is a separate decision.

### Breaking (rc.24): `synapse-mcp` is now the generic adapter over `synapsed` (M6b)

`synapse-mcp-server` (binary `synapse-mcp`) drops its UDP backend and its TOML config and talks to `synapsed`
through `synapse-client`, as one role. **Removed:** the `--config` file and `SYNAPSE_MCP_CONFIG`, the static
peers, the `poll` tool (replaced by `fetch`), `McpConfig`'s old fields, `SynapseMcpServer::start_with_sink`,
and the UDP transport it carried. **Now:** `synapse-mcp --role <role> [--home <dir>]` (or `SYNAPSE_ROLE`;
the home defaults as for the `synapse` CLI); tools `send(to, body, message_id?)`, `fetch(max?, lease_secs?)`,
`ack(message_id)`, `list()`, `set_summary(summary)`, `whoami()`. The adapter claims its role once, implicitly,
when the home has no session for it, and heartbeats every 30 s. A superseded or unknown session is reported as
a tool error and is never answered by re-claiming; take the role back with `synapse claim`. Fetched bodies
and summaries are escaped for control characters (newlines and tabs kept). New in `synapse-client`:
`Daemon::instance_id` and `Daemon::session_info`. Measured by the PM on 2026-10-08, on one box and its 11
MCP/settings files only: none names `synapse-mcp` as a server.
Alert delivery is still only a seam (`AlertTransport` has no implementation; board 131).

### Added (rc.23): `synapse-client` crate (M6a)

The blocking client for `synapsed` (find the daemon, prove it, claim a role, keep one session) moves out of
`synapsectl` into its own library crate, `synapse-client`, so the CLI and the coming MCP adapters share one
implementation. Pure move: `synapsectl` keeps its behaviour and its `tests/cli.rs` and `tests/mail.rs` pass
unchanged. The security-events surface string is still `synapsectl/health-proof`. A new test pins the exports
(`Daemon`, `MailError`, `encode_body`, `inbox_line`, `printable`, `events`).
Note: migration `002_drop_trust_tables.sql` is not applied anywhere.

### Changed (rc.22): auth-framework 0.3.0 -> 0.5.0-rc26

The optional `auth-framework` dependency moves to the newest published release. 0.3.0 pulled reqwest 0.11,
hyper 0.14 and h2 0.3.27 (RUSTSEC-2026-0258, no fix on the 0.3 line) and rustls-pemfile 1.0.4
(RUSTSEC-2025-0134, unmaintained); 0.5.0-rc26 resolves h2 0.4 and reqwest 0.12/0.13 only. `cargo audit`
at this change reports no vulnerabilities. Nothing that compiles today calls auth-framework (its only user,
`src/auth_integration_enhanced.rs`, is behind the deliberately broken `enhanced-auth` feature), so no
Synapse API changes. The `auth` feature now builds against a pre-release crate.
Two manifest lines had to follow: `lettre` gains `tokio1-native-tls` (auth-framework 0.5 enables lettre's
`tokio1`, which fails to compile beside the default `native-tls` without it; same TLS backend as before), and
`ring` gains `std` (another crate's graph used to switch it on; `src/synapse/auth/utils.rs` needs ring's errors
to be `std::error::Error`).

### Removed (breaking, rc.21): the trust system is spun out

The blockchain, staking, consensus and trust-score system is removed from the core. It was in-memory,
unwired in places (`ConsensusEngine`, `VerificationEngine` had no caller), unreachable from every shipped
binary, and is to be rebuilt as its own project around vouchers and revocations. Source is preserved at the
git tag `pre-trust-removal` (`30a6e06`). Core keeps authenticated senders (`sender_auth::TrustStore`,
`certificate`) and the optional `services::TrustSource` hook.

- `synapse::blockchain` and everything in it: `SynapseBlockchain`, `BlockchainConfig`, `StakingManager`,
  `ConsensusEngine`, `VerificationEngine`, `Block`, `Transaction`, `TrustReport`, and the bincode impls.
- `synapse::synapse::blockchain::serialization::*`: `DateTimeWrapper` and `UuidWrapper` are at `synapse::wire`
  (also re-exported from `synapse::types`).
- `SynapseNode` and `SynapseConfig`.
- `services::TrustManager`, `api::TrustAPI`, `models::trust` (`TrustBalance`, `TrustRatings`,
  `EntityTrustRatings`, `NetworkTrustRating`, `TrustCalculator` and the rest).
- `ParticipantProfile::trust_ratings` is now an opaque `serde_json::Value` (default `{}`, as the column's). Stored profiles
  still load: the old JSON is kept as is.
- `ParticipantRegistry::new(database, cache)` and `ParticipantAPI::new(registry, discovery, telemetry)` no longer
  take a `TrustManager`. `ParticipantStatistics` loses `trust_reports_today` and `average_trust_score`.
- `PrivacyManager::new_with_trust` (use `with_trust_source`) and `PrivacyManager::can_contact`, a stub with no
  caller that approved every request.
- `storage::Database`: `upsert_trust_balance`, `get_trust_balance`, `get_balances_for_decay`,
  `count_reports_since`, `record_trust_report`, `count_trust_reports_today`, `get_average_trust_score`.
  `storage::Cache`: `cache_trust_score`, `get_cached_trust_score`, `cache_block_hash`, `get_block_hash`.
- `From<bincode::error::{EncodeError, DecodeError}> for SynapseError`, and the `bincode` dependency
  (RUSTSEC-2025-0141 no longer applies).
- Migration `002_drop_trust_tables.sql` drops `trust_balances`, `trust_ratings`, `trust_reports`,
  `blockchain_blocks`, `blockchain_transactions` and two views (`DROP ... IF EXISTS`; `trust_reports` was never
  created by a migration). `participant_relationships.trust_score` is left alone.
- `[blockchain]` in `config/example.toml`; the README and API-reference trust sections;
  `docs/BLOCKCHAIN_TRUST_SYSTEM.md`.

### Fixed (rc.21)

- `ParticipantRegistry::search_participants` re-applies the privacy and trust filters to cached results. It
  used to return cached ids without checking the current policy or trust source.

### Added (rc.20)

- `synapse::services::TrustSource`, an optional hook for a trust score, with `NoTrustSource` (the default) and
  `TrustAnswer::{Score, Unsupported}`. Contact search (`min_trust_score`) and the privacy policy
  (`trust_threshold`) read through it. `ParticipantRegistry::with_trust_source` and
  `PrivacyManager::with_trust_source` set it.

### Changed (rc.20, behaviour)

- `PrivacyManager::evaluate_contact_request` no longer allows contact when a positive `trust_threshold` has no
  score. With no source, or a failing one, it returns an error (`TrustUnsupported` for no source). It used to log a warning and allow.
- `ParticipantRegistry` contact search with `min_trust_score` returns an error when the source fails. It used to
  treat a failure as a score of 0.0, and one failing lookup now fails the whole search rather than dropping that
  profile. A `min_trust_score` of 0.0 or less consults no source, as in `PrivacyManager`.

### Removed (breaking)

The binary codec that RUSTSEC-2025-0141 flags as unmaintained has been removed from the core types
(step B1 of `docs/superpowers/plans/2026-10-07-remove-bincode.md`). The wire format was always JSON
and is unchanged.

- `SimpleMessage::to_bytes` and `SimpleMessage::from_bytes`
- `SecureMessage::to_bytes` and `SecureMessage::from_bytes`
- `StreamChunk::to_bytes` and `StreamChunk::from_bytes`
- `StreamMetadata::to_bytes` and `StreamMetadata::from_bytes`
- The `bincode::Encode`/`Decode` impls on `MessageType`, `SecurityLevel`, `SimpleMessage`,
  `SecureMessage`, `StreamPriority`, `StreamType`, `StreamChunk`, `StreamMetadata`,
  `sender_auth::ProofAlg` and `sender_auth::SenderProof`.

Use `serde_json::to_vec` and `serde_json::from_slice` instead, which is the wire format.

### Moved

- `DateTimeWrapper` and `UuidWrapper` now live in `synapse::wire`. `synapse::types::…` and
  `synapse::blockchain::serialization::…` still re-export them.

### Added

- **`MultiTransportRouter::set_security_sink` (6.0.0-rc.16).** `MultiTransportRouter` builds its
  own Direct-mode email transport, outside any `TransportManager`, and gave it no sink. It now
  passes the sink to each of its transports, and `SynapseRouter::set_security_sink` passes the
  router's sink on to its `MultiTransportRouter`. Like `TransportManager`'s, this sink records only
  in Direct mode, whose SMTP listener enforces the inbound limits. `MultiTransportRouter` never
  starts its email transport itself, so today that listener is bound but not served; the path is
  wired and tested by injection, with the test starting the transport.
- **`SynapseRouter::set_security_sink` (6.0.0-rc.15).** The router's email transport now records
  its own security events to the sink you give it. That happens only in Direct mode, where its SMTP
  listener enforces the inbound limits. Before, it enforced them but recorded nothing. The router
  also passes the sink to its `SynapseEmailServer` (login failures and lockouts), but nothing
  populates that server yet. `SynapseEmailServer::set_security_sink` sets the sink on a server
  already behind an `Arc`.

### Changed (behaviour)

- **Email logins: attempts in progress count against the lockout (6.0.0-rc.13).** SMTP `AUTH` and
  IMAP `LOGIN` share one budget per username (10 failures) and per source address (50 failures)
  across both servers. A login whose password is still being checked now counts as a failure
  until it finishes. So while recent failures plus logins in progress reach a limit, even a
  correct password is refused. The refusal is logged as an `auth_failure` security event with
  detail `in_flight`, unlike a real lockout, which has detail `locked`. It clears when the logins
  in progress finish, unless they fail: each wrong password becomes a recorded failure and can
  complete a real lockout (15 minutes). This closes a race in which parallel connections could each guess
  past the limit.

## [1.0.0] - 2023-07-01

### Added

- Full production-ready release with all core features implemented
- Comprehensive error handling system with standardized API errors
- Enhanced security features and input validation
- Trust system security audit and improvements
- Rate limiting for all public endpoints
- Transport abstraction layer with HTTP, WebSocket, WebRTC support
- Circuit breaker patterns for external service resilience
- Complete API documentation with examples
- Telemetry and monitoring integration
- Docker containerization and deployment scripts
- CI/CD pipeline for automated testing and deployment
- WASM support for browser environments

### Changed

- Renamed message_routing_system to synapse throughout the codebase
- Enhanced error handling patterns across all components
- Optimized critical performance paths
- Updated all examples to use the latest API
- Improved configuration management with environment variable support
- Enhanced logging with structured log format

### Fixed

- Multiple concurrency issues in the participant registry
- Trust propagation algorithm security issues
- Database connection pool management
- Memory leaks in long-running WebRTC connections
- WASM compatibility issues on Safari mobile
- Registry search with special characters
- Blockchain transaction verification

## [0.9.0] - 2023-06-15

### New Features

- Initial WebAssembly (WASM) support
- Browser compatibility layer
- Trust system blockchain integration
- Enhanced identity resolution system
- Email transport layer
- Participant discovery system
- Registry service with search capabilities
- Message routing with transport selection
- Circuit breaker pattern implementation

### Improvements

- Refactored core architecture for better modularity
- Enhanced error handling
- Improved logging
- Updated configuration system

### Bug Fixes

- Multiple threading issues
- Connection handling edge cases
- Discovery service timeout issues
- Message routing failures in high-load scenarios
