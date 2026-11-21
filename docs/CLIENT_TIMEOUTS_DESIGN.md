<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Client timeouts under load (design note, pm-platform [TASK] 2026-11-21)

Status: **design note first; tests and fixes follow in the same PR.** Facts below were read at `origin/main`
`c6fcc4a4` unless marked *unverified*. The task came from the PM's measurement (2026-11-21 22:25Z: daemon pid
50276 alive holding the store, an HTTP probe took 3.2 s at 100% CPU) and CireSnave's question (verbatim per
the PM): *"Can the timeouts be based on a running average so when things take longer it allows them to take
longer unless it is excessively longer?"*

## 1. What is there today (checked)

`crates/synapsed-client/src/lib.rs`:

| Constant | Value | Used for |
|---|---|---|
| `HEALTH_TIMEOUT` | 2 s (line 61) | the one health probe (`health()`, line 791) |
| `CALL_TIMEOUT` | 30 s (line 62) | the whole HTTP client, every call (`http_client()`, line 205) |
| `START_TIMEOUT` | 5 s (line 56) | how long a freshly spawned daemon gets to answer (`connect`, line 278) |
| `LOCK_TIMEOUT` | 10 s (line 67) | another command's claim of the same role (line 973) |
| `MAX_WAITING_POLL_SECS` | 25 s (line 65) | the longest `waiting` poll, kept under `CALL_TIMEOUT` |

Other crates, by `git grep` for `Duration` / `timeout` at the same ref:
- **`synapse-claude-channel`: no timeouts of its own.** It has no `Duration` or `timeout` in `src/`; every call
  goes through `synapse-mcp-server` and so `synapsed-client`'s 30 s `CALL_TIMEOUT`.
- **`synapse-mcp-server`:** `HEARTBEAT_EVERY` 30 s (`lib.rs:32`), the push loop polls every 1 s
  (`push.rs:103`); no HTTP timeout of its own. It uses `Daemon::connect_existing`, which never spawns a daemon.

How a slow daemon is read today:
1. `connect` probes health twice (`for _ in 0..2`), each with a 2 s limit. A probe that fails to answer in 2 s is
   `Health::Silent`, which becomes `Answer::Nothing`: the same as "no daemon".
2. Only `read_announce` checks that the announced **pid is alive** (`daemon_alive`); that result is thrown away
   once the probe is silent. So a live pid with a slow answer and a dead daemon look identical.
3. `connect` (the CLI path; not `connect_existing`) then **spawns another `synapsed`**. `synapsed` exits with code
   2 on a startup refusal (`crates/synapsed/src/main.rs` lines 62-140 return `ExitCode::from(2)`; which of them
   is the held store lock was *not* identified for this note).
4. `Daemon::call` / `request` make one attempt. A transport failure is returned as
   `MailError::Transport(e.without_url().to_string())`, which for a reqwest connect or timeout error prints only
   `error sending request`. The message does not say which of connect, read timeout or total timeout fired.

**A discrepancy to settle with a measurement.** The PM's chain (probe over 2 s, spawn, spawned daemon exits 2,
call fails with `error sending request`) does not match the code: a failed spawn in `connect` reports
`NoDaemon("synapsed exited ...")`, not `Transport`. `error sending request` is what `request()` prints for a
failure of an established call, and the adapter path (`connect_existing`) cannot spawn at all. So the observed
failures on the MCP adapter (this lane saw one at about 22:3x UTC the same evening, `mcp__synapse__send` failing
with `talking to synapsed: error sending request`, then working; `/v1/health` then reported `"mailbox":"busy"`)
are at least partly **call-time failures with no retry**, and the cause (refused connect, reset, or the 30 s
total timeout) is *unproven* until the timeout in force and the error kind are logged (fix 4 below). The design
covers both paths and does not assume which one the PM's incident took.

## 2. Rules

**R1. A slow answer is not a dead daemon.** If the announce file names a pid that is alive, a silent probe means
"slow", not "down". The client waits and re-probes; it does not conclude `Nothing`.

**R2. Never auto-spawn while a live `synapsed` is announced.** `connect` spawns only when there is no announce
file, or its pid is dead, or the announced address answers with a failed proof (the existing squatter rule is
unchanged). With a live pid that stays silent for the whole allowance (R3), `connect` fails with
`NoDaemon("synapsed pid N is alive but did not answer health within <t>; not starting a second one")` and the
announce path, the same shape as today's `no_daemon_answered`. *Proposal, with a cost:* a stale announce whose
pid was reused by another process would then block autostart until the file is removed. The message names the
file; a reused pid with a silent port is rare and the failure is loud. A store-lock probe (the PM's "pid and
store lock") is **not** proposed: the lock is the daemon store's own, and a client opening it risks contending
with the daemon, so it needs a safe probe nobody has shown yet (open question 2).

**R3. The allowance adapts (CireSnave's question; the PM's method).** The timeout in force for a probe or a call
is `clamp(srtt + 4 * rttvar, FLOOR, CEILING)` with `FLOOR` 2 s and `CEILING` 60 s. It is the TCP
retransmission-timer estimator (Jacobson/Karels, RFC 6298):
- first sample `s`: `srtt = s`, `rttvar = s / 2`;
- later: `rttvar = 3/4 * rttvar + 1/4 * |srtt - s|`, then `srtt = 7/8 * srtt + 1/8 * s`;
- **each sample is capped at `CEILING`** so one spike does not stretch the average for long;
- a call that **times out** is not a sample; the next allowance for that caller doubles, up to `CEILING`
  (Karn's rule), and falls back to the estimator after a success;
- slower than `CEILING` is excessive and fails.
Between floor and ceiling the allowance grows with load and shrinks when load drops.

**R4. Where the average lives.**
- The long-lived adapter keeps `srtt`/`rttvar` in memory (it makes calls every second or so).
- The CLI is short-lived, so it needs the number to survive: the daemon measures the latency of its own request
  handling (accept to response) with the same estimator and writes `{srtt_ms, rttvar_ms, at}` to
  `<home>/synapsed-latency.json` at most every 5 s (owner-only, like the announce file). A client reads it and
  uses `clamp(srtt + 4 * rttvar)`; absent, stale (older than 60 s) or unreadable means `FLOOR`. The file is
  advisory: a wrong value only moves the allowance inside `[FLOOR, CEILING]`, so a hostile writer can cost the
  caller at most `CEILING`, the same as a slow daemon.
- *Unverified:* the daemon's handler latency under a 100% CPU spike measures time **in** the handler, not time
  queued in the accept backlog, so it can under-read exactly when the PM saw 3.2 s. The client's own measured
  round trips are the better signal for the adapter; for the CLI the file is a floor-raiser, not the whole
  answer, and R1/R2 carry the safety.

**R5. A refused or failed idempotent call is retried a few times.** On a transport error (connect failure,
reset, timeout) `Daemon::call` retries up to 3 times after 0.5 s, 1 s and 2 s (jitter up to 25%), bounded by
`CEILING` overall, and only for calls that are safe to repeat:
- `/v1/send` (the adapter and CLI send a stable `message_id` per call, so a repeat is `duplicate`, not a second
  message), `/v1/ack`, `/v1/nack` (once #375 lands; `already_*` outcomes), `/v1/heartbeat`, and `/v1/fetch`
  (a lost reply leaves leases that expire by the daemon's own back-off, so nothing is lost).
- **Not retried:** `/v1/claim` (a signed nonce; a replay is refused and a re-claim is a takeover),
  state writes (`/v1/state/*`, signed and revision-checked; a retry after an unseen success would answer a
  revision conflict), `/v1/launch-*`, admin routes. They fail once with the improved error.
A caller never silently loses a message: after the retries it gets the error, and the existing message ids make a
manual resend safe.

**R6. Say which timeout fired.** Every `MailError::Transport` from the client carries
`phase=<health|call|spawn-wait>`, `kind=<connect|timeout|reset|other>`, `timeout_ms=<in force>`,
`elapsed_ms`, `attempt=<n>/<max>`, so the next incident names itself. `eprintln!` as the client already does for
the start notice; no new dependency.

## 3. What changes where

- `crates/synapsed-client/src/lib.rs`: the estimator (a small private type with unit tests); `health()` takes the
  allowance; `answering()` returns whether the announced pid was alive so `connect` can apply R1/R2; `call`/`request`
  apply R5/R6; `connect_existing` gets R1 (wait instead of two quick tries).
- `crates/synapsed/src`: writes `synapsed-latency.json` (R4). No protocol change.
- `synapse-mcp-server`, `synapse-claude-channel`: no change; they inherit the client.
- `docs/` and the `synapsed.schema.toml`: the floor and ceiling are constants, not settings, until someone needs
  to tune them (open question 3).

## 4. Tests (written before the code; one mutation per rule)

A tiny fake daemon in the test (a TCP listener that speaks the health and a call route with a controllable delay):
- **R1/R2:** delay the health answer to 3 s under an announce naming a live pid (the test's own pid): `connect`
  must return the daemon, and must **not** spawn (a counter on a fake `synapsed` path stays 0). Mutation: treat a
  silent probe as `Nothing` again, so the test fails by spawning.
- **R3:** delay ramps 0.2 s -> 3 s -> 0.2 s: the allowance grows past 3 s, then shrinks back toward the floor; a
  delay above `CEILING` fails with the timeout named. Mutations: no cap on a sample (the average stays stretched
  after one spike), no doubling after a timeout, floor/ceiling removed.
- **R4:** a stale or garbage `synapsed-latency.json` gives `FLOOR`; a fresh one raises the CLI's first probe.
  Mutation: trust an out-of-range value.
- **R5:** the fake drops the first two connections on `/v1/send`: the send succeeds on the third and the daemon
  saw one message id (or `duplicate`); `/v1/claim` and a state write are tried once. Mutation: retry a claim.
- **R6:** the failure text carries the phase, kind and timeout in force. Mutation: drop the fields.

## 5. Open questions

1. Is the 60 s ceiling right? A send that waits 60 s is a long time for an agent in a turn, but a message lost is
   worse; the PM proposed 60 s.
2. A store-lock probe (the PM asked for pid **and** lock): is there a safe, cheap one (a lock file the daemon
   holds that the client may try with a non-blocking shared lock), or is pid plus health enough?
3. Floor and ceiling as constants, or `synapsed.toml` settings?
4. Should the adapter surface a slow-daemon state to the model ("the daemon is slow, retrying") rather than
   waiting silently up to the ceiling?
