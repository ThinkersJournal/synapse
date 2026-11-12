# `synapsed` latency under load (ROADMAP row 37d)

Measured 2026-10-25 with `crates/synapsed/examples/latency_probe.rs` (release build, loopback, one process, a
Windows laptop). The question (PM, 2026-10-25): `Shared.mailbox` is a `std::sync::Mutex` held across blocking store
I/O on a tokio worker; **touch it only if the numbers say so**.

## Method

An in-process daemon; `C` roles each loop `send` (256-byte body) to a neighbour, `fetch` (max 8), `ack`, for 4 s per
level. A separate role times a `heartbeat` (presence only, plus the epoch check under the mailbox lock) and a `list` (reads
every role's depth under the lock) every 25 ms. The store is `redb` (default) or `sqlite` (`--features sqlite-store`, WAL,
`synchronous=FULL`). Every figure is milliseconds. 34 roles were claimed for the largest level.

## redb

store: Redb; release build recommended; loopback; one process (daemon and clients share the machine)

**0 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 115 | 0.66 | 1.22 | 2.02 | 2.43 |
| probe list | 115 | 3.89 | 6.66 | 9.05 | 10.99 |

**1 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 112 | 0.40 | 4.24 | 7.18 | 9.45 |
| probe list | 112 | 7.31 | 10.43 | 13.44 | 14.92 |
| send | 492 | 4.11 | 7.92 | 9.97 | 15.86 |
| fetch | 492 | 2.81 | 6.24 | 7.80 | 57.10 |

**8 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 46 | 22.31 | 34.30 | 52.73 | 52.73 |
| probe list | 46 | 32.08 | 47.02 | 61.12 | 61.12 |
| send | 342 | 29.79 | 48.35 | 62.11 | 83.30 |
| fetch | 342 | 27.35 | 44.14 | 60.03 | 78.21 |
| ack | 407 | 29.03 | 44.34 | 50.59 | 66.67 |

**32 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 16 | 98.57 | 124.25 | 140.73 | 140.73 |
| probe list | 16 | 96.56 | 199.40 | 201.00 | 201.00 |
| send | 432 | 104.75 | 174.26 | 216.38 | 247.00 |
| fetch | 432 | 103.75 | 171.51 | 203.95 | 244.28 |
| ack | 353 | 107.29 | 170.04 | 203.85 | 229.10 |

## sqlite

store: Sqlite; release build recommended; loopback; one process (daemon and clients share the machine)

**0 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 71 | 0.58 | 0.79 | 0.80 | 20.47 |
| probe list | 71 | 21.72 | 26.45 | 27.94 | 30.88 |

**1 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 62 | 0.39 | 2.85 | 2.96 | 4.45 |
| probe list | 62 | 34.38 | 57.14 | 72.58 | 78.46 |
| send | 273 | 4.25 | 42.87 | 59.47 | 85.14 |
| fetch | 273 | 2.64 | 26.85 | 39.51 | 51.13 |

**8 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 40 | 19.64 | 32.12 | 34.21 | 34.21 |
| probe list | 40 | 48.53 | 71.01 | 102.98 | 102.98 |
| send | 305 | 31.24 | 60.61 | 71.19 | 105.73 |
| fetch | 305 | 29.44 | 62.89 | 72.89 | 112.54 |
| ack | 367 | 27.92 | 60.49 | 77.52 | 109.90 |

**32 concurrent roles** (4 s)

| call | n | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| probe heartbeat | 18 | 76.53 | 100.53 | 107.31 | 107.31 |
| probe list | 18 | 111.13 | 144.61 | 146.44 | 146.44 |
| send | 507 | 93.63 | 140.47 | 154.80 | 187.67 |
| fetch | 507 | 93.32 | 140.33 | 149.79 | 180.84 |
| ack | 416 | 90.21 | 136.45 | 158.70 | 181.72 |

## What the numbers say

1. **The lock does serialise unrelated calls behind store writes.** The cheap `heartbeat` takes the mailbox lock only for its
   epoch check, yet its p50 goes from 0.4 to 0.7 ms (idle, or one writer) to about 22 ms with 8 writers and about 99 ms with 32
   on redb (sqlite: 20 and 77 ms). Throughput is flat at roughly 100 writes a second whatever the concurrency, which is what a
   single lock around a synchronous commit would produce: a write holds the lock and everything else queues behind it. This
   probe shows the pattern, not the cause; it did not time the lock itself.
2. **At the traffic Synapse really carries this does not matter.** The P0 measurement of lane traffic
   (`AI_TO_AI_P0_MEASUREMENT_2026-10-25.md`) found 12,995 messages in 35 days, about 6 a minute across the whole fleet: roughly
   a thousandth of the load at which the queueing starts. At that rate every call sees the idle numbers.
3. **`list` is the one call that is slow when idle**, and that is its own work, not the mutex: it reads every role's depth,
   and with 34 roles it costs about 4 ms on redb and 20 to 35 ms on sqlite (two runs). The fleet has about 5 roles; the PM and
   OverMind poll it rarely.

## Decision rule and recommendation

Change the Mutex only if a real deployment shows contention, which would look like a `heartbeat` p99 climbing while
`send` volume stays modest; the rule is: re-run this probe (`cargo run --release -p synapsed --example latency_probe`) after any
change that raises the message rate by 100 times. **Recommendation: no change now.** If the mutex is ever replaced, the thing to
move off the lock is the synchronous store commit, not the epoch check.

## Limits

One process: the daemon and its clients share the machine's cores and disk, and here the same four tokio worker threads,
so some of the queueing at 32 clients is the clients' own CPU, not the lock. The disk is one laptop SSD and `fsync` cost differs
by machine. 4 seconds per level is short; the pattern, not the third digit, is the finding. Bodies are 256 bytes; real lane
messages are about 1,700 characters, which changes the commit size, not the lock.
