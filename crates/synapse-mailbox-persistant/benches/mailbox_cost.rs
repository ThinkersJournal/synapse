// SPDX-License-Identifier: MIT OR Apache-2.0
//! The adapter's counterpart of the root crate's `mailbox_fetch_cost` and `mailbox_depth_cost`
//! benches (adoption-fit gap 2): the same workload (1 KiB bodies, one role of N messages with half
//! of them leased, 100 samples) against `SqliteMailStore` and, as the control on the same machine
//! and run, `RedbStore`. A measurement, not a test (its own `main`; minutes): run with
//! `cargo bench -p synapse-mailbox-persistant --bench mailbox_cost`. `BENCH_TOTALS=1000,5000` sets the
//! queue sizes and `BENCH_LEASED=10` how many messages are leased first (default: half, a stuck
//! consumer; a handful is the usual case).
//! Numbers go in the PR that changed the adapter, with the ref and machine.

use std::time::{Duration as StdDuration, Instant};

use chrono::Duration;
use synapse::mailbox::conformance as suite;
use synapse::mailbox::{MailConfig, MailStore, Mailbox, RedbStore};
use synapse_mailbox_persistant::SqliteMailStore;

fn pct(mut s: Vec<StdDuration>, q: f64) -> StdDuration {
    s.sort();
    s[((s.len() - 1) as f64 * q).round() as usize]
}

fn run<S: MailStore>(label: &str, store: S, total: usize) {
    let mut mb = Mailbox::open_volatile(
        store,
        MailConfig::default(),
        suite::t0() - Duration::seconds(1),
    )
    .unwrap();
    let ids = suite::Ids::new();
    let body = vec![b'x'; 1024];
    let now = suite::t0();
    let addr = "r0@acct".to_string();
    let epoch = ids.claim(&mut mb, "r0", now);
    let fill = Instant::now();
    let mut enq = Vec::with_capacity(total);
    for i in 0..total {
        let t = Instant::now();
        mb.enqueue(suite::env(&format!("r0-{i}"), &addr, &body), now)
            .unwrap();
        enq.push(t.elapsed());
    }
    let fill = fill.elapsed();
    let leased = std::env::var("BENCH_LEASED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(total / 2);
    mb.fetch(&addr, epoch, leased, None, now).unwrap();
    let mut fetches = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        mb.fetch(&addr, epoch, 1, None, now).unwrap();
        fetches.push(t.elapsed());
    }
    let mut depths = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        mb.depths(now).unwrap();
        depths.push(t.elapsed());
    }
    println!(
        "{label:7} {total:>6} msgs: fill {fill:>9.2?} | enqueue p50 {:>9.2?} p99 {:>9.2?} | fetch(1) p50 {:>9.2?} p99 {:>9.2?} | depths p50 {:>9.2?} p99 {:>9.2?}",
        pct(enq.clone(), 0.5),
        pct(enq, 0.99),
        pct(fetches.clone(), 0.5),
        pct(fetches, 0.99),
        pct(depths.clone(), 0.5),
        pct(depths, 0.99),
    );
}

fn main() {
    let totals: Vec<usize> = std::env::var("BENCH_TOTALS")
        .ok()
        .map(|v| v.split(',').filter_map(|n| n.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1_000, 5_000, 10_000]);
    for total in totals {
        let dir = tempfile::tempdir().unwrap();
        run(
            "redb",
            RedbStore::open(&dir.path().join("mailbox.redb")).unwrap(),
            total,
        );
        run(
            "sqlite",
            SqliteMailStore::open(dir.path().join("mailbox.sqlite")).unwrap(),
            total,
        );
    }
}
