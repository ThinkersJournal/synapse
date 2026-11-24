Fixed: widen the online window in the stall test `an_online_role_is_never_stalled`

`an_online_role_is_never_stalled` failed once on main at 0415e545 (run 45304206420, attempt 1; attempt 2 passed):

    thread 'an_online_role_is_never_stalled' panicked at crates/synapsed/tests/stall.rs:198:5:
    assertion failed: stalled(&inbox(&d, &beta).await).is_empty()

The cause is unproven. It was not reproduced locally (30 of 30 single-test runs idle, 30 of 30 under 64 spinners, 40 of 40 full-binary runs on 2 cores with 4 spinners). The test used a 300 ms online window against 100 ms heartbeats, a thin margin if a runner stalls for 200 ms or more. This changes only that test's window to 1 s; no daemon code changes. If it fails again, capture heartbeat timings before widening anything further.

— lane: synapse
