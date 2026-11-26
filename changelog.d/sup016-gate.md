Changed: SUP-016 per-file licence gate in CI; five empty stub files removed

The `spdx` job now also installs coderipper 0.48.1 from crates.io and runs `coderipper check SUP-016 --deny medium`,
configured by a new `[sup016]` section in `.coderipper.toml` (`min_files = 120`; extensions `.rs .py .ps1 .sh .sql`).
The `spdx_gate.py` step stays beside it until the fleet job retires. The job timeout rises from 5 to 30 minutes for the
cold install, and `RUSTC_WRAPPER` is cleared for it.

The gate failed on five 0-byte files with no header, so they are deleted: `src/types_new.rs`,
`tests/high_load_test_new.rs`, `tests/multi_transport_integration_new.rs`, `tests/registry_integration_test_new.rs`,
`tests/webrtc_transport_integration_test.rs`. They held no code or tests (the `.disabled` sibling of the last stays).
`CAPABILITY_INVENTORY.md` now says they were removed. Before the deletion the gate exited 1 naming 5 of 258 files;
after it, see the PR checks.

— lane: synapse
