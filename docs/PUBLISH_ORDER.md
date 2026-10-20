# Publish order for the workspace crates

Measured at `origin/main` f9f49af (rc.115) with `cargo publish --dry-run --locked` per crate from a clean `git archive`. crates.io tops out at rc.105 for the seven existing crates; `synapse-mailbox-persistant` is not on crates.io yet.

| # | Crate | Needs published first |
|---|-------|-----------------------|
| 1 | `synapse` | - |
| 2 | `synapse-security` | 1 |
| 3 | `synapse-mailbox-persistant` | 1 (and `persistant-kv`, `persistant-sqlx` 0.9) |
| 4 | `synapsed-client` | 1, 2 |
| 5 | `synapse-mcp-server` | 1, 4 |
| 6 | `synapsed` | 1, 2, 3 (optional dep) |
| 7 | `synapsectl` | 1, 2, 4 |
| 8 | `synapse-claude-channel` | 1, 5 (4 as a dev-dependency) |
| 9 | `synapse-agent` | 1, 5 (4 as a dev-dependency) |

`cargo publish --dry-run` verifies only `synapse`: every other crate fails at resolve until its predecessors are on the index (`synapse ^6.0.0-rc.N` not found). Run the dry-run for each crate after the one before it is published, and wait for the index to show it.

Not covered: a real publish; the dry-run of crates 2-8.
