# Synapse developer guide

**Scope.** How to build, test and find your way around the repository at 6.0.0-rc.99, read from `Cargo.toml`,
`.github/workflows/ci_cd.yml` and the tree. The former guide (tutorials on a router, discovery and
approval API; about 670 lines) was replaced in rc.100 because most of its method names no longer exist
(`python .github/docs_staleness.py` measured 61 of 72 unknown). It is in git: `git show 519bd52:docs/DEVELOPER_GUIDE.md`.

## Build and test

Rust 2024 edition, minimum Rust 1.98. These are the commands CI runs (`Build and Test` job, ubuntu); run them
from a clean checkout:

```bash
cargo build --locked --workspace
cargo test --locked --workspace --no-fail-fast
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
python .github/spdx_gate.py          # every source file declares its licence
```

`--workspace` matters: the root package has members, and without it `cargo test` runs only the root package.
`--locked` matters too: `Cargo.lock` is tracked and CI refuses a build that would change it.

Rules the tests and reviews enforce: no `#[ignore]` and no `#[allow(dead_code)]` (fix the cause; a last
resort needs a stated reason); a test that cannot run on GitHub is named as unverified or moves to the
self-hosted runner, never skipped silently; the core crate stays model-agnostic (`tests/core_is_model_agnostic.rs`).

## Layout

```text
Cargo.toml              the library crate `synapse` and the workspace (members = crates/*)
src/                    the library: mailbox, roles, keystore, sealing, sender_auth, replay,
                        security_events, wire, transports (src/transport/), email server, streaming
crates/synapsed/        the daemon: loopback HTTP /v1 API over the redb mailbox
crates/synapsectl/      the `synapse` command line
crates/synapsed-client/ the client library the CLI and adapters share
crates/synapse-mcp-server/      generic MCP adapter (binary `synapse-mcp`)
crates/synapse-claude-channel/  Claude Code channel adapter (pushes mail into the session)
crates/synapse-security/        sinks for security events (owner-only file, stderr, alert seam)
tests/                  integration tests (mailbox_*, roles, sealing, security_*, ...)
docs/                   API_REFERENCE.md, runbooks, specs and plans under docs/superpowers/
```

Binary names: the `synapsectl` crate builds `synapse`; `synapse-mcp-server` builds `synapse-mcp`.

## The mailbox and its contract

The daemon's store is `RedbStore` (feature `mailbox-redb`). Any other store implements the `MailStore` trait
(`write` runs one atomic transaction over a `MailTxn`) and must pass the conformance suite:

```rust
// Cargo.toml: synapse = { version = "...", features = ["mailbox-conformance"] }
synapse::mailbox::conformance::run_all(synapse::mailbox::MemoryStore::new); // yours: a closure returning a fresh store
```

Each case takes a closure returning a fresh, empty store. A case is added only when the mailbox gains a
guarantee, and a case is never loosened to let a store pass. `tests/mailbox.rs` and `tests/mailbox_redb.rs` run the suite against the
memory and redb stores.

## Making a change

- One change, one PR, with a version bump (`6.0.0-rc.N`, the number is the maintainers' to allocate): every
  `Cargo.toml` and `Cargo.lock` entry, and an entry in `docs/CHANGELOG.md`.
- Check what you claim: a behaviour you describe in a doc or a changelog should have a test that fails without it.
- Docs: `python .github/docs_staleness.py` reports the share of method names in a page's Rust samples that match no
  `fn` in the workspace. Pages with a high share carry an unverified banner until they are rewritten or deleted.
- The README links are tested (`tests/readme_links_resolve.rs`): a link to a file that does not exist fails.

More: `docs/API_REFERENCE.md` (the CLI, the `/v1` routes and the MCP tools), `docs/CONFIGURATION_GUIDE.md`,
`docs/TROUBLESHOOTING.md`, `docs/RESTARTTEST_SOAK_PROCEDURE.md`, `docs/PILOT_T0_RUNBOOK.md`.
