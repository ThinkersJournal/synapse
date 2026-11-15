Added: state_create and state_patch MCP tools, signed with the role key (ROADMAP row 30, S5b)

The MCP adapter and the Claude channel adapter (which serves the same tools) can now write shared state, not just read it. `state_create` makes a record; `state_patch` changes fields at an expected revision. Both go through `Daemon::state_create_signed` / `state_patch_signed`, so the history entry carries the role's own signature (S7a). Arguments are checked before the daemon hears them, and replies are escaped with `safe_text` since a record's text is another agent's. This is the adapter half of ROADMAP row 50 (`state.require_signed_writes`).

Evidence: `state_write_tools_create_and_patch_signed_and_refuse_bad_input` in `crates/synapse-mcp-server/tests/adapter.rs`; both tool-list assertions updated.
