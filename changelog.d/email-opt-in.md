Breaking, Changed: `email` is an opt-in feature outside `native-base` (ROADMAP row 54)

`lettre` is now an optional dependency (`dep:lettre` under `email`), and `email` moved from `native-base` to `native`. The `email` and `email_server` modules, `transport::email_unified` and their re-exports, the email arm of `create_email_transport` in `transport/providers.rs` (a stub returning `Ok(None)` without the feature), the `email_server` field of the merged router and the email contact import in `identity.rs` are cfg-gated.

**Who is hit:** consumers that depend on `synapse` with only `native-base` (agentlife, `synapsed-client`) no longer get `EmailTransport` or `SynapseSmtpServer`; enable `email` (or `native`) to keep them.

**Evidence:** `cargo tree -p synapse --no-default-features --features native-base -i lettre -e normal` is empty, as is `-p synapsed-client -i lettre`; `--features native` shows `lettre`. `cargo clippy -D warnings` is clean under `native-base` and `--workspace --all-targets`; the email lib tests (21), smtp (3), `email_security_events` (11), `email_server_has_no_default_users` (2) and `synapsed` tests pass.
