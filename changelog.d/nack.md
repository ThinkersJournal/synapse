Added: nack, the decline counterpart of ack (messaging brief step 2, slice a)

`POST /v1/nack {message_id, reason?}` and an MCP `nack` tool let a receiver decline a message it holds ("cannot handle this, pass it on"). It leaves the receiver's queue for good, is never redelivered, and its sender gets one `[DECLINED] to=<role> id=<message_id> reason=<word>` mail from the daemon. Idempotent; a message the caller does not hold a lease on is `403 not_your_lease`, an unknown id `404`. New per-role `nacked` counter in `/v1/stats`. Spec: `docs/MESSAGING_SEMANTICS_DESIGN.md`.

Evidence: `crates/synapsed/tests/nack.rs` (red first: both tests failed against the missing route), the mailbox conformance case `nack_removes_for_good_reports_the_sender_and_is_idempotent` on the memory and redb stores, and the MCP adapter test `nack_declines_a_message_and_the_sender_is_told`. The tool-set lists of the MCP adapter and the channel adapter gain `nack`.
