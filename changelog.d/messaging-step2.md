Added: messaging step 2 (nack, delivery modes, room outcomes), launch.senders_mode, and the account-hierarchy design note

**nack, the decline counterpart of ack (messaging brief step 2, slice a)**

`POST /v1/nack {message_id, reason?}` and an MCP `nack` tool let a receiver decline a message it holds ("cannot handle this, pass it on"). It leaves the receiver's queue for good, is never redelivered, and its sender gets one `[DECLINED] to=<role> id=<message_id> reason=<word>` mail from the daemon. Idempotent; a message the caller does not hold a lease on is `403 not_your_lease`, an unknown id `404`. New per-role `nacked` counter in `/v1/stats`. Spec: `docs/MESSAGING_SEMANTICS_DESIGN.md`.

Evidence: `crates/synapsed/tests/nack.rs` (red first: both tests failed against the missing route), the mailbox conformance case `nack_removes_for_good_reports_the_sender_and_is_idempotent` on the memory and redb stores, and the MCP adapter test `nack_declines_a_message_and_the_sender_is_told`. The tool-set lists of the MCP adapter and the channel adapter gain `nack`.

**`fire_and_forget` delivery mode on `POST /v1/send` (messaging brief step 2, slice b, first part)**

`send` takes an optional `delivery: {"mode": "reliable"|"fire_and_forget"}`. A fire-and-forget message is leased once, never redelivered, and its sender gets no `[UNACKED]` notice; an unknown mode is `400`. The flag is stored with the message in all three mailbox stores. Evidence: `fire_and_forget_is_delivered_once_and_its_sender_is_not_told` in `crates/synapsed/tests/delivery_backoff.rs`. Spec: `docs/MESSAGING_SEMANTICS_DESIGN.md` section 3.

Also: `delivery.mode = room_broadcast` (every room copy fire and forget; refused for a direct recipient), and an opt-in queue TTL (`Daemon::with_queue_ttl`) after which an unread message is set aside and its sender told `[EXPIRED]`. The MCP `send` tool takes `delivery`.

Also: `delivery.mode = room_any | room_all` on a room post (messaging step 2c): the sender gets one `[ROOM-OUTCOME]` mail per post (acked, complete, failed, incomplete or timeout) with who acked, declined, was unreachable or is pending; an any-of never recalls the other copies. In-memory: a daemon restart forgets pending posts.

**`launch.senders_mode` (`list`, the default, or `any`): with `any` every authenticated sender's pending mail may raise a launch signal and no allow list is kept (CireSnave 2026-11-21)**

`SYNAPSE_LAUNCH_SENDERS_MODE` or `launch.senders_mode` in `synapsed.toml`; the daemon re-reads it every 5 s with `launch.senders`. `list` is unchanged and fail-closed (an empty list allows nobody). `ancestors` is refused with a message until the account hierarchy exists (`docs/HIERARCHY-DESIGN.md` section 5). The rate cap and launch record are unchanged. Evidence: `any_mode_signals_for_an_unlisted_sender_and_list_mode_does_not` (`crates/synapsed/tests/launch.rs`) and `launch_senders_mode_defaults_to_list_and_takes_any_but_not_ancestors_yet` (`tests/settings.rs`).

Docs: `docs/HIERARCHY-DESIGN.md` (design note only, board 477; no code), `docs/PATENT_READING_DELIVERY_FEATURES.md`.
