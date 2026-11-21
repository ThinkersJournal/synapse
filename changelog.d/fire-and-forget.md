Added: `fire_and_forget` delivery mode on `POST /v1/send` (messaging brief step 2, slice b, first part)

`send` takes an optional `delivery: {"mode": "reliable"|"fire_and_forget"}`. A fire-and-forget message is leased once, never redelivered, and its sender gets no `[UNACKED]` notice; an unknown mode is `400`. The flag is stored with the message in all three mailbox stores. Evidence: `fire_and_forget_is_delivered_once_and_its_sender_is_not_told` in `crates/synapsed/tests/delivery_backoff.rs`. Spec: `docs/MESSAGING_SEMANTICS_DESIGN.md` section 3.

Also: `delivery.mode = room_broadcast` (every room copy fire and forget; refused for a direct recipient), and an opt-in queue TTL (`Daemon::with_queue_ttl`) after which an unread message is set aside and its sender told `[EXPIRED]`. The MCP `send` tool takes `delivery`.
