<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Messaging semantics: ack, nack, receipt, delivery modes (build step 2)

Source: the messaging build brief (CireSnave, 2026-11-19, approved to build). This page is Synapse's side of
step 2. Each slice below says what is built at which ref; a slice marked *planned* is not built.

## 1. Three facts, kept apart

| Fact | Who states it | Effect |
|---|---|---|
| **Receipt**: the daemon put the message in the receiver's queue | the daemon, automatically, in the `send` reply (`queued` / `duplicate`) | weaker than ack; never stops reminders or failover |
| **Ack**: "seen and being dealt with" (CireSnave: *"Acknowledgement should always mean 'seen and being dealt with'."*) | the receiver, `POST /v1/ack` | the message leaves the queue; reminders and failover stop |
| **Nack**: "cannot handle this, pass it on" (CireSnave: *"every place we can ack we should also be able to nack"*) | the receiver, `POST /v1/nack` | the message leaves the queue for good; the sender is told at once, so failover can start immediately |

Receipt is the existing `send` reply; no new mail is sent for it. A mode that wants a receipt as mail asks for
it explicitly (slice 2b).

## 2. Slice 2a: nack (BUILT)

`POST /v1/nack {message_id, reason?}`; MCP tool `nack {message_id, reason?}`.

- The caller must hold the message's lease (it fetched it): no lease is `403 not_your_lease`, an unknown id is
  `404 not_found`; both count against the role's misuse budget exactly like a bad ack.
- Declined: the message is removed from the queue and recorded as handled, so it is never redelivered and a resend
  of the same id is a duplicate. Reply `{"outcome": "declined"}`. A repeat (or a nack after an ack) answers
  `{"outcome": "already_handled"}` and changes nothing: nobody is told twice.
- The sender gets one mail from `synapsed@<account>`: `[DECLINED] to=<role> id=<message_id> reason=<word>`. `reason`
  is the receiver's text folded to one header word (letters, digits, `- . :`, others become `_`, at most 60 bytes;
  `-` when none was given); the raw text is capped at 200 bytes. The notice is delivered once, like `[UNACKED]`, and
  there is never a notice about a notice.
- A room copy's decline is not reported per copy: the per-post outcome is slice 2c.
- Per-role counter `nacked` in `/v1/stats`.
- Tests: `crates/synapsed/tests/nack.rs` (red before the route existed: the first run answered `null` for both),
  `nack_removes_for_good_reports_the_sender_and_is_idempotent` in the mailbox conformance suite (runs on the memory,
  redb and persistant stores), `nack_declines_a_message_and_the_sender_is_told` in the MCP adapter tests.

## 3. Slice 2b: sender-settable modes (`fire_and_forget` BUILT; the rest PLANNED)

Built: `POST /v1/send {..., "delivery": {"mode": "fire_and_forget"}}`. The envelope carries `fire_and_forget`
(persisted in the memory, redb and persistant stores); it is leased once, never redelivered, set aside quietly and
counted in `dead_lettered`, and its sender gets no `[UNACKED]`. `reliable` or no `delivery` is today's behaviour;
any other mode is `400 malformed`. Test: `fire_and_forget_is_delivered_once_and_its_sender_is_not_told` in
`crates/synapsed/tests/delivery_backoff.rs`. The MCP `send` tool takes `delivery` too (test `send_takes_a_delivery_mode_and_the_daemon_refuses_an_unknown_one`). Not yet: room modes, TTL.


`send` gains an optional `delivery` object; absent means today's behaviour (reliable direct). The sender's request is
capped by each receiver's policy (a later step); every refusal is returned to the sender, never silent.

| `delivery.mode` | Behaviour |
|---|---|
| `fire_and_forget` | enqueue once with no redelivery and no `[UNACKED]` notice; it gets there or it does not |
| `reliable` (default) | the current at-least-once mailbox: back-off redelivery, dead set, `[UNACKED]` |
| `room_broadcast` | to everyone in the room at send time, no ack required |
| `room_any` | needs at least one ack |
| `room_all` | needs an ack from every member in the roll call |

Bounded buffers: the per-receiver queue already has `max_messages`/`max_bytes`; a send over the bound is refused
(`mailbox_full`) and the sender told. A default `ttl_secs` is added so an unread message expires instead of sitting
forever; expiry is reported to the sender like a dead letter.

## 4. Slice 2c: outcome to the sender (PLANNED)

For rooms the sender gets one outcome mail per post: which members acked, which declined, which did not, and what
happened at the timeout. The roll-call member list is fixed at send time, so a dead lane or a leaver cannot wedge an
`all-of`. The sender decides what a failed delivery does (retry, fail over, give up). Failover chains, urgency and
receiver-policy caps are step 3.
