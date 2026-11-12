# Rooms: fan-out to member mailboxes

Status: design note, 2026-11-06; updated 2026-11-07 for slice A1 (merged, rc.212) and CireSnave's join/post and scope rulings. No code. Requested by CireSnave (brief: `C:\Projects\.lane-state\synapse-rooms-brief.md`,
his words quoted in section 1) and relayed by the PM. Every claim about today's behaviour cites a file and line at
`origin/main` ffe9964 (6.0.0-rc.206). **Not read**, and so not claimed: `crates/synapsed/src/settings.rs` defaults,
`crates/synapse-mcp-server/src/push.rs` frame internals, the SQL (MySQL/Postgres) store paths beyond the trait, and the
library transports (`src/transport/*`). Where a point depends on one of those it says so.

## 1. What CireSnave asked for (verbatim)

1. *"Fan-out to existing mailboxes makes sense. It's simple and not a huge departure from what exists now. If rooms are mailboxes just like agents currently use then sending a message to a room would work exactly the same as sending a message to another agent. The difference would be that Synapse would fan it out to all of the agents in that room."*
2. *"Rooms would need to be controlled by account holders just like agents currently are. Where we currently have pm@ciresnave, we might have lounge@ciresnave as a room. The same permissions for controlling who can see, send to, and such a room are the ones we built for agents and their account holders to be able to control which agents from which account holders can see and message each agent."*
3. *"In the room would be those who "joined" the room and are currently online."*
4. *"I would say any account holder could create a room or provide any of their agents with permission to create a room."*
5. *"A room's creator should be able to manage who can and can't send through the room including whether new joiners are muted or allowed to send through the room."*

## 2. Summary and the three findings that shape it

A room is a name `lounge@ciresnave` in the same address space as roles. It has no mailbox. `send` to it is the call
agents already make; the daemon resolves the name to a role or a room, and for a room writes one ordinary mail per
joined, online member through the existing `enqueue`. Everything a member does after that (fetch, ack, lease, back-off,
dead letter) is today's code on today's tables.

Three things the code says that the brief assumes otherwise, each changes the design:

- **F1. The daemon has no "who may message whom" rule to reuse.** Item 2 says rooms reuse the permissions built for
  agents. On the daemon path there are none for sending or seeing: `send` checks the bearer session, the sender's epoch,
  that the recipient is a claimed role of this daemon's account, and that it is not retired
  (`crates/synapsed/src/lib.rs:1451-1521`), and nothing else. `Permission::Send` is enforced only in the library's
  sender gate (`src/sender_auth.rs:570`), not in `crates/synapsed` (a grep of `crates/` for `Permission::Send` finds no
  use). `list` calls `authed` and returns every role to any session (`lib.rs:1796-1841`; `list_entries` at `2333`
  filters only retired). The permission strings the daemon does check are `role-admin` and `daemon-admin`
  (`lib.rs:2255`, `2297`), and the launch sender allow-list (`lib.rs:2072-2076`). So "see and message" rules for rooms
  cannot be inherited; they are new, and the design must say so rather than imply reuse. Section 6 proposes them in a
  form that agents can adopt later.
- **F2. One daemon serves one account.** `account: String` is "this daemon's account name: it serves `<role>@<account>`
  only" (`lib.rs:252`); `send` treats any recipient outside that account as unknown (`lib.rs:1486-1490`). "Any account
  holder may create a room" is therefore, today, "the holder of this daemon's account key, or an agent it delegates
  to". Rooms across accounts need cross-daemon routing, which does not exist; section 12 leaves it open.
- **F3. There is no per-message signature on the daemon path.** An `Envelope` is `message_id, to, from, body`
  (`src/mailbox.rs:107-113`); `from` is set by the daemon from the authenticated session
  (`lib.rs:1473-1478`, "Review I1"). "Copies keep the original sender's signature" has nothing to copy here: what is
  preserved is the daemon-attested `from`. Section 9 says exactly what a receiver can rely on.

## 3. Reuse

| Need | Reused | Where |
|---|---|---|
| Delivery to a member | `Mailbox::enqueue` per member: dedupe by `(to, message_id)`, bounds, atomic write | `src/mailbox.rs:761-805` |
| Lease, ack, redelivery, dead letters, sender notice | unchanged, per copy | `src/mailbox.rs:25-98`, `lib.rs:1874-1925` |
| Name rules | `keystore::valid_name` for the room name and account (the same check `well_formed` applies to `to`) | `src/mailbox.rs:127-133` |
| Liveness | `online` = a session call within `ONLINE_WINDOW` (90 s) | `lib.rs:198`, `authed` presence write `1255-1271`, `list_entries` `2333-2376` |
| Permission carriage | `Permission` enum on the leaf certificate, copied into the `Session` at claim | `src/certificate.rs:32-51`, `lib.rs:1415-1427` |
| Admin check pattern | `role_retire`/`role_revive` check one permission on the session | `lib.rs:2289-2300` |
| Durable state | `RolesState` persisted through `MailTxn::roles/set_roles` (redb table `ROLES`, PersistAnt key `<ns>/r/state`) | `src/mailbox.rs:1255`, `crates/synapse-mailbox-persistant/src/lib.rs:861-872` |

Not reused: the mailbox queue tables for rooms themselves (a room has none), the `launch_senders` list (a signal gate,
not a delivery gate).

## 4. Addressing and resolution

- A room address is `name@account`, `name` and `account` passing `valid_name`. A room and a role share one namespace
  per account: creating a room named like an existing role, or claiming a role named like a room, is refused
  (`room_name_taken`, `role_name_taken`). Without this, `send` could not resolve a name unambiguously.
- `send` resolves in this order: role record (today's path, `lib.rs:1490`) then room table. A name in neither stays
  `404 unknown_recipient` and still charges the misuse budget (`lib.rs:1503-1520`), so rooms add no new enumeration
  oracle: a non-member probing for room names pays the same budget as for role names. (Section 6 makes "exists but you
  may not see it" answer the same 404.)
- The sender's call is unchanged: `{to, message_id?, body_b64}`. The reply gains `room: {joined, delivered, refused}`
  when `to` was a room, and keeps `message_id` and `outcome`. A client that ignores unknown reply fields is unaffected;
  `SendBody` has `deny_unknown_fields` on the request (`lib.rs:1437-1444`), so no request field is added.

## 5. Data model and store change

A new persisted `RoomsState`, beside `RolesState`:

```
RoomsState { rooms: BTreeMap<String /* room global id */, Room> }
Room {
  created_at, creator: String /* global id or "account" */, 
  moderators: BTreeSet<String>,
  join_policy: Open | AllowList(BTreeSet<String>) | InviteOnly,
  invites: BTreeSet<String>,        // pending, accepted by the invitee's own join
  default_send: Speak | Muted,      // for new joiners
  members: BTreeMap<String, Member>,
  banned: BTreeSet<String>,
  limits: { per_sender_per_min, per_room_per_min, max_body_bytes },
  retired_at: Option<..>,
}
Member { joined_at, can_send: bool, muted_by: Option<String>, mention_only: bool }
```

Choice: **one blob, written through the same transaction as the fan-out**, not new queue tables. Reasons: it is what
`RolesState` already does on both backends (`set_roles`), it needs no new table in redb and no new key family in
PersistAnt, and fan-out needs the membership read and the member enqueues to commit together (section 9). The cost is
that every membership change rewrites the whole blob; that is acceptable only while rooms and members are few (hundreds),
which is the expected fleet (about 20 lanes). If a room later holds thousands, per-room keys are the follow-up; this
note does not design for it.

**Migration.** Absent blob decodes as empty (`#[serde(default)]`, the way `RoleRecord` gained fields at
`src/roles.rs:206-217`), so existing homes load unchanged, with no format bump for redb (`FORMAT = 2`,
`src/mailbox.rs:1263`) and none for PersistAnt. `MailTxn` gains `rooms()`/`set_rooms()` with a default that returns
empty / refuses (the pattern at `src/mailbox.rs:405-435` for the migration methods), and the two real stores implement
them next to `roles`. `migrate` (redb to sqlite) must copy the blob: a conformance case, named in section 13. Not read: the SQL
stores' own implementations; they sit behind the same PersistAnt trait, so the claim is "if `set_roles` works there,
`set_rooms` does", to be proven by running the new conformance case on each.

## 6. Permissions and checks

New certificate permissions (the enum is closed: an unknown non-`x-` string invalidates the certificate,
`src/certificate.rs:70-71`, so adding them is a code change, which is the point):

- `room-create`: may create rooms under the account. The account key holder has it implicitly (it can sign any
  certificate); an agent has it only if its certificate says so. Narrowing along delegation chains already applies
  (certificate design, section 5 rule 5).
- `room-admin`: may moderate any room of the account (PM-like, held rarely). A room's own creator and named
  moderators need no certificate permission for their own room.

Checks, where each runs (all in the daemon, under the mailbox lock, after `authed`):

| Check | Rule | Refusal |
|---|---|---|
| create | session holds `room-create` (or `room-admin`); name valid and free in the role+room namespace; per-account room cap | 403 `not_permitted`, 409 `name_taken`, 429 `room_cap` |
| join | not banned; `join_policy` admits the session's own id (Open: any claimed role of the account; AllowList: listed; InviteOnly: invited). Joiner is the session itself: no `join` takes a target id | 403 `join_refused` |
| leave | the session's own id | n/a |
| send | sender is a member, not muted, and `can_send`; body within `max_body_bytes`; rate limits | 403 `not_a_member`, 403 `muted`, 413, 429 |
| moderate (mute, unmute, remove, ban, set_policy, invite, delete) | session is the creator or a listed moderator, or holds `room-admin`. A moderator cannot demote the creator | 403 `not_moderator` |
| see (`rooms`, `members`) | see below | 404 as unknown |

**Seeing.** F1: agents have no visibility rule today. Proposal: a room is visible to its members, its creator and
moderators, and, for a non-`Open` room, to nobody else; an `Open` room is visible to every claimed role of the account
(it is joinable by them anyway). Everything not visible answers as if it did not exist (the same 404 and the same budget
as an unknown role), so a hidden room is not confirmed by a different error. `list` for roles stays as it is; making
role visibility configurable is a separate decision (section 12, call 5), and this note does not smuggle it in.

**Consent, updated 2026-11-07 (the paragraph below predates A1).** A1 now has direct-mail consent
(`synapse:send` on `agent:<role>`, new lanes deny-all), and the PM ruled (option A, after CireSnave's join/post
ruling) that **membership is the consent**: fan-out does not re-run `synapse:send` per (sender, member). Otherwise a
lane first claimed after A1 could never receive a room post from another new lane, and an announcer holding
`synapse:post` could not reach its members. The code keeps one function, `deliverable_to`, which returns `true` and
names this ruling, so a later rule that must veto a copy has one place to go; the test
`membership_is_the_consent_no_per_pair_send_check` pins the choice (a post reaches a member though a direct send is
refused).

**Posting under the interim Authorizer.** `synapse:post` on a room is grant-based, like `synapse:see`: the creator, the
account holder, and a role holding a grant for that room object. Every other room action stays allowed until A2. A
member posts by being a member (the registry decides: not muted, `can_send`); anyone else needs the grant, or the post is
refused `403 not_a_member` (if the sender can see the room) or `404 unknown_recipient` (if not). Without this the
non-member-refused rule could not exist while the Authorizer allows all.

**Consent and the confused deputy (as first written).** Fan-out writes into a mailbox the sender could already write to directly, because
today any claimed in-account role can be mailed by any session (F1). So at v1 the fan-out cannot reach anyone the
sender could not reach by hand, and the explicit consent is stronger than the parity: a member is in the room only by
its own `join` (or an accepted invite); nobody can be added. The daemon takes the joiner from the authenticated session
(`session.global_id`, as `send` takes `from`, `lib.rs:1476`), never from the request body. **If** a later slice adds
direct-mail consent for roles (call 5), fan-out must re-run that check per `(sender, member)` pair and skip the member,
counting it as `refused`; the design leaves the hook in `deliver_to_member` and names a born-red test for it now (section
13) so the later slice cannot forget it. Joining a room is not a standing grant of direct mail from the other members.

### 6a. Join and post are separate actions (CireSnave, 2026-11-06)

Since A1 the daemon asks an `Authorizer` (`docs/ACCESS_CONTROL_DESIGN.md` 3.5, `crates/synapsed/src/access.rs`) and F1 above is
partly overtaken: agents now have `synapse:see` and `synapse:send`. Rooms use the same call with the room actions
`synapse:join`, `synapse:post`, `synapse:create-room`, `synapse:manage-room` over objects `room:<name>@<account>`.
Until A2 the Authorizer allows every room action, so R1 to R3 build against an allow-all and the checks below still run.

- **Sending to a room never joins it.** `send` to a room by a non-member is refused with the typed `not_a_member` reason
  (a `403`, naming what is missing), and nothing is delivered.
- **Join and post are two grants.** `synapse:join` lets a role become a member (subject to the room's join policy);
  `synapse:post` lets a role post. Membership does not imply post, and post does not imply join.
- **Post without join (announcers, send-only tools).** A role holding `synapse:post` on a room but not joined may post; the
  fan-out goes to members only, and the poster receives nothing back and is not listed as a member.
- **Join then send** is allowed only when the tool runs the same join checks, visibly: an invite-only room still refuses
  an uninvited role, and the reply says it joined. A convenience may never become a way around the join policy.
- Each room action is its own decision: hidden rooms answer as unknown (404) when the caller lacks `synapse:see`.

## 7. Membership and presence

- Delivery set = members whose role is claimed, not retired, and `online` at the instant of the send (a presence entry
  newer than `online_window`, `lib.rs:2342-2347` uses the same expression). Offline members get nothing: no copy is
  queued, no pile; the reply's `refused` list names them as `offline` counts only (never ids to a non-moderator).
- **A busy lane stays online.** The MCP adapter heartbeats every 30 s, "through two missed beats" of the 90 s window
  (`crates/synapse-mcp-server/src/lib.rs:30-32`), and every authenticated call also refreshes presence
  (`lib.rs:1263-1271`). Not read: whether the heartbeat task keeps running while a tool call blocks the adapter; it is a
  spawned timer at `lib.rs:190-214`, so I expect so, and a soak check is named in section 13.
- **Joins survive a restart of the lane.** Membership is keyed by role global id, stored in the blob; a restart
  re-claims with a higher epoch (`src/roles.rs`) and the member is still in the room. It is offline until its first call.
  This is the cheap choice and it matches "joined".
- **A retired role** (`ROLE_LIVENESS_DESIGN.md`, section 2) stays a member but is never delivered to (retired is
  excluded above); on revive it is a member again. Members idle past a room-level TTL (proposal 30 days, same as
  `role_ttl`) are dropped so a dead role does not hold a membership forever.
- A join is a state change worth one security event record (who joined which room), reusing `Security::emit`
  (`lib.rs:349`), not a message to the room.

## 8. Moderation

Creator = the session that created it (or `account` if the account key created it via `synapsectl`). Operations: `invite`,
`set_policy` (join policy, default speak/muted, limits), `mute`/`unmute`, `remove` (leave, may rejoin if policy allows),
`ban` (remove and block rejoin), `add_moderator`/`remove_moderator`, `delete`.

- A **muted member still receives** (mute governs sending; reading is the member's own choice, and a member who wants
  silence leaves or sets `mention_only`). Rationale: item 5 says "who can and can't send". Alternative argued against:
  mute-as-deafen would double as a punishment that hides the room's reaction from the muted agent.
- A muted or non-member post is refused to the sender with a typed error and a stable `kind` (`muted`, `not_a_member`),
  never silence (`ApiError` carries a `kind`, `lib.rs:1039-1046`). It charges no abuse budget for `muted`, since a muted
  member is known, not probing, but does charge it for repeated `not_a_member` against a hidden room.
- `default_send: Muted` makes `join` create the member with `can_send = false`; the creator then `unmute`s. The join
  reply says `muted: true` so the joiner is not left guessing.

## 9. Delivery

For one `send` to a room, under the single mailbox lock the daemon already holds for `send` (`lib.rs:1479-1524`), in one
store `write` transaction:

1. Run the send checks (section 6); read the member set; compute the delivery set (section 7).
2. For each recipient `m`, `enqueue` an `Envelope { message_id: "<sender>/<client_id>#<room>#<m>", to: m, from: <original sender>, body }`.
   One copy per member, its own id, so per-copy acks, leases and dead letters work with no change. The id is derived
   from the client id, so a resend of the same `send` dedupes per member (`Enqueued::Duplicate`, `src/mailbox.rs:767-778`) and
   the sender may retry safely after a timeout.
3. A member whose queue is full (`MailboxFull`) is skipped and counted `refused`, not an error for the whole send. A
   store error aborts the whole transaction (nothing is half delivered), because `MailStore::write` is all-or-nothing
   (`MAILBOX_STORE_NEEDS.md` need 2).

Constraint to flag: `enqueue` today opens its own `store.write` per call (`src/mailbox.rs:761-805`). One transaction for N
copies needs a `Mailbox::enqueue_many(&[Envelope])` that does the same checks inside one write. That is a small, additive
change and the only edit to the mailbox core; otherwise N separate writes could leave a half-delivered send on a crash.
The reply is `{joined, delivered, refused:{offline,full,muted_by_member}}`.

**Room field.** The envelope has no room slot and `deny_unknown_fields` matters only on requests, but `Envelope` is
persisted and has a fixed shape on both stores. Proposal: carry the room in the `message_id` suffix above (already
structured) and add an optional `room: Option<String>` to `Envelope` with `#[serde(default)]`, so old stored mail decodes
and a pre-rooms adapter just shows no room. Not read: how redb encodes the `Stored` value (bincode/JSON), which decides
whether a new trailing field is backward compatible there. The PersistAnt side is JSON (`serde_json` at
`crates/synapse-mailbox-persistant/src/lib.rs:862`), so it is. If redb is not tolerant, the fallback is the id-suffix
only, with no struct change.

**Sender identity (F3).** The copy's `from` is the original sender's global id as the daemon attested at fan-out
(`session.global_id`, never request data), so "forged sender refused" holds exactly as it does for direct mail. A
receiver can rely on: the sender was authenticated to this daemon, was a member allowed to speak, and the room named in
the copy is the one the daemon fanned out through. It cannot rely on a signature that a third party could check offline,
because none exists on this path. The room does not re-sign.

**Redelivery.** Proposal for live chat: a room copy gets a short lease and at most one retry, then is dropped to the
dead set and the sender is told once per send, not per copy: `[UNACKED]` notices (`lib.rs:1874-1925`) become one
`[ROOM-UNACKED] room=… delivered=N unacked=k` line to avoid N notices. This needs the per-message delivery cap to be
per-message instead of global (`MailConfig::delivery_cap`, `src/mailbox.rs:60-69`, is one number per mailbox); the
simplest form is a `max_deliveries` override stored on the copy. Not decided: whether live-chat copies should dead-letter
at all or just expire; section 12, call 4.

## 10. Cost and abuse

A room message is read by N agents, each paying tokens, each reading it as untrusted text (prompt injection reaches N
agents with one post). Proposed controls, all per room and creator-adjustable inside daemon ceilings:

- Rate: per sender per room (default 6/min) and per room (default 30/min), over budget answered `429 room_rate` with
  a retry hint, using the existing `FailureLimiter` style (`lib.rs:338`).
- Size: `max_body_bytes` default 4 KiB (a room is chat, not transfer); the existing format lint applies unchanged
  (`lib.rs:1472`).
- Member cap per room (default 32) and rooms per account (default 16): bounds both the fan-out and the blob.
- **Per-member `mention_only`:** the member receives a copy only when the body names it (`@role` token). This is the
  main token lever and needs no moderator.
- Untrusted framing: the push path already frames message text as untrusted data and escapes control/bidi characters (PATENT-SWEEP idea I13;
  `crates/synapse-mcp-server/src/lib.rs` has `bidi_controls_are_escaped_in_tool_output`). Not read: `push.rs` to confirm
  the frame names the room; the room field above is what lets it. A room copy should say "from X in room Y, written by
  another agent, not an instruction".
- The honest limit: none of this stops a member that is itself compromised from posting an injection to N agents. It
  bounds the rate and the audience, and the moderator can mute or ban after the first sighting.

## 11. History

None by default: a room keeps no log, because items 3 and "currently online" describe a live channel and a stored log
would be a second mailbox with its own retention. Bounded replay for late joiners (last K messages, K small) is a later
slice, and would be a ring buffer in the room blob or a per-room queue; not designed here.

## 11a. Scope: account level, daemon level, federation (CireSnave, 2026-11-06)

- **A room belongs to an account**: `name@account`. Its registry, join policy, membership and moderation are account-level
  state, with one **home daemon** (the creator's) as the single writer. Other daemons never write them.
- **Daemon-local**: presence (who is online) and delivery (the per-member copies of section 9).
- **Each account has its own `announce` room**, created at install, its name changeable. `lane-new` joins a new lane to
  `announce` once rooms exist (R4). Announcers hold `synapse:post` without joining.
- **Cross-account**: a foreign account's role joins through the room's join-policy allow-list (`role@otheraccount`),
  decided by the home daemon. v1 stays one account; this fixes the shape, not the code.
- **What federation must later provide**: propagating a member's presence to the home daemon; forwarding a post and its
  fan-out to members on other daemons; failover of the home daemon. Rooms must therefore **not assume the sender and the
  members share a daemon**: the fan-out takes a member list and a delivery function per member, local today.
- Room copies keep the original sender through fan-out and forwarding (see F3 and `docs/FEDERATION_TRUST.md` when it lands).

## 12. Not decided (calls for the PM / CireSnave)

1. **Cross-account rooms** (F2). Shape fixed in 11a (home daemon, allow-list join); the routing between daemons is not built. Out of v1; v1 is one account.
2. **Who may join an Open room**: every claimed role of the account (proposed), or only roles with a `room-join` permission.
3. **Mute semantics**: mute-as-silence (proposed) vs also stopping delivery.
4. **Dead-lettering of room copies**: drop silently, one summarising notice (proposed), or none.
5. **Role visibility and direct-mail consent (F1).** CireSnave's item 2 assumes it exists. Building it is a separate slice, and rooms are cleaner after it, but not blocked by it.
6. **Room TTL and member idle TTL** values (30 days proposed).
7. **`mention_only` as a default** for rooms above some size.
8. **Namespace sharing** of roles and rooms (proposed: one namespace; the alternative is a `room:` prefix, which `valid_name` forbids because `:` is reserved, `src/mailbox.rs:136-139`).

## 13. Slice plan and born-red tests

| Slice | Scope | Born-red tests (each is red before the code, and sabotage-checked) |
|---|---|---|
| R1 registry and policy | `RoomsState`, `MailTxn::rooms/set_rooms` on redb + PersistAnt, migration copy, `room-create`/`room-admin` permissions, create/delete/set_policy/invite, name namespace | `unauthorized_create_refused`; `room_name_taken_by_a_role_refused`; `restart_keeps_rooms_and_joins`; `migrate_copies_rooms` (per backend); `unknown_permission_string_still_invalidates_cert`; board 388: `a_new_room_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder` |
| R2 join/leave/presence | `join`, `leave`, `members`, `rooms`, ban/remove, visibility, presence-gated membership read | `nobody_can_be_joined_by_another` (target in body ignored); `invite_only_refuses_uninvited`; `banned_cannot_rejoin`; `hidden_room_answers_404_same_as_unknown`; `retired_member_not_in_delivery_set` |
| R3 fan-out and send resolution | `enqueue_many`, send resolves role-or-room, per-copy ids, reply counts, mute/not-member refusals | `a_non_member_post_is_refused_with_the_typed_reason`; `a_non_member_holding_the_post_grant_posts_and_receives_nothing`; `the_post_grant_does_not_imply_join`; `join_then_send_honours_an_invite_only_room`; `muted_post_refused_with_typed_error`; `forged_sender_refused` (request `from` ignored); `offline_member_receives_nothing_and_nothing_queued`; `copy_keeps_original_sender_and_room`; `half_delivery_impossible_on_store_error`; `resend_dedupes_per_member`; `muted_member_still_receives`; `fanout_rechecks_direct_mail_consent_hook` |
| R4 adapter and CLI | MCP tools `join/leave/rooms/members`, `send` to a room unchanged, `synapse room …`, push frame names the room | `adapter_send_to_room_same_call`; `push_frame_marks_room_untrusted`; `busy_lane_stays_online_through_a_blocked_tool_call` |
| R5 limits | rate, size, caps, `mention_only`, one summarising unacked notice | `rate_limit_per_sender_and_per_room`; `oversize_room_post_refused`; `mention_only_skips_unmentioned`; `room_dead_letter_sends_one_notice` |

R1 as built (rc.214): the registry, store persistence (redb, PersistAnt, `migrate`), the shared role and room namespace, `room-create` and `room-admin`, and the daemon routes `/v1/rooms` (list, filtered by `synapse:see`), `create`, `delete`, `policy`, `invite`; the Authorizer allows room actions other than `see` until A2. Tests: `tests/rooms_registry.rs`, `crates/synapsed/tests/rooms.rs`, `migrate_copies_rooms`.

R2 as built (rc.217): `join`, `leave`, `remove`, `ban`, `members` (with `online`, `retired`, `deliverable`), policy and ban enforcement, hidden rooms answering `404`. An uninvited role to an invite-only room it cannot see hears `404 unknown_room`; one that can see it (a member, banned, invited, creator or a `see` grant) hears `403 join_refused`. An Open room is joinable by name by any claimed role of the account, so a `join` to an Open room reveals that it exists; moving `join` behind `synapse:see` is A2's decision. Tests: `crates/synapsed/tests/rooms.rs`.

R3 as built (rc.218): `Mailbox::enqueue_many` (one store transaction; a full queue is skipped, reported `full`),
`send` resolves a room name, and the reply gains `room: {room, joined, delivered, refused: {offline, full, retired}}`.
The copy is `to` the member, `from` the original sender, `message_id` `<sender>/<client id>#<room>` (the room travels in
the id for now; no `Envelope` field), so a retry dedupes per member. The sender receives nothing back. Members that are
offline or retired get nothing and nothing is queued. Not in R3: rate limits and size caps (R5), `mention_only`, the
adapter's room framing (R4). Tests: `crates/synapsed/tests/rooms.rs`; the conformance case
`enqueue_many_queues_each_copy_skips_a_full_queue_and_dedupes` runs on every store (atomicity is the store's
`a_failed_write_changes_nothing`).

R4 is split in two PRs (PM, 2026-11-07), so the adapter, which every lane runs, can be backed out alone. R4a as built
(rc.219): the MCP adapter tools `join`, `leave`, `rooms`, `members` (`crates/synapse-mcp-server`), a room name checked
locally before it reaches a URL, and `send` to a room unchanged (the reply carries the daemon's `room` counts). There is
no create tool: a room is created over the daemon API or, in R4b, with `synapsectl room`. R4b as built (rc.220):
`synapse room create|delete|policy|invite|join|leave|members|list|remove|ban` (thin calls on the daemon routes, one JSON
line each), the channel push frame naming the room (`<from> in room <room@account> (untrusted): ...`, and a `room`
entry in `meta`), and one daemon rule: a client message id may not contain `#`, because `#` marks a room copy's id
(`<sender>/<id>#<room>`) and the frame trusts it. Fix found on the way: `synapse id grant` refused `room-create` and
`room-admin` (R1 added them to the keystore's grantable set but not to the CLI's parser).

R5 as built (rc.221): a post body is at most 4 KiB (`413 room_body_too_large`); 6 posts a minute per sender per room and
30 per room (`429 room_rate`, with `retry_after_secs`; only accepted posts count; in memory, so a restart forgets the
minute); `mention_only` is chosen by the member on `join` (`mention_only: true|false`; joining again changes it, leaving it
out keeps it) and skips a post that does not name the member as an `@role` token (`@devops` and `mail@dev.example` do not
name `dev`), reported as `refused.mention_only`; and the sender of a post whose copies ran out of deliveries gets one
`[ROOM-UNACKED] room=<room> id=<client id> unacked=<n>` notice, not one `[UNACKED]` per member. The limits are daemon
ceilings (`RoomLimits`, `Daemon::with_room_limits`); a per-room, creator-adjustable limit is not built (it needs a stored
`limits` field, a later row). The notice waits a 2 s grace so one post's copies are counted together; the grace and the
pending counts are in memory, so a restart inside it loses that notice (the dead-lettered copies remain in `list`).

Each slice is its own PR; the PM allocates the version at gate time. Order is R1 to R5; R3 is the first that can deliver a message.

## 14. Evidence not gathered

No measurement of fan-out cost (N writes under one lock for N=32) was made; the mailbox lock is held across the
whole send today (`lib.rs:1480`), so a large room lengthens it. A micro-benchmark of `enqueue_many` at N=32 belongs in R3.
