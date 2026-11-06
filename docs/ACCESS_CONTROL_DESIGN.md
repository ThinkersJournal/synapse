# Access control: who may see and message whom (design note, no code)

Status: proposal, read at `origin/main` f8d155d (rc.208). Task from the PM, 2026-11-06. Nothing here is built.
Claims carry a file:line or commit. "Not found" claims say what was searched.

## 1. The requirement: where it was written, and why the daemon never got it

**What CireSnave said** (relayed by the PM, not found in any file I could search): account-holder control over who
can see and message their agents was foundational; certificates "were always a stop gap designed to work until we
could set up an authorization server"; "what we already have shouldn't limit what we should build." I searched for
"stop gap" and "authorization server" in synapse, OverMind, agentlife, FAM, claude-peers, the PM docs and
`.lane-state`: no hit that says this. The only "stopgap" hits are unrelated (`CUTOVER_RUNBOOK.md:50,103`).

**First written statement I can find: 2026-11-06**, CireSnave verbatim in `C:\Projects\.lane-state\synapse-rooms-brief.md:6`:
*"The same permissions for controlling who can see, send to, and such a room are the ones we built for agents and
their account holders to be able to control which agents from which account holders can see and message each agent."*
The PM's overnight write-up (`C:\Projects\OVERNIGHT-WRITEUP-2026-11-06-ROOMS-AND-AUTHORITY.md:21,50,107`) restates it.
The premise ("the ones we built") is true of the library and false of the daemon (section 2).

**What the older record says instead** (each is a design that stopped short of a see/send rule):

| date | where | what it says |
|---|---|---|
| 2026-09-17 | `docs/superpowers/specs/2026-09-17-agent-certificates-design.md:180-182` (commit 623e45a) | "The one enforced permission: a leaf lacking `send`... Every other permission is reported, never enforced: Synapse says who an agent is and what its owner granted; the consumer decides what that allows." |
| 2026-09-17 | commit 28f0f75 "enforce the send permission" | the one enforced check, in the library gate `src/sender_auth.rs:568-575` |
| 2026-09-17 | `...specs/2026-09-17-replay-suppression-design.md:275-279` | permissions are "what a consumer authorizes an action against... OverMind asked for exactly this"; what each may do "stays the receiver's local policy" |
| 2026-10-01 | `...specs/2026-10-01-m3-roles-design.md:104` | Q4 "Do claims need a permission? Recommended: no new permission. Holding the role's key plus a valid certificate is the authorization." |
| 2026-10-02 | commit 7a04da4 (M5a, first `crates/synapsed` commit); `...specs/2026-10-02-m5-synapsed-design.md:60-64` | per-request auth is a session token tied to `(role, epoch)`; no per-pair rule |
| 2026-10-08 | `C:\Projects\PORTFOLIO-ROADMAP.md:503` (board 138), CireSnave | "Trust vouching isn't needed for agent-to-agent communication within a single account holder's agents. Trust vouching is very much needed when opening up agents to the Internet." Not scheduled. Cross-account only. |
| 2026-10-15 | commit 2efac30 (rc.83, board 199/200); `ROADMAP.md:59` | the `auth-framework` dependency removed as "consumed but not used", on CireSnave's "Retire the auth-framework feature." |
| 2026-10-23 | `...specs/2026-10-23-shared-state-design.md:77` | state visibility "by party": the one place the daemon does gate by who you are |

**Answer to "when and why":** the daemon path (2026-10-02, M5) was built as a new bearer-session service while the
only send gate lived in the library's transport (`sender_auth.rs`), and nothing ported it. The governing design
principle written down at the time was "Synapse reports permissions, the consumer decides" (2026-09-17), and the
single-account trust model (board 138) made a per-pair rule look unnecessary. **I found no document or commit that
records the rule being deferred, dropped, or expected from auth-framework or an authorization server.** It was
never decided against; it was never written down before 2026-11-06. If it was said earlier in chat or a board item
I did not search, I have not seen it (board archives were searched only in part; not every worktree was searched).

## 2. What is enforced today (nothing below should be rebuilt)

| mechanism | where | what it gates | does NOT gate |
|---|---|---|---|
| `Permission::Send`, `NoSendPermission` | `src/sender_auth.rs:568-575`; enum `src/certificate.rs:32-51` | a certificate-chained sender on the library/transport path | the daemon: `grep Permission::` in `crates/synapsed/src/lib.rs` finds only `DaemonAdmin` (2243) and `RoleAdmin` (2285) |
| daemon `send` | `crates/synapsed/src/lib.rs:1446-1525` | valid session and epoch; recipient is in this account, has a role record, is not retired | who the sender is allowed to reach |
| daemon `list` | `lib.rs:1796-1830` | any valid session | what it may see: every role is returned |
| `SYNAPSE_LAUNCH_SENDERS` | `crates/synapsed/src/launch.rs:51-84`; use at `lib.rs:2048-2066` | whose pending mail may raise a launch signal; empty allows nobody | delivery. Mail from anyone is still delivered |
| `launcher_roles` | spec `2026-10-15-cutover-and-lane-launch.md:147-160` | who may call `/v1/waiting` | |
| state permissions | `state_api.rs:17-32`; `src/state.rs:541-547` | `state-write`, `state-admin`, `state-read-all`, `state-derive` read from the session's certificate | mail |
| role-admin / daemon-admin | `lib.rs:2243`, `2285` | retire, revive, admin calls | |
| `synapse-agent` allow-list | `crates/synapse-agent/src/lib.rs:167-199` | the one tool a model-driven agent has: it may send only to listed roles | anything but that tool in that process |
| sessions carry certificate grants | `lib.rs:218-226` (`Session.permissions`, "the verified leaf certificate's grants at claim time") | nothing yet for mail: the data is there | |
| unauthenticated email path | `CAPABILITY_INVENTORY.md:705-726` | `SynapseRouter` holds no trust store | out of scope here |

So: any session of the account can message any role it can name and list all roles. Enforced rules are per-feature
and cert-based; the cert grants already reach the daemon in `Session`, which is the hook for what follows.

## 3. Design

### 3.1 One policy decision point
A single function in `crates/synapsed` (new module `access.rs`), called by every route that lets one principal reach
another:

`decide(subject, action, object) -> Allow | Deny(reason)`

- **subject**: the authenticated global id `role@account` (the daemon sets it from the session, `lib.rs:1468`).
- **action**: `see`, `send` (mail to an agent), `join`, `post`, `manage` (rooms: `ROOMS_DESIGN.md` section 6).
- **object**: an agent `role@account` or a room `name@account`. Rooms and agents share one object kind, one rule
  table and one check, as CireSnave required ("the same permissions").
- **Deny is silent to the asker where seeing is denied**: `send` to a role the sender may not see returns the same
  `404 unknown_recipient` as an absent role (`lib.rs:1512`), so the rule is not an oracle for who exists.
- System senders (the daemon's own `[UNACKED]` and dead-letter notices) are exempt from `send` rules; they originate in the daemon, not a session.

### 3.2 Rules are the account holder's, stored by the daemon
A new blob like `RolesState` (the pattern `ROOMS_DESIGN.md` section 5 already uses): `AccessState { default, rules[] }`,
each rule `{ subject_pattern, action, object_pattern, effect }`, patterns `role@account`, `role@*`, `*@account`, `*`.
Evaluation: explicit deny, then explicit allow, then `default`. Edited only by the account holder or an agent the
holder delegated `access-admin` to; every edit and every denial emits a security event (as `StateDenied` does,
`state_api.rs:37-42`).

**Default (needs a ruling, section 6):** `default = allow` inside this account on upgrade, so nothing changes until a rule is added;
the account holder can flip to deny-by-default. Cross-account subjects default to deny (a daemon serves one
account today, `lib.rs:252`, so this is future-proofing, not a case that occurs now).

### 3.3 Grants come from auth-framework, not from certificates
The rules say who may; **grants** say who a holder has authorized an agent to act as or for. Both feed the same `decide`:

- A grant is a **GNAP access token** (draft-ietf-gnap-core-protocol) bound to the agent's own key. The access
  entry is typed for Synapse, e.g. `{ "type": "synapse", "actions": ["see","send"], "locations": ["pm@ciresnave", "lounge@ciresnave"] }`.
  `locations` can be a pattern; the account holder (the AS's resource owner) approves, which is the tool-enforced
  human approval the PM's write-up wants (Windows Hello consent).
- **What auth-framework offers** (local checkout 3156a62c, `src/protocols/gnap.rs`): transactions, client key binding via JWK
  (ES256, RS256, EdDSA), `introspect_token` (1032), `validate_token_key_binding` (1080), `revoke_token` (968),
  `rotate_token` (978). Synapse's role keys are Ed25519, which the key binding supports.
- **Daemon flow:** at `claim`, the agent presents its token and proof of the key. The daemon verifies key binding and
  introspects (embedded library call, or the AS over loopback), copies the grants into `Session` beside
  `permissions` (`lib.rs:218-226`), and `decide` consults them. Re-checked on a short TTL so revocation is bounded
  (the bound is a number to choose; section 6). A failed or unreachable AS keeps rules in force and **denies grant-derived
  allows** (fail closed); it never widens access.
- **Limits stated plainly:** (1) the `auth-framework` dependency was removed on CireSnave's ruling (rc.83,
  `ROADMAP.md:59`); taking it back is a new decision, and its transitive dependencies must pass the no-new-non-Rust
  rule (aws-lc-rs is the recorded exception). (2) A GNAP proof-verification defect was fixed recently according to
  the PM write-up (section 4 there, "rc209"); I did not verify that, and the key-binding path is the part Synapse would lean on. (3) I have not read
  whether `GnapService` persists transactions or tokens across restarts, or whether the AS can run as a long-lived local service on this box.
  Those are the first things slice A3 must measure.

### 3.4 Certificates stay as a bridge, with a sunset
- Effective authority = rules AND (grant OR bridge). The bridge maps what certificates already say:
  `Permission::Send` allows `send` to any visible agent (today's behaviour); a missing `Send` denies, matching the library gate.
  The `state-*` permissions keep their meaning (they are a separate feature).
- Switch `grants_required` (per account, default off). When on, certificate `Send` no longer authorizes mail; only grants do.
  Certificates continue to prove identity (the claim path) and carry `role-admin` / `daemon-admin` until those are grants too.
- Sunset: the bridge is removed when the account holder turns `grants_required` on and the cutover soak shows no
  bridge-only allow for a full week (counted by a `decide` metric `allowed_by=cert`).

### 3.5 Where it is enforced
| route | action | note |
|---|---|---|
| `send` `lib.rs:1446` | `send` on the recipient | before enqueue and before the unknown-recipient budget |
| `list` `lib.rs:1796` | `see` | filter entries; `include_retired` follows the same filter |
| presence/summary endpoints | `see` | whatever returns another role's presence |
| rooms (ROOMS_DESIGN.md R-slices) | `join`, `post`, `manage`, `see` | same `decide`; room copies are not re-checked per member except mute/ban state |
| `fetch`, `ack` | none | a role reads its own mailbox |
| launch (`lib.rs:2048`) | keep `SYNAPSE_LAUNCH_SENDERS` | it gates a process launch, not delivery; later it can be a `launch` action |
| `synapse-agent` allow-list | keep | a second, tighter bound for model-driven sends; policy sits under it |

**Mail already queued is kept** when a rule changes; only new sends are refused (same as retire, `lib.rs:1491-1502`).

## 4. What not to rebuild
The enforced `Send` check (`sender_auth.rs:568`), the state permissions (`state_api.rs`), role-admin/daemon-admin,
`SYNAPSE_LAUNCH_SENDERS`, and the agent allow-list stay. `decide` reuses `Session.permissions` as its bridge input
and the security-event machinery for denials. The new code is: the policy module, `AccessState` and its API, the
grant intake at claim, and the enforcement calls at the routes above.

## 5. Slices and born-red tests (design only; no code before the PM reads this)
| slice | content | born-red tests (fail before the change) |
|---|---|---|
| A1 | `access.rs`, `AccessState` blob, `decide`, rule API, default allow; no behaviour change | `no_rules_changes_nothing`; `a_deny_rule_refuses_send_with_unknown_recipient_shape`; `rules_survive_restart` |
| A2 | enforce `send` and `see` at the routes; denial events; system senders exempt | `list_hides_roles_the_caller_may_not_see`; `send_to_an_unseen_role_is_indistinguishable_from_absent`; `queued_mail_survives_a_new_deny_rule`; `daemon_unacked_notice_ignores_send_rules` |
| A3 | grant intake at claim from a GNAP token (key-bound); fail closed | `a_token_bound_to_another_key_is_refused`; `a_revoked_token_stops_allowing_within_the_ttl`; `an_unreachable_authorization_server_never_widens_access` |
| A4 | bridge switch `grants_required`, `allowed_by` metric | `cert_send_alone_stops_authorizing_when_grants_are_required` |
| R1+ | rooms on top (`ROOMS_DESIGN.md`), one rule table | `a_room_uses_the_same_rules_as_an_agent` |

Rooms R1 should not start before A1, so rooms are written against `decide`, not a second mechanism.

## 6. Calls for the PM / CireSnave
1. **Default on upgrade:** allow within the account (recommended: nothing changes until a rule is written), or deny?
2. **Reintroduce auth-framework** as a dependency for grant intake? It reverses rc.83 for this one use, and a real consumer is what that crate lacked.
   Alternative: A1/A2 first with rules only (no tokens), A3 later; this delivers see/send control without the dependency.
3. **Who edits rules:** the account key only, or a delegated `access-admin` (a certificate permission now, a grant later)?
4. **Revocation bound:** the grant re-check TTL (suggest 60 s, matching the order of `ONLINE_WINDOW`, `lib.rs:198`).
5. **Seeing vs reaching:** may an agent that cannot see a role still be reached by that role? Recommended: `see` and `send` are separate actions, no implication.

## 7. Not done
No code. I did not run any daemon. I did not read auth-framework's tests, its storage, or its current published API
(only the local checkout's `gnap.rs` signatures). The cross-account case is out of scope (one daemon, one account).
The patent screen for this note is not done: access-control rules over messaging are a different claim family from
rooms (`PATENT-SWEEP.md` I20), and a screen from the claims is owed before A1 is built.
