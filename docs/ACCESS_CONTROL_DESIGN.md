# Access control: who may see and message whom (design note, no code)

Status: proposal v2, read at `origin/main` f8d155d (rc.208). Rewritten 2026-11-06 after CireSnave ruled board 384 (verbatim in 3.0). Nothing here is built.
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
and cert-based; the cert grants already reach the daemon in `Se## 3. Design v2 (after CireSnave's ruling on board 384; board 385 open)

### 3.0 The rulings this applies (CireSnave, 2026-11-06, `CIRESNAVE-DECIDED-ARCHIVE.md` item 384, verbatim)
1. *"Since upgrades are a one time thing and all future lanes will be deny all by default, yes, allow all for all existing lanes."*
2. *"Bring auth-framework back in as a dependency now. It was removed so we could get Synapse working without worrying about authentication and authorization."*
3. *"Anyone with the permission/grant needed to edit a rule can edit it. An account holder starts with permission to create and edit any rule relating to their own agents and rooms. Anyone (account holder or agent) may share some subset of their permissions to others (including to agents)."*
4. *"60 seconds at the most. For sensitive grants, they should be checked each time live from the source."*
5. *"Agreed. Separate actions, no implication either way."* And his open question (board 385): should some or all of this be built outside Synapse?

The PM's recommendation on 385, which this design is shaped to: **auth-framework holds principals, grants, delegation and the decision engine; Synapse registers its actions and enforces.** Nothing below depends on 385 going the other way, because Synapse talks to the engine only through one trait (3.1).

### 3.1 The split: Synapse enforces, an engine decides
Synapse owns (small):
- **The action registry**: `synapse:see`, `synapse:send` (mail to an agent), `synapse:join`, `synapse:post`, `synapse:create-room`, `synapse:manage-room`, `synapse:grant` (share), `synapse:edit-rule`. Each is registered with a `sensitive` default (3.6).
- **The object names**: `agent:<role>@<account>` and `room:<name>@<account>`. A room and an agent are the same kind of object to the engine, which is what CireSnave's rooms brief asked for ("the same permissions").
- **The principal**: the authenticated global id `role@account` the daemon already sets from the session (`lib.rs:1468`); never a request field.
- **The enforcement calls** (3.5) and the trait they call.

```text
trait Authorizer { fn decide(&self, principal, action, object, freshness) -> Decision }
Decision  = Allow { grant_ref } | Deny { reason }   // a Deny on `see` is never shown to the asker
freshness = Cached (at most 60 s old) | Live        // Live is used for sensitive actions
```

The engine (auth-framework) owns: principals, grants, delegation chains, the decision, revocation, and the audit of edits. If 385 moves more outside Synapse, the trait implementation becomes a call to another process and nothing at the enforcement points changes.

### 3.2 What auth-framework offers today, and what it does not
Read from source at `origin/main` 3156a62c (published `0.6.0-rc209` per the crates.io index): `src/permissions.rs`, `src/authorization.rs`, `src/protocols/macaroons.rs`, `src/protocols/gnap.rs`. Nothing was built or run.

| need | in auth-framework | gap |
|---|---|---|
| principal, action, resource | `Permission { action, resource, instance }` (`permissions.rs:330`), roles, ABAC rules (`AbacPolicy`, `check_abac`) | whether `implies` supports patterns like `agent:*@acct` was not read |
| delegation | `Delegation { delegator, delegatee, permissions, expires_at }` and `check_delegation` (`permissions.rs:94`, `205`) | **it does not check that the delegator holds what it delegates, is one level only, and has no chain**: attenuation ("a grant can only narrow") is not enforced by the type |
| attenuation by construction | `MacaroonManager::attenuate` (`macaroons.rs:129`) | an HMAC bearer credential verified by the root-key holder, not bound to an agent's public key |
| key-bound token, revoke, introspect | GNAP `introspect_token`, `validate_token_key_binding`, `revoke_token`, `rotate_token` (`gnap.rs:1032, 1080, 968, 978`) | persistence across a restart not read |
| deny rules | none seen: `Permission` is positive only | needed if "allow all for existing lanes" must be narrowable (3.3) |
| live check from the source, sensitive marking | none seen | the registry flag and the `freshness` argument are Synapse's; the engine must answer `Live` without a cache |

So the engine the PM describes is partly there (permissions, roles, ABAC, GNAP tokens, macaroons) and partly to be built in auth-framework, which is the same owner's crate: verified attenuation, a delegation chain, a deny effect, a live-check path. **Synapse can only depend on a published crates.io version, so each gap is an auth-framework release first** (portfolio rule on sources: crate versions, no path or git deps).

### 3.3 Defaults and the upgrade (ruling 1)
- **New lanes (roles that first claim after the upgrade): deny all.** They can see nothing and message nothing until granted.
- **Existing lanes at upgrade: allow all.** The upgrade writes, once, a grant per existing role record (`RolesState`, `src/roles.rs:206`) tagged `legacy`: `synapse:see` and `synapse:send`. Tagging lets a report list what is still legacy and lets the account holder replace it with narrower grants.
- **Interpretation to confirm (call 1 below):** if the legacy grant's object is `agent:*@<account>`, existing lanes can also reach a *new* lane (it is an agent in the account) while the new lane can reach nobody. If new lanes should be unreachable by default, the legacy grant's object is the list of roles that existed at upgrade instead. Recommended: the list.
- **Narrowing a legacy grant** needs a deny effect or enumerated replacement grants. Recommended: ask auth-framework for a deny effect (gap in 3.2); until then, replace the wildcard with enumerated grants (about 45 x 45 pairs; the 45 is the role homes under `synapse-lanes`, not the daemon's list).
- **Account holder:** starts with `synapse:*` on `agent:*@acct` and `room:*@acct`, including `grant` and `edit-rule` (ruling 3). The daemon recognises the account holder by the account key, as it recognises `RoleAdmin` today (`lib.rs:2285`). **A1 (temporary):** nothing in a session marks the account holder, so A1 treats a session holding `role-admin` as the account holder (`principal_of` in `crates/synapsed/src/lib.rs`, marked TEMPORARY). Remove when grants carry that authority (A2). Any lane granted `role-admin` is therefore an account holder for `see` and `send`.

### 3.4 Editing rules and sharing (ruling 3)
- A "rule" is a grant: `{ principal, action, object, effect, expires, sensitive }`. **Anyone holding `synapse:edit-rule` on an object can create, change or remove grants about it**; the account holder holds it for everything in the account from the start.
- **Sharing a subset (attenuation).** Any principal, account holder or agent, may delegate to another principal (an agent included) any subset of what it holds. The engine must enforce, at issue and at every use: (a) the delegator holds the permission now, so a delegation dies when its source is revoked or expires; (b) the delegatee's effective rights are the **intersection** along the chain, so a grant can only narrow; (c) a delegation expires no later than its source, with a depth limit (3 suggested, a number to choose); (d) a delegatee cannot re-delegate more than it received. These are A2's born-red tests; the stock `Delegation` type does none of (a) to (d) today.
- Every grant, edit and share emits a security event with who, what and the chain (the pattern of `StateDenied`, `state_api.rs:37-42`).

### 3.5 Where Synapse enforces
| route | action | note |
|---|---|---|
| `send` `lib.rs:1446` | `synapse:send` on the recipient | before enqueue and before the unknown-recipient budget; a send to an agent the sender may not **see** is refused as `404 unknown_recipient` (`lib.rs:1512`), so there is no existence oracle; a role the sender **can** see but may not message gets `403 forbidden` naming the missing action (PM, 2026-11-06: the sender already knows the role exists, and a lane debugging a refusal needs the reason) |
| `list` `lib.rs:1796` | `synapse:see` | filter rows; `include_retired` follows the same filter |
| presence and summary endpoints | `synapse:see` | any endpoint that returns another role's state |
| rule and grant API (new) | `edit-rule`, `grant` | sensitive (3.6) |
| rooms (`ROOMS_DESIGN.md`) | `join`, `post`, `create-room`, `manage-room`, `see` | the same call; fan-out copies are not re-checked per member except mute/ban state |
| `fetch`, `ack` | none | a role reads its own mailbox |
| launch `lib.rs:2048` | keep `SYNAPSE_LAUNCH_SENDERS` | gates a process launch, not delivery |
| `synapse-agent` allow-list | keep | a tighter bound for a model-driven sender |
| daemon-originated notices (`[UNACKED]`, dead letters) | exempt | they originate in the daemon, not a session |

Mail already queued is kept when a grant is revoked; only new sends are refused (as retire does, `lib.rs:1491-1502`). `see` and `send` are separate: holding one implies nothing about the other (ruling 5), and each has its own test.

### 3.6 Freshness and "sensitive" (ruling 4)
- **Cached:** a decision may be reused for at most 60 s per (principal, action, object). A revoke therefore takes effect within 60 s everywhere.
- **Sensitive: checked live from the source on every call.** A decision is `Live` if any of these hold: (1) the **action** is registered sensitive (default for `grant`, `edit-rule`, `create-room`, `manage-room`, anything that changes who may do what); (2) the **grant** that would authorise it is marked sensitive by its issuer (an issuer may raise sensitivity, never lower a registry default); (3) the **object** is on the account's sensitive list (for example `agent:pm@acct`).
- `see` and `send` are not sensitive by default: they ride on every message, and a live call per message is a cost this note has not measured. A message to a sensitive object pays the live check; the budget for that (an embedded call against a call to another process) is a number to measure in A2, not a claim.
- **Fail closed.** If the source cannot be reached: a `Live` decision is `Deny`; a `Cached` one is served until its 60 s end and then `Deny`. Unreachability never widens access.

### 3.7 Certificates
Certificates remain the proof of identity (the claim path) and still carry `role-admin` and `daemon-admin` until those move to grants. They no longer authorise mail: every existing lane receives a legacy grant at upgrade (3.3) and every new lane is deny-all, so certificate `Send` has nothing left to do on the daemon path. There is no bridge switch and no sunset date to run. The library gate (`sender_auth.rs:568`) is untouched.

### 3.9 The A2a / A2b seam (what the engine must answer)

A2 is split (PM, 2026-11-07). **A2a** (built, rc.222) is everything on Synapse's side of the `Authorizer` trait, with the
minimal in-memory engine behind it: the grant, revoke and list API, attenuation at issue and "dies with its source" at
use, the creator's ownership of what it created, `join` and `see` for rooms behind `synapse:see`, and the `Cached` wrapper.
**A2b** swaps the engine for auth-framework once a release that carries it is published to crates.io (AC1, the deny-wins
core, is on its `main`; the attenuation and live-check rows follow; Synapse does not depend on `main`). The swap is meant
to be one file: `crates/synapsed/src/access.rs`.

The seam is this signature (`Authorizer`, `Principal`, `Decision`, `Freshness`, `Unreachable` in `access.rs`):

```text
decide(principal { id, account_holder }, action, object, freshness) -> Allow | Deny
try_decide(...)                                                      -> Ok(Allow | Deny) | Err(Unreachable)
```

and these cases, each pinned by a test in `crates/synapsed/src/access.rs` or `crates/synapsed/tests/rooms.rs` and each
one the engine must answer the same way (the tests are the acceptance suite for A2b):

| case | answer | test |
|---|---|---|
| the account holder (a daemon fact, never the engine's) | Allow on any agent or room | `the_account_holder_can_edit_any_rule_about_its_own_agents` |
| an object kind other than `agent:` or `room:` | Deny | `access.rs` `decide_at` |
| a role on itself (`see`, `send`) | Allow | A1 tests |
| the creator of a room | Allow every action on it | `a_new_room_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder` |
| the creator of a sub-agent | Allow `see`, `send`, `edit-rule`, `grant` on it | A1 tests |
| a room, `see` / `post` / `edit-rule` / `grant`, anyone else | Deny unless a live grant covers it | `a_join_to_an_open_room_the_caller_may_not_see_answers_as_unknown` |
| an agent, anything else | Deny unless a live grant covers it | A1 tests |
| a grant past its `expires_at` | covers nothing | `an_expired_grant_grants_nothing`, `an_expired_grant_stops_granting_and_grants_survive_a_restart` |
| a grant issued by a role | covers only while the issuer still holds what it gave (the action, or `edit-rule` if it acted as owner); chain at most 4; a cycle covers nothing | `a_delegation_dies_with_its_sources_grant`, `a_delegation_that_the_issuer_never_could_give_grants_nothing` |
| `Cached` freshness | reusable for at most 60 s | `a_revoke_applies_within_60_seconds` |
| a sensitive action (`create-room`, `manage-room`, `grant`, `edit-rule`), or `Live` | always asks the source | `a_sensitive_decision_is_checked_live_on_every_call` |
| the source cannot be asked | `Live` Deny; `Cached` served until its minute ends, then Deny; a cached Deny stays Deny; never widens | `an_unreachable_source_denies_a_live_decision_and_never_widens_a_cached_one` |

What stays Synapse's after A2b: the action registry and object names, who the principal is, the account-holder fact, the
`created_by` records, the HTTP API and its issue-time checks (a grant can only narrow: `a_delegation_cannot_widen`,
`a_delegatee_cannot_redelegate_more_than_it_got`, `an_agent_without_edit_rule_cannot_edit`), the security event for every
grant and revoke, and fail-closed handling. What moves into the engine: where grants live and persist, the chain and
expiry arithmetic, the deny effect, the live source, and `sensitive` on a grant (the in-memory engine stores the flag and
is always live). Known gap, not a regression: a `join` to an Open room is allowed by the Authorizer for any principal; the
room's visibility and join policy decide it, so a role that cannot see an Open room cannot join it (board 388 A).

### 3.8 The dependency
Reintroduce `auth-framework` from crates.io (no path or git), at the newest published version at the time (`0.6.0-rc209` per the index today), `default-features = false` and only the features the permissions and GNAP modules need. Not yet measured, and measured first in A0: which features those are, whether the minimal build compiles on this toolchain, and the lockfile cost (rc.83 removed 136 packages when it left, `docs/CHANGELOG.md`, rc.83 entry). The non-Rust dependency rule applies to whatever it pulls (aws-lc-rs is the recorded exception). The PM's write-up reports a recent GNAP defect fix; the key-bound path is the part Synapse would lean on and is read in A0.

## 4. What not to rebuild
The enforced `Send` check (`sender_auth.rs:568`), the state permissions (`state_api.rs`), role-admin and daemon-admin, `SYNAPSE_LAUNCH_SENDERS`, the agent allow-list, `Session.permissions`, and the security-event machinery stay as they are. New in Synapse: the registry, the trait, the enforcement calls, the upgrade migration and the grant API. New in auth-framework (its own releases): verified attenuation and chains, a deny effect, a live-check path.

## 5. Slices and born-red tests (design only; the PM starts none until board 385 is confirmed)
| slice | content | born-red tests |
|---|---|---|
| A0 | no Synapse code: in a scratch crate, build auth-framework `0.6.0-rc209` with `default-features = false` and the minimal feature set; file the gaps of 3.2 as issues for the auth-framework lane; measure the lockfile delta | one scratch test per claim in 3.2, kept with the measurement |
| A1 | the registry, `Authorizer` trait, enforcement at `send` and `list`, default deny for new roles, `legacy` grants written once at upgrade; the engine behind the trait is a minimal in-memory one | `a_new_role_can_neither_see_nor_message_anyone`; `an_upgraded_role_keeps_seeing_and_messaging_every_existing_role`; `see_does_not_imply_send_and_send_does_not_imply_see`; `send_to_an_unseen_role_is_indistinguishable_from_absent`; `list_hides_roles_the_caller_may_not_see`; `queued_mail_survives_a_revoke`; `daemon_notices_ignore_the_rules`; `the_upgrade_migration_runs_once`; board 388: `a_new_sub_agent_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder`, `a_sub_agent_provisioned_directly_has_no_creator` (all in `crates/synapsed/tests/access.rs`) |
| A2 | **split (PM, 2026-11-07): A2a built (rc.222, section 3.9)**: the grant, edit and share API, attenuation, dies-with-source, the creator's ownership, join behind see, the 60 s cache, sensitive live and fail closed, against the in-memory engine; **A2b** (waits for a published auth-framework): auth-framework as the engine, a one-file swap. Original scope: auth-framework as the engine; grant, edit and share API; attenuation; 60 s cache; sensitive live checks; fail closed | `a_delegation_cannot_widen`; `a_delegation_dies_with_its_sources_grant`; `a_delegatee_cannot_redelegate_more_than_it_got`; `an_agent_without_edit_rule_cannot_edit`; `the_account_holder_can_edit_any_rule_about_its_own_agents`; `a_join_to_an_open_room_the_caller_may_not_see_answers_as_unknown` (board 388 A: until A2, joining an Open room reveals it exists; A2 enforces the creator-and-account-holder default, PM 2026-11-07); `a_revoke_applies_within_60_seconds`; `a_sensitive_decision_is_checked_live_on_every_call`; `an_unreachable_source_denies_a_live_decision_and_never_widens_a_cached_one` |
| A3 (part 1, dotted ids, built rc.226: `keystore::valid_role_id`, depth 3; part 2, delegating certificates, built rc.227: `role-admin` gets `may_delegate: 2`, `Keystore::delegate`) | sub-agents that can be created and mailed: delegating certificates (the keystore issues `may_delegate: 0` today, so no lane can issue one), and recipient addressing that accepts a dotted id such as `worker.pm@acct` (`mailbox::well_formed` uses `keystore::valid_name`, which refuses `.`; found in A1, mail to such a sub-agent is `400 malformed`) | `a_chain_issued_sub_agent_can_be_mailed_by_its_creator`; `a_delegated_certificate_cannot_widen_its_parent` |
| R1 | rooms on the same call (`ROOMS_DESIGN.md`), after A1 | `a_room_uses_the_same_rules_as_an_agent`; board 388: `a_new_room_is_invisible_to_a_third_agent_and_visible_to_its_creator_and_the_account_holder`; join and post apart (CireSnave 2026-11-06): `a_non_member_post_is_refused_with_the_typed_reason`, `a_non_member_holding_the_post_grant_posts_and_receives_nothing`, `the_post_grant_does_not_imply_join`, `join_then_send_honours_an_invite_only_room` |

## 6. Calls still open (for the PM)
1. **Legacy grant reach** (3.3): existing lanes may reach new lanes (object `agent:*`), or only the lanes that existed at upgrade. Recommended: the second, so a new lane is reachable by nobody until granted, matching "deny all by default".
2. **Deny effect**: ask auth-framework for one, or enumerate replacement grants until it ships. Recommended: ask.
3. **Delegation depth** (3 suggested) and the **sensitive defaults** in 3.6.
4. **Board 385**: this note holds on the PM's recommendation; confirm before A0.

## 7. Not done
No code and no daemon run. auth-framework was read as source only (3.2), not built; its tests, its storage and the `implies` semantics were not read. The cross-account case is out of scope (one daemon, one account, `lib.rs:252`). Patent row I21 covers rules and key-bound tokens; the live check for sensitive grants and the verified attenuation of this version have not been screened separately.
