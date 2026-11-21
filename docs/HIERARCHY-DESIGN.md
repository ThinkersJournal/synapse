<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Synapse hierarchical accounts: design note (board 477)

Status: **DESIGN NOTE ONLY. No code, no rename, until CireSnave has read it.** Written by the synapse lane
from `SYNAPSE-HIERARCHY-BRIEF.md` (CireSnave, 2026-11-19) and the 2026-11-21 rulings relayed by pm-platform
("477: I agree with your recommendations", verbatim per the PM). Everything marked *proposal* is for him to rule
on; everything marked *checked* was read at this branch's tree (`feat/messaging-step2`), not recalled.

## 1. Names, grammar and parsing

**The chain.** `child@holder@...@root`. The leftmost segment is the agent; each segment to its right is the
holder in charge of the one before it; the rightmost is the root account. Example from the brief:
`gate@pm-assist@pm@ciresnave`. Today's flat id `pm@ciresnave` is the depth-1 case, so nothing existing changes
meaning.

**Segment rules (proposal).**
- An **agent name** is today's `valid_name`: ASCII letters, digits, `-`, `_`, 1 to 64 bytes. It never contains
  `@` and never contains `.` (checked: `src/keystore.rs:182`). `@` is forbidden inside a name.
- The **root account** is a name, or an email `local@domain` (exactly one `@`; the PM's ruling that an account may
  be an email). Parsing from the right: a last segment that contains `.` is the domain of an email root (a name
  never contains a dot), so the root is the last two segments; otherwise the root is the last segment. This
  makes `pm@ciresnave@gmail.com` and `pm@ciresnave` both unambiguous. **Open question 1** below asks whether the
  email form is wanted at all, since the brief's own example uses the name form.
- **Dotted ids are retired.** The earlier slice let a recipient be `worker.lead.pm@acct` (up to 3 dotted levels,
  `valid_role_id`, `MAX_ROLE_DEPTH`; checked `src/keystore.rs:190-208`, tests `dotted_recipient_tests` in
  `src/mailbox.rs`). The `@` chain replaces it: `worker@lead@pm@acct`. Migration drops `valid_role_id` and its
  tests in the same change that lands the chain parser (section 6).
- A **short alias** (a bare `gate`) that matches more than one agent is refused by the daemon with the candidate
  list, never resolved by guessing. A bare name keeps meaning "in my own account" only when it is unique.
- **Email aliases are not in the grammar.** Contact by email (including `+` forwarding such as
  `pm+gate@...`) is a later alias table mapping an address to a chain; the name syntax is not widened for it.

**What each id is.** The chain is a *label* for where an agent sits today. The identity is the stable internal id
in section 2.

### The `@`-parsing census (checked, `git grep` over non-test Rust at this tree)

Each line splits or tests an id on `@`. After the chain lands, "first `@`" no longer separates `role` from
`account`: it separates the agent from the rest of its chain. Each must be re-read for which it means.

| # | Where | What it assumes | Chain-safe? |
|---|---|---|---|
| 1 | `src/mailbox.rs:170` `well_formed` | `to` is `valid_role_id@valid_name` | no: rewrite to the chain parser |
| 2 | `src/keystore.rs:199` `valid_role_id` and `:182` `valid_name` | one dotted role, one account | no: retire dots |
| 3 | `src/keystore.rs:636` `rsplit_once('@')` | the account is after the **last** `@` | yes for a name root, **no** for an email root (the last `@` would split the email) |
| 4 | `src/rooms.rs:333` `valid_room_id` | `name@account`, both plain names | room ids stay flat: a room is not an agent (proposal) |
| 5 | `crates/synapsed/src/lib.rs:1804` (send: `in_account`, recipient's account equals the daemon's) | account = right of first `@` | no: compare the root, not the remainder |
| 5b | `crates/synapsed/src/lib.rs:2024` (room fan-out, mention-only check) | local name = left of first `@` | yes: leftmost is the agent |
| 6 | `crates/synapsed/src/lib.rs:2422`, `:2942` (notice text `to=<role>`) | role = left of first `@` | yes: leftmost is the agent |
| 7 | `crates/synapsed/src/lib.rs:2837` (`short` in the stalled-role notice) | short name = left of first `@` | yes: leftmost is the agent |
| 8 | `crates/synapsed/src/launch.rs:76-79` (`allows`: a list entry with `@` is a full id compared whole, one without is a role in the sender's account) and `:192` (`role_name`, left of first `@`) | entry is `role` or `role@account` | `:192` yes; `allows` no: a bare entry must match the sender's leftmost segment and the root, and the `ancestors` mode replaces the list |
| 9 | `crates/synapsed/src/settings.rs:85` (validates `launch.senders` entries: `role` or `role@account`, both `valid_name`) | one `@` at most | no: a chain entry would be refused |
| 10 | `crates/synapsed/src/state_api.rs:24` `split('@').next()` | the caller's role = leftmost segment | yes |
| 11 | `src/state/signed.rs:189` `signer.split('@').next() == writer` | the signer's agent name is the leftmost segment | yes |
| 12 | `crates/synapse-mcp-server/src/lib.rs:460`, `:707`, `:711` and `crates/synapsectl/src/main.rs:800`, `:1336` | a `to` with an `@` is already global; a bare one gets the sender's account appended | no: appending the account to a bare name must append the sender's whole chain tail, or refuse when ambiguous |
| 13 | `src/identity.rs:777` | test fixture only | n/a |

Not address parsers, so out of scope: `crates/synapsectl/src/checker.rs:111-134` and `src/state.rs:128-133` split
`repo@branch` / `repo@sha` references.

Outside Rust, the lane tool and the portfolio scripts split a lane id on the first `@` (the brief says this
already matches); `tools/sync-launch-senders.py` writes `<home>/synapsed.toml` role lists. Not read for this note;
they are in the migration checklist (section 6).

## 2. The identity is a stable internal id, not the chain

*Proposal (PM, agreed 2026-11-21).* Every agent gets an opaque internal id (a random 128-bit value) when it is
minted. Keys, certificates, mailboxes, grants, audit entries, room membership and launch records refer to that id.
The chain is a label looked up from the id, so **re-parenting changes the label, not the identity**, and an email
address is only ever a label.

- Today a role's identity is its signing and sealing keys plus its `role@account` name (the certificate's
  `subject_label`; checked `src/keystore.rs:630-634`). Section 6 maps today's roles to ids without changing keys.
- A label change (re-parent) is an audited event, and messages in flight keep their internal recipient id, so a
  re-parent never loses mail.
- Names stay unique among siblings only; uniqueness across the account is the chain.

## 3. The account holder is a distinct principal (slice A2)

**Current threat boundary (stated plainly, from the PM's 2026-11-21 notice, lane-reported and not re-verified by
this lane):** role-admin is held by the role `ciresnave`, and every agent runs as the same Windows user. So *any
agent on this PC can act as the account holder today.* Nothing in the daemon can tell a human from an agent that
reads the same files. The hierarchy does not fix this by itself.

*Proposal.* The account holder is a principal that is **not a role**. Acts that only the holder may do (mint a
direct child of the root, change slot budgets, delete a branch, grant `role-admin`, read any history) are signed
with a key that needs an approval an agent cannot give: a Windows Hello or UAC prompt, or `with-secret`
(CireSnave 2026-11-06: tool-enforced human approval is sufficient authority for the one action it covers, with no
extra typed confirmation). Agents hold only delegated slices of the holder's authority, and rule 4 (nobody
grants what they do not hold) is enforced at signing time, not by convention.

Until that principal exists the note's other sections describe intent, not protection: a hostile or confused agent
on the same user account can still reach the key files.

## 4. Slots, visibility, deletion, history, audit

Taken from the brief's rulings; numbers are for CireSnave.

- **Slots.** Minting costs the parent 1 slot plus whatever allocation the child is given. The root is unlimited.
  *Proposed initial budgets:* `pm` 200, each cluster PM and `pm-assist` 20, each project lane 3 (enough for a
  helper or two). An agent with 0 slots cannot mint, so there is no separate depth limit.
  1. An allocation stays tied up until the child relinquishes it to the parent that gave it.
  2. A child can relinquish to its parent; an agent that ceases to exist relinquishes everything it held to its
     creator.
  3. A parent may change a child's allocation and permissions at any time, up to deleting the child. Reducing
     below what the child's live agents use is refused; deletion is the explicit way.
  4. Delegation only narrows: nobody grants what they do not hold. This includes the model pin (Sonnet only): a
     child inherits it and can only narrow it, never widen.
- **Visibility across branches.** The parent decides agent by agent, and may delegate that right to a sub-agent,
  within rule 4.
- **Deletion.** First list every still-active item the delete would remove and require confirmation. A branch with
  agents mid-task waits for idle (as `lane-restart assert-idle` does); a forced delete is an explicit override.
- **History access.** Any ancestor can read, grep and regex the full history of its descendants to any depth
  (messages, audit trail, whatever Synapse keeps). **Privacy boundary (proposal):** access is by ancestry only,
  never sideways; an ancestor's read is itself an audit entry visible to the one it read; message bodies sealed to
  a human recipient (the account holder's own mail) are not readable by agents however far up they sit.
- **Audit.** Every mint, relinquish, reallocation, grant, re-parent and delete is logged, signed by the actor, and
  readable by everyone above in the chain.

## 5. Launch senders, and the `ancestors` mode

CireSnave, 2026-11-21 (verbatim per the PM): *"Rather that putting every lane on the allow list, why not remove
the allow list requirement so we don't have to keep updating the allow list?  Once we get the parent<->child
arrangement squared away, we can limit wake on message to only ancestors being able to wake descendents.  Until
then, we can make it anyone."*

Setting `launch.senders_mode`:
- `list`: today's allow list (default, fail-closed).
- `any`: every authenticated sender may wake any role it can already send to. No list to maintain. The rate cap
  and the launch record are unchanged. (Built separately from this note; see the PM-ordered queue.)
- `ancestors` *(proposal, needs the chain)*: only an ancestor of the target may wake it. The check walks the
  target's chain from its stable id, not the label, so a re-parent updates it for free. A sender that is not an
  ancestor is refused with the reason and nothing is launched. The same rate cap and record apply.

## 6. Migration, quiet window, rollback

1. **Census first.** Land the parser as a library function with tests for every row in the census table, behind no
   switch; nothing calls it yet.
2. **Assign ids.** One migration step writes an internal id for every existing role and records
   `label = role@account`. Keys and certificates are unchanged, so every signature still verifies. Every existing
   role is a direct child of its holder (depth 1), as the brief says.
3. **Dual read.** For one release the daemon accepts the flat form and the chain form and resolves both to the id.
4. **Quiet window.** Cutover to the new parser needs all lanes restarted with no mail in flight: drain queues,
   stop, migrate, start. The lane restart tool and `assert-idle` already express "idle"; the window is announced
   by the PM like earlier cutovers (`CUTOVER_RUNBOOK.md`).
5. **Rollback.** The migration only adds ids and labels, never rewrites keys or messages, so rollback is the old
   binary reading the old name field; the id table is ignored. Take a store backup first (same discipline as the
   redb-to-SQLite store switch, `RUNBOOK_MAILBOX_STORE_SWITCH.md`).
6. **Outside the daemon.** Update the lane tool, `tools/sync-launch-senders.py`, MESSAGE-FORMATS examples and the
   portfolio docs that show `role@account`.

## 7. Prior art (not re-checked against the sources for this note)

| System | What it offers here | Gap |
|---|---|---|
| UCAN, Macaroons | capabilities that only narrow along a chain (rule 4) | no quota or mint budget |
| SPIFFE trust domains | stable identity separate from a path label (section 2) | no parent power over children |
| Kubernetes namespaces and resource quotas | a quota tree with parent limits (slots) | no delegation of the quota-setting right |
| DNS delegation | a right-to-left name chain with zone authority | no ack, no audit by ancestors |
| This repo's `AgentCertificate` chains (`may_delegate`) | a signed delegation chain already exists | permissions are coarse; no slots |

None gives all of: narrowing delegation, a mint budget, ancestry-only history access, and a stable id. The design
composes them; nothing here needs a new cryptographic primitive.

## 8. Open questions for CireSnave

1. **Email roots.** The PM's relay says an account is an email; the brief's example uses the name `ciresnave`.
   Is the root a name, an email, or either (the grammar above allows both)?
2. **Slot numbers** in section 4 (200 / 20 / 3).
3. **Room ids** stay flat (`room@account`): agree?
4. **History privacy boundary**: is "ancestry only, a read is audited to the one read, human-sealed mail excluded"
   the right line?
5. **Quiet window** length and who calls it (the PM, as for earlier cutovers)?
6. **Alias table** (`+` forwarding): in scope for 6.x or later?
