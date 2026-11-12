<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Role liveness, part 2: tell someone when mail waits for a role that is not there

Status: design, 2026-11-12, no code. Task from the PM (ROADMAP row 31 follow-up). Read against `origin/main` 8fbd5b12 and the
live pilot (rc.241). Extends `docs/ROLE_LIVENESS_DESIGN.md`, whose L1-L3 (retire after a TTL, retire/revive, 410
`recipient_retired`) are built. Those retire a role that is gone for good; this note is about a role that is gone **today**.

## What happened (2026-11-12, measured on the pilot)
`synapse list` (caller kiss, which sees 45 roles) showed roles with `online=false` and mail waiting, none retired:
bonefish (2 queued since 2026-11-01), capant (2 since 11-09), cpufish (1), sageant (2), surfaceant (1),
thinkersfoundation (1). agent-loop, humboldt and webhostant had sat offline with mail dead-lettered until CireSnave
reconnected them. Nothing told a human or the senders: the sender got `queued`, which is true and says nothing about
whether anyone will read it. The existing `[UNACKED]` notice fires only after a *delivery* ran out, so it cannot fire
for a role that never fetches (no delivery is ever attempted).

## Gap 1: queued mail for an offline role is silent
### Design
A daemon sweep (the one that already runs `maintain_roles`) computes, per role, `waiting_since` = the oldest
`queued` message's enqueue time, and `offline_since` = `last_seen` (else `claimed_at`). A role is **stalled** when it is
not online, has `queued > 0`, and both clocks are older than `stall_after` (default 15 min; `[liveness] stall_after_secs`).
For each stalled role the daemon sends **one** notice, from the daemon's own notice sender, to:
1. the senders of the waiting messages (one mail per sender per role per stall episode):
   `[STALLED] role=<role> waiting=<n> oldest=<age> online=false`; and
2. the roles in `SYNAPSE_ALERT_ROLES` (the existing alert list), one digest per sweep per episode.
An episode ends when the role fetches (any fetch), is retired, or the queue empties. A new episode may alert again only
after `stall_realert` (default 6 h), so a role left down for a week produces 28 notices, not 700.
Notices follow the existing rule: never about a notice, outside the access rules, delivered once.

### Not in scope
Relaunching the lane. The launch signal (`SYNAPSE_LAUNCHER_ROLES`, `GET /v1/waiting`) already exists and is opt-in; a
stall notice does not start anything. Someone who wants wake-on-stall reads the notice, or the launcher polls `waiting`.

### What a sender gets without an alert (also fix, cheap)
`send` returns `outcome: queued` plus `recipient: {online: bool, last_seen}` so the sender sees at send time that the
mail is going to an offline role. Additive field; no behaviour change. This alone would have caught most of today's cases.

### Tests (red first, injected clock)
`an_offline_role_with_queued_mail_gets_one_stalled_notice_per_sender`; `an_online_role_is_never_stalled`;
`a_fetch_ends_the_episode_and_a_new_stall_waits_for_stall_realert`; `a_retired_role_is_not_stalled`;
`a_stalled_notice_is_not_itself_stalled_mail` (no notice about a notice); `the_alert_roles_get_one_digest_not_one_per_message`.
Sabotage: drop the `online` test; drop the episode reset.

## Gap 2: a new lane is deny-all both ways, and says so as "unknown recipient"
### Finding (measured on the pilot, 2026-11-12, live repro from the lane's home)
ml-convertant claimed (epoch 2, session file names the pilot's instance) yet could not send to pm
(`404 unknown_recipient: pm@ciresnave`), and the PM's `list` did not show it. Cause: `access.json` (migrated 13:39:50Z)
holds 45 `legacy` grants, one per role that existed then; a role first claimed later is deny-all (ACCESS_CONTROL_DESIGN
3.3, shipped as designed) and a send to a role the caller cannot see answers as an absent role. The same applies to
agentlife-launcher, provisioned 14:00Z. A wake-on-message launch hits the same wall: the message to a deny-all lane is a
404, never queued, so no wake fires. Fix on the pilot needed the account holder (a session holding `role-admin`), and
the PM ran it by minting a temporary `role-admin` role.

### Design: a default grant set applied by the account holder, at provision time
Provisioning (`synapse id provision`, which already holds the account key) takes `--grants <file>` (or
`[provision] default_grants` in `synapsed.toml`): a list of `{peer, actions}` where `peer` is a role or a group name
resolved from the roles file. For each provisioned role R it writes, through the daemon's account-holder path, two
grants per entry: R -> peer and peer -> R (`see`+`send`), tagged `provision` (so a report lists them and they can be
narrowed), idempotent (a grant already present is `ok`). The default file ships with one entry: the PM role, both ways
(R can report, the PM can message and wake R). Everything else stays deny-all: the ruling in ACCESS_CONTROL_DESIGN 3.3
stands; this makes the operator's choice a file, not a hand edit after the first failure.
`provision` prints one line per grant `<role> <peer> ok|added|refused`, and never a key.

### The error
A 404 `unknown_recipient` for a role the caller *cannot see* must stay identical to absent (that is the A1 test
`send_to_an_unseen_role_is_indistinguishable_from_absent`). So the help goes to the **sender's own** side: `synapse
send`'s failure text, when the caller holds no `see` grant on anyone newly provisioned, gains one line: "If this role
exists, you may not have been granted rights over it: ask the account holder (`synapse access grant`)". Does not
distinguish absent from unseen; says only the possibility.

### Tests
`provision_applies_the_default_grants_both_ways`; `provision_is_idempotent_on_grants`; `a_provisioned_lane_can_message_the_pm_and_be_messaged_by_it`;
`a_provisioned_lane_is_still_deny_all_toward_everyone_else`; `a_deny_all_sender_failure_text_names_the_grant_possibility`.

## Gap 3: nothing keeps the temporary admin from lingering
The PM's temp `access-tmp-pm` role (role-admin removed, home deleted) cannot be retired by anyone now holding
`role-admin`. It will idle to the 30-day TTL. Proposal: `synapse id grant-once --role X <permission> --for <secs>`, a
permission that lapses (the cert lifetime is already 1 day for lane homes; use it), plus the account holder may retire any
role without holding `role-admin` through the account key. Small; separate slice.

## Slices (each bumps the version; the PM allocates)
S1 `send` reports `recipient.online`/`last_seen` (additive). S2 the stall sweep and `[STALLED]` notices (Gap 1).
S3 `provision` default grants and the sender-side hint (Gap 2). S4 a lapsing grant and account-key retire (Gap 3).

## Open calls (PM or CireSnave)
1. `stall_after` 15 min and `stall_realert` 6 h: proposed; shorter is noisier.
2. Notice the **senders**, the alert roles, or both. Recommended both (the sender can reroute; the operator can restart).
3. Default grant set: the PM only, or also the lane's peers by repo (e.g. mlmf)? Recommended PM only; more per lane by file.
4. S4 is worth building, or the 30-day idle-out is acceptable for a one-off. Recommended: acceptable until a second case.
