# Role liveness: retiring a role that is gone

Status: design, 2026-10-24. Asked for by CireSnave 2026-10-24 (*"lets ensure something is added to Synapse that does"*,
about the pile of dead peers), relayed by the PM. Read against `origin/main` 033f399 (6.0.0-rc.149).

## What is true today

- A role is one identity, `role@account`. A restarted session claims it with a signed claim and gets a strictly higher
  **epoch**; calls under the old epoch get `Superseded` (`src/roles.rs`). So a restarted lane already supersedes its old
  session, and there is never a second row for the same role.
- `list` shows each role with `online` (a call within 90 s, `ONLINE_WINDOW`), `last_seen`, `epoch` and pending counts.
- Nothing ever retires a role. A role that was claimed once and never comes back (`lane-commysdk`: online=false,
  last_seen=null) stays in `list` forever, and its mail queues forever.
- The "17 agents named mlmf" ambiguity is Claude Code's own session registry, not Synapse. Synapse cannot clean it and
  this design does not try (CireSnave: claude-peers is being replaced by Synapse, so that pile needs no fix).

## Design

### 1. Restart supersedes the old session (exists; one gap to close)
No new mechanism. Gap: the superseded session is told only when it next calls. Add nothing now; revisit only if a
superseded adapter is seen to keep a stale connection open. (Positive evidence needed first.)

### 2. Retire after a TTL
`RoleRecord` gains `retired_at: Option<DateTime<Utc>>` and `last_seen: Option<DateTime<Utc>>` (both `#[serde(default)]`, so existing stores load unchanged). Presence lives in memory and is lost at a restart, so the sweep writes a sighting into `last_seen` at most once an hour per role; without it a role seen yesterday would look idle since its claim after any restart. Built in L1 (rc.154). The ttl is a daemon constant (30 days) until the daemon has a config file.
The daemon's existing periodic sweep marks a role retired when it is offline and its last activity (`last_seen`, or
`claimed_at` for a role never seen) is older than `role_ttl` (default 30 days, `[roles] ttl` in the daemon config).
Nothing is deleted: the epoch, the certificate binding and the queued mail are kept, so a role can come back.
`list` hides retired roles unless asked (`include_retired`), and shows `retired_at` when it does.

### 3. Explicit retire and revive
`synapse role retire <role>` and `synapse role revive <role>` (HTTP `POST /v1/roles/{role}/retire|revive`), gated by a
new `role-admin` permission through the existing grant mechanism. Retire takes effect at once, whatever the TTL.
Revive clears `retired_at` and restarts the TTL clock. A valid signed claim by the role's own key also revives it:
holding the key is the authorization (the M3 rule), so a lane that returns needs no operator.

### 4. Addressing by role only
Already so for Synapse: an address is `role@account`, a bare role means the sender's account, and one role is one
identity, so a name cannot match two things. The change is to make failure explicit: a send to a retired or unknown
role fails with a typed error naming the role and its state, never a silent queue. A test pins that a bare name
resolves to exactly one role.

### Not covered
Claude Code's session registry (`ListAgents`) and the claude-peers broker. Nothing in Synapse reaches them.

## Open design calls (need CireSnave or the PM)
1. **TTL default.** 30 days proposed. Shorter retires a lane that is only on holiday; it revives itself on its next
   claim, so the cost of too short is a hidden row, not lost mail.
2. **Mail sent to a retired role.** Recommend refusing the send (typed error) rather than queueing. The alternative,
   queue and revive on claim, risks mail piling for a role nobody will claim.
3. **Mail already queued for a role at retirement.** Recommend keeping it until the existing delivery TTL expires it;
   do not move it to the dead set early.
4. **Who may retire.** Recommend a `role-admin` permission, granted to the PM role only, not "any role".

## Slices
L1 `retired_at` + sweep + hidden `list` (red-first with an injected clock). L2 retire/revive op, CLI and permission.
L3 typed send error and the bare-name test. Each bumps the version; the PM allocates numbers.
