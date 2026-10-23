# Shared state between lanes (design)

**Status:** DRAFT for PM approval. Nothing is built.
**Tasked by:** the PM, 2026-10-23, quoting CireSnave: *"Synapse should have the ability to store shared stated between lanes. Commy will likely eventually become one of Synapse's communication interfaces."*
**Measured at:** `origin/main@b149f10` (6.0.0-rc.137).
**Builds on:** the mailbox (M4), the daemon API (M5), role certificates and permissions (slice f), the alert path (`SYNAPSE_ALERT_ROLES`, rc.101), and the MCP/channel adapters (M6/M7).

## 1. Problem

Cross-lane threads live in messages and in each lane's own HANDOFF, so every lane acts on its own stale copy. Three cases from one day: a lane told CireSnave to run a setup that was already done; a roadmap said a crate was unpublished after it was published; a lane waited on a PR that had merged hours earlier. In each, the fact was cheap to check and nobody was made to check it.

The fix is one record per thread that every party reads, whose forge-answerable facts are **derived by a checker, never typed**, and which tells a reader when it was last verified and by whom.

## 2. Requirements (from the task) and where each is met

| # | Requirement | Section |
|---|---|---|
| 1 | A record per cross-lane thread: id, parties, owner, state, blocked-on, a VERIFY fact, last-verified time and by whom | 3 |
| 2 | One writer-wins-by-revision model (compare-and-set), full history, who changed what | 4 |
| 3 | Messages carry only record ids; subscribers are notified on change | 6 |
| 4 | Role-based access, signed writes, no free text trusted as instructions | 5, 8 |
| 5 | Forge-answerable facts are derived by a checker | 7 |
| 6 | A human-readable export for CireSnave's board | 9 |
| 7 | Commy as a future interface: a transport-neutral API | 10 |

## 3. The record

```
Record {
  id:         "T-<n>"            daemon-allocated, never reused
  title:      bounded text       data, never instructions
  parties:    [role]             who the thread concerns (they are subscribed)
  owner:      role               exactly one, a party
  state:      open | blocked | waiting | done | cancelled
  blocked_on: [Blocker]          a record id, or a fact condition (below); empty unless state=blocked
  verify:     [Condition]        the facts that make this record true or done (below)
  notes:      bounded text       data, never instructions
  revision:   u64                1 at creation, +1 per accepted write
  created_at, updated_at
}
Condition { fact: FactSpec, op: eq | ge | exists | absent, value: text }
Blocker   = Record(id) | Condition
```

**A `verify` entry is a fact specification from a closed registry, not a command.** The task says "VERIFY command/fact"; a command would make every record an arbitrary-execution instruction written by one lane and run by another, which breaks requirement 4. The registry (section 7) names what can be asked; adding a kind is a code change reviewed like any other.

Derived, read-only fields, computed at read time and never stored as typed:

- `facts`: for each `verify`/`blocked_on` condition, the checker's latest observation: `{observed, observed_at, observed_by, error?}`.
- `satisfied`: per condition, whether the observation meets `op value`.
- `last_verified`: the **oldest** `observed_at` among the record's conditions, and who observed it. A record with no conditions says `never verified`.
- `stale`: `last_verified` older than the record's staleness limit (default 6 h, per-kind, set by the daemon's config), or any condition unobserved. A stale record is **shown as stale everywhere** (get, list, export, notifications); it is never silently served as current.
- `unblocked`: `state=blocked` and every `blocked_on` condition is satisfied. This is a derived flag, not a state change: only a party moves the state.

## 4. Writes: compare-and-set, full history

- Every write names the revision it was made against: `patch(id, expected_revision, patch)`.
  - A match applies the patch atomically and returns the record at `revision + 1`.
  - A mismatch changes nothing and returns `stale_revision` with the **current record**, so the writer re-reads in the same round trip and decides again. There is no merge: last-writer-wins is not offered, and a lost update is not possible.
- The patch is a field-level object (RFC 7396 shaped) over `title`, `parties`, `owner`, `state`, `blocked_on`, `verify`, `notes`. Unknown fields are refused, not ignored. Derived fields are not patchable.
- **History is append-only.** Each accepted write stores `{id, revision, writer, written_at, patch, signature, prev_hash, hash}`: the writer's verified global id, the exact patch, and a hash chain over the previous entry, so a reader can check that no entry was removed or altered. `history(id)` returns it; nothing deletes a record, and `cancelled` is a state.
- `create` allocates the id and writes revision 1.
- Size bounds (title 200 bytes, notes 8 KiB, 32 conditions, 16 parties) are refused with `malformed`, like the mailbox's body cap.

## 5. Access

Four new permissions in the certificate (slice f; amended in S2, see below). Unlike `x-` extensions, Synapse interprets these:

| permission | allows |
|---|---|
| (no permission) | `get`, `list`, `history` on records the role is a party to: being a party is the read grant |
| `state-write` | `create`, and `patch` on records the role is a party to (the owner, or any listed party). **Every role holds it by default** |
| `state-read-all` | read every record; no write. The PM and the export role (decided 2026-10-23) |
| `state-admin` | read and patch any record; change `owner`; patch terminal records |
| `state-derive` | write facts (section 7). **Held only by the checker role.** No other grant lets a role write a fact |

- **Visibility is by party.** A role sees a record only if it is a party (or holds `state-admin`). Recommended over world-readable: a record names who is blocked on whom, and leaking that across accounts is a default we cannot take back. Open question Q2.
- A write by a non-party is refused with `forbidden` and recorded as a security event (the existing `events::record` path).
- The role is the daemon's verified session role, never a field in the request, as for `send`.
- Adding variants to `Permission` changes the certificate wire format for parsers that reject unknown names (`Permission::parse` returns `None` for an unknown non-`x-` name). The slice that adds them bumps the certificate version note and says so as Breaking in its changelog.

## 6. Notifications: ids only

- Every accepted write puts `{id, revision, changed_by, changed_fields}` into an **outbox** table in the same transaction as the write. A daemon task drains it into the mailbox as mail from `daemon:state@<account>` to each party except the writer, exactly as `daemon:alerts` does.
  - The `message_id` is `state:<id>:<revision>:<role>`, so a crash between commit and enqueue re-enqueues the same message and the mailbox's duplicate rule drops it. The at-least-once chain stays at-least-once.
  - The body contains **no title, no notes and no values**: only the ids and field names. A receiver that wants content calls `get`, which applies the access rule fresh. This keeps free text out of the channel (`<channel>` events are untrusted input) and means a revoked party stops learning anything.
- A lane that sends a message about a thread puts the record id in it (`T-41`), not a copy of the state. This is a convention and a lint in the CLI (`synapse send` warns on text matching a known record's title), not an enforcement.
- Derived changes notify too: when the checker's observation flips a condition's `satisfied`, or a record becomes `stale`, the parties get the same id-only mail (`changed_fields: ["facts"]`, `["stale"]`). Staleness is raised by a timer in the daemon, once per transition.

## 7. Derived facts: the checker

**A fact is never typed by a lane.** The only writer of the `facts` table is the **checker**, a separate role (`checker@<account>`, `state-derive`), signed like any other. It is a lane-sized process outside the daemon, for three reasons: the daemon is loopback-only and holds no forge credentials; the checker needs `gh`/network that a daemon should not have; and a checker bug must not be able to corrupt records, only facts.

Closed registry of fact kinds (slice 1; each is one function with a test against a recorded response):

| kind | spec | answers | source |
|---|---|---|---|
| `crate_version` | `crate_version:<crate>` | max non-yanked version | crates.io API |
| `pr_state` | `pr_state:<owner/repo>#<n>` | `open` / `merged` / `closed`, plus merge SHA | GitHub API |
| `ref_sha` | `ref_sha:<owner/repo>@<branch>` | head SHA | GitHub API |
| `check_state` | `check_state:<owner/repo>@<sha>` | `success` / `failure` / `pending` over required checks | GitHub API |
| `file_at_ref` | `file_at_ref:<owner/repo>@<ref>:<path>` | blob SHA, or `absent` | GitHub API |

- The checker polls the **distinct set** of fact specs across all non-terminal records (`state` not `done`/`cancelled`) on a timer (default 5 min) and on a daemon "recheck" nudge, and writes `{observed, observed_at, observed_by}`.
- A failed lookup is recorded as `error` with the time. It is **not** read as "absent": a fetch failure leaves the previous observation in place, marked stale after the limit, and never satisfies an `absent` condition. (The portfolio rule: an exit code is not a state read, and a smaller population looks like good news.)
- Comparison semantics are fixed per kind: `ge` on `crate_version` is a semver comparison with pre-release ordering as Cargo does it; `eq` elsewhere is exact string equality. Anything else is refused at `patch` time, so a record cannot be written that no checker can evaluate.
- **What stays typed** is only what no forge can answer: `title`, `parties`, `owner`, `state`, `notes`, and a human's decision. A lane may therefore say "I am waiting on PR 238"; it cannot say "PR 238 is merged". The record shows the checker's answer beside it.

## 8. No free text as instructions

- Every free-text field (`title`, `notes`, fact values, error text) is **data**: stored as given, escaped on output for the surface it lands on (the channel adapter's `escape`, which today escapes `char::is_control` and `<`/`>`; issue #106's bidi gap must be closed before notes render in a channel, so it is a prerequisite of slice 5).
- No daemon, adapter or checker ever executes, `eval`s, fetches or follows text from a record. A `FactSpec` is parsed against the registry; text that does not parse is refused at write time.
- Notifications carry ids only (section 6); the export (section 9) escapes for Markdown.
- **Signed writes.** Slice 2 attests the writer by the authenticated session (as `send`'s `from` is today). Slice 7 adds the client signature: the writer signs `(id, expected_revision, canonical patch)` with the role signing key, the daemon verifies it against the role's certificate and stores it in the history entry, so the history proves who wrote what without trusting the daemon. Sequenced after the base because the CLI, MCP server and channel adapter each need the signing path; the hash chain (section 4) ships in slice 1.

## 9. Export for CireSnave's board

`synapse state export [--format md|json] [--state open,blocked,waiting] [--party <role>]` renders every record the caller may read:

- Markdown: one table, one row per record: id, title, owner, state, blocked-on (with each condition's observed value and whether satisfied), **last verified (age, by whom)**, and `STALE` or `NEVER VERIFIED` in bold where it applies. Nothing is rendered from a typed claim without its observation beside it.
- Deterministic (sorted by id, no wall-clock in the body except `generated_at` in the header) so two exports diff cleanly.
- JSON is the same data, for the PM's board tooling.
- The caller is a role, so the export obeys the access rule; `state-admin` gets the whole board.

## 10. Transport-neutral API, and Commy

The store is a Rust trait in the root crate, with no HTTP or JSON in its signatures:

```
trait StateStore {              // memory + redb impls; a conformance suite like the mailbox's
    fn create(&mut self, writer: &Role, new: NewRecord, now) -> Result<Record, StateError>;
    fn get(&self, reader: &Role, id: &str) -> Result<Option<Record>, StateError>;
    fn list(&self, reader: &Role, filter: &Filter) -> Result<Vec<Record>, StateError>;
    fn patch(&mut self, writer: &Role, id: &str, expected: u64, patch: Patch, now) -> Result<Record, StateError>;
    fn history(&self, reader: &Role, id: &str) -> Result<Vec<HistoryEntry>, StateError>;
    fn put_facts(&mut self, checker: &Role, facts: Vec<FactObservation>, now) -> Result<(), StateError>;
    fn facts(&self, specs: &[FactSpec]) -> Result<Vec<FactObservation>, StateError>;
    fn drain_outbox(&mut self, max: usize) -> Result<Vec<Notice>, StateError>;
}
```

Access, CAS, history and the hash chain live **in the store**, not in an adapter, so no interface can bypass them. Bindings are thin and all call the same trait:

- the daemon HTTP binding: `POST /v1/state/{create,get,list,patch,history,export}` and `/v1/state/facts/*` for the checker, behind the existing session auth;
- the CLI: `synapse state new|show|list|set|history|export`;
- the MCP server and channel adapter: `state_get`, `state_list`, `state_patch` tools (read tools first);
- **Commy** (future): another binding over the same trait, or over the same wire shapes. Nothing in the trait assumes a socket, a session token, or JSON, so Commy needs a role identity and a way to call it, nothing more. We do not know Commy's interface yet; this keeps the cost of finding out low.

**Storage.** A new file `state.redb` beside `mailbox.redb`, owner-only, opened by the same single daemon. Not the mailbox's tables: the `MailStore` trait is mailbox-shaped and has its own migration and conformance contract, and the soak's mailbox is untouched by this work. The outbox-then-mailbox hand-off (section 6) replaces a cross-store transaction.

## 11. Slices

Each is its own PR with a version bump (PM allocates).

| slice | content | exit test |
|---|---|---|
| S1 | `StateStore` trait, `Record`, `Patch`, memory + redb stores, CAS, history with hash chain, access by party, conformance suite | two writers race on one revision: exactly one wins, the other gets the current record; a tampered history entry is detected |
| S2a | permissions (`state-*`) in the certificate, `synapse id grant`/`ungrant` (**done**, split from S2) | every role holds `state-write`; a grant reaches the certificate |
| S2b | daemon `/v1/state/*` + `synapse state` CLI; security events on refusal; `state.redb` opened by the daemon | a non-party is refused and the refusal is an event; roles without `state-write` cannot create |
| S3 | outbox and `daemon:state` notifications, ids only | a patch notifies each other party once; a crash between commit and enqueue yields one message, not two or none |
| S4 | `FactSpec` registry; checker role + `put_facts`; derived `facts`/`satisfied`/`last_verified`/`stale`/`unblocked`; stale timer | a recorded forge response flips `satisfied`; a failed fetch never satisfies `absent`; a record turns stale exactly once |
| S5 | MCP/channel tools (read first); needs #106 closed | a channel event shows an id and field names, never a title |
| S6 | `export` (md, json) | golden-file test; stale and never-verified rows are marked |
| S7 | client-signed writes verified against the role certificate | a write whose signature does not match the session's role is refused |

S1-S3 give a usable shared ledger with typed facts only. **S4 is the part that fixes the three incidents**, so it is the milestone, not an afterthought.

## 12. Schedule against the soak

This work does not touch `mailbox.redb`, the daemon's mailbox code or the pilot daemon, so it **does not restart the soak clock** while it is unreleased; an upgrade of the pilot daemon to a build containing it does, as any upgrade does. It is not queued behind soak work silently: it is ahead of the unstarted rows 20-29 of the ROADMAP, except #61 (mechanical, small) and #106 (a prerequisite of S5). Order after #236 merges: design (this PR) -> S1 -> S2 -> S3 -> S4 -> #106 -> S5 -> S6 -> S7. Estimates are in PRs, not days, because gate time is the PM's: seven code PRs, S1 and S4 the large ones.

## 13. Decided (PM, 2026-10-23) and amended in S2

- **Q1** checker: a PM-run process as `checker@ciresnave`, now. CireSnave prefers a read-only GitHub App to a token later, so the checker's forge-credential source is a pluggable interface from S4 (token today, App installation token later).
- **Q2** visibility: by party; `pm` and CireSnave's export role read everything (`state-read-all`).
- **Q3** ids: `T-<n>`, daemon-allocated, with a reserved `uid` field so a ULID can replace it.
- **Q4** staleness: 6 h default, per-kind override.
- **Q5** seeding: a one-off script after S4; the PM owns the content.
- **Amended in S2:** `state-read` is gone (party membership is the read grant) and `state-read-all` is new, so there are four permissions again: `state-write` (default for every role), `state-read-all`, `state-admin`, `state-derive`. The three non-default ones are granted by the account holder with `synapse id grant --role <role> <permission>`, stored in `roles/<role>/grants`, and reach the certificate on its next issue (a full home renews on the next load; `id issue` uses them for a role-only home). Adding the names makes certificates that carry them unreadable to a parser from before S2 (`Permission::parse` rejects an unknown non-`x-` name): Breaking for such parsers, in a pre-release line.

## 14. The questions as asked

- **Q1. Checker host.** Recommended: a small process run by the PM lane (it already holds forge access) as `checker@ciresnave`. Alternative: a daemon-side checker with its own token, rejected above for credential reasons.
- **Q2. Visibility.** Recommended: by party (section 5). Alternative: every claimed role reads everything, simpler and what the board does today.
- **Q3. Id format.** Recommended: `T-<n>` daemon-allocated, short enough for a message. Alternative: ULIDs, safer across a future multi-daemon setup, harder to say aloud.
- **Q4. Staleness limit.** Recommended: 6 h default, configurable per record kind. It decides how loud the stale marker is.
- **Q5. Seeding.** Not designed here: importing the existing board and HANDOFF items into records is a one-off script after S4, not a feature.
