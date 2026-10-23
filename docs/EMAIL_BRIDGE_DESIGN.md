# Two Synapse daemons over email: feasibility (design note, no code)

Asked by CireSnave via the PM, 2026-10-23. Read at `origin/main` bd726e4 (6.0.0-rc.131).

## Verdict
Feasible, and it fits the model: a **bridge role** on each daemon carries **origin-signed envelopes** over email. It is not
a small change, because three things the daemon does today are exactly what blocks it, and the old email code is mostly
not reusable as a transport. Honest size: a 1-2 day spike with no daemon change; a shippable version is roughly
**8-10 PRs, 8-10 lane-days, plus a security review**. Direct daemon-to-daemon TLS/QUIC (LAN_MODE.md, QUIC slice #50) is smaller
and better when both sides can accept an inbound connection; email earns its keep only when neither can.

## What blocks it today (verified)
1. **Foreign recipients are refused by design.** `synapsed/src/lib.rs` ~1195: `to` must be `<role>@<this account>` and a role that has
   claimed here, else `404 unknown_recipient`. So `lane@accountB` cannot even be queued on daemon A.
2. **`from` is the authenticated sender of THIS daemon.** The daemon stamps `from` from the claimed session. A bridge that re-enqueues
   mail on daemon B would appear as `bridge@B`, not `lane@A`: the origin is lost, or must be trusted on the bridge's word.
3. **Trust is one account per daemon** (`/v1/claim` verifies against `shared.account_key`; docs/LAN_MODE.md). There is no place for
   a peer account's key. The library does have the pieces: `sender_auth::TrustStore::pin_account_key(_pem)`, `certificate` chain
   verification with a caller-supplied `account_keys` lookup, revocations, `replay.rs`. None is wired to `synapsed`.

## Design
- **Addressing:** unchanged `role@account`. Daemon A learns a routing table `account -> bridge role` (config; e.g. `accountB -> bridge-b`).
  A `to` for a configured foreign account is queued for that bridge role instead of refused. Everything else still refuses.
  *Daemon change #1 (small, security-sensitive: the table is the allow-list; budgets per sender stay).*
- **Origin signs, not the relay.** The sending adapter signs `(domain tag, message_id, from, to, sent_at, body hash, audience=accountB)`
  with the role's signing key and attaches its certificate chain (the claim path already does this for claims: `sign_claim_for`).
  The receiving bridge verifies the chain against the **pinned account key of A** (out-of-band, per peer), freshness, replay set,
  revocations, and that the cert's global id equals `from`. A forged `from` fails; a compromised relay can drop or delay, not forge.
  *Client change (new): `send` to a foreign account attaches the signed envelope.* Role certs are 24 h by default: a role-only lane
  needs the PM's re-issue (WSL-PILOT-DESIGN.md) or the signature outlives the cert, which the verifier must allow only within the cert's window.
- **Delivery into B with the origin intact:** a new daemon endpoint for a role holding a `bridge` permission (the certificate already has
  `permissions` and extensions) that accepts `{origin envelope + proof}`, **re-verifies the origin signature itself** (so B does not
  trust the bridge for identity), and enqueues with `from = role@A`. *Daemon change #2 (the larger one): new permission, new endpoint,
  per-peer-account pinned key store, replay set.*
- **Confidentiality:** seal the body to the recipient's sealing key (HPKE, `sealing.rs`, exists) so the mail provider cannot read it.
  Needs the recipient's certificate (it carries `subject_sealing_key`): exchange role certs out of band or have each bridge publish a directory message.
- **Reliability:** at-least-once. Bridge A keeps a durable outbox (retry with backoff, give up to the dead set); bridge B dedups on
  `(origin account, message_id)` (the mailbox already treats a repeated id as a duplicate within one daemon). Acks: the receiving role acks
  locally on B; an end-to-end acknowledgement is a normal return message `B -> A` (bridged back), not a transport ack. Ordering is not
  guaranteed; latency is the polling interval (5-60 s). Size limit per mail (provider caps ~25 MB; the mailbox body limit is separate).

## What the old email code is worth
- `src/email.rs` (327 lines): `EmailTransport::send_message` **refuses unconditionally** (no signing, owner's rule "never unsigned"); nothing to reuse but subject formatting.
- `src/transport/email_unified.rs` (986), `src/router_merged.rs` (1656): the old EMRP router and `SecureMessage` types; tied to a different envelope. The
  daemon (`crates/synapsed`) has **no** reference to email at all (grep: none). Treat as reference, not a base.
- `src/email_server/` (SMTP 819, IMAP 446, auth 312, ...): an in-process SMTP/IMAP **server**. A bridge should not run an MX; it should use an
  ordinary mailbox over IMAP + SMTP submission. The server is useful as a **test fixture** (no non-Rust test dependency, as required).
- Reusable as dependencies, already in the tree: `lettre` (SMTP submission), `async-imap` (poll/IDLE), `mail-parser`/`async-smtp` (optional features).
- Missing: a real SMTP/IMAP **client transport** with credentials handling (app password in env, never logged), MIME framing of the envelope, bounce/NDR handling, provider rate limits.

## Risks
Provider credentials and content scanning/blocking; a mailbox is an attack surface (accept only mail from pinned senders, size caps, no HTML parsing);
clock skew for freshness; revocation latency; account-name collisions between operators (pin by key id, not by name); email metadata (who talks to whom) is visible to the provider.

## Size
| step | PRs | note |
|---|---|---|
| spike: two daemons + a script bridge over a local SMTP/IMAP fixture, origin-signed envelope | 0 (branch) | 1-2 days; no daemon change; proves signing + dedup |
| daemon: foreign-account routing table + `bridge` permission | 1-2 | security review |
| daemon: verify-and-deliver endpoint, peer account key pins, replay | 2 | the core |
| client: sign foreign-account envelopes; seal to recipient | 1-2 | |
| bridge crate: outbox/inbox, retry, dedup, dead set | 2 | |
| email transport (lettre + async-imap), fixture-based tests | 1-2 | |
| docs, runbook, CI job | 1 | |

Recommendation: do the spike first; if email is only wanted for "A cannot reach B", compare with LAN_MODE option A (TLS with pinned certs), which needs
the same trust/signing work (#2, #3) but no email transport, and email can then be a second transport behind the same bridge.
