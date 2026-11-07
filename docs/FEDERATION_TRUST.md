# Federation trust: how a message from another account is believed

Status: design note, 2026-11-07. No code. Inputs: the PM's premises of 2026-11-06 (no single hosted authority; each
account may run its own auth-framework; the receiver finds the sender's keys through the sender's account; trusting an
account is a local allow-list). Facts about today's code cite a file at `origin/main` 14c93d4 (6.0.0-rc.213).
This note does **not** design the vouching system (board 138); where vouching would plug in it says so and stops.

## 1. The question

Account `alice` and account `bob` each run Synapse. `pm@alice` sends to `dev@bob`, or posts to a room whose members
include `dev@bob`. What does `dev@bob`'s daemon check before it hands the message to its lane, and who or what does it
trust to have said so?

## 2. What exists

| Layer | What it does | Where |
|---|---|---|
| Sender proof | Mandatory `SenderProof { alg, key_id, sig }` on a `SecureMessage`; Ed25519 over canonical input v1 (domain tag, `protocol_version`, `message_id`, `from`, `to`, timestamp, security level, `key_id`, SHA-256 of the content, sorted metadata). `routing_path` is not signed (relays append). | `src/sender_auth.rs` `canonical_input`, `SenderProof` |
| Verdict | `TrustStore::verify` turns the proof plus keys the **receiver** pinned into one `SenderVerdict`: `Verified{key_id}`, `Unverifiable{reason}` (unsigned, unknown sender, unknown issuer, invalid chain, unsupported version...), `Contradicted{reason}` (key mismatch, bad signature, identity mismatch). Never read from the wire. | `src/sender_auth.rs` |
| Pinning | Per sender (`pin`) or per account (`pin_account_key`, then the sender presents a certificate chain whose root is that account key). Nothing in a received message adds a pin. | `TrustStore` |
| Certificates | Account-signed role certificates, chains leaf-first, each child's id the parent's with one label prepended, permissions only narrow, validity nests, revocations. | `src/certificate.rs` |
| Replay, sealing, acknowledgement | Specs of 2026-09-17: replay suppression, sealing (confidentiality to a pinned sealing key), receiver acknowledgement. | `docs/superpowers/specs/2026-09-17-*` |

**The daemon path does not use any of this today.** A lane talks to its own daemon with a bearer session; `from` on
every envelope is set by the daemon from the authenticated session, never from the request (`docs/ROOMS_DESIGN.md` F3;
`Envelope` is `message_id, to, from, body`, no proof). Inside one daemon that is sound: the daemon is the authority for
its account's roles. It stops being enough at a daemon boundary, because the receiving daemon has no reason to believe
another daemon's `from`.

## 3. What a receiver must verify for a message that crossed daemons

For every cross-daemon message, at the **receiving daemon**, before the copy reaches a mailbox:

1. **A proof exists and is for this message**: the sender's signature over the canonical bytes (so the body, `to`,
   `from`, `message_id` and timestamp are bound together). A missing proof is `Unverifiable`, not a pass.
2. **The key is the sender's**: either pinned for that exact `from`, or reached through a certificate chain whose root is
   an account key the receiver has put on its allow-list (section 5). The chain's leaf subject must equal `from`
   (`IdentityMismatch` otherwise).
3. **The chain is current**: validity window, no revoked certificate, permission `send` present.
4. **Not a replay**: the replay-suppression record (spec 2026-09-17) for `(key_id, message_id)`.
5. **The account is allowed to speak to this recipient**: the receiver's own access rule (`docs/ACCESS_CONTROL_DESIGN.md`:
   `synapse:send` on `agent:dev@bob`, with `pm@alice` as principal). A valid signature says who sent it, never that they
   may.

The verdict is computed locally and is the only thing a lane is ever told. A lane sees "verified sender
`pm@alice`" or "unverified"; it never sees a claim.

### Room copies

A room message crosses two boundaries: sender to the room's **home daemon**, then home daemon to each member's daemon
(`docs/ROOMS_DESIGN.md` 11a). The fan-out copy must carry the **original sender's proof**, not a new one from the home
daemon, otherwise a member could only conclude "the home daemon says pm@alice wrote this". Two consequences:

- The proof covers `to`. For a room post the signed `to` is the room (`lounge@alice`), and a member checks the proof
  against that, plus its own membership record, rather than against its own address. The canonical input does not need to
  change; the receiver's rule changes: "the signed `to` is a room I am a member of".
- The home daemon may add a forwarding record (`routing_path` already exists and is deliberately unsigned) but cannot
  alter anything the signature covers. A home daemon that drops or reorders is a delivery fault, not a forgery.

## 4. Who signs

Two variants; both are viable, they differ in where the key lives and what a compromise costs.

**A. The Synapse MCP adapter signs with the role's own key.** The adapter runs beside the lane, loads the role key
(`keystore`), and signs each outbound cross-daemon message. The daemon relays without being able to forge.
- For: the daemon (and anything that compromises it) cannot impersonate a role; the signature is the role's.
- Against: every adapter holds a signing key in a user-readable file (section 6); the key must be present wherever the
  adapter runs; lanes that do not use the MCP adapter (`synapsectl`, the agent crate, a hand-written client) each need the
  same signing code.

**B. The daemon signs, with keys it holds for its roles.** The daemon already holds each role's session and, in its
home, the account material. It attests `from` today; signing makes that attestation portable.
- For: one implementation; clients stay thin; the daemon is already the authority for its account.
- Against: a compromised daemon can sign as any of its roles. Fine for the receiver's trust model if trust is placed in
  the *account* (the receiver allow-lists `alice`, not `pm@alice`); not fine if the receiver wants per-role assurance.

Recommendation: **B for the first federation slice, A kept possible**. Receivers allow-list accounts (section 5), so the
account's daemon vouching for its own roles is exactly the unit of trust being granted; the canonical input and the
verdict are the same either way, so moving to A later changes who holds the key, not the wire or the receiver. Whichever
is chosen, the receiver's code is the same `TrustStore::verify`.

## 5. Finding keys, and who is trusted

- **No single hosted authority.** There is no Synapse-run directory every account must use.
- **Each account may run its own auth-framework** (`docs/ACCESS_CONTROL_DESIGN.md` A2): it is the source of that
  account's grants and of the keys for its agent principals. Keys and grants come from agent principals there; certificates
  are not the long-term base (PM ruling), so the verification interface should ask "give me the key(s) for principal
  `pm@alice`" and not assume a certificate is in hand. Today's certificate chain is one implementation of that answer.
- **Discovery by name**: given `from = pm@alice`, the receiver finds the keys through `alice`'s own endpoint (the account
  name resolves to where that account publishes its account key and its revocation list). How the name resolves (DNS,
  a well-known URL, a configured address) is not decided here.
- **Trust is a local allow-list.** The receiving account lists the accounts it will believe (`pin_account_key` is the
  existing form: a key id and an operator label). An account not on the list yields `Unverifiable(UnknownIssuer)`, and
  the message goes nowhere. Adding an account is the receiving account holder's act, never a message's.
- **Vouching** (an account being trusted because accounts you trust trust it) would add entries to that allow-list by a
  rule. It is board 138 and is **not designed here**. This note only fixes that it feeds the same allow-list and does not
  change how a message is verified.

## 6. Weaknesses, stated

1. **Same-user file access.** A role key and the account key are files (`keystore`, 0600, owner-only on Unix). Any process
   running as the same OS user, including a compromised lane or tool, can read them and sign. Owner-only permissions stop
   other users, not the user's own processes. For variant A that means every lane's key is exposed to every process of the
   user; for B, the daemon's.
2. **Non-exportable keys are the real fix.** A TPM or the OS key store (Windows CNG/DPAPI, macOS Keychain, a platform
   secure element) can sign without ever releasing the key, so a compromised process can use the key while it runs but
   not carry it away. That needs a signer abstraction behind the keystore; none exists, and `ring`'s Ed25519 takes
   key bytes. Hardware support for Ed25519 varies, so the abstraction must allow another algorithm without changing the
   proof format (`ProofAlg` already names the algorithm).
3. **A signature proves origin, not behaviour.** `Verified` means the account's key signed it. A verified member can
   still post a prompt injection to every member of a room; the controls are rate and audience limits and moderation
   (`docs/ROOMS_DESIGN.md` 10), and untrusted framing on the receiving lane, not the signature.
4. **Revocation takes up to 60 seconds.** The access design's bound (CireSnave, `docs/ACCESS_CONTROL_DESIGN.md` 3.6) is a
   60 s cache for ordinary decisions, with sensitive ones checked live. A revoked certificate or removed allow-list entry
   can therefore still be honoured for up to a minute by a receiver that cached the answer. Fail closed when the source
   (the sender's account endpoint) cannot be reached: a live check is a deny; a cached one is served to the end of its
   60 s and then denied.
5. **A compromised account key is total for that account.** The account key signs every role certificate. The receiver's
   only remedy is to remove the account from its allow-list.
6. **Clock.** Certificate validity and replay windows depend on both sides' clocks; the existing freshness windows apply.

## 7. What is reusable as is

- `canonical_input` v1 and `SenderProof`: unchanged; the room rule in section 3 is a receiver rule, not a format change.
- `TrustStore` and `SenderVerdict`: the receiver side is already the right shape. The pinning calls are the local
  allow-list.
- Certificate chains, revocations, `validate_chain`: reusable as one source of keys; the principal-keyed lookup of
  section 5 should sit in front of them.
- Replay suppression and acknowledgement specs of 2026-09-17: reused per `(key_id, message_id)`.

**Not present, to be built when federation is scheduled:** a signer abstraction (section 6.2); the name-to-keys discovery;
the daemon-to-daemon transport and its authentication; presence propagation and home-daemon failover for rooms; a place for
the daemon to keep a per-peer-account allow-list and for `access.json`/A2 to be asked about a foreign principal.
