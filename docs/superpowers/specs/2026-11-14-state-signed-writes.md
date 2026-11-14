<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Shared state: client-signed writes (design, S7, not built)

Written 2026-11-14 against `origin/main@b85949cc`. Slice S7 of ROW 30; parent design
`2026-10-23-shared-state-design.md` section 8 ("Signed writes") and section 11 (S7 exit test: *a write whose
signature does not match the session's role is refused*). S1-S6 are merged. Nothing here is built.

## 1. Problem

Today a history entry names `writer` because the **daemon** says the session's role wrote it (S1). Anyone who
can edit `state.redb`, or a bug in the daemon, can forge a writer and re-hash the chain, because the chain proves
only that entries were not edited *without* recomputing it. S7 makes each entry carry the writer's own Ed25519
signature, so a reader can check who wrote what **without trusting the daemon**.

## 2. What is signed

A new domain-tagged text, in the style of `roles::claim_signing_input_v2`:

```
synapse-state-write/1
<global_id>                 role@account of the writer (the session's)
<audience>                  the daemon's instance id (no replay against another daemon)
<op>                        create | patch
<target>                    the record id for patch, "-" for create
<expected_revision>         u64 for patch, 0 for create
<sha256 of the canonical body, hex>
<nonce hex, 16 bytes>
<signed_at RFC3339, seconds>
```

The **canonical body** is the `NewRecord` (create) or `Patch` (patch) re-serialised with sorted keys, no
whitespace, UTF-8, absent fields omitted: the daemon rebuilds it from what it parsed, never from the request's
bytes, so the client and daemon agree because both derive it from the typed value. A golden-vector test pins the
bytes (one per op) so a serde upgrade that reorders fields fails loudly.

## 3. Verification, replay, and the key

- The session already proved the role key at claim time. It additionally keeps the **leaf public key** from the
  validated chain (a `[u8; 32]` in `Session`); a re-claim replaces the session and its key. No new key store.
- The signature is checked against that key, **and** the signed `global_id` must equal the session's: a signature
  by another role's key, or one naming another role, is `forbidden` (and a `state_denied` security event, as for
  any refusal).
- **Replay.** A `patch` names `expected_revision`, so a replayed patch fails `stale_revision`: the revision moved.
  A `create` has no revision, so it uses the claim's rules: `signed_at` inside a freshness window (120 s) and at
  or after the daemon's start, plus a nonce accepted once (the existing nonce table's shape; in memory, as the
  claim's is). After a restart the freshness rule alone covers it, as for claims.
- Canonical-body and audience binding stop a signature being reused for a different patch or daemon.

## 4. What is stored

`HistoryEntry` gains `sig: Option<WriteSig { key: [u8;32] hex, nonce, signed_at, signature }>`.

- It is **inside the hash**: `HashInput` includes `sig` only when present (`skip_serializing_if`), so entries
  written before S7 hash exactly as before and every existing chain still verifies. A tampered signature breaks
  the chain.
- `verify_chain` stays as is. A new `verify_signatures(history, trust)` recomputes each entry's signing text from
  the entry (it holds `change`, `writer`, revision) and checks `sig` against `sig.key`; `trust(writer, key)` says
  whether that key belongs to that role (a keystore lookup of the pinned account-signed certificate). It returns
  the first entry that fails, or the list of unsigned entries, so "unsigned" is a visible state and never read as
  "fine".
- `synapse state history` and the S6 export show a `signed` flag per entry and call a record whose entries are
  not all signed `PARTLY SIGNED`; an unverifiable signature is called out the same way `STALE` is.

## 5. Where signing happens (the three bindings)

The signer is `synapsed_client`, next to the claim code, taking a `RoleIdentity` from the home, so no binding
gets its own crypto:

- `Daemon::state_create_signed` / `state_patch_signed` build the text, sign, and add `"sig": {nonce, signed_at,
  signature_b64}` to the request body.
- The CLI (`synapse state new|set`) calls them by default when the home holds the role's key.
- The MCP adapter and the channel adapter have the home and the role in their config, so they sign the same way
  when they gain write tools (`state_create`, `state_patch`: not part of S7; S5 shipped read tools only).
- The daemon route takes `sig` as optional (phase 1) and verifies it when present.

## 6. Phases and the decision this needs

- **Phase 1 (S7a):** signing code, `sig` accepted and stored, CLI signs by default, unsigned still accepted and
  recorded as unsigned. Exit tests: S7's (a mismatched signature is refused) plus a mutation that breaks each of
  the signing text's fields, golden vectors, replay of a signed create, an old-format chain still verifying.
- **Phase 2 (S7b):** a daemon setting `state.require_signed_writes` (env `SYNAPSE_STATE_REQUIRE_SIGNED`, file key
  `state.require_signed`) makes unsigned writes `forbidden`. It is off until every writer signs, or the pilot
  would lock lanes out of the board.

**Decision for the PM (or CireSnave):** the parent design says S7 *adds* the client signature but not whether
unsigned writes stay allowed. Recommended: phase 1 now, phase 2 only after the CLI and both adapters sign and a
week of the board shows no unsigned entry. Alternative: required from the first release (simpler contract, but
the checker and every lane must be upgraded in one step).

## 7. Out of scope

Signing `put_facts` (the checker is a single role with `state-derive`; its observations are already attributed by
`observed_by`, and a follow-up can sign them the same way); signing outbox notices (ids only, nothing to forge);
key rotation across history (an old entry keeps the key it was signed with, which is why the key is stored in it).
