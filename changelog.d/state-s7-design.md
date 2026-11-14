Docs: design for client-signed state writes (ROADMAP row 30, S7)

`docs/superpowers/specs/2026-11-14-state-signed-writes.md`: what the writer signs (domain-tagged text binding role, daemon instance, op, target, expected revision, a canonical-body hash, nonce and time), how the daemon verifies it against the session's leaf key, how replay is stopped, how the signature joins the hash chain without breaking existing chains, where the three bindings sign, and a two-phase rollout (optional, then required) that needs one decision from the PM. Design only; nothing is built.
