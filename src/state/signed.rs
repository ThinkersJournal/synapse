// SPDX-License-Identifier: MIT OR Apache-2.0
//! Client-signed writes (design: docs/superpowers/specs/2026-11-14-state-signed-writes.md, slice S7a).
//!
//! A writer signs the exact text built by [`signing_text`] with its role key; the daemon checks the
//! signature against the session's leaf key and the store keeps it in the history entry, inside the
//! hash chain. Everything here is pure: signing itself happens in the client, which holds the key.

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{Change, HistoryEntry};

/// First line of every signed text: a signature for another purpose can never be replayed as a write.
pub const WRITE_DOMAIN_TAG: &str = "synapse-state-write/1";
/// How far `signed_at` may be from the daemon's clock, in seconds (the same window a claim gets).
pub const WRITE_WINDOW_SECS: i64 = 120;

/// What a stored signature carries: enough to re-check it without the daemon.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteSig {
    /// The signer's `role@account`.
    pub signer: String,
    /// The daemon instance the write was signed for.
    pub audience: String,
    /// The Ed25519 public key (hex, 32 bytes): the leaf key the daemon verified at claim time.
    pub key: String,
    /// Hex, 16 bytes.
    pub nonce: String,
    pub signed_at: DateTime<Utc>,
    /// Hex, 64 bytes.
    pub signature: String,
}

/// How many of a record's history entries are signed, and whether the signatures hold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    /// Signed, and the signature verifies against the stored key and the entry's own content.
    pub signed: u32,
    /// No signature: written before S7, or by a client that did not sign.
    pub unsigned: u32,
    /// A signature is present and does NOT verify.
    pub bad: u32,
}

/// What one write signs, as the fields of [`signing_text`].
pub struct SignedWrite<'a> {
    pub signer: &'a str,
    pub audience: &'a str,
    /// `create` or `patch`.
    pub op: &'a str,
    /// The record id for a patch, `-` for a create.
    pub target: &'a str,
    /// The revision the patch was made against; 0 for a create.
    pub expected_revision: u64,
    /// [`body_hash`] of the new record or the patch.
    pub body_hash: &'a str,
    pub nonce: &'a str,
    pub signed_at: DateTime<Utc>,
}

/// The exact text a write signs.
#[must_use]
pub fn signing_text(w: &SignedWrite<'_>) -> String {
    format!(
        "{WRITE_DOMAIN_TAG}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        w.signer,
        w.audience,
        w.op,
        w.target,
        w.expected_revision,
        w.body_hash,
        w.nonce,
        w.signed_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

/// The body as sorted-key, whitespace-free JSON: what both sides hash, derived from the typed
/// value and never from the request's bytes.
#[must_use]
pub fn canonical_body<T: Serialize>(body: &T) -> String {
    let mut out = String::new();
    canonical(&serde_json::to_value(body).unwrap_or(Value::Null), &mut out);
    out
}

/// SHA-256 of [`canonical_body`], hex.
#[must_use]
pub fn body_hash<T: Serialize>(body: &T) -> String {
    hex(&Sha256::digest(canonical_body(body).as_bytes()))
}

#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// Does `signature` (hex) sign `text` under `key` (hex)?
#[must_use]
pub fn verify_text(key: &str, text: &str, signature: &str) -> bool {
    let (Some(key), Some(signature)) = (unhex(key), unhex(signature)) else {
        return false;
    };
    key.len() == 32
        && UnparsedPublicKey::new(&ED25519, &key)
            .verify(text.as_bytes(), &signature)
            .is_ok()
}

/// Is `signed_at` close enough to `now` to be a fresh write?
#[must_use]
pub fn fresh(signed_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    (now - signed_at).abs() <= Duration::seconds(WRITE_WINDOW_SECS)
}

/// The text this entry's signature must have signed, rebuilt from the entry alone.
fn entry_text(entry: &HistoryEntry, sig: &WriteSig) -> String {
    let (op, target, expected, hash) = match &entry.change {
        Change::Create(new) => ("create", "-", 0, body_hash(new)),
        Change::Patch(patch) => (
            "patch",
            entry.id.as_str(),
            entry.revision.saturating_sub(1),
            body_hash(patch),
        ),
    };
    signing_text(&SignedWrite {
        signer: &sig.signer,
        audience: &sig.audience,
        op,
        target,
        expected_revision: expected,
        body_hash: &hash,
        nonce: &sig.nonce,
        signed_at: sig.signed_at,
    })
}

/// Whether the entry's signature verifies against its own stored key and content. The writer's
/// role must also be the signer's role: a signature by another role's key is not this writer's.
#[must_use]
pub fn entry_signature_ok(entry: &HistoryEntry) -> bool {
    let Some(sig) = &entry.sig else {
        return false;
    };
    sig.signer.split('@').next() == Some(entry.writer.as_str())
        && verify_text(&sig.key, &entry_text(entry, sig), &sig.signature)
}

/// Count a record's history by signature state.
#[must_use]
pub fn summarize(history: &[HistoryEntry]) -> Signing {
    let mut out = Signing::default();
    for entry in history {
        match &entry.sig {
            None => out.unsigned += 1,
            Some(_) if entry_signature_ok(entry) => out.signed += 1,
            Some(_) => out.bad += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Caller, MemoryState, NewRecord, Patch, StateStore};
    use chrono::TimeZone;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 14, 12, 0, 0).unwrap()
    }

    fn caller() -> Caller {
        Caller {
            role: "alice".into(),
            write: true,
            admin: false,
            read_all: false,
            derive: false,
        }
    }

    fn key() -> Ed25519KeyPair {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
    }

    fn sign<T: Serialize>(
        pair: &Ed25519KeyPair,
        op: &str,
        target: &str,
        expected: u64,
        body: &T,
        signer: &str,
    ) -> WriteSig {
        let nonce = "00112233445566778899aabbccddeeff".to_string();
        let text = signing_text(&SignedWrite {
            signer,
            audience: "inst-1",
            op,
            target,
            expected_revision: expected,
            body_hash: &body_hash(body),
            nonce: &nonce,
            signed_at: now(),
        });
        WriteSig {
            signer: signer.into(),
            audience: "inst-1".into(),
            key: hex(pair.public_key().as_ref()),
            nonce,
            signed_at: now(),
            signature: hex(pair.sign(text.as_bytes()).as_ref()),
        }
    }

    fn new_record() -> NewRecord {
        serde_json::from_value(serde_json::json!({
            "title": "t", "parties": ["alice"], "owner": "alice"
        }))
        .unwrap()
    }

    #[test]
    fn golden_vectors_pin_the_canonical_bytes() {
        let patch: Patch = serde_json::from_value(
            serde_json::json!({"state": "waiting", "notes": "n", "title": "x"}),
        )
        .unwrap();
        assert_eq!(
            canonical_body(&patch),
            r#"{"notes":"n","state":"waiting","title":"x"}"#
        );
        assert_eq!(
            body_hash(&patch),
            hex(&Sha256::digest(
                br#"{"notes":"n","state":"waiting","title":"x"}"#
            ))
        );
        let text = signing_text(&SignedWrite {
            signer: "alice@acct",
            audience: "inst-1",
            op: "patch",
            target: "T-1",
            expected_revision: 3,
            body_hash: "ab",
            nonce: "cd",
            signed_at: now(),
        });
        assert_eq!(
            text,
            "synapse-state-write/1\nalice@acct\ninst-1\npatch\nT-1\n3\nab\ncd\n2026-11-14T12:00:00Z"
        );
    }

    #[test]
    fn a_signed_create_and_patch_verify_and_are_counted() {
        let pair = key();
        let store = MemoryState::in_memory();
        let new = new_record();
        let sig = sign(&pair, "create", "-", 0, &new, "alice@acct");
        store
            .create_signed(&caller(), new, Some(sig), now())
            .unwrap();
        let patch: Patch = serde_json::from_value(serde_json::json!({"notes": "hello"})).unwrap();
        let sig = sign(&pair, "patch", "T-1", 1, &patch, "alice@acct");
        store
            .patch_signed(&caller(), "T-1", 1, patch, Some(sig), now())
            .unwrap();
        // An unsigned write beside them.
        let patch: Patch = serde_json::from_value(serde_json::json!({"notes": "x"})).unwrap();
        store.patch(&caller(), "T-1", 2, patch, now()).unwrap();
        let history = store.history(&caller(), "T-1").unwrap();
        assert!(crate::state::verify_chain(&history).is_ok());
        assert_eq!(
            summarize(&history),
            Signing {
                signed: 2,
                unsigned: 1,
                bad: 0
            }
        );
    }

    /// A signature must break when ANY field of the signed text, or the body, changes.
    #[test]
    fn every_signed_field_matters() {
        let pair = key();
        let store = MemoryState::in_memory();
        let new = new_record();
        let sig = sign(&pair, "create", "-", 0, &new, "alice@acct");
        store
            .create_signed(&caller(), new, Some(sig), now())
            .unwrap();
        let entry = store.history(&caller(), "T-1").unwrap().remove(0);
        assert!(entry_signature_ok(&entry));
        type Mutation = Box<dyn Fn(&mut HistoryEntry)>;
        let mutate: [(&str, Mutation); 7] = [
            (
                "signer",
                Box::new(|e| e.sig.as_mut().unwrap().signer = "bob@acct".into()),
            ),
            (
                "audience",
                Box::new(|e| e.sig.as_mut().unwrap().audience = "inst-2".into()),
            ),
            (
                "nonce",
                Box::new(|e| e.sig.as_mut().unwrap().nonce = "00".repeat(16)),
            ),
            (
                "signed_at",
                Box::new(|e| e.sig.as_mut().unwrap().signed_at += Duration::seconds(1)),
            ),
            (
                "body",
                Box::new(|e| {
                    if let Change::Create(n) = &mut e.change {
                        n.title = "other".into();
                    }
                }),
            ),
            ("writer", Box::new(|e| e.writer = "bob".into())),
            (
                "key",
                Box::new(|e| e.sig.as_mut().unwrap().key = hex(key().public_key().as_ref())),
            ),
        ];
        for (name, f) in mutate {
            let mut e = entry.clone();
            f(&mut e);
            assert!(!entry_signature_ok(&e), "mutating {name} must break it");
        }
    }

    #[test]
    fn garbage_hex_and_a_missing_signature_never_verify() {
        assert!(!verify_text("zz", "t", "zz"));
        assert!(!verify_text(&"00".repeat(32), "t", &"00".repeat(64)));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("0aff"), Some(vec![10, 255]));
        assert!(fresh(now(), now() + Duration::seconds(WRITE_WINDOW_SECS)));
        assert!(!fresh(
            now(),
            now() + Duration::seconds(WRITE_WINDOW_SECS + 1)
        ));
        assert!(!fresh(
            now() + Duration::seconds(WRITE_WINDOW_SECS + 1),
            now()
        ));
    }

    /// An entry written before S7 has no `sig`: it hashes as it always did and still verifies.
    #[test]
    fn an_unsigned_chain_keeps_its_old_hash() {
        let store = MemoryState::in_memory();
        store.create(&caller(), new_record(), now()).unwrap();
        let history = store.history(&caller(), "T-1").unwrap();
        let json = serde_json::to_string(&history[0]).unwrap();
        assert!(!json.contains("\"sig\""), "{json}");
        assert!(crate::state::verify_chain(&history).is_ok());
    }
}
