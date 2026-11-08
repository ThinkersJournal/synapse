// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sender authentication for [`SecureMessage`](crate::types::SecureMessage).
//!
//! Every message carries a mandatory [`SenderProof`]. A receiver turns the proof plus keys it
//! pinned itself into exactly one [`SenderVerdict`]; the verdict is never read from the wire.
//! Design: `docs/superpowers/specs/2026-09-17-sender-authentication-design.md`.

use crate::certificate::{
    self, Revocation, RevocationLookup, VerifiedChain, chain_from_pem, validate_chain,
};
use crate::error::{CryptoError, Result};
use crate::types::{SecureMessage, SecurityLevel};
use chrono::{DateTime, Timelike, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

/// The signature algorithm a sender used. Any other value fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofAlg {
    /// The sender had no key. Receivers mark the message `Unverifiable(Unsigned)`.
    #[default]
    None,
    /// Ed25519 over [`canonical_input`] v1.
    Ed25519,
}

/// The sender's claim of authorship. Mandatory on the wire: a message without it does not parse.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SenderProof {
    pub alg: ProofAlg,
    /// Lowercase hex SHA-256 of the signer's 32-byte public key; empty when `alg` is `None`.
    pub key_id: String,
    /// 64 bytes for Ed25519; empty when `alg` is `None`.
    pub sig: Vec<u8>,
}

impl SenderProof {
    /// An explicit "no signature" proof.
    pub fn unsigned() -> Self {
        Self::default()
    }
}

/// Domain-separation tag: the first field of canonical input v1.
pub const CANONICAL_DOMAIN_TAG: &[u8] = b"synapse/sender-proof/v1";

/// Lowercase hex SHA-256 of an Ed25519 public key.
pub fn key_id(public_key: &[u8; 32]) -> String {
    to_hex(&Sha256::digest(public_key))
}

/// Lowercase hex.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The serde name of a security level. The match is exhaustive, so a new variant fails to compile
/// here instead of silently signing a wrong name.
pub(crate) fn security_level_name(level: &SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::Public => "public",
        SecurityLevel::Private => "private",
        SecurityLevel::Authenticated => "authenticated",
        SecurityLevel::Secure => "secure",
    }
}

pub(crate) fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("a signed field longer than 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The bytes a sender signs (spec §4, v1). Each field is a 4-byte big-endian length followed by
/// its bytes, in this order: domain tag, `protocol_version` (2 raw bytes, big-endian),
/// `message_id` (16 raw bytes), `from_global_id`, `to_global_id`, timestamp (Unix microseconds, i64
/// BE), `security_level` (serde name), `sender_proof.key_id`, SHA-256(`encrypted_content`),
/// metadata. The metadata field's bytes are a 4-byte count followed by each (key, value) pair, each
/// length-prefixed, sorted by key bytes.
///
/// `protocol_version` sits immediately after the domain tag so a relay that rewrites it (for
/// example to downgrade two peers to an older wire format) invalidates the signature.
///
/// **`protocol_version` was added to this layout before 2.0 was published** (transport-contract,
/// Task 5) -- this changes the signed bytes, so a message or ack signed before this change does
/// not verify after it. Acceptable as part of 2.0's single wire break. The domain tag stays
/// `synapse/sender-proof/v1`: the old (9-field) and new (10-field) layouts cannot be confused,
/// since they differ at the first byte after the tag, and no published release ever produced the
/// old layout.
///
/// `routing_path` is NOT covered: relays append to it.
pub fn canonical_input(message: &SecureMessage) -> Vec<u8> {
    let mut out = Vec::new();
    put(&mut out, CANONICAL_DOMAIN_TAG);
    put(&mut out, &message.protocol_version.to_be_bytes());
    put(&mut out, message.message_id.0.as_bytes());
    put(&mut out, message.from_global_id.as_bytes());
    put(&mut out, message.to_global_id.as_bytes());
    put(
        &mut out,
        &message.timestamp.0.timestamp_micros().to_be_bytes(),
    );
    put(
        &mut out,
        security_level_name(&message.security_level).as_bytes(),
    );
    put(&mut out, message.sender_proof.key_id.as_bytes());
    put(&mut out, &Sha256::digest(&message.encrypted_content));

    let mut pairs: Vec<(&String, &String)> = message.metadata.iter().collect();
    pairs.sort();
    let count = u32::try_from(pairs.len()).expect("more than 4 GiB metadata pairs");
    let mut metadata = count.to_be_bytes().to_vec();
    for (key, value) in pairs {
        put(&mut metadata, key.as_bytes());
        put(&mut metadata, value.as_bytes());
    }
    put(&mut out, &metadata);
    out
}

/// Drop sub-microsecond digits so the wire timestamp and the signed timestamp agree exactly.
/// Python's `datetime` holds only microseconds (spec §4).
pub fn truncate_timestamp_to_micros(message: &mut SecureMessage) {
    let ts = message.timestamp.0;
    let nanos = ts.nanosecond();
    message.timestamp.0 = ts
        .with_nanosecond(nanos - nanos % 1_000)
        .expect("a smaller nanosecond value is always valid");
}

pub(crate) fn has_sub_micro_digits(message: &SecureMessage) -> bool {
    !message.timestamp.0.nanosecond().is_multiple_of(1_000)
}

/// What a receiver concluded about a message's sender. Computed locally; never read from the wire.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderVerdict {
    Verified { key_id: String },
    Unverifiable { reason: UnverifiableReason },
    Contradicted { reason: ContradictedReason },
}

impl SenderVerdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, SenderVerdict::Verified { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableReason {
    /// `protocol_version` is not in [`crate::types::SUPPORTED_PROTOCOL_VERSIONS`]. Checked first,
    /// before any other interpretation of the message -- including the signature itself, since an
    /// unsupported version may not even mean what this build assumes it means.
    UnsupportedVersion,
    /// The sender declared `alg: none`.
    Unsigned,
    /// No key is pinned for `from_global_id`, and the message carries no certificate chain.
    UnknownSender,
    /// The chain's root names an account key that is not pinned. No signature in the chain is
    /// checked before this verdict is reached.
    UnknownIssuer,
    /// The chain parsed but failed [`validate_chain`]'s rules (or named a revoked certificate).
    InvalidChain,
    /// The chain text or its certificate count exceeds the trust store's bounds.
    ChainTooLarge,
    /// The chain route validated, but the leaf's permissions do not include
    /// [`crate::certificate::Permission::Send`]. Direct pinning has no certificate and so no
    /// permissions to check; this applies only to the chain route.
    NoSendPermission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContradictedReason {
    /// The timestamp has sub-microsecond digits, which v1 never signs.
    NonCanonicalTimestamp,
    /// The proof names a key other than the one pinned for this sender.
    KeyMismatch,
    /// The signature is malformed or does not verify against the pinned key.
    BadSignature,
    /// A certificate chain verified, but for a different `subject_global_id` than the message
    /// claims as `from_global_id`. The leaf's signer is not in question -- it just is not who the
    /// message says it is.
    IdentityMismatch,
}

/// An account key pinned by its `key_id`, with the operator's own label kept only for reporting
/// (never for lookup, and never printed with the key itself).
#[derive(Clone)]
struct AccountKeyEntry {
    key: [u8; 32],
    label: String,
}

impl fmt::Debug for AccountKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeyEntry")
            .field("label", &self.label)
            .finish()
    }
}

/// Ed25519 public keys pinned out of band, by global id. Nothing in a received message can add or
/// change an entry.
#[derive(Debug, Clone)]
pub struct TrustStore {
    keys: HashMap<String, [u8; 32]>,
    /// X25519 sealing keys (P2 slice d), pinned separately from the signing keys.
    sealing: HashMap<String, crate::sealing::SealingPublicKey>,
    /// Pinned account keys, by `key_id`. A chain whose root names one of these is trusted for
    /// however many agents that account signs certificates for.
    account_keys: HashMap<String, AccountKeyEntry>,
    /// Accepted revocations, keyed by issuer `key_id` and then by serial. Keying on the issuer as
    /// well as the serial means one pinned account can never evict another's entries: serials are
    /// visible in any chain, so without this any pinned account could silently un-trust another's
    /// agents (`validate_chain` separately allows an account key to revoke anything in its own
    /// subtree, not only what it issued directly -- see `resolve_chain`).
    revocations: HashMap<String, HashMap<[u8; 16], Revocation>>,
    /// A chain's PEM text longer than this is refused before parsing.
    pub max_chain_bytes: usize,
    /// A parsed chain with more certificates than this is refused before any signature in it is
    /// checked.
    pub max_chain_links: usize,
}

/// At most this many revocations are held for a single issuer; the oldest of that issuer's by
/// `issued_at` is evicted beyond it.
const MAX_REVOCATIONS_PER_ISSUER: usize = 512;
/// At most this many revocations are held overall; the oldest by `issued_at` is evicted beyond it.
const MAX_REVOCATIONS: usize = 4096;

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            sealing: HashMap::new(),
            account_keys: HashMap::new(),
            revocations: HashMap::new(),
            max_chain_bytes: 16 * 1024,
            max_chain_links: 64,
        }
    }
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin an account key under a caller-chosen label (kept only for reporting; lookup is always
    /// by `key_id`). A chain rooted in this key becomes trusted for any agent it certifies -- in
    /// plain terms, pinning an account key means that account holder may speak as ANY identity
    /// this node has not directly pinned, not merely the agents it happens to know about today. A
    /// directly pinned identity always wins outright and can never be claimed by a chain, no
    /// matter which account key roots it (see [`TrustStore::verify_at`]).
    pub fn pin_account_key(&mut self, label: impl Into<String>, key: [u8; 32]) {
        self.account_keys.insert(
            key_id(&key),
            AccountKeyEntry {
                key,
                label: label.into(),
            },
        );
    }

    /// Pin an account key in the PEM form `CryptoManager::get_public_key_pem` produces.
    pub fn pin_account_key_pem(&mut self, label: &str, pem: &str) -> Result<()> {
        let block = pem::parse(pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = block.contents().try_into().map_err(|_| {
            CryptoError::InvalidKey("Ed25519 public key must be exactly 32 bytes".to_string())
        })?;
        self.pin_account_key(label, key);
        Ok(())
    }

    /// The `key_id` of every pinned account key.
    pub fn account_key_ids(&self) -> Vec<String> {
        self.account_keys.keys().cloned().collect()
    }

    /// Why `revocation` is refused as foreign or forged: `unsupported_version`, `unknown_issuer` or
    /// `bad_signature`. `None` when it is acceptable; a duplicate is acceptable here, because it is
    /// not a failure.
    fn revocation_refusal(&self, revocation: &Revocation) -> Option<&'static str> {
        if revocation.version != 1 {
            return Some("unsupported_version");
        }
        let Some(entry) = self.account_keys.get(&revocation.issuer_key_id) else {
            return Some("unknown_issuer");
        };
        if !revocation.verify_signature(&entry.key) {
            return Some("bad_signature");
        }
        None
    }

    /// Accept `revocation` if its issuer is a pinned account key, its signature verifies against
    /// that key, and its `(issuer_key_id, serial)` is not already held. Returns whether it was
    /// stored. Before inserting, evicts that issuer's oldest `issued_at` entry once that issuer is
    /// already at [`MAX_REVOCATIONS_PER_ISSUER`], and (once the store is already at
    /// [`MAX_REVOCATIONS`] overall) the oldest entry belonging to whichever issuer currently holds
    /// the most, so one busy issuer cannot cost another issuer its own revocations -- always from
    /// the existing entries, never the one about to be inserted.
    pub fn add_revocation(&mut self, revocation: Revocation) -> bool {
        matches!(self.try_add_revocation(revocation), Ok(true))
    }

    /// As [`Self::add_revocation`], but says why a revocation was refused: `Err` names a foreign or
    /// forged one (`unsupported_version`, `unknown_issuer`, `bad_signature`); `Ok(false)` is a
    /// duplicate, which is not a failure; `Ok(true)` means it was stored.
    pub fn try_add_revocation(
        &mut self,
        revocation: Revocation,
    ) -> std::result::Result<bool, &'static str> {
        if let Some(reason) = self.revocation_refusal(&revocation) {
            return Err(reason);
        }
        let issuer = revocation.issuer_key_id.clone();
        if self
            .revocations
            .get(&issuer)
            .is_some_and(|bucket| bucket.contains_key(&revocation.serial))
        {
            return Ok(false);
        }

        if let Some(bucket) = self.revocations.get(&issuer)
            && bucket.len() >= MAX_REVOCATIONS_PER_ISSUER
            && let Some(oldest) = bucket
                .iter()
                .min_by_key(|(_, r)| r.issued_at)
                .map(|(serial, _)| *serial)
        {
            self.revocations
                .get_mut(&issuer)
                .expect("just read")
                .remove(&oldest);
        }

        let total: usize = self.revocations.values().map(HashMap::len).sum();
        if total >= MAX_REVOCATIONS
            && let Some(biggest_issuer) = self
                .revocations
                .iter()
                .max_by_key(|(_, bucket)| bucket.len())
                .map(|(issuer, _)| issuer.clone())
            && let Some(oldest) = self.revocations[&biggest_issuer]
                .iter()
                .min_by_key(|(_, r)| r.issued_at)
                .map(|(serial, _)| *serial)
        {
            self.revocations
                .get_mut(&biggest_issuer)
                .expect("just read")
                .remove(&oldest);
        }

        self.revocations
            .entry(issuer)
            .or_default()
            .insert(revocation.serial, revocation);
        Ok(true)
    }

    /// Whether a certificate serial has been revoked by that same issuer.
    pub fn is_revoked(&self, issuer_key_id: &str, serial: &[u8; 16]) -> bool {
        self.revocations
            .get(issuer_key_id)
            .is_some_and(|bucket| bucket.contains_key(serial))
    }

    /// How many revocations are currently held, across all issuers.
    pub fn revocation_count(&self) -> usize {
        self.revocations.values().map(HashMap::len).sum()
    }

    /// Steps 3-6 of [`TrustStore::verify`]'s chain route: bound the chain's size before parsing,
    /// bound its link count before any signature is checked, refuse an unpinned root without
    /// verifying any signature in the chain, then hand it to [`validate_chain`] at `now`.
    fn resolve_chain(
        &self,
        chain_text: &str,
        now: DateTime<Utc>,
    ) -> std::result::Result<VerifiedChain, UnverifiableReason> {
        if chain_text.len() > self.max_chain_bytes {
            return Err(UnverifiableReason::ChainTooLarge);
        }
        let chain = chain_from_pem(chain_text).map_err(|_| UnverifiableReason::InvalidChain)?;
        if chain.len() > self.max_chain_links {
            return Err(UnverifiableReason::ChainTooLarge);
        }
        // `chain_from_pem` never returns an empty vec on success, but this stays honest rather
        // than indexing on that assumption.
        let root = chain.last().ok_or(UnverifiableReason::InvalidChain)?;
        if !self.account_keys.contains_key(&root.issuer_key_id) {
            return Err(UnverifiableReason::UnknownIssuer);
        }
        let account_keys = &self.account_keys;
        let lookup = move |id: &str| account_keys.get(id).map(|entry| entry.key);
        validate_chain(&chain, &lookup, self, now).map_err(|_| UnverifiableReason::InvalidChain)
    }

    /// The account key id the message's chain names as its root, for the trust book (ROADMAP row 33):
    /// what a holder would pin. It parses the chain within the store's own size and link bounds and
    /// checks nothing else, no signature and no pin, so it is safe to call for a stranger's message
    /// and its answer is only a claim. `None` for a message with no chain or an unparseable or
    /// oversized one.
    pub fn chain_root_key_id(&self, message: &SecureMessage) -> Option<String> {
        let chain_text = message.metadata.get(certificate::CHAIN_KEY)?;
        if chain_text.len() > self.max_chain_bytes {
            return None;
        }
        let chain = chain_from_pem(chain_text).ok()?;
        if chain.len() > self.max_chain_links {
            return None;
        }
        chain.last().map(|root| root.issuer_key_id.clone())
    }

    /// The verified chain summary a certificate chain WOULD grant if the sender proved possession
    /// of the leaf's private key -- it does NOT check the message's own signature, so it can
    /// return `Some` for a message whose signature `verify` would reject. Never present its
    /// contents as this message's authenticated sender unless `verify` (or `verify_at`, at the
    /// same `now`) returned `Verified` for the same message. `None` for any reason `verify`'s
    /// chain route would reject it, including one with no chain at all.
    pub fn verified_chain(&self, message: &SecureMessage) -> Option<VerifiedChain> {
        self.verified_chain_at(message, Utc::now())
    }

    /// [`TrustStore::verified_chain`], at a caller-supplied clock instead of the wall clock.
    pub fn verified_chain_at(
        &self,
        message: &SecureMessage,
        now: DateTime<Utc>,
    ) -> Option<VerifiedChain> {
        let chain_text = message.metadata.get(certificate::CHAIN_KEY)?;
        self.resolve_chain(chain_text, now).ok()
    }

    pub fn pin(&mut self, global_id: impl Into<String>, public_key: [u8; 32]) {
        self.keys.insert(global_id.into(), public_key);
    }

    /// Pin a key in the PEM form `CryptoManager::get_public_key_pem` produces.
    pub fn pin_pem(&mut self, global_id: &str, pem: &str) -> Result<()> {
        let block = pem::parse(pem).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = block.contents().try_into().map_err(|_| {
            CryptoError::InvalidKey("Ed25519 public key must be exactly 32 bytes".to_string())
        })?;
        self.pin(global_id, key);
        Ok(())
    }

    /// Pin a peer's X25519 sealing key.
    pub fn pin_sealing_key(
        &mut self,
        global_id: impl Into<String>,
        key: crate::sealing::SealingPublicKey,
    ) {
        self.sealing.insert(global_id.into(), key);
    }

    /// Pin a peer's X25519 sealing key from a SubjectPublicKeyInfo PEM.
    pub fn pin_sealing_key_pem(&mut self, global_id: &str, pem: &str) -> Result<()> {
        let key = crate::sealing::SealingPublicKey::from_spki_pem(pem)?;
        self.pin_sealing_key(global_id, key);
        Ok(())
    }

    /// The sealing key pinned for `global_id`.
    pub fn sealing_key_for(&self, global_id: &str) -> Option<&crate::sealing::SealingPublicKey> {
        self.sealing.get(global_id)
    }

    /// The id of the sealing key pinned for `global_id`.
    pub fn sealing_key_id(&self, global_id: &str) -> Option<String> {
        self.sealing.get(global_id).map(|key| key.key_id())
    }

    pub fn is_pinned(&self, global_id: &str) -> bool {
        self.keys.contains_key(global_id)
    }

    /// The `key_id` of the key pinned for `global_id`.
    pub fn pinned_key_id(&self, global_id: &str) -> Option<String> {
        self.keys.get(global_id).map(key_id)
    }

    /// Spec §5, extended by the P2f1 chain route (task-3 brief): a key pinned for
    /// `from_global_id` still wins outright and behaves exactly as before; only when there is none
    /// does a certificate chain rooted in a pinned account key get a chance to verify the sender.
    pub fn verify(&self, message: &SecureMessage) -> SenderVerdict {
        self.verify_at(message, Utc::now())
    }

    /// [`TrustStore::verify`], at a caller-supplied clock instead of the wall clock -- so an
    /// expiry boundary can be tested without racing the real clock, and so one delivered message
    /// gets one answer no matter how many times it is checked.
    pub fn verify_at(&self, message: &SecureMessage, now: DateTime<Utc>) -> SenderVerdict {
        // Checked before anything else: an unsupported version may not even mean what this build
        // assumes it means, so nothing downstream -- not the timestamp check, not the signature --
        // may be trusted to interpret the message correctly. Refused by name, never as a parse
        // failure.
        if !crate::types::SUPPORTED_PROTOCOL_VERSIONS.contains(&message.protocol_version) {
            return SenderVerdict::Unverifiable {
                reason: UnverifiableReason::UnsupportedVersion,
            };
        }

        // A non-canonical timestamp is outside the signed bytes on every route (direct pin or
        // chain), so it must be caught before either route runs: otherwise a relay could add
        // sub-microsecond digits to a chain-routed message and see it verify anyway.
        if message.sender_proof.alg == ProofAlg::Ed25519 && has_sub_micro_digits(message) {
            return SenderVerdict::Contradicted {
                reason: ContradictedReason::NonCanonicalTimestamp,
            };
        }

        if let Some(pinned) = self.keys.get(&message.from_global_id) {
            return Self::verify_against_pinned_key(message, pinned);
        }

        let Some(chain_text) = message.metadata.get(certificate::CHAIN_KEY) else {
            // No certificate to fall back on: an explicit "no algorithm" proof is `Unsigned`
            // (today's behaviour, unchanged), and any other unrecognised sender is `UnknownSender`.
            return match message.sender_proof.alg {
                ProofAlg::None => SenderVerdict::Unverifiable {
                    reason: UnverifiableReason::Unsigned,
                },
                ProofAlg::Ed25519 => SenderVerdict::Unverifiable {
                    reason: UnverifiableReason::UnknownSender,
                },
            };
        };

        let verified = match self.resolve_chain(chain_text, now) {
            Ok(verified) => verified,
            Err(reason) => return SenderVerdict::Unverifiable { reason },
        };

        // `alg: none` asserts nothing -- there is no failed signature to be `Contradicted` about,
        // only an absent one. Spec rule 1 puts "no signature" ahead of every other rule that
        // depends on the signature, including the identity check just below, and it matters
        // operationally: `Contradicted` is always dropped, while `Unverifiable` is delivered under
        // `accept_unverified`. This runs before the identity check so both routes (direct-pin and
        // chain) agree on precedence.
        if message.sender_proof.alg == ProofAlg::None {
            return SenderVerdict::Unverifiable {
                reason: UnverifiableReason::Unsigned,
            };
        }

        // The chain authenticates a subject id; the message merely claims one in
        // `from_global_id`. Without this check, any agent under a pinned account could send as
        // any id it likes -- another account's namespace, or its own account holder's -- simply
        // by not using its narrowed id, making identity-narrowing dead on the receive path.
        if verified.subject_global_id != message.from_global_id {
            return SenderVerdict::Contradicted {
                reason: ContradictedReason::IdentityMismatch,
            };
        }

        // The pinned route binds `sender_proof.key_id` to the pinned key before checking the
        // signature (`verify_against_pinned_key`); the chain route must do the same against the
        // leaf's signing key. The verdict below is safe either way, since it is recomputed from
        // the chain rather than trusting the proof's `key_id` -- but the raw proof still travels
        // on `ReceivedMessage`, and `receive_messages` hands `sender_proof.key_id` to the gate for
        // knock attribution. Without this check a chain-routed sender could put any key_id in its
        // own proof and control what gets recorded about it in another peer's knock records.
        if message.sender_proof.key_id != key_id(&verified.subject_signing_key) {
            return SenderVerdict::Contradicted {
                reason: ContradictedReason::KeyMismatch,
            };
        }

        // The one permission Synapse itself enforces: a validated leaf that was never granted
        // `send` may not originate a message, no matter how valid the rest of its chain is.
        // Checked here (not in the transport) so every consumer of `verify_at` -- an adapter
        // included -- inherits it from the single verdict path.
        if !verified
            .permissions
            .contains(&certificate::Permission::Send)
        {
            return SenderVerdict::Unverifiable {
                reason: UnverifiableReason::NoSendPermission,
            };
        }

        // The chain is valid and names the right subject, but that alone proves nothing about who
        // signed this message: the sender must also hold the leaf's private key. A chain paired
        // with any other signature has no innocent reading.
        match UnparsedPublicKey::new(&ED25519, &verified.subject_signing_key)
            .verify(&canonical_input(message), &message.sender_proof.sig)
        {
            Ok(()) => SenderVerdict::Verified {
                key_id: key_id(&verified.subject_signing_key),
            },
            Err(_) => SenderVerdict::Contradicted {
                reason: ContradictedReason::BadSignature,
            },
        }
    }

    /// Today's direct-pin verification, unchanged: a message from a sender whose key is pinned
    /// directly must behave exactly as it did before certificates existed. The non-canonical
    /// timestamp guard now runs once, in `verify_at`, ahead of this and the chain route alike.
    fn verify_against_pinned_key(message: &SecureMessage, pinned: &[u8; 32]) -> SenderVerdict {
        let proof = &message.sender_proof;
        match proof.alg {
            ProofAlg::None => {
                return SenderVerdict::Unverifiable {
                    reason: UnverifiableReason::Unsigned,
                };
            }
            ProofAlg::Ed25519 => {}
        }
        let pinned_id = key_id(pinned);
        if proof.key_id != pinned_id {
            return SenderVerdict::Contradicted {
                reason: ContradictedReason::KeyMismatch,
            };
        }
        if proof.sig.len() != 64 {
            return SenderVerdict::Contradicted {
                reason: ContradictedReason::BadSignature,
            };
        }
        match UnparsedPublicKey::new(&ED25519, pinned).verify(&canonical_input(message), &proof.sig)
        {
            Ok(()) => SenderVerdict::Verified { key_id: pinned_id },
            Err(_) => SenderVerdict::Contradicted {
                reason: ContradictedReason::BadSignature,
            },
        }
    }
}

impl RevocationLookup for TrustStore {
    fn is_revoked(&self, issuer_key_id: &str, serial: &[u8; 16]) -> bool {
        TrustStore::is_revoked(self, issuer_key_id, serial)
    }
}

/// Test-only convenience: a manager with a freshly generated Ed25519 keypair, so cert/chain tests
/// don't have to thread key generation through by hand.
#[cfg(test)]
impl crate::crypto::CryptoManager {
    pub(crate) fn new_with_keypair() -> Self {
        let mut manager = Self::new();
        manager.generate_keypair().expect("keypair generation");
        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoManager;
    use crate::types::SecurityLevel;
    use chrono::DateTime;
    use ed25519_dalek::SigningKey;

    /// A time comfortably inside a freshly minted test certificate's validity window.
    fn t_now() -> DateTime<Utc> {
        Utc::now()
    }

    /// A one-link certificate: `account` vouches for `agent`'s signing (and an unused sealing) key
    /// under `subject_id`, valid for an hour either side of `now`.
    fn signed_cert_for(
        account: &SigningKey,
        agent: &CryptoManager,
        subject_id: &str,
        now: DateTime<Utc>,
    ) -> certificate::AgentCertificate {
        let unsigned = certificate::AgentCertificate {
            version: 1,
            serial: [7u8; 16],
            issuer_key_id: key_id(&account.verifying_key().to_bytes()),
            subject_label: "test agent".to_string(),
            subject_global_id: subject_id.to_string(),
            subject_signing_key: agent.public_key_bytes().expect("agent has a public key"),
            subject_sealing_key: [9u8; 32],
            not_before: now - chrono::Duration::hours(1),
            not_after: now + chrono::Duration::hours(1),
            permissions: vec![certificate::Permission::Send],
            may_delegate: 0,
            signature: [0u8; 64],
        };
        certificate::AgentCertificate::sign(unsigned, account)
    }

    /// A revocation for `serial`, signed by `account`.
    fn signed_revocation(account: &SigningKey, serial: [u8; 16]) -> Revocation {
        let unsigned = Revocation {
            version: 1,
            serial,
            issuer_key_id: key_id(&account.verifying_key().to_bytes()),
            issued_at: t_now(),
            reason: "test".to_string(),
            signature: [0u8; 64],
        };
        Revocation::sign(unsigned, account)
    }

    #[test]
    fn a_pinned_account_key_verifies_an_agent_it_has_never_seen() {
        // Alice's account key signs a certificate for an agent key; Bob pins only the account key.
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert!(store.verify(&message).is_verified());
        let chain = store.verified_chain(&message).expect("a summary");
        assert_eq!(chain.subject_global_id, "agent@alice.test");
        assert_eq!(chain.links, 1);

        // Control: with the account key unpinned, the same message is unverifiable.
        assert_eq!(
            TrustStore::new().verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::UnknownIssuer
            }
        );
    }

    #[test]
    fn a_chain_with_too_many_links_is_refused() {
        // A resource guard: 65 links exceeds the default max_chain_links of 64. The certificates do
        // not need to be valid — the refusal happens before any of them is verified.
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let one = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        let chain: Vec<_> = std::iter::repeat_with(|| one.clone()).take(65).collect();
        agent.set_certificate_chain(chain);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::ChainTooLarge
            }
        );
    }

    #[test]
    fn an_oversized_chain_is_refused_without_parsing() {
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        message.add_metadata(certificate::CHAIN_KEY, "A".repeat(17 * 1024));
        let store = TrustStore::new();
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::ChainTooLarge
            }
        );
    }

    #[test]
    fn a_chain_that_does_not_match_the_signing_key_is_contradicted() {
        // The chain is valid, but the message is signed by a different key than the leaf names.
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let agent = CryptoManager::new_with_keypair();
        let mut impostor = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        // The impostor carries and signs with Alice's chain, but the signature is the impostor's
        // own -- exactly the scenario this test checks.
        impostor.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        impostor.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        // FIX 4 (P2f1 fix wave): the chain route now binds `sender_proof.key_id` to the leaf's
        // signing key before it ever reaches the signature check, exactly like the pinned route.
        // The impostor's own `sign_secure_message` call sets `key_id` to ITS OWN key, which does
        // not name the leaf, so this is now caught as `KeyMismatch` rather than reaching (and
        // failing) the signature check as `BadSignature`. Both reasons are "not verified"; this
        // reason is more specific and is what `the_chain_route_rejects_a_proof_key_id_that_does_
        // not_name_the_leaf` exercises directly.
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::KeyMismatch
            }
        );
    }

    #[test]
    fn direct_pinning_still_wins_and_still_works() {
        // An existing deployment: no certificate anywhere, a pinned agent key.
        let agent = CryptoManager::new_with_keypair();
        let mut message = SecureMessage::new(
            "bob@test",
            "alice@test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        let mut store = TrustStore::new();
        store.pin("alice@test", agent.public_key_bytes().unwrap());
        assert!(store.verify(&message).is_verified());
    }

    #[test]
    fn a_revocation_is_stored_once_and_refuses_an_unknown_issuer() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let account_id = key_id(&account.verifying_key().to_bytes());
        let mut store = TrustStore::new();
        let revocation = signed_revocation(&account, [7u8; 16]);
        // Not pinned yet: refused, and nothing stored.
        assert!(!store.add_revocation(revocation.clone()));
        assert_eq!(store.revocation_count(), 0);
        // Pinned: accepted once, and the duplicate is ignored.
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert!(store.add_revocation(revocation.clone()));
        assert!(!store.add_revocation(revocation));
        assert_eq!(store.revocation_count(), 1);
        assert!(store.is_revoked(&account_id, &[7u8; 16]));
        assert!(!store.is_revoked(&account_id, &[8u8; 16]));
    }

    #[test]
    fn a_revoked_certificate_stops_verifying() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        let serial = cert.serial;
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert!(
            store.verify(&message).is_verified(),
            "valid before revocation"
        );
        assert!(store.add_revocation(signed_revocation(&account, serial)));
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::InvalidChain
            }
        );
    }

    // Fix 1: a valid chain names one subject; a message may not borrow that chain's trust while
    // claiming to be someone else in `from_global_id`.
    #[test]
    fn a_chain_cannot_vouch_for_a_different_claimed_sender() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "ceo@bob.test", // not the chain's subject
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::IdentityMismatch
            }
        );

        // Control: the same chain and signature, with the matching claimed sender, verifies.
        let mut matching = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut matching).unwrap();
        assert!(store.verify(&matching).is_verified());
    }

    // Fix 2: sub-microsecond digits are outside the signed bytes on every route, not only the
    // direct-pin one.
    #[test]
    fn the_chain_route_also_refuses_a_non_canonical_timestamp() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        // Add sub-microsecond digits after signing: an unauthenticated field a relay could add.
        let ts = message.timestamp.0;
        message.timestamp.0 = ts
            .with_nanosecond(ts.timestamp_subsec_nanos() + 7)
            .expect("still a valid instant");
        assert!(has_sub_micro_digits(&message));

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::NonCanonicalTimestamp
            }
        );
    }

    // Existing direct-pin behaviour for a non-canonical timestamp must stay byte-identical after
    // hoisting the guard out of `verify_against_pinned_key`.
    #[test]
    fn the_direct_pin_route_still_refuses_a_non_canonical_timestamp() {
        let agent = CryptoManager::new_with_keypair();
        let mut message = SecureMessage::new(
            "bob@test",
            "alice@test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        let ts = message.timestamp.0;
        message.timestamp.0 = ts
            .with_nanosecond(ts.timestamp_subsec_nanos() + 7)
            .expect("still a valid instant");
        let mut store = TrustStore::new();
        store.pin("alice@test", agent.public_key_bytes().unwrap());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::NonCanonicalTimestamp
            }
        );
    }

    // Fix 3: an unsigned message backed by an otherwise-valid chain is missing evidence, not
    // contradicted by any -- and `Unverifiable` (unlike `Contradicted`) is what `accept_unverified`
    // deployments deliver.
    #[test]
    fn an_unsigned_message_with_a_valid_chain_is_unverifiable_not_contradicted() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        message.add_metadata(certificate::CHAIN_KEY, certificate::chain_to_pem(&[cert]));
        // Deliberately never signed: sender_proof stays `ProofAlg::None`.
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::Unsigned
            }
        );
    }

    // Fix round 2, fix 4: the unsigned check now runs before the identity check on the chain
    // route too, so an unsigned message with a valid chain reports `Unsigned` even when the
    // chain's subject also does not match `from_global_id` -- both routes now agree that missing
    // evidence is reported before any conclusion that depends on a signature existing at all.
    #[test]
    fn an_unsigned_mismatched_chain_reports_unsigned_not_identity_mismatch() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        let mut message = SecureMessage::new(
            "bob@test",
            "ceo@bob.test", // mismatched claimed sender, on top of being unsigned
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        message.add_metadata(
            certificate::CHAIN_KEY,
            certificate::chain_to_pem(std::slice::from_ref(&cert)),
        );
        // Deliberately never signed.
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::Unsigned
            }
        );
    }

    // Fix round 2, fix 1: an account key's revocation must reach a certificate it did not issue
    // directly, as long as that certificate is in the account's own subtree. Before this fix,
    // the trust store only ever checked a certificate's revocation status under its own immediate
    // issuer, so revoking a grandchild's serial with the account key was silently a no-op: it
    // returned `true` from `add_revocation`, but the certificate kept verifying.
    #[test]
    fn an_account_key_revokes_a_certificate_it_did_not_issue_directly() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[12u8; 32]); // intermediate: delegates to the worker
        let mut worker = CryptoManager::new_with_keypair();
        let now = t_now();

        let root = certificate::AgentCertificate::sign(
            certificate::AgentCertificate {
                version: 1,
                serial: [7u8; 16],
                issuer_key_id: key_id(&account.verifying_key().to_bytes()),
                subject_label: "agent".to_string(),
                subject_global_id: "agent@alice.test".to_string(),
                subject_signing_key: agent.verifying_key().to_bytes(),
                subject_sealing_key: [9u8; 32],
                not_before: now - chrono::Duration::hours(1),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![certificate::Permission::Send],
                may_delegate: 1,
                signature: [0u8; 64],
            },
            &account,
        );
        let leaf_serial = [8u8; 16];
        let leaf = certificate::AgentCertificate::sign(
            certificate::AgentCertificate {
                version: 1,
                serial: leaf_serial,
                issuer_key_id: key_id(&agent.verifying_key().to_bytes()),
                subject_label: "worker".to_string(),
                subject_global_id: "worker.agent@alice.test".to_string(),
                subject_signing_key: worker.public_key_bytes().expect("worker has a public key"),
                subject_sealing_key: [9u8; 32],
                not_before: now - chrono::Duration::hours(1),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![certificate::Permission::Send],
                may_delegate: 0,
                signature: [0u8; 64],
            },
            &agent,
        );

        worker.set_certificate_chain(vec![leaf, root]);
        let mut message = SecureMessage::new(
            "bob@test",
            "worker.agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        worker.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert!(
            store.verify(&message).is_verified(),
            "valid before any revocation"
        );

        // The account revokes the leaf's serial directly -- it never issued the leaf (the agent
        // did) -- and `add_revocation` must both accept it AND have it actually bite.
        assert!(store.add_revocation(signed_revocation(&account, leaf_serial)));
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::InvalidChain
            }
        );
    }

    // Fix round 2, fix 1 (continued): the same reach extends past one level -- revoking a
    // non-root, non-leaf certificate with the account key kills its whole subtree, not just that
    // one certificate.
    #[test]
    fn revoking_an_intermediate_certificate_with_the_account_key_kills_its_subtree() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let agent = SigningKey::from_bytes(&[12u8; 32]);
        let worker = SigningKey::from_bytes(&[13u8; 32]);
        let mut subworker = CryptoManager::new_with_keypair();
        let now = t_now();

        let root = certificate::AgentCertificate::sign(
            certificate::AgentCertificate {
                version: 1,
                serial: [7u8; 16],
                issuer_key_id: key_id(&account.verifying_key().to_bytes()),
                subject_label: "agent".to_string(),
                subject_global_id: "agent@alice.test".to_string(),
                subject_signing_key: agent.verifying_key().to_bytes(),
                subject_sealing_key: [9u8; 32],
                not_before: now - chrono::Duration::hours(1),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![certificate::Permission::Send],
                may_delegate: 2,
                signature: [0u8; 64],
            },
            &account,
        );
        let middle_serial = [8u8; 16];
        let middle = certificate::AgentCertificate::sign(
            certificate::AgentCertificate {
                version: 1,
                serial: middle_serial,
                issuer_key_id: key_id(&agent.verifying_key().to_bytes()),
                subject_label: "worker".to_string(),
                subject_global_id: "worker.agent@alice.test".to_string(),
                subject_signing_key: worker.verifying_key().to_bytes(),
                subject_sealing_key: [9u8; 32],
                not_before: now - chrono::Duration::hours(1),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![certificate::Permission::Send],
                may_delegate: 1,
                signature: [0u8; 64],
            },
            &agent,
        );
        let leaf = certificate::AgentCertificate::sign(
            certificate::AgentCertificate {
                version: 1,
                serial: [9u8; 16],
                issuer_key_id: key_id(&worker.verifying_key().to_bytes()),
                subject_label: "subworker".to_string(),
                subject_global_id: "sub.worker.agent@alice.test".to_string(),
                subject_signing_key: subworker
                    .public_key_bytes()
                    .expect("subworker has a public key"),
                subject_sealing_key: [9u8; 32],
                not_before: now - chrono::Duration::hours(1),
                not_after: now + chrono::Duration::hours(1),
                permissions: vec![certificate::Permission::Send],
                may_delegate: 0,
                signature: [0u8; 64],
            },
            &worker,
        );

        subworker.set_certificate_chain(vec![leaf, middle, root]);
        let mut message = SecureMessage::new(
            "bob@test",
            "sub.worker.agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        subworker.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert!(
            store.verify(&message).is_verified(),
            "valid before revocation"
        );

        // The account revokes the MIDDLE certificate (issued by the agent, not the account); the
        // leaf's own serial was never revoked, but its whole branch must die with its parent.
        assert!(store.add_revocation(signed_revocation(&account, middle_serial)));
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::InvalidChain
            }
        );
    }

    // Reported, not fixed: an unpinned, chain-less sender using `alg: Ed25519` with
    // sub-microsecond digits used to report `Unverifiable { UnknownSender }` (delivered under
    // `accept_unverified`) and now reports `Contradicted { NonCanonicalTimestamp }` (always
    // dropped), because the timestamp guard now runs before the pin/chain lookup on every route.
    // Pinned here deliberately: the digits are unauthenticated on every route regardless of
    // whether the sender is otherwise recognised, so this is judged correct and intended.
    #[test]
    fn an_unrecognised_signed_sender_with_a_non_canonical_timestamp_is_contradicted() {
        let agent = CryptoManager::new_with_keypair();
        let mut message = SecureMessage::new(
            "bob@test",
            "mallory@nowhere.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        let ts = message.timestamp.0;
        message.timestamp.0 = ts
            .with_nanosecond(ts.timestamp_subsec_nanos() + 7)
            .expect("still a valid instant");
        let store = TrustStore::new(); // unpinned, no chain
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::NonCanonicalTimestamp
            }
        );
    }

    // Fix 4a: a revocation is scoped to its own issuer; account B cannot revoke account A's
    // certificate by reusing its serial.
    #[test]
    fn a_revocation_cannot_cross_issuers() {
        let account_a = SigningKey::from_bytes(&[11u8; 32]);
        let account_b = SigningKey::from_bytes(&[22u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account_a, &agent, "agent@alice.test", t_now());
        let serial = cert.serial;
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account_a.verifying_key().to_bytes());
        store.pin_account_key("bob-account", account_b.verifying_key().to_bytes());
        // Account B revokes a certificate under A's serial, but B never issued it.
        assert!(store.add_revocation(signed_revocation(&account_b, serial)));
        assert!(
            store.verify(&message).is_verified(),
            "a same-serial revocation from a different issuer must not revoke A's certificate"
        );
        // Control: A's own revocation of the same serial does revoke it.
        assert!(store.add_revocation(signed_revocation(&account_a, serial)));
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::InvalidChain
            }
        );
    }

    // Fix 4b + Fix 7: filling one issuer's revocation quota evicts only that issuer's oldest
    // entry, never another issuer's, and never the entry that was just inserted.
    #[test]
    fn filling_one_issuers_revocation_quota_does_not_evict_another_issuers_entries() {
        let account_a = SigningKey::from_bytes(&[11u8; 32]);
        let account_b = SigningKey::from_bytes(&[22u8; 32]);
        let account_a_id = key_id(&account_a.verifying_key().to_bytes());
        let account_b_id = key_id(&account_b.verifying_key().to_bytes());
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account_a.verifying_key().to_bytes());
        store.pin_account_key("bob-account", account_b.verifying_key().to_bytes());

        let b_serial = [1u8; 16];
        assert!(store.add_revocation(signed_revocation(&account_b, b_serial)));

        // Fill account A past its per-issuer cap with distinct serials.
        for i in 0..600u32 {
            let mut serial = [0u8; 16];
            serial[..4].copy_from_slice(&i.to_be_bytes());
            assert!(store.add_revocation(signed_revocation(&account_a, serial)));
        }

        // B's single entry survives A's eviction pressure.
        assert!(store.is_revoked(&account_b_id, &b_serial));
        // The most recently added A entries survive; eviction removed only A's own oldest.
        let mut last_serial = [0u8; 16];
        last_serial[..4].copy_from_slice(&599u32.to_be_bytes());
        assert!(store.is_revoked(&account_a_id, &last_serial));
    }

    // Fix 5: `verify_at` and `verified_chain_at` at the same fixed clock never disagree about
    // expiry, and an expiry boundary is now testable without racing the real clock.
    #[test]
    fn expiry_is_testable_at_a_fixed_clock_and_agrees_across_both_entry_points() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let now = t_now();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", now);
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());

        let still_valid = now + chrono::Duration::minutes(30);
        assert!(store.verify_at(&message, still_valid).is_verified());
        assert!(store.verified_chain_at(&message, still_valid).is_some());

        let after_expiry = now + chrono::Duration::hours(2);
        assert_eq!(
            store.verify_at(&message, after_expiry),
            SenderVerdict::Unverifiable {
                reason: UnverifiableReason::InvalidChain
            }
        );
        assert!(store.verified_chain_at(&message, after_expiry).is_none());
    }

    // FIX 4 (P2f1 fix wave): the chain route must bind `sender_proof.key_id` to the leaf's signing
    // key, exactly as the pinned route binds it to the pinned key. Without this a chain-routed
    // sender could put any key_id in its own proof, which `receive_messages` hands to the gate for
    // knock attribution.
    #[test]
    fn the_chain_route_rejects_a_proof_key_id_that_does_not_name_the_leaf() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        // Tamper with the proof's key_id after signing, without touching the signature bytes --
        // the signature will then fail to verify against the leaf's key too, but the key_id check
        // must be what actually catches it (checked via the reason).
        message.sender_proof.key_id = key_id(&[0xAAu8; 32]);

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::KeyMismatch
            }
        );
    }

    // Follow-up to FIX 4: once the key_id check fires two steps earlier, the chain route's own
    // terminal `BadSignature` arm (the actual Ed25519 signature check, not the key_id check) had
    // no test left reaching it -- `a_chain_that_does_not_match_the_signing_key_is_contradicted`
    // now stops at `KeyMismatch` before it gets there. Reach it here: sign correctly with the
    // leaf's own key (so `sender_proof.key_id` names the leaf and the identity check passes), then
    // tamper `encrypted_content` after signing -- a field the signature covers but no earlier
    // check inspects.
    #[test]
    fn the_chain_route_rejects_a_signature_that_does_not_verify_against_the_leaf() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut agent = CryptoManager::new_with_keypair();
        let cert = signed_cert_for(&account, &agent, "agent@alice.test", t_now());
        agent.set_certificate_chain(vec![cert]);
        let mut message = SecureMessage::new(
            "bob@test",
            "agent@alice.test",
            b"hi".to_vec(),
            SecurityLevel::Authenticated,
        );
        agent.sign_secure_message(&mut message).unwrap();
        // `sender_proof.key_id` correctly names the leaf, and `from_global_id` matches the chain's
        // subject -- both earlier checks pass. Tampering the ciphertext after signing invalidates
        // only the signature itself.
        message.encrypted_content.push(0xFF);

        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());
        assert_eq!(
            store.verify(&message),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::BadSignature
            }
        );
    }

    // FIX 5 (P2f1 fix wave): `Revocation.version` is checked, just as certificates already refuse
    // an unknown version in two places -- a future v2 revocation must not be stored and applied
    // under v1 semantics.
    #[test]
    fn add_revocation_refuses_an_unknown_version() {
        let account = SigningKey::from_bytes(&[11u8; 32]);
        let mut store = TrustStore::new();
        store.pin_account_key("alice", account.verifying_key().to_bytes());

        let mut bad = signed_revocation(&account, [7u8; 16]);
        bad.version = 2;
        // Re-sign so it fails on the version check, not on a stale signature over version 1.
        let bad = Revocation::sign(bad, &account);
        assert!(!store.add_revocation(bad));
        assert_eq!(store.revocation_count(), 0);

        // Control: the same revocation at version 1 is accepted.
        assert!(store.add_revocation(signed_revocation(&account, [7u8; 16])));
        assert_eq!(store.revocation_count(), 1);
    }

    #[test]
    fn security_level_names_match_their_serde_names() {
        for level in [
            SecurityLevel::Public,
            SecurityLevel::Private,
            SecurityLevel::Authenticated,
            SecurityLevel::Secure,
        ] {
            let serde_name = serde_json::to_string(&level).unwrap();
            assert_eq!(serde_name, format!("\"{}\"", security_level_name(&level)));
        }
    }

    #[test]
    fn key_id_is_64_lowercase_hex() {
        let id = key_id(&[7u8; 32]);
        assert_eq!(id.len(), 64);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn canonical_input_starts_with_the_length_prefixed_domain_tag() {
        let m = SecureMessage::new("b", "a", vec![], SecurityLevel::Public);
        let input = canonical_input(&m);
        assert_eq!(
            &input[..4],
            &(CANONICAL_DOMAIN_TAG.len() as u32).to_be_bytes()
        );
        assert_eq!(
            &input[4..4 + CANONICAL_DOMAIN_TAG.len()],
            CANONICAL_DOMAIN_TAG
        );
    }

    #[test]
    fn canonical_input_ignores_metadata_insertion_order_and_routing_path() {
        let mut a = SecureMessage::new("b", "a", b"x".to_vec(), SecurityLevel::Public);
        let mut b = a.clone();
        a.add_metadata("k1", "v1");
        a.add_metadata("k2", "v2");
        b.add_metadata("k2", "v2");
        b.add_metadata("k1", "v1");
        b.add_routing_hop("relay-1");
        assert_eq!(canonical_input(&a), canonical_input(&b));
    }

    #[test]
    fn truncation_leaves_whole_microseconds() {
        let mut m = SecureMessage::new("b", "a", vec![], SecurityLevel::Public);
        m.timestamp = crate::wire::DateTimeWrapper::new(
            chrono::DateTime::parse_from_rfc3339("2026-09-17T04:00:00.123456789Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        assert!(has_sub_micro_digits(&m));
        truncate_timestamp_to_micros(&mut m);
        assert!(!has_sub_micro_digits(&m));
        assert_eq!(m.timestamp.0.timestamp_subsec_nanos(), 123_456_000);
    }

    /// The relay test in `tests/protocol_version.rs` shows `verify_at`'s version-first gate
    /// refuses a rewritten version, which alone does not prove the SIGNATURE binds to
    /// `protocol_version` -- `verify_at` never even reaches the signature check for an
    /// unsupported version. This calls `TrustStore::verify_against_pinned_key` directly, bypassing
    /// the version gate entirely (it runs inside `verify_at`, not here), so a rewrite can only be
    /// caught by the signature itself.
    #[test]
    fn verify_against_pinned_key_rejects_a_rewritten_version_on_the_signature() {
        let agent = CryptoManager::new_with_keypair();
        let pinned = agent.public_key_bytes().unwrap();

        let mut message = SecureMessage::new("b", "a", b"hello".to_vec(), SecurityLevel::Public);
        assert_eq!(message.protocol_version, crate::types::PROTOCOL_VERSION);
        agent.sign_secure_message(&mut message).unwrap();

        // Control: the message as signed verifies.
        assert_eq!(
            TrustStore::verify_against_pinned_key(&message, &pinned),
            SenderVerdict::Verified {
                key_id: key_id(&pinned)
            }
        );

        // The relay's rewrite: change the version in place, WITHOUT re-signing. With the version
        // gate bypassed (this function is called directly, not through `verify_at`), the only
        // thing that can catch this is the signature no longer matching `canonical_input`.
        let mut rewritten = message.clone();
        rewritten.protocol_version = 2;
        assert_eq!(
            TrustStore::verify_against_pinned_key(&rewritten, &pinned),
            SenderVerdict::Contradicted {
                reason: ContradictedReason::BadSignature
            },
            "the signature must bind to protocol_version even with the version gate bypassed"
        );
    }
}
