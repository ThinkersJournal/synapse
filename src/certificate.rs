// SPDX-License-Identifier: MIT OR Apache-2.0
//! Account keys and agent certificates (P2 slice f1).
//!
//! No I/O and no clock: `now` is passed in. See
//! `docs/superpowers/specs/2026-09-17-agent-certificates-design.md`.

use crate::sender_auth::{put, to_hex};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pem::{EncodeConfig, LineEnding, Pem, encode_config};
use std::fmt;

/// Domain-separation tag: the first field of an [`AgentCertificate`]'s signing input.
pub const CERT_DOMAIN_TAG: &[u8] = b"synapse/agent-cert/v1";
/// Domain-separation tag: the first field of a [`Revocation`]'s signing input.
pub const REVOCATION_DOMAIN_TAG: &[u8] = b"synapse/agent-revocation/v1";
/// PEM label for an encoded [`AgentCertificate`].
pub const CERT_PEM_LABEL: &str = "SYNAPSE AGENT CERT";
/// PEM label for an encoded [`Revocation`].
pub const REVOCATION_PEM_LABEL: &str = "SYNAPSE REVOCATION";
/// Spec bound: `AgentCertificate::subject_label` longer than this is refused as malformed.
const MAX_SUBJECT_LABEL_LEN: usize = 128;
/// Spec bound: `Revocation::reason` longer than this is refused as malformed.
const MAX_REVOCATION_REASON_LEN: usize = 128;
/// Signed metadata carrying the sender's chain, leaf first.
pub const CHAIN_KEY: &str = "synapse.cert.chain";
/// Signed metadata carrying relayed revocations.
pub const REVOCATIONS_KEY: &str = "synapse.cert.revocations";

/// A grant carried by an [`AgentCertificate`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Send,
    RequestAck,
    Ack,
    /// Shared state: create records and patch those the role is a party to (every role by default).
    StateWrite,
    /// Shared state: read every record (the PM and the export role). Grants no write.
    StateReadAll,
    /// Shared state: read and patch any record, change owners, patch terminal records.
    StateAdmin,
    /// Shared state: write derived facts. Held only by the checker role.
    StateDerive,
    /// Role liveness: retire and revive roles (`/v1/roles/retire`, `/v1/roles/revive`). Held only
    /// by the PM role.
    RoleAdmin,
    /// Daemon control: stop the daemon cleanly (`/v1/daemon/shutdown`). Held only by the PM role.
    DaemonAdmin,
    /// A consumer-defined grant. Always begins `x-`; Synapse carries it and never interprets it.
    Extension(String),
}

impl Permission {
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Permission::Send => "send".to_string(),
            Permission::RequestAck => "request-ack".to_string(),
            Permission::Ack => "ack".to_string(),
            Permission::StateWrite => "state-write".to_string(),
            Permission::StateReadAll => "state-read-all".to_string(),
            Permission::StateAdmin => "state-admin".to_string(),
            Permission::StateDerive => "state-derive".to_string(),
            Permission::RoleAdmin => "role-admin".to_string(),
            Permission::DaemonAdmin => "daemon-admin".to_string(),
            Permission::Extension(text) => text.clone(),
        }
    }

    /// `None` for an unknown permission that is not `x-` prefixed: a typo must not look like a
    /// grant of nothing.
    #[must_use]
    pub fn parse(text: &str) -> Option<Permission> {
        match text {
            "send" => Some(Permission::Send),
            "request-ack" => Some(Permission::RequestAck),
            "ack" => Some(Permission::Ack),
            "state-write" => Some(Permission::StateWrite),
            "state-read-all" => Some(Permission::StateReadAll),
            "state-admin" => Some(Permission::StateAdmin),
            "state-derive" => Some(Permission::StateDerive),
            "role-admin" => Some(Permission::RoleAdmin),
            "daemon-admin" => Some(Permission::DaemonAdmin),
            other if other.starts_with("x-") => Some(Permission::Extension(other.to_string())),
            _ => None,
        }
    }
}

/// Why a certificate, revocation or chain could not be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    Malformed,
    UnknownPermission,
    TooLarge,
    UnknownIssuer,
    BadSignature,
    NotYetValid,
    Expired,
    ValidityNotNested,
    PermissionWidened,
    DelegationNotAllowed,
    IdentityNotNarrowed,
    Revoked,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChainError::Malformed => "malformed",
            ChainError::UnknownPermission => "unknown_permission",
            ChainError::TooLarge => "too_large",
            ChainError::UnknownIssuer => "unknown_issuer",
            ChainError::BadSignature => "bad_signature",
            ChainError::NotYetValid => "not_yet_valid",
            ChainError::Expired => "expired",
            ChainError::ValidityNotNested => "validity_not_nested",
            ChainError::PermissionWidened => "permission_widened",
            ChainError::DelegationNotAllowed => "delegation_not_allowed",
            ChainError::IdentityNotNarrowed => "identity_not_narrowed",
            ChainError::Revoked => "revoked",
        })
    }
}

impl std::error::Error for ChainError {}

/// An agent's certificate: an issuer's account (or delegate) key vouching for one agent's signing
/// and sealing keys, for a bounded validity window and a bounded set of permissions (spec §4).
#[derive(Clone)]
pub struct AgentCertificate {
    pub version: u8,
    pub serial: [u8; 16],
    /// Lowercase hex SHA-256 of the issuer's public key (see [`crate::sender_auth::key_id`]).
    pub issuer_key_id: String,
    pub subject_label: String,
    pub subject_global_id: String,
    pub subject_signing_key: [u8; 32],
    pub subject_sealing_key: [u8; 32],
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub permissions: Vec<Permission>,
    /// How many further links this certificate may delegate through (0 = a leaf).
    pub may_delegate: u8,
    pub signature: [u8; 64],
}

impl fmt::Debug for AgentCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCertificate")
            .field("serial", &to_hex(&self.serial))
            .field("subject_label", &self.subject_label)
            .field("subject_global_id", &self.subject_global_id)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

fn read_field<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ChainError> {
    if data.len() < *pos + 4 {
        return Err(ChainError::Malformed);
    }
    let len_bytes: [u8; 4] = data[*pos..*pos + 4]
        .try_into()
        .map_err(|_| ChainError::Malformed)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    *pos += 4;
    if data.len() < *pos + len {
        return Err(ChainError::Malformed);
    }
    let field = &data[*pos..*pos + len];
    *pos += len;
    Ok(field)
}

fn field_str(field: &[u8]) -> Result<String, ChainError> {
    std::str::from_utf8(field)
        .map(str::to_string)
        .map_err(|_| ChainError::Malformed)
}

fn field_array<const N: usize>(field: &[u8]) -> Result<[u8; N], ChainError> {
    field.try_into().map_err(|_| ChainError::Malformed)
}

fn field_u8(field: &[u8]) -> Result<u8, ChainError> {
    if field.len() != 1 {
        return Err(ChainError::Malformed);
    }
    Ok(field[0])
}

fn field_timestamp(field: &[u8]) -> Result<DateTime<Utc>, ChainError> {
    let bytes: [u8; 8] = field.try_into().map_err(|_| ChainError::Malformed)?;
    let micros = i64::from_be_bytes(bytes);
    DateTime::<Utc>::from_timestamp_micros(micros).ok_or(ChainError::Malformed)
}

/// Encode `permissions` as a 4-byte big-endian count followed by each `as_str()`, sorted, each
/// length-prefixed. Sorting makes the encoding independent of the caller's insertion order.
fn put_permissions(out: &mut Vec<u8>, permissions: &[Permission]) {
    let mut names: Vec<String> = permissions.iter().map(Permission::as_str).collect();
    names.sort();
    let mut encoded = Vec::new();
    let count = u32::try_from(names.len()).expect("more than 4 GiB permissions");
    encoded.extend_from_slice(&count.to_be_bytes());
    for name in &names {
        put(&mut encoded, name.as_bytes());
    }
    put(out, &encoded);
}

fn read_permissions(field: &[u8]) -> Result<Vec<Permission>, ChainError> {
    if field.len() < 4 {
        return Err(ChainError::Malformed);
    }
    let count_bytes: [u8; 4] = field[..4].try_into().map_err(|_| ChainError::Malformed)?;
    let count = u32::from_be_bytes(count_bytes) as usize;
    // Each entry needs at least a 4-byte length prefix, so a `count` larger than the field could
    // possibly hold is a lying wire value: reject it before allocating rather than trusting it
    // enough to size a `Vec`.
    let max_possible_entries = (field.len() - 4) / 4;
    if count > max_possible_entries {
        return Err(ChainError::Malformed);
    }
    let mut pos = 4;
    let mut permissions = Vec::with_capacity(count);
    for _ in 0..count {
        let name_bytes = read_field(field, &mut pos)?;
        let name = field_str(name_bytes)?;
        let permission = Permission::parse(&name).ok_or(ChainError::UnknownPermission)?;
        permissions.push(permission);
    }
    if pos != field.len() {
        return Err(ChainError::Malformed);
    }
    Ok(permissions)
}

fn pem_text(label: &str, der: Vec<u8>) -> String {
    encode_config(
        &Pem::new(label, der),
        EncodeConfig::new().set_line_ending(LineEnding::LF),
    )
}

impl AgentCertificate {
    /// The bytes the issuer signs: the domain tag, then each field in declaration order, each a
    /// 4-byte big-endian length followed by its bytes (see [`crate::sender_auth::put`]).
    /// `permissions` is its own length-prefixed blob: a count, then each sorted name,
    /// length-prefixed in turn. `signature` is never covered by its own input.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, CERT_DOMAIN_TAG);
        put(&mut out, &[self.version]);
        put(&mut out, &self.serial);
        put(&mut out, self.issuer_key_id.as_bytes());
        put(&mut out, self.subject_label.as_bytes());
        put(&mut out, self.subject_global_id.as_bytes());
        put(&mut out, &self.subject_signing_key);
        put(&mut out, &self.subject_sealing_key);
        put(&mut out, &self.not_before.timestamp_micros().to_be_bytes());
        put(&mut out, &self.not_after.timestamp_micros().to_be_bytes());
        put_permissions(&mut out, &self.permissions);
        put(&mut out, &[self.may_delegate]);
        out
    }

    /// Sign `unsigned` (whose `signature` field is ignored) with `issuer` and return the signed
    /// certificate.
    #[must_use]
    pub fn sign(mut unsigned: AgentCertificate, issuer: &SigningKey) -> AgentCertificate {
        let input = unsigned.signing_input();
        let signature: Signature = issuer.sign(&input);
        unsigned.signature = signature.to_bytes();
        unsigned
    }

    /// Whether this certificate's signature verifies against `issuer_public`.
    #[must_use]
    pub fn verify_signature(&self, issuer_public: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(issuer_public) else {
            return false;
        };
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&self.signing_input(), &signature)
            .is_ok()
    }

    /// The PEM body is `signing_input()` followed by the 64 signature bytes: the same canonical
    /// encoding that is signed, so parsing is the inverse of one function.
    pub fn to_pem(&self) -> String {
        let mut body = self.signing_input();
        body.extend_from_slice(&self.signature);
        pem_text(CERT_PEM_LABEL, body)
    }

    /// The inverse of [`AgentCertificate::to_pem`]. Refuses an unknown permission with
    /// [`ChainError::UnknownPermission`] and anything else malformed with
    /// [`ChainError::Malformed`].
    pub fn from_pem(text: &str) -> Result<Self, ChainError> {
        let block = pem::parse(text).map_err(|_| ChainError::Malformed)?;
        if block.tag() != CERT_PEM_LABEL {
            return Err(ChainError::Malformed);
        }
        Self::from_body(block.contents())
    }

    fn from_body(data: &[u8]) -> Result<Self, ChainError> {
        let mut pos = 0usize;
        let domain_tag = read_field(data, &mut pos)?;
        if domain_tag != CERT_DOMAIN_TAG {
            return Err(ChainError::Malformed);
        }
        let version = field_u8(read_field(data, &mut pos)?)?;
        let serial = field_array::<16>(read_field(data, &mut pos)?)?;
        let issuer_key_id = field_str(read_field(data, &mut pos)?)?;
        let subject_label = field_str(read_field(data, &mut pos)?)?;
        if subject_label.chars().count() > MAX_SUBJECT_LABEL_LEN {
            return Err(ChainError::Malformed);
        }
        let subject_global_id = field_str(read_field(data, &mut pos)?)?;
        let subject_signing_key = field_array::<32>(read_field(data, &mut pos)?)?;
        let subject_sealing_key = field_array::<32>(read_field(data, &mut pos)?)?;
        let not_before = field_timestamp(read_field(data, &mut pos)?)?;
        let not_after = field_timestamp(read_field(data, &mut pos)?)?;
        let permissions = read_permissions(read_field(data, &mut pos)?)?;
        let may_delegate = field_u8(read_field(data, &mut pos)?)?;
        if data.len() != pos + 64 {
            return Err(ChainError::Malformed);
        }
        let signature = field_array::<64>(&data[pos..])?;
        Ok(AgentCertificate {
            version,
            serial,
            issuer_key_id,
            subject_label,
            subject_global_id,
            subject_signing_key,
            subject_sealing_key,
            not_before,
            not_after,
            permissions,
            may_delegate,
            signature,
        })
    }
}

/// A signed statement that a certificate's serial is no longer trusted (spec §6).
#[derive(Debug, Clone)]
pub struct Revocation {
    pub version: u8,
    pub serial: [u8; 16],
    /// Lowercase hex SHA-256 of the issuer's public key.
    pub issuer_key_id: String,
    pub issued_at: DateTime<Utc>,
    pub reason: String,
    pub signature: [u8; 64],
}

impl Revocation {
    /// The bytes the issuer signs: the domain tag, then each field in declaration order (same
    /// length-prefixing discipline as [`AgentCertificate::signing_input`]).
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, REVOCATION_DOMAIN_TAG);
        put(&mut out, &[self.version]);
        put(&mut out, &self.serial);
        put(&mut out, self.issuer_key_id.as_bytes());
        put(&mut out, &self.issued_at.timestamp_micros().to_be_bytes());
        put(&mut out, self.reason.as_bytes());
        out
    }

    #[must_use]
    pub fn sign(mut unsigned: Revocation, issuer: &SigningKey) -> Revocation {
        let input = unsigned.signing_input();
        let signature: Signature = issuer.sign(&input);
        unsigned.signature = signature.to_bytes();
        unsigned
    }

    #[must_use]
    pub fn verify_signature(&self, issuer_public: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(issuer_public) else {
            return false;
        };
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&self.signing_input(), &signature)
            .is_ok()
    }

    pub fn to_pem(&self) -> String {
        let mut body = self.signing_input();
        body.extend_from_slice(&self.signature);
        pem_text(REVOCATION_PEM_LABEL, body)
    }

    pub fn from_pem(text: &str) -> Result<Self, ChainError> {
        let block = pem::parse(text).map_err(|_| ChainError::Malformed)?;
        if block.tag() != REVOCATION_PEM_LABEL {
            return Err(ChainError::Malformed);
        }
        Self::from_body(block.contents())
    }

    fn from_body(data: &[u8]) -> Result<Self, ChainError> {
        let mut pos = 0usize;
        let domain_tag = read_field(data, &mut pos)?;
        if domain_tag != REVOCATION_DOMAIN_TAG {
            return Err(ChainError::Malformed);
        }
        let version = field_u8(read_field(data, &mut pos)?)?;
        let serial = field_array::<16>(read_field(data, &mut pos)?)?;
        let issuer_key_id = field_str(read_field(data, &mut pos)?)?;
        let issued_at = field_timestamp(read_field(data, &mut pos)?)?;
        let reason = field_str(read_field(data, &mut pos)?)?;
        if reason.chars().count() > MAX_REVOCATION_REASON_LEN {
            return Err(ChainError::Malformed);
        }
        if data.len() != pos + 64 {
            return Err(ChainError::Malformed);
        }
        let signature = field_array::<64>(&data[pos..])?;
        Ok(Revocation {
            version,
            serial,
            issuer_key_id,
            issued_at,
            reason,
            signature,
        })
    }
}

/// Encode a chain leaf first: each certificate's own PEM block, concatenated.
pub fn chain_to_pem(chain: &[AgentCertificate]) -> String {
    chain.iter().map(AgentCertificate::to_pem).collect()
}

/// Parse zero or more concatenated [`Revocation`] PEM blocks, as carried in [`REVOCATIONS_KEY`]
/// metadata. Unlike [`chain_from_pem`], an empty input is not an error: a message may legitimately
/// carry the key with no revocations, or none at all.
pub fn revocations_from_pem(text: &str) -> Result<Vec<Revocation>, ChainError> {
    let blocks = pem::parse_many(text).map_err(|_| ChainError::Malformed)?;
    blocks
        .iter()
        .map(|block| {
            if block.tag() != REVOCATION_PEM_LABEL {
                return Err(ChainError::Malformed);
            }
            Revocation::from_body(block.contents())
        })
        .collect()
}

/// The inverse of [`chain_to_pem`]. Returns [`ChainError::Malformed`] on an empty or unparsable
/// input.
pub fn chain_from_pem(text: &str) -> Result<Vec<AgentCertificate>, ChainError> {
    let blocks = pem::parse_many(text).map_err(|_| ChainError::Malformed)?;
    if blocks.is_empty() {
        return Err(ChainError::Malformed);
    }
    blocks
        .iter()
        .map(|block| {
            if block.tag() != CERT_PEM_LABEL {
                return Err(ChainError::Malformed);
            }
            AgentCertificate::from_body(block.contents())
        })
        .collect()
}

/// A verified certificate chain's subject: the identity, keys and permissions a receiver may act
/// on, plus which account key rooted the trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    pub account_key_id: String,
    /// Display-only free text carried by the leaf certificate. It is never an identity and
    /// nothing binds it to `subject_global_id`; never key trust or routing decisions off it.
    pub subject_label: String,
    pub subject_global_id: String,
    pub subject_signing_key: [u8; 32],
    pub subject_sealing_key: [u8; 32],
    pub permissions: Vec<Permission>,
    /// The number of certificates in the validated chain.
    pub links: usize,
}

/// Whether a certificate's serial has been revoked by its own issuer. Scoped by `issuer_key_id` so
/// one pinned account can never revoke (or, in the trust store, evict) another's entries -- serials
/// are visible in any chain, so without this any pinned account could silently un-trust another's
/// agents. Kept as a trait so this module never depends on the trust store's storage: it is
/// unit-testable with an in-memory fake.
pub trait RevocationLookup {
    fn is_revoked(&self, issuer_key_id: &str, serial: &[u8; 16]) -> bool;
}

/// A child's id is its parent's with exactly one label prepended: `worker.agent@host` under
/// `agent@host`. Without this, a delegate could mint itself a certificate for any id, including its
/// own account holder's (spec §5 rule 8).
#[must_use]
pub fn identity_narrows(parent: &str, child: &str) -> bool {
    // An empty parent would let `child.strip_suffix("")` match anything, and an empty child
    // cannot narrow anything: close both off before the suffix logic runs.
    if parent.is_empty() || child.is_empty() {
        return false;
    }
    let Some(prefix) = child.strip_suffix(parent) else {
        return false;
    };
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    if label.is_empty() || label.contains('.') {
        return false;
    }
    // A label is one component: it may not carry the '@' that separates local part from host,
    // nor anything unprintable that could render as another identity at the display layer (this
    // crate splits ids on '@' elsewhere, e.g. `src/identity.rs`).
    label
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validate a certificate chain, leaf first (`chain[0]` is the leaf, `chain[chain.len() - 1]` is
/// the root), against the rules in spec §5. Walks from the root down to the leaf, carrying the
/// parent's public key, validity window, permission set and delegation budget, and returns the
/// first error encountered. On success, returns the leaf's identity, keys and permissions.
///
/// This function applies no length cap on `chain`: a caller taking a chain off the network must
/// bound `chain.len()` itself before calling (the trust store wiring in Task 3 adds that cap).
pub fn validate_chain(
    chain: &[AgentCertificate],
    account_keys: &dyn Fn(&str) -> Option<[u8; 32]>,
    revoked: &dyn RevocationLookup,
    now: DateTime<Utc>,
) -> Result<VerifiedChain, ChainError> {
    // Rule 1: the chain is non-empty.
    let Some(root) = chain.last() else {
        return Err(ChainError::Malformed);
    };

    // Every certificate, including the root, must be a version this module knows how to apply
    // these rules to.
    if root.version != 1 {
        return Err(ChainError::Malformed);
    }
    // An empty root id would key every downstream record (knock attribution, the replay guard)
    // by the empty string once a single-link chain verifies it as `from_global_id`.
    // `identity_narrows` guards every link below the root, but never the root's own id.
    if root.subject_global_id.is_empty() {
        return Err(ChainError::Malformed);
    }

    // Rule 2: the root's issuer resolves through the account-key lookup, and its signature
    // verifies against that key.
    let account_key = account_keys(&root.issuer_key_id).ok_or(ChainError::UnknownIssuer)?;
    let account_key_id = root.issuer_key_id.clone();
    if !root.verify_signature(&account_key) {
        return Err(ChainError::BadSignature);
    }

    // Carried state, seeded from the root and narrowed at each step down to the leaf. The parent
    // key for the certificate directly under the root is the root's own subject signing key, not
    // the account key that vouches for the root.
    let mut parent_key = root.subject_signing_key;
    let mut parent_not_before = root.not_before;
    let mut parent_not_after = root.not_after;
    let mut parent_permissions = root.permissions.clone();
    let mut parent_may_delegate = root.may_delegate;
    let mut parent_global_id = root.subject_global_id.clone();

    // Rule 4 (window) and rule 8 (revocation) apply to the root itself too.
    if now < root.not_before {
        return Err(ChainError::NotYetValid);
    }
    if now > root.not_after {
        return Err(ChainError::Expired);
    }
    if revoked.is_revoked(&root.issuer_key_id, &root.serial) {
        return Err(ChainError::Revoked);
    }

    // Walk from the root (last element) down to the leaf (first element), skipping the root
    // itself since it was already checked above.
    for cert in chain[..chain.len() - 1].iter().rev() {
        if cert.version != 1 {
            return Err(ChainError::Malformed);
        }

        // Rule 3: the certificate's signature verifies against its parent's signing key.
        if !cert.verify_signature(&parent_key) {
            return Err(ChainError::BadSignature);
        }

        // The issuer_key_id a certificate declares must actually name its parent. Authentication
        // rides on the signature check above, so this is not itself exploitable, but the field is
        // signature-covered and diagnostics or revocation lookups may key off it later.
        if cert.issuer_key_id != crate::sender_auth::key_id(&parent_key) {
            return Err(ChainError::BadSignature);
        }

        // Rule 4: `now` within this certificate's own window, and nested inside the parent's.
        if now < cert.not_before {
            return Err(ChainError::NotYetValid);
        }
        if now > cert.not_after {
            return Err(ChainError::Expired);
        }
        if cert.not_before < parent_not_before || cert.not_after > parent_not_after {
            return Err(ChainError::ValidityNotNested);
        }

        // Rule 5: every child permission appears in its parent (a containment test -- Task 1
        // sorts permission names when encoding, so a parsed certificate's permission order is
        // not the order it was written in).
        if !cert
            .permissions
            .iter()
            .all(|permission| parent_permissions.contains(permission))
        {
            return Err(ChainError::PermissionWidened);
        }

        // Rule 6: a parent with may_delegate == 0 may not issue, and the child's budget must be
        // strictly less than its parent's.
        if parent_may_delegate == 0 || cert.may_delegate >= parent_may_delegate {
            return Err(ChainError::DelegationNotAllowed);
        }

        // Rule 7: the child's id is its parent's with exactly one label prepended.
        if !identity_narrows(&parent_global_id, &cert.subject_global_id) {
            return Err(ChainError::IdentityNotNarrowed);
        }

        // Rule 8: no certificate's serial is revoked. Checked under both the certificate's own
        // issuer (an intermediate agent may revoke only what it itself issued) and the chain's
        // root account key (an account holder may revoke anything in their own subtree, not only
        // what they issued directly -- otherwise an account-signed revocation of a
        // grandchild's serial would silently do nothing, since validate_chain looks a non-root
        // certificate up under its immediate issuer).
        if revoked.is_revoked(&cert.issuer_key_id, &cert.serial)
            || revoked.is_revoked(&account_key_id, &cert.serial)
        {
            return Err(ChainError::Revoked);
        }

        parent_key = cert.subject_signing_key;
        parent_not_before = cert.not_before;
        parent_not_after = cert.not_after;
        parent_permissions = cert.permissions.clone();
        parent_may_delegate = cert.may_delegate;
        parent_global_id = cert.subject_global_id.clone();
    }

    let leaf = &chain[0];
    Ok(VerifiedChain {
        account_key_id,
        subject_label: leaf.subject_label.clone(),
        subject_global_id: leaf.subject_global_id.clone(),
        subject_signing_key: leaf.subject_signing_key,
        subject_sealing_key: leaf.subject_sealing_key,
        permissions: leaf.permissions.clone(),
        links: chain.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).expect("valid timestamp")
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    /// An unsigned certificate with everything filled in; tests tweak one field at a time.
    fn unsigned(issuer: &SigningKey, subject: &SigningKey, id: &str) -> AgentCertificate {
        AgentCertificate {
            version: 1,
            serial: [7u8; 16],
            issuer_key_id: crate::sender_auth::key_id(&public(issuer)),
            subject_label: "test agent".to_string(),
            subject_global_id: id.to_string(),
            subject_signing_key: public(subject),
            subject_sealing_key: [9u8; 32],
            not_before: t(0),
            not_after: t(86_400),
            permissions: vec![Permission::Send, Permission::Ack],
            may_delegate: 2,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn a_signed_certificate_verifies_against_its_issuer() {
        let (issuer, subject) = (key(1), key(2));
        let cert = AgentCertificate::sign(unsigned(&issuer, &subject, "agent@host"), &issuer);
        assert!(cert.verify_signature(&public(&issuer)));
        // Control: another key does not verify it.
        assert!(!cert.verify_signature(&public(&key(3))));
    }

    #[test]
    fn one_flipped_signature_byte_fails() {
        let (issuer, subject) = (key(1), key(2));
        let mut cert = AgentCertificate::sign(unsigned(&issuer, &subject, "agent@host"), &issuer);
        cert.signature[0] ^= 1;
        assert!(!cert.verify_signature(&public(&issuer)));
    }

    #[test]
    fn every_signed_field_is_covered_by_the_signature() {
        let (issuer, subject) = (key(1), key(2));
        let cert = AgentCertificate::sign(unsigned(&issuer, &subject, "agent@host"), &issuer);
        // Changing any one field must break verification: the signing input covers them all.
        type Mutation = Box<dyn Fn(&mut AgentCertificate)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|c| c.version = 2),
            Box::new(|c| c.serial[0] ^= 1),
            Box::new(|c| c.issuer_key_id.push('a')),
            Box::new(|c| c.subject_label.push('a')),
            Box::new(|c| c.subject_global_id.push('a')),
            Box::new(|c| c.subject_signing_key[0] ^= 1),
            Box::new(|c| c.subject_sealing_key[0] ^= 1),
            Box::new(|c| c.not_before = t(1)),
            Box::new(|c| c.not_after = t(2)),
            Box::new(|c| c.permissions.push(Permission::RequestAck)),
            Box::new(|c| c.may_delegate = 1),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut altered = cert.clone();
            mutate(&mut altered);
            assert!(
                !altered.verify_signature(&public(&issuer)),
                "field {index} is not covered by the signature"
            );
        }
    }

    #[test]
    fn permissions_parse_and_reject_typos() {
        assert_eq!(Permission::parse("send"), Some(Permission::Send));
        assert_eq!(
            Permission::parse("request-ack"),
            Some(Permission::RequestAck)
        );
        assert_eq!(Permission::parse("ack"), Some(Permission::Ack));
        assert_eq!(
            Permission::parse("x-dispatch"),
            Some(Permission::Extension("x-dispatch".to_string()))
        );
        // A typo of a known permission is refused, rather than silently granting nothing.
        assert_eq!(Permission::parse("sned"), None);
        assert_eq!(Permission::parse(""), None);
    }

    #[test]
    fn a_certificate_round_trips_through_pem() {
        let (issuer, subject) = (key(1), key(2));
        let cert = AgentCertificate::sign(unsigned(&issuer, &subject, "agent@host"), &issuer);
        let parsed = AgentCertificate::from_pem(&cert.to_pem()).expect("parses");
        assert_eq!(parsed.signing_input(), cert.signing_input());
        assert_eq!(parsed.signature, cert.signature);
        assert!(parsed.verify_signature(&public(&issuer)));
    }

    #[test]
    fn a_chain_round_trips_leaf_first() {
        let (root, middle, leaf) = (key(1), key(2), key(3));
        let upper = AgentCertificate::sign(unsigned(&root, &middle, "agent@host"), &root);
        let lower = AgentCertificate::sign(unsigned(&middle, &leaf, "worker.agent@host"), &middle);
        let text = chain_to_pem(&[lower.clone(), upper.clone()]);
        let parsed = chain_from_pem(&text).expect("parses");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0].subject_global_id, "worker.agent@host",
            "leaf first"
        );
        assert_eq!(parsed[1].subject_global_id, "agent@host");
    }

    #[test]
    fn a_certificate_with_an_unknown_permission_will_not_parse() {
        let (issuer, subject) = (key(1), key(2));
        let mut cert = unsigned(&issuer, &subject, "agent@host");
        cert.permissions = vec![Permission::Extension("not-prefixed".to_string())];
        let signed = AgentCertificate::sign(cert, &issuer);
        // Encoding is allowed, but parsing refuses it: the wire form is what a receiver trusts.
        assert!(matches!(
            AgentCertificate::from_pem(&signed.to_pem()),
            Err(ChainError::UnknownPermission)
        ));
    }

    /// Assemble a well-formed certificate body except that its permissions field is exactly
    /// `permissions_blob` — bypassing `put_permissions` so a test can hand it a dishonest count.
    fn build_cert_body(permissions_blob: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, CERT_DOMAIN_TAG);
        put(&mut out, &[1u8]); // version
        put(&mut out, &[7u8; 16]); // serial
        put(&mut out, b"issuer-key-id"); // issuer_key_id
        put(&mut out, b"test agent"); // subject_label
        put(&mut out, b"agent@host"); // subject_global_id
        put(&mut out, &[0u8; 32]); // subject_signing_key
        put(&mut out, &[0u8; 32]); // subject_sealing_key
        put(&mut out, &0i64.to_be_bytes()); // not_before
        put(&mut out, &86_400i64.to_be_bytes()); // not_after
        put(&mut out, permissions_blob); // permissions: caller controls the raw blob
        put(&mut out, &[0u8]); // may_delegate
        out.extend_from_slice(&[0u8; 64]); // signature (unchecked by from_pem's structural parse)
        out
    }

    #[test]
    fn a_lying_permissions_count_is_rejected_before_allocating() {
        // A permissions field that is only 4 bytes long -- just the count, no entries -- but
        // claims ~4.3 billion entries. `Vec::with_capacity` on that count would try to allocate
        // roughly 100 GB and abort the process; parsing must refuse it structurally first.
        let malicious_permissions = u32::MAX.to_be_bytes().to_vec();
        let malicious_pem = pem_text(CERT_PEM_LABEL, build_cert_body(&malicious_permissions));
        assert!(matches!(
            AgentCertificate::from_pem(&malicious_pem),
            Err(ChainError::Malformed)
        ));
        // The process reaching this line at all is part of the assertion: an aborting allocation
        // would have killed the test binary before any assert could run.

        // Control: the same construction with an honest count (one real entry) parses fine.
        let mut honest_permissions = 1u32.to_be_bytes().to_vec();
        put(&mut honest_permissions, b"send");
        let honest_pem = pem_text(CERT_PEM_LABEL, build_cert_body(&honest_permissions));
        let parsed = AgentCertificate::from_pem(&honest_pem).expect("honest count parses");
        assert_eq!(parsed.permissions, vec![Permission::Send]);
    }

    #[test]
    fn a_revocation_verifies_and_round_trips() {
        let issuer = key(1);
        let revocation = Revocation::sign(
            Revocation {
                version: 1,
                serial: [7u8; 16],
                issuer_key_id: crate::sender_auth::key_id(&public(&issuer)),
                issued_at: t(10),
                reason: "key leaked".to_string(),
                signature: [0u8; 64],
            },
            &issuer,
        );
        assert!(revocation.verify_signature(&public(&issuer)));
        let parsed = Revocation::from_pem(&revocation.to_pem()).expect("parses");
        assert_eq!(parsed.serial, revocation.serial);
        assert!(parsed.verify_signature(&public(&issuer)));
        // Control: a different key does not verify it.
        assert!(!parsed.verify_signature(&public(&key(4))));
    }

    struct NoRevocations;
    impl RevocationLookup for NoRevocations {
        fn is_revoked(&self, _issuer_key_id: &str, _serial: &[u8; 16]) -> bool {
            false
        }
    }

    /// A fake that only revokes `serial` when asked under exactly `issuer_key_id` -- unlike the
    /// old serial-only fake, this exercises the issuer scoping `validate_chain` actually enforces.
    struct Revoked {
        issuer_key_id: String,
        serial: [u8; 16],
    }
    impl RevocationLookup for Revoked {
        fn is_revoked(&self, issuer_key_id: &str, serial: &[u8; 16]) -> bool {
            issuer_key_id == self.issuer_key_id && serial == &self.serial
        }
    }

    /// A two-link chain: account -> agent -> worker. Returns (leaf-first chain, account public key).
    ///
    /// The two certificates are given different serials (root `[7u8; 16]` from `unsigned`, leaf
    /// `[8u8; 16]` here) so that revocation tests can distinguish which certificate was revoked --
    /// with a shared serial, revoking one would always revoke both, and the "unaffected" half of
    /// each revocation test would pass without testing anything.
    fn two_link_chain() -> (Vec<AgentCertificate>, [u8; 32]) {
        let (account, agent, worker) = (key(1), key(2), key(3));
        let upper = AgentCertificate::sign(unsigned(&account, &agent, "agent@host"), &account);
        let mut lower_unsigned = unsigned(&agent, &worker, "worker.agent@host");
        lower_unsigned.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
        lower_unsigned.may_delegate = 1;
        lower_unsigned.serial = [8u8; 16];
        let lower = AgentCertificate::sign(lower_unsigned, &agent);
        (vec![lower, upper], public(&account))
    }

    fn pinned(account_key: [u8; 32]) -> impl Fn(&str) -> Option<[u8; 32]> {
        let id = crate::sender_auth::key_id(&account_key);
        move |key_id: &str| (key_id == id).then_some(account_key)
    }

    #[test]
    fn a_valid_two_link_chain_verifies() {
        let (chain, account) = two_link_chain();
        let verified =
            validate_chain(&chain, &pinned(account), &NoRevocations, t(10)).expect("valid");
        assert_eq!(verified.subject_global_id, "worker.agent@host");
        assert_eq!(verified.links, 2);
        assert_eq!(
            verified.account_key_id,
            crate::sender_auth::key_id(&account)
        );
    }

    #[test]
    fn a_chain_whose_root_is_not_pinned_is_refused() {
        let (chain, _account) = two_link_chain();
        let nobody = |_key_id: &str| None;
        assert_eq!(
            validate_chain(&chain, &nobody, &NoRevocations, t(10)),
            Err(ChainError::UnknownIssuer)
        );
    }

    #[test]
    fn validity_must_nest_inside_the_parents() {
        // A child's not_after outside the parent's window.
        let (mut chain, account_key) = two_link_chain();
        let agent = key(2);
        let worker = key(3);
        let mut child = unsigned(&agent, &worker, "worker.agent@host");
        child.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
        child.may_delegate = 1;
        child.serial = [8u8; 16];
        child.not_after = t(999_999); // outside the parent's window
        chain[0] = AgentCertificate::sign(child, &agent);
        assert_eq!(
            validate_chain(&chain, &pinned(account_key), &NoRevocations, t(10)),
            Err(ChainError::ValidityNotNested)
        );

        // Mirror case: a child's not_before earlier than the parent's. The `||` in the nesting
        // check has two arms; without this, only the not_after arm would ever be exercised.
        let (mut chain, account_key) = two_link_chain();
        let mut child = unsigned(&agent, &worker, "worker.agent@host");
        child.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
        child.may_delegate = 1;
        child.serial = [8u8; 16];
        child.not_before = t(-1); // earlier than the parent's not_before
        chain[0] = AgentCertificate::sign(child, &agent);
        assert_eq!(
            validate_chain(&chain, &pinned(account_key), &NoRevocations, t(10)),
            Err(ChainError::ValidityNotNested)
        );
    }

    #[test]
    fn an_expired_or_not_yet_valid_certificate_is_refused() {
        let (chain, account) = two_link_chain();
        assert_eq!(
            validate_chain(&chain, &pinned(account), &NoRevocations, t(-1)),
            Err(ChainError::NotYetValid)
        );
        assert_eq!(
            validate_chain(&chain, &pinned(account), &NoRevocations, t(86_401)),
            Err(ChainError::Expired)
        );
        // Control: exactly on each boundary is valid.
        assert!(validate_chain(&chain, &pinned(account), &NoRevocations, t(0)).is_ok());
        assert!(validate_chain(&chain, &pinned(account), &NoRevocations, t(86_400)).is_ok());
    }

    #[test]
    fn a_child_cannot_widen_its_permissions() {
        let (account, agent, worker) = (key(1), key(2), key(3));
        let upper_unsigned = {
            let mut c = unsigned(&account, &agent, "agent@host");
            c.permissions = vec![Permission::Send];
            c
        };
        let upper = AgentCertificate::sign(upper_unsigned, &account);
        let lower = {
            let mut c = unsigned(&agent, &worker, "worker.agent@host");
            c.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
            c.may_delegate = 1;
            c.permissions = vec![Permission::Send, Permission::Ack]; // Ack was never granted
            AgentCertificate::sign(c, &agent)
        };
        assert_eq!(
            validate_chain(
                &[lower, upper],
                &pinned(public(&account)),
                &NoRevocations,
                t(10)
            ),
            Err(ChainError::PermissionWidened)
        );
    }

    #[test]
    fn delegation_budgets_must_decrease_and_zero_cannot_issue() {
        let (account, agent, worker) = (key(1), key(2), key(3));
        // A parent with may_delegate 0 may not issue at all.
        let upper = {
            let mut c = unsigned(&account, &agent, "agent@host");
            c.may_delegate = 0;
            AgentCertificate::sign(c, &account)
        };
        let lower = {
            let mut c = unsigned(&agent, &worker, "worker.agent@host");
            c.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
            c.may_delegate = 0;
            AgentCertificate::sign(c, &agent)
        };
        assert_eq!(
            validate_chain(
                &[lower, upper],
                &pinned(public(&account)),
                &NoRevocations,
                t(10)
            ),
            Err(ChainError::DelegationNotAllowed)
        );
    }

    #[test]
    fn a_child_cannot_claim_an_id_outside_its_parents_namespace() {
        // The impersonation case: a delegate mints itself a certificate for its account holder's id.
        let (account, agent, worker) = (key(1), key(2), key(3));
        let upper = AgentCertificate::sign(unsigned(&account, &agent, "agent@host"), &account);
        let lower = {
            let mut c = unsigned(&agent, &worker, "ciresnave@host"); // not under agent@host
            c.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
            c.may_delegate = 1;
            AgentCertificate::sign(c, &agent)
        };
        assert_eq!(
            validate_chain(
                &[lower, upper],
                &pinned(public(&account)),
                &NoRevocations,
                t(10)
            ),
            Err(ChainError::IdentityNotNarrowed)
        );
    }

    #[test]
    fn identity_narrowing_accepts_one_prepended_label_only() {
        assert!(identity_narrows("agent@host", "worker.agent@host"));
        assert!(identity_narrows(
            "worker.agent@host",
            "task.worker.agent@host"
        ));
        assert!(!identity_narrows("agent@host", "agent@host"));
        assert!(
            !identity_narrows("agent@host", "a.b.agent@host"),
            "one label at a time"
        );
        assert!(!identity_narrows("agent@host", "evil@host"));
        assert!(
            !identity_narrows("agent@host", "workeragent@host"),
            "the dot is required"
        );
        assert!(!identity_narrows("agent@host", "worker.agent@other"));
        // An empty parent must not act as a wildcard suffix, and an empty child cannot narrow.
        assert!(!identity_narrows("", "evil."));
        assert!(!identity_narrows("agent@host", ""));
        // A label may not smuggle an '@', which would present as another identity once split.
        assert!(!identity_narrows("agent@host", "ciresnave@host.agent@host"));
        // A label may not contain unprintable/whitespace characters either.
        assert!(!identity_narrows("agent@host", "wor ker.agent@host"));
        // Positive control: an ordinary label of alphanumerics, '-' and '_' is still accepted.
        assert!(identity_narrows("agent@host", "worker-1_a.agent@host"));
    }

    #[test]
    fn a_revoked_certificate_invalidates_the_chain() {
        let (chain, account) = two_link_chain();
        let leaf_serial = chain[0].serial;
        let agent_id = crate::sender_auth::key_id(&public(&key(2)));
        assert_eq!(
            validate_chain(
                &chain,
                &pinned(account),
                &Revoked {
                    issuer_key_id: agent_id.clone(),
                    serial: leaf_serial
                },
                t(10)
            ),
            Err(ChainError::Revoked)
        );
        // Control: revoking an unrelated serial, from the same issuer, leaves the chain valid.
        assert!(
            validate_chain(
                &chain,
                &pinned(account),
                &Revoked {
                    issuer_key_id: agent_id,
                    serial: [1u8; 16]
                },
                t(10)
            )
            .is_ok()
        );
    }

    #[test]
    fn a_revoked_parent_invalidates_everything_below_it() {
        let (chain, account) = two_link_chain();
        let root_serial = chain[1].serial;
        assert_eq!(
            validate_chain(
                &chain,
                &pinned(account),
                &Revoked {
                    issuer_key_id: crate::sender_auth::key_id(&account),
                    serial: root_serial
                },
                t(10)
            ),
            Err(ChainError::Revoked)
        );
    }

    // Fix 6 (P2f1 fix round 2): a revocation is only honoured under the right issuer -- neither an
    // unrelated key nor even the leaf's own serial-holder is enough on its own.
    #[test]
    fn a_revocation_under_the_wrong_issuer_does_not_revoke_it() {
        let (chain, account) = two_link_chain();
        let leaf_serial = chain[0].serial;
        // Neither the leaf's own key nor an unrelated third key issued the leaf: only its actual
        // issuer (the agent) or the account root may revoke it (the latter checked below).
        let unrelated_issuer = crate::sender_auth::key_id(&public(&key(9)));
        assert!(
            validate_chain(
                &chain,
                &pinned(account),
                &Revoked {
                    issuer_key_id: unrelated_issuer,
                    serial: leaf_serial
                },
                t(10)
            )
            .is_ok()
        );
    }

    // Fix 1 (P2f1 fix round 2): an account key's revocation reaches a certificate it did not
    // issue directly, as long as that certificate is somewhere in the account's own subtree.
    // Before this fix, `validate_chain` only ever looked a certificate up under its own immediate
    // issuer, so an account-signed revocation of a grandchild's serial silently did nothing.
    #[test]
    fn an_account_key_can_revoke_a_certificate_it_did_not_issue_directly() {
        let (chain, account) = two_link_chain();
        let leaf_serial = chain[0].serial; // issued by the agent, not the account
        assert_eq!(
            validate_chain(
                &chain,
                &pinned(account),
                &Revoked {
                    issuer_key_id: crate::sender_auth::key_id(&account),
                    serial: leaf_serial
                },
                t(10)
            ),
            Err(ChainError::Revoked)
        );
    }

    #[test]
    fn an_empty_chain_is_malformed() {
        assert_eq!(
            validate_chain(&[], &|_| None, &NoRevocations, t(10)),
            Err(ChainError::Malformed)
        );
    }

    #[test]
    fn a_root_signed_by_the_wrong_key_for_its_known_issuer_id_fails() {
        let (chain, account) = two_link_chain();
        // A known issuer id, but the pinned bytes are for a different key than actually signed
        // the root.
        let id = crate::sender_auth::key_id(&account);
        let wrong = public(&key(9));
        let wrong_key = move |key_id: &str| (key_id == id).then_some(wrong);
        assert_eq!(
            validate_chain(&chain, &wrong_key, &NoRevocations, t(10)),
            Err(ChainError::BadSignature)
        );
    }

    #[test]
    fn a_flipped_leaf_signature_byte_fails() {
        let (mut chain, account) = two_link_chain();
        chain[0].signature[0] ^= 1;
        assert_eq!(
            validate_chain(&chain, &pinned(account), &NoRevocations, t(10)),
            Err(ChainError::BadSignature)
        );
    }

    #[test]
    fn a_childs_delegation_budget_must_be_strictly_less_than_its_parents() {
        let (account, agent, worker) = (key(1), key(2), key(3));
        // Equal budgets (parent 2, child 2) are refused.
        let upper = {
            let mut c = unsigned(&account, &agent, "agent@host");
            c.may_delegate = 2;
            AgentCertificate::sign(c, &account)
        };
        let lower = {
            let mut c = unsigned(&agent, &worker, "worker.agent@host");
            c.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
            c.may_delegate = 2;
            c.serial = [8u8; 16];
            AgentCertificate::sign(c, &agent)
        };
        assert_eq!(
            validate_chain(
                &[lower, upper.clone()],
                &pinned(public(&account)),
                &NoRevocations,
                t(10)
            ),
            Err(ChainError::DelegationNotAllowed)
        );

        // Positive control: a strictly smaller budget (parent 2, child 1) is accepted.
        let lower_ok = {
            let mut c = unsigned(&agent, &worker, "worker.agent@host");
            c.issuer_key_id = crate::sender_auth::key_id(&public(&agent));
            c.may_delegate = 1;
            c.serial = [8u8; 16];
            AgentCertificate::sign(c, &agent)
        };
        assert!(
            validate_chain(
                &[lower_ok, upper],
                &pinned(public(&account)),
                &NoRevocations,
                t(10)
            )
            .is_ok()
        );
    }

    #[test]
    fn a_single_link_chain_verifies() {
        let (chain, account) = two_link_chain();
        let root_only = &chain[1..];
        let verified = validate_chain(root_only, &pinned(account), &NoRevocations, t(10))
            .expect("a lone root is a valid one-link chain");
        assert_eq!(verified.links, 1);
        assert_eq!(verified.subject_global_id, "agent@host");
    }

    #[test]
    fn an_unknown_certificate_version_is_malformed() {
        let (mut chain, account) = two_link_chain();
        chain[0].version = 2;
        assert_eq!(
            validate_chain(&chain, &pinned(account), &NoRevocations, t(10)),
            Err(ChainError::Malformed)
        );
    }

    // FIX 3 (P2f1 fix wave): the spec's 128-char bound on `subject_label` is enforced on parse.
    #[test]
    fn a_subject_label_over_128_chars_is_rejected() {
        let (issuer, subject) = (key(1), key(2));
        let mut cert = unsigned(&issuer, &subject, "agent@host");
        cert.subject_label = "a".repeat(129);
        let signed = AgentCertificate::sign(cert, &issuer);
        assert!(matches!(
            AgentCertificate::from_pem(&signed.to_pem()),
            Err(ChainError::Malformed)
        ));

        // Control: exactly 128 chars parses fine.
        let mut ok_cert = unsigned(&issuer, &subject, "agent@host");
        ok_cert.subject_label = "a".repeat(128);
        let ok_signed = AgentCertificate::sign(ok_cert, &issuer);
        assert!(AgentCertificate::from_pem(&ok_signed.to_pem()).is_ok());
    }

    // FIX 3 (P2f1 fix wave): the spec's 128-char bound on `Revocation::reason` is enforced on
    // parse.
    #[test]
    fn a_revocation_reason_over_128_chars_is_rejected() {
        let issuer = key(1);
        let mut revocation = Revocation {
            version: 1,
            serial: [7u8; 16],
            issuer_key_id: crate::sender_auth::key_id(&public(&issuer)),
            issued_at: t(10),
            reason: "a".repeat(129),
            signature: [0u8; 64],
        };
        revocation = Revocation::sign(revocation, &issuer);
        assert!(matches!(
            Revocation::from_pem(&revocation.to_pem()),
            Err(ChainError::Malformed)
        ));

        // Control: exactly 128 chars parses fine.
        let ok = Revocation::sign(
            Revocation {
                version: 1,
                serial: [7u8; 16],
                issuer_key_id: crate::sender_auth::key_id(&public(&issuer)),
                issued_at: t(10),
                reason: "a".repeat(128),
                signature: [0u8; 64],
            },
            &issuer,
        );
        assert!(Revocation::from_pem(&ok.to_pem()).is_ok());
    }

    // FIX 6 (P2f1 fix wave): a root certificate with an empty `subject_global_id` must not verify
    // -- otherwise a single-link chain roots an empty `from_global_id`, which then keys knock
    // records and the replay guard.
    #[test]
    fn a_root_with_an_empty_subject_global_id_is_malformed() {
        let (account, agent) = (key(1), key(2));
        let root = AgentCertificate::sign(unsigned(&account, &agent, ""), &account);
        assert_eq!(
            validate_chain(&[root], &pinned(public(&account)), &NoRevocations, t(10)),
            Err(ChainError::Malformed)
        );
    }

    #[test]
    fn an_unknown_root_certificate_version_is_malformed() {
        // chain[1] is the root in this crate's leaf-first ordering. Mutating `version` changes
        // the signing input, so the root must be re-signed afterwards -- otherwise this would
        // pass for the wrong reason, by hitting BadSignature instead of the version check.
        let (mut chain, account_key) = two_link_chain();
        let account = key(1);
        let mut root = chain[1].clone();
        root.version = 2;
        chain[1] = AgentCertificate::sign(root, &account);
        assert_eq!(
            validate_chain(&chain, &pinned(account_key), &NoRevocations, t(10)),
            Err(ChainError::Malformed)
        );
    }
}
