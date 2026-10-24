// SPDX-License-Identifier: MIT OR Apache-2.0
//! Roles (M3): a role is a stable identity that a restarted session takes over.
//!
//! A session claims `role@account` by signing a short, domain-separated text with the role's key.
//! The role certificate (M2's keystore, f1's [`AgentCertificate`]) binds that key to the role, so
//! holding the key is the authorization. The newest valid claim always wins and gets a strictly
//! increasing **epoch**; any call made under an older epoch gets [`Superseded`].
//!
//! No I/O and no clock: `now` is passed in. M4 persists [`RolesState`]; M5's daemon calls this.
//! Design: `docs/superpowers/specs/2026-10-01-m3-roles-design.md`.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat, SubsecRound, Utc};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::certificate::{AgentCertificate, ChainError, RevocationLookup, validate_chain};
use crate::keystore::RoleIdentity;
use crate::replay::{Decision, Freshness, ReplayConfig, ReplayGuard};

/// The first line of every signed claim, so a claim signature can never be mistaken for (or
/// replayed as) a signature over anything else.
pub const CLAIM_DOMAIN_TAG: &str = "synapse/role-claim/v1";

/// The domain tag of a claim bound to an audience (a specific daemon instance, M5a): the audience
/// is part of what is signed, so a claim made for one daemon cannot be relayed to another.
pub const CLAIM_DOMAIN_TAG_V2: &str = "synapse/role-claim/v2";

/// The longest certificate chain a claim may carry. `validate_chain` leaves the cap to callers
/// that take chains from untrusted input, and the claim path is one (final review I2).
pub const MAX_CLAIM_CHAIN: usize = 8;

/// What a session sends to take a role.
#[derive(Debug, Clone)]
pub struct ClaimRequest {
    /// The role's certificate chain, leaf first. The claimed role is the leaf's subject.
    pub chain: Vec<AgentCertificate>,
    /// Fresh for every claim; a nonce is accepted once.
    pub nonce: [u8; 16],
    pub signed_at: DateTime<Utc>,
    /// Ed25519 by the leaf's signing key over [`claim_signing_input`] (or, with an audience,
    /// [`claim_signing_input_v2`]). A `Vec`, not `[u8; 64]`, because a request off the wire may
    /// carry any length and a wrong one must be refused.
    pub signature: Vec<u8>,
    /// Who this claim is for (e.g. a daemon's instance id). Signed when present; a verifier that
    /// requires an audience compares it before accepting the claim.
    pub audience: Option<String>,
}

/// The exact text an audience-bound claim signs.
#[must_use]
pub fn claim_signing_input_v2(
    global_id: &str,
    audience: &str,
    nonce: &[u8; 16],
    signed_at: DateTime<Utc>,
) -> String {
    format!(
        "{CLAIM_DOMAIN_TAG_V2}\n{global_id}\n{audience}\n{}\n{}",
        hex(nonce),
        signed_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

/// Sign a claim for `identity`'s role bound to `audience` (M5a: the daemon's instance id).
pub fn sign_claim_for(
    identity: &RoleIdentity,
    audience: &str,
    nonce: [u8; 16],
    now: DateTime<Utc>,
) -> Result<ClaimRequest, ClaimError> {
    let signature = identity
        .crypto
        .sign_message(&claim_signing_input_v2(
            &identity.global_id,
            audience,
            &nonce,
            now,
        ))
        .map_err(|_| ClaimError::NoSigningKey)?;
    Ok(ClaimRequest {
        chain: identity.chain.clone(),
        nonce,
        signed_at: now,
        signature,
        audience: Some(audience.to_string()),
    })
}

/// The exact text a claim signs.
#[must_use]
pub fn claim_signing_input(global_id: &str, nonce: &[u8; 16], signed_at: DateTime<Utc>) -> String {
    format!(
        "{CLAIM_DOMAIN_TAG}\n{global_id}\n{}\n{}",
        hex(nonce),
        signed_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

/// The client half: sign a claim for `identity`'s role.
pub fn sign_claim(
    identity: &RoleIdentity,
    nonce: [u8; 16],
    now: DateTime<Utc>,
) -> Result<ClaimRequest, ClaimError> {
    let signature = identity
        .crypto
        .sign_message(&claim_signing_input(&identity.global_id, &nonce, now))
        .map_err(|_| ClaimError::NoSigningKey)?;
    Ok(ClaimRequest {
        chain: identity.chain.clone(),
        nonce,
        signed_at: now,
        signature,
        audience: None,
    })
}

/// A granted claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub global_id: String,
    pub epoch: u64,
    /// The epoch this claim displaced, if the role was held.
    pub superseded: Option<u64>,
}

/// Why a claim was refused. A refused claim changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// The certificate chain does not validate against the pinned account keys.
    Chain(ChainError),
    /// The signature is not the role key's over this role's claim text.
    BadSignature,
    /// `signed_at` is outside the freshness window (too old, or ahead of `now`), or at or before
    /// this table started: after a restart the replay record is empty, so such a claim could be a
    /// captured one. The client signs a fresh claim.
    Stale,
    /// This nonce was already used by this key.
    Replayed,
    /// The identity has no signing key loaded (client side only).
    NoSigningKey,
    /// The chain is longer than [`MAX_CLAIM_CHAIN`].
    ChainTooLong,
    /// The role is at the last representable epoch; no newer one can be granted.
    EpochExhausted,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::Chain(e) => write!(f, "the role certificate is not valid: {e:?}"),
            ClaimError::BadSignature => write!(f, "the claim is not signed by the role's key"),
            ClaimError::Stale => write!(f, "the claim is outside the freshness window"),
            ClaimError::Replayed => write!(f, "the claim was already used"),
            ClaimError::NoSigningKey => write!(f, "no signing key is loaded for the role"),
            ClaimError::ChainTooLong => write!(f, "the certificate chain is too long"),
            ClaimError::EpochExhausted => write!(f, "the role has no epochs left"),
        }
    }
}

impl std::error::Error for ClaimError {}

/// A call made under an epoch that is not the role's current one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superseded {
    /// The role's current epoch; 0 if it was never claimed.
    pub current: u64,
}

impl fmt::Display for Superseded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "superseded: the role's current epoch is {}",
            self.current
        )
    }
}

impl std::error::Error for Superseded {}

/// Persisted state that cannot be valid: an epoch of 0 for the named role. No claim is ever
/// granted epoch 0, so such a record can only be corruption, and restoring it would let
/// `check(role, 0)` pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidState {
    pub global_id: String,
}

impl fmt::Display for InvalidState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "persisted role state is invalid for {}", self.global_id)
    }
}

impl std::error::Error for InvalidState {}

/// One role's persisted state: its current epoch and when it was claimed, when it was last seen
/// (written at most hourly, so a restarted daemon still knows) and when it was retired.
/// Design: `docs/ROLE_LIVENESS_DESIGN.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRecord {
    pub epoch: u64,
    pub claimed_at: DateTime<Utc>,
    /// The last time a session of the role was seen; absent in state written before liveness.
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    /// Set when the role was idle past the retire ttl; cleared by the role's next claim. A retired
    /// role keeps its epoch, certificate binding and queued mail.
    #[serde(default)]
    pub retired_at: Option<DateTime<Utc>>,
}

/// How much newer a sighting must be than the recorded one to be worth writing down.
const SEEN_GRANULARITY: chrono::Duration = chrono::Duration::hours(1);

/// Everything that must survive a restart (spec rule 6): every role's epoch, so a restarted table
/// never reissues an old one. The replay record is deliberately absent; see [`Roles::restore`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RolesState {
    pub roles: BTreeMap<String, RoleRecord>,
}

/// The role table: the current epoch of every claimed role.
pub struct Roles {
    roles: BTreeMap<String, RoleRecord>,
    claims: ReplayGuard,
}

impl Roles {
    #[must_use]
    pub fn new(now: DateTime<Utc>) -> Self {
        Roles {
            roles: BTreeMap::new(),
            claims: ReplayGuard::new(ReplayConfig::default(), now),
        }
    }

    /// Verify `req` and, if it holds, make it the role's newest epoch.
    ///
    /// Order matters: the chain and the signature are checked before the replay guard records the
    /// nonce, so a request that fails verification cannot burn a legitimate client's nonce.
    pub fn claim(
        &mut self,
        req: &ClaimRequest,
        account_keys: &dyn Fn(&str) -> Option<[u8; 32]>,
        revoked: &dyn RevocationLookup,
        now: DateTime<Utc>,
    ) -> Result<Grant, ClaimError> {
        if req.chain.len() > MAX_CLAIM_CHAIN {
            return Err(ClaimError::ChainTooLong);
        }
        let leaf =
            validate_chain(&req.chain, account_keys, revoked, now).map_err(ClaimError::Chain)?;
        let global_id = leaf.subject_global_id;
        // The signed text carries whole seconds, so judge freshness on exactly that: a sub-second
        // part is unsigned, and an attacker could otherwise nudge a captured claim past a
        // restart's horizon within its second (final review I1).
        let signed_at = req.signed_at.trunc_subsecs(0);
        let text = match &req.audience {
            None => claim_signing_input(&global_id, &req.nonce, signed_at),
            Some(audience) => claim_signing_input_v2(&global_id, audience, &req.nonce, signed_at),
        };
        UnparsedPublicKey::new(&ED25519, &leaf.subject_signing_key)
            .verify(text.as_bytes(), &req.signature)
            .map_err(|_| ClaimError::BadSignature)?;

        // Every check that can fail runs before the replay guard records the nonce, so a refused
        // claim never burns it.
        let previous = self.roles.get(&global_id).map(|r| r.epoch);
        let epoch = previous
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ClaimError::EpochExhausted)?;

        let key_id = crate::sender_auth::key_id(&leaf.subject_signing_key);
        match self.claims.check(&key_id, &hex(&req.nonce), signed_at, now) {
            Decision::Deliver(Freshness::Fresh) => {}
            Decision::Deliver(_) => return Err(ClaimError::Stale),
            Decision::Drop => return Err(ClaimError::Replayed),
        }

        self.roles.insert(
            global_id.clone(),
            RoleRecord {
                epoch,
                claimed_at: now,
                last_seen: None,
                retired_at: None,
            },
        );
        Ok(Grant {
            global_id,
            epoch,
            superseded: previous,
        })
    }

    /// `Ok` only for the role's current epoch. A never-claimed role has current epoch 0, which no
    /// claim is ever granted, so no epoch can be presumed valid.
    pub fn check(&self, global_id: &str, epoch: u64) -> Result<(), Superseded> {
        match self.roles.get(global_id) {
            Some(record) if record.epoch == epoch => Ok(()),
            Some(record) => Err(Superseded {
                current: record.epoch,
            }),
            None => Err(Superseded { current: 0 }),
        }
    }

    /// The state to persist (M4).
    #[must_use]
    pub fn snapshot(&self) -> RolesState {
        RolesState {
            roles: self.roles.clone(),
        }
    }

    /// Rebuild a table from persisted state. Epochs continue from where they were. The replay
    /// record starts empty with its horizon at `now`, so any claim signed at or before `now` is
    /// refused as [`ClaimError::Stale`]: a claim captured before the restart cannot be replayed
    /// after it.
    pub fn restore(state: RolesState, now: DateTime<Utc>) -> Result<Roles, InvalidState> {
        if let Some((global_id, _)) = state.roles.iter().find(|(_, record)| record.epoch == 0) {
            return Err(InvalidState {
                global_id: global_id.clone(),
            });
        }
        Ok(Roles {
            roles: state.roles,
            claims: ReplayGuard::new(ReplayConfig::default(), now),
        })
    }

    /// Record that a session of `global_id` was seen at `seen`. Returns whether the record changed,
    /// which is only so when `seen` is at least an hour past the recorded sighting, so the caller
    /// writes the table out rarely. An unknown role is ignored.
    pub fn note_seen(&mut self, global_id: &str, seen: DateTime<Utc>) -> bool {
        let Some(record) = self.roles.get_mut(global_id) else {
            return false;
        };
        if record
            .last_seen
            .is_some_and(|recorded| seen - recorded < SEEN_GRANULARITY)
        {
            return false;
        }
        record.last_seen = Some(seen);
        true
    }

    /// Retire every role whose last activity (`last_seen`, else `claimed_at`) is more than `ttl`
    /// before `now` and that is not already retired. Returns the ids retired. Nothing else about
    /// a role changes: its epoch stays, so a returning session claims as usual.
    pub fn retire_idle(&mut self, now: DateTime<Utc>, ttl: chrono::Duration) -> Vec<String> {
        let mut retired = Vec::new();
        for (global_id, record) in &mut self.roles {
            let active = record
                .last_seen
                .map_or(record.claimed_at, |seen| seen.max(record.claimed_at));
            if record.retired_at.is_none() && now - active > ttl {
                record.retired_at = Some(now);
                retired.push(global_id.clone());
            }
        }
        retired
    }

    #[must_use]
    pub fn current(&self, global_id: &str) -> Option<u64> {
        self.roles.get(global_id).map(|r| r.epoch)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
