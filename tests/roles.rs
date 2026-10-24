// SPDX-License-Identifier: MIT OR Apache-2.0
//! Roles in core (M3): claim a role with its key; the newest epoch wins.
//! Design: `docs/superpowers/specs/2026-10-01-m3-roles-design.md`.

use chrono::{DateTime, Duration, TimeZone, Utc};
use synapse::certificate::{ChainError, RevocationLookup};
use synapse::keystore::{Keystore, RoleIdentity};
use synapse::roles::{ClaimError, ClaimRequest, Grant, Roles, Superseded, sign_claim};

struct NoRevocations;
impl RevocationLookup for NoRevocations {
    fn is_revoked(&self, _issuer_key_id: &str, _serial: &[u8; 16]) -> bool {
        false
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    store: Keystore,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        Keystore::init_account(dir.path(), "acct").expect("init");
        let store = Keystore::open(dir.path()).expect("open");
        Fixture { _dir: dir, store }
    }

    fn role(&self, name: &str) -> RoleIdentity {
        self.store.role(name, t0()).expect("role")
    }

    fn lookup(&self) -> impl Fn(&str) -> Option<[u8; 32]> + use<> {
        let key_id = self.store.account().key_id;
        let key = self.store.account_public_key();
        move |kid: &str| (kid == key_id).then_some(key)
    }

    fn claim(
        &self,
        roles: &mut Roles,
        req: &ClaimRequest,
        now: DateTime<Utc>,
    ) -> Result<Grant, ClaimError> {
        roles.claim(req, &self.lookup(), &NoRevocations, now)
    }
}

/// A table that started just before t0: claims signed at or before a table's start are refused
/// (see `a_claim_signed_before_the_table_started_is_refused`), so the fixtures sign after it.
fn table() -> Roles {
    Roles::new(t0() - Duration::seconds(1))
}

/// A per-process random base with `n` mixed into the last byte: the same `n` always gives the
/// same nonce within a run, distinct `n` give distinct ones, and no key material is a literal.
fn nonce(n: u8) -> [u8; 16] {
    static BASE: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();
    let mut out = *BASE.get_or_init(|| *uuid::Uuid::new_v4().as_bytes());
    out[15] ^= n;
    out
}

#[test]
fn first_claim_gets_epoch_one_and_a_second_supersedes_it() {
    let f = Fixture::new();
    let lane = f.role("lane");
    let mut roles = table();

    let a = f
        .claim(
            &mut roles,
            &sign_claim(&lane, nonce(1), t0()).unwrap(),
            t0(),
        )
        .expect("claim A");
    assert_eq!(
        a,
        Grant {
            global_id: "lane@acct".into(),
            epoch: 1,
            superseded: None
        }
    );

    let later = t0() + Duration::seconds(30);
    let b = f
        .claim(
            &mut roles,
            &sign_claim(&lane, nonce(2), later).unwrap(),
            later,
        )
        .expect("claim B");
    assert_eq!(
        b,
        Grant {
            global_id: "lane@acct".into(),
            epoch: 2,
            superseded: Some(1)
        }
    );

    assert_eq!(roles.check("lane@acct", 1), Err(Superseded { current: 2 }));
    assert_eq!(roles.check("lane@acct", 2), Ok(()));
    assert_eq!(roles.current("lane@acct"), Some(2));
}

#[test]
fn a_never_claimed_role_is_superseded_at_zero() {
    let roles = table();
    assert_eq!(roles.check("x@acct", 1), Err(Superseded { current: 0 }));
    assert_eq!(roles.current("x@acct"), None);
}

#[test]
fn an_unknown_account_is_refused_and_changes_nothing() {
    let f = Fixture::new();
    let req = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap();
    let mut roles = table();

    let refused = roles.claim(&req, &|_: &str| None, &NoRevocations, t0());
    assert_eq!(refused, Err(ClaimError::Chain(ChainError::UnknownIssuer)));
    assert_eq!(roles.current("lane@acct"), None);

    // The refused attempt must not have consumed the nonce.
    let granted = f
        .claim(&mut roles, &req, t0())
        .expect("the same request, with the right lookup");
    assert_eq!(granted.epoch, 1);
}

#[test]
fn a_signature_by_another_key_is_refused() {
    let f = Fixture::new();
    let lane = f.role("lane");
    let other = f.role("other");
    let mut forged = sign_claim(&other, nonce(1), t0()).unwrap();
    forged.chain = lane.chain.clone();
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &forged, t0()),
        Err(ClaimError::BadSignature)
    );
    assert_eq!(roles.current("lane@acct"), None);
}

#[test]
fn a_claim_for_another_role_cannot_reuse_a_certificate() {
    // A signature over role A's text, presented with role B's certificate: the signed text names A,
    // the certificate names B, and the key that signed is A's, so nothing verifies.
    let f = Fixture::new();
    let a = f.role("alpha");
    let b = f.role("beta");
    let mut mixed = sign_claim(&a, nonce(1), t0()).unwrap();
    mixed.chain = b.chain.clone();
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &mixed, t0()),
        Err(ClaimError::BadSignature)
    );
    assert_eq!(roles.current("beta@acct"), None);
    assert_eq!(roles.current("alpha@acct"), None);
}

#[test]
fn a_replayed_claim_is_refused_without_a_new_epoch() {
    let f = Fixture::new();
    let req = sign_claim(&f.role("lane"), nonce(7), t0()).unwrap();
    let mut roles = table();
    assert_eq!(f.claim(&mut roles, &req, t0()).unwrap().epoch, 1);
    let again = f.claim(&mut roles, &req, t0() + Duration::seconds(1));
    assert_eq!(again, Err(ClaimError::Replayed));
    assert_eq!(roles.current("lane@acct"), Some(1));
}

#[test]
fn a_stale_or_future_claim_is_refused() {
    let f = Fixture::new();
    let lane = f.role("lane");
    let mut roles = table();

    let old = sign_claim(&lane, nonce(1), t0()).unwrap();
    assert_eq!(
        f.claim(&mut roles, &old, t0() + Duration::minutes(6)),
        Err(ClaimError::Stale)
    );
    let future = sign_claim(&lane, nonce(2), t0() + Duration::minutes(2)).unwrap();
    assert_eq!(f.claim(&mut roles, &future, t0()), Err(ClaimError::Stale));
    assert_eq!(roles.current("lane@acct"), None);
}

#[test]
fn a_short_signature_is_refused_not_a_panic() {
    let f = Fixture::new();
    let mut req = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap();
    req.signature.truncate(10);
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &req, t0()),
        Err(ClaimError::BadSignature)
    );
}

#[test]
fn an_expired_certificate_is_refused() {
    let f = Fixture::new();
    let lane = f.role("lane"); // certificate issued at t0 for 24h
    let late = t0() + Duration::hours(25);
    let req = sign_claim(&lane, nonce(1), late).unwrap();
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &req, late),
        Err(ClaimError::Chain(ChainError::Expired))
    );
}

/// After a daemon restart the replay record is empty, so a claim signed before the table started
/// could be a captured, already-used claim. It is refused; a live client simply signs a new one.
#[test]
fn a_claim_signed_before_the_table_started_is_refused() {
    let f = Fixture::new();
    let req = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap();
    let mut restarted = Roles::new(t0() + Duration::seconds(10));
    assert_eq!(
        f.claim(&mut restarted, &req, t0() + Duration::seconds(11)),
        Err(ClaimError::Stale)
    );
    let resigned = sign_claim(&f.role("lane"), nonce(2), t0() + Duration::seconds(11)).unwrap();
    assert_eq!(
        f.claim(&mut restarted, &resigned, t0() + Duration::seconds(11))
            .unwrap()
            .epoch,
        1
    );
}

// ---- Task 2: snapshot and restore ----

fn claimed_twice(f: &Fixture) -> Roles {
    let lane = f.role("lane");
    let mut roles = table();
    f.claim(
        &mut roles,
        &sign_claim(&lane, nonce(1), t0()).unwrap(),
        t0(),
    )
    .unwrap();
    let later = t0() + Duration::seconds(30);
    f.claim(
        &mut roles,
        &sign_claim(&lane, nonce(2), later).unwrap(),
        later,
    )
    .unwrap();
    roles
}

#[test]
fn restore_continues_epochs() {
    let f = Fixture::new();
    let roles = claimed_twice(&f);
    let json = serde_json::to_string(&roles.snapshot()).expect("serialize");
    let state: synapse::roles::RolesState = serde_json::from_str(&json).expect("deserialize");
    let restart = t0() + Duration::minutes(1);
    let mut restored = Roles::restore(state, restart).expect("valid state");
    assert_eq!(restored.current("lane@acct"), Some(2));

    let after = restart + Duration::seconds(1);
    let grant = f
        .claim(
            &mut restored,
            &sign_claim(&f.role("lane"), nonce(3), after).unwrap(),
            after,
        )
        .expect("claim after restore");
    assert_eq!(grant.epoch, 3);
    assert_eq!(grant.superseded, Some(2));
}

#[test]
fn restore_does_not_resurrect_superseded_epochs() {
    let f = Fixture::new();
    let restored = Roles::restore(claimed_twice(&f).snapshot(), t0() + Duration::minutes(1))
        .expect("valid state");
    assert_eq!(
        restored.check("lane@acct", 1),
        Err(Superseded { current: 2 })
    );
    assert_eq!(restored.check("lane@acct", 2), Ok(()));
}

// ---- Final-review fixes ----

/// Review I1: the signed text carries whole seconds only, so a captured claim's `signed_at` could
/// be nudged within its second to land after a restart's horizon and pass as fresh. The table
/// judges freshness on exactly what was signed.
#[test]
fn a_captured_claim_cannot_be_nudged_past_a_restart_within_its_second() {
    let f = Fixture::new();
    let captured = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap(); // whole-second t0
    let restart = t0() + Duration::milliseconds(500);
    let mut restarted = Roles::new(restart);
    let mut nudged = captured.clone();
    nudged.signed_at = t0() + Duration::milliseconds(999);
    assert_eq!(
        f.claim(
            &mut restarted,
            &nudged,
            restart + Duration::milliseconds(600)
        ),
        Err(ClaimError::Stale)
    );
    assert_eq!(restarted.current("lane@acct"), None);
}

/// Review I2: the claim path is the first to take chains from untrusted input, and
/// `validate_chain` leaves the length cap to its caller.
#[test]
fn an_overlong_chain_is_refused_before_validation() {
    let f = Fixture::new();
    let mut req = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap();
    let leaf = req.chain[0].clone();
    req.chain = vec![leaf; synapse::roles::MAX_CLAIM_CHAIN + 1];
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &req, t0()),
        Err(ClaimError::ChainTooLong)
    );
}

/// PR #67 review (Sourcery, and the final review's M2): no claim is ever granted epoch 0, so a
/// persisted epoch-0 record can only be corruption, and `check(role, 0)` would pass on it.
#[test]
fn restore_refuses_an_epoch_zero_record() {
    let mut state = synapse::roles::RolesState::default();
    state.roles.insert(
        "lane@acct".into(),
        synapse::roles::RoleRecord {
            epoch: 0,
            claimed_at: t0(),
            last_seen: None,
            retired_at: None,
        },
    );
    assert!(Roles::restore(state, t0()).is_err());
}

/// PR #67 review (Sourcery, and the final review's M1): `epoch + 1` at `u64::MAX` would panic in
/// debug and wrap to 0 in release, which `check` would then accept.
#[test]
fn a_claim_past_the_last_epoch_is_refused() {
    let f = Fixture::new();
    let mut state = synapse::roles::RolesState::default();
    state.roles.insert(
        "lane@acct".into(),
        synapse::roles::RoleRecord {
            epoch: u64::MAX,
            claimed_at: t0(),
            last_seen: None,
            retired_at: None,
        },
    );
    let mut roles = Roles::restore(state, t0() - Duration::seconds(1)).expect("valid state");
    let req = sign_claim(&f.role("lane"), nonce(1), t0()).unwrap();
    assert_eq!(
        f.claim(&mut roles, &req, t0()),
        Err(ClaimError::EpochExhausted)
    );
    assert_eq!(roles.current("lane@acct"), Some(u64::MAX));
}

/// M5a review I3: an audience-bound (v2) claim signs its audience, so a captured claim can't be
/// re-addressed to another daemon by editing the field.
#[test]
fn an_audience_is_covered_by_the_signature() {
    let f = Fixture::new();
    let lane = f.role("lane");
    let req = synapse::roles::sign_claim_for(&lane, "daemon-a", nonce(1), t0()).unwrap();
    let mut readdressed = req.clone();
    readdressed.audience = Some("daemon-b".into());
    let mut roles = table();
    assert_eq!(
        f.claim(&mut roles, &readdressed, t0()),
        Err(ClaimError::BadSignature)
    );
    assert_eq!(
        f.claim(&mut roles, &req, t0()).unwrap().epoch,
        1,
        "the unedited claim is valid"
    );
}

// ---- Liveness: retiring a role that never returns (docs/ROLE_LIVENESS_DESIGN.md, slice L1) ----

const TTL_DAYS: i64 = 30;

fn claimed_once(f: &Fixture) -> Roles {
    let mut roles = table();
    f.claim(
        &mut roles,
        &sign_claim(&f.role("lane"), nonce(1), t0()).unwrap(),
        t0(),
    )
    .unwrap();
    roles
}

#[test]
fn a_role_idle_past_the_ttl_is_retired_and_keeps_its_epoch() {
    let f = Fixture::new();
    let mut roles = claimed_once(&f);
    let ttl = Duration::days(TTL_DAYS);
    assert!(
        roles
            .retire_idle(t0() + Duration::days(TTL_DAYS - 1), ttl)
            .is_empty(),
        "not yet idle for the whole ttl"
    );
    let now = t0() + Duration::days(TTL_DAYS + 1);
    assert_eq!(roles.retire_idle(now, ttl), vec!["lane@acct".to_string()]);
    assert_eq!(roles.snapshot().roles["lane@acct"].retired_at, Some(now));
    assert_eq!(roles.check("lane@acct", 1), Ok(()), "epoch kept");
    assert!(roles.retire_idle(now, ttl).is_empty(), "retired once");
}

#[test]
fn a_role_seen_recently_is_not_retired() {
    let f = Fixture::new();
    let mut roles = claimed_once(&f);
    let ttl = Duration::days(TTL_DAYS);
    assert!(roles.note_seen("lane@acct", t0() + Duration::days(20)));
    assert!(
        roles
            .retire_idle(t0() + Duration::days(TTL_DAYS + 1), ttl)
            .is_empty(),
        "claimed 31 days ago but seen 11 days ago"
    );
    assert_eq!(
        roles
            .retire_idle(t0() + Duration::days(20 + TTL_DAYS + 1), ttl)
            .len(),
        1
    );
}

#[test]
fn note_seen_reports_a_change_only_when_it_is_worth_persisting() {
    let f = Fixture::new();
    let mut roles = claimed_once(&f);
    let seen = t0() + Duration::hours(2);
    assert!(roles.note_seen("lane@acct", seen));
    assert!(
        !roles.note_seen("lane@acct", seen + Duration::minutes(30)),
        "within the hour"
    );
    assert!(roles.note_seen("lane@acct", seen + Duration::hours(2)));
    assert!(
        !roles.note_seen("nobody@acct", seen),
        "an unknown role is ignored"
    );
}

#[test]
fn a_claim_revives_a_retired_role() {
    let f = Fixture::new();
    let mut roles = claimed_once(&f);
    let ttl = Duration::days(2);
    let back = t0() + Duration::days(3);
    roles.retire_idle(back, ttl);
    // A role certificate lasts a day, so the returning session holds a fresh one.
    let fresh = f.store.role("lane", back).expect("role");
    let grant = f
        .claim(
            &mut roles,
            &sign_claim(&fresh, nonce(2), back + Duration::seconds(1)).unwrap(),
            back + Duration::seconds(1),
        )
        .unwrap();
    assert_eq!(grant.epoch, 2);
    assert_eq!(roles.snapshot().roles["lane@acct"].retired_at, None);
}

#[test]
fn state_persisted_before_liveness_still_loads() {
    let old = r#"{"roles":{"lane@acct":{"epoch":3,"claimed_at":"2026-10-01T12:00:00Z"}}}"#;
    let state: synapse::roles::RolesState = serde_json::from_str(old).unwrap();
    let record = &state.roles["lane@acct"];
    assert_eq!((record.last_seen, record.retired_at), (None, None));
    let mut roles = Roles::restore(state, t0()).unwrap();
    assert_eq!(
        roles
            .retire_idle(
                t0() + Duration::days(TTL_DAYS + 1),
                Duration::days(TTL_DAYS)
            )
            .len(),
        1,
        "claimed_at stands in for a never-seen role"
    );
}
