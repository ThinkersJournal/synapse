// SPDX-License-Identifier: MIT OR Apache-2.0
//! The persistent keystore (M2): a stable `role@account` identity on disk.
//! Design: `docs/superpowers/specs/2026-10-01-m2-keystore-design.md`.

use std::path::Path;

use synapse::keystore::{Keystore, KeystoreError, default_home, valid_name};

fn account_key_path(home: &Path) -> std::path::PathBuf {
    home.join("account").join("account.key.pem")
}

/// The home path in both slash styles, so a message can be checked for either.
fn path_forms(home: &Path) -> [String; 2] {
    let s = home.display().to_string();
    [s.replace('/', "\\"), s.replace('\\', "/")]
}

#[test]
fn init_creates_an_account_that_open_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let created = Keystore::init_account(dir.path(), "acct").expect("init");
    assert_eq!(created.account, "acct");
    assert_eq!(created.key_id.len(), 64);
    assert!(created.key_id.chars().all(|c| c.is_ascii_hexdigit()));

    let store = Keystore::open(dir.path()).expect("open");
    let read = store.account();
    assert_eq!(read.account, created.account);
    assert_eq!(read.key_id, created.key_id);
}

#[test]
fn init_refuses_when_an_account_exists() {
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init");
    let before = std::fs::read(account_key_path(dir.path())).unwrap();

    let again = Keystore::init_account(dir.path(), "other");
    assert!(
        matches!(again, Err(KeystoreError::AccountExists)),
        "a second init_account must fail with AccountExists (it succeeded: {})",
        again.is_ok()
    );
    assert_eq!(std::fs::read(account_key_path(dir.path())).unwrap(), before);
}

#[test]
fn open_without_an_account_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Keystore::open(dir.path()),
        Err(KeystoreError::NoAccount)
    ));
}

#[test]
fn names_are_validated() {
    for good in ["synapse", "a-b_1", &"x".repeat(64)] {
        assert!(valid_name(good), "{good:?} should be valid");
    }
    for bad in ["", "a.b", "a@b", "../x", "a b", &"x".repeat(65)] {
        assert!(!valid_name(bad), "{bad:?} should be invalid");
    }
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Keystore::init_account(dir.path(), "a.b"),
        Err(KeystoreError::InvalidName)
    ));
}

#[test]
fn a_garbage_account_key_is_corrupt_and_unnamed() {
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init");
    // Overwrite in place: the owner may write its own key, and the file keeps its owner-only
    // permissions, so the only thing wrong is the content.
    let key = account_key_path(dir.path());
    std::fs::write(&key, b"junk").unwrap();

    let err = Keystore::open(dir.path()).expect_err("garbage must not load");
    assert!(
        matches!(err, KeystoreError::Corrupt("account key")),
        "{err:?}"
    );
    let msg = err.to_string();
    for form in path_forms(dir.path()) {
        assert!(!msg.contains(&form), "message names the path: {msg}");
    }
    assert!(!msg.contains("junk"), "message carries file bytes: {msg}");
}

#[cfg(unix)]
#[test]
fn keys_are_owner_only_and_widened_keys_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init");
    let key = account_key_path(dir.path());
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&dir.path().join("account")), 0o700);

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Keystore::open(dir.path()),
        Err(KeystoreError::PermissionsTooOpen(_))
    ));
}

#[test]
fn a_leftover_temp_file_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    // The account directory must be owner-only for the keystore to accept it at all, so the
    // leftover is planted in one created the way the keystore creates it.
    let account = dir.path().join("account");
    std::fs::create_dir_all(&account).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&account, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(account.join(".tmp-1-1"), b"junk").unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init despite a leftover temp file");
    Keystore::open(dir.path()).expect("open despite a leftover temp file");
}

#[test]
fn default_home_prefers_synapse_home() {
    // The only test in this binary that touches the environment.
    let chosen = std::env::temp_dir().join("synapse-home-test");
    // SAFETY: no other test in this binary reads or writes these variables.
    unsafe { std::env::set_var("SYNAPSE_HOME", &chosen) };
    assert_eq!(default_home().unwrap(), chosen);
    unsafe { std::env::remove_var("SYNAPSE_HOME") };
    let fallback = default_home().unwrap();
    assert!(fallback.ends_with("synapse"), "{}", fallback.display());
    #[cfg(windows)]
    assert!(fallback.starts_with(std::env::var("LOCALAPPDATA").unwrap()));
}

// ---- Task 2: roles ----

use chrono::{DateTime, Duration, TimeZone, Utc};
use synapse::certificate::{Permission, RevocationLookup, validate_chain};

struct NoRevocations;
impl RevocationLookup for NoRevocations {
    fn is_revoked(&self, _issuer_key_id: &str, _serial: &[u8; 16]) -> bool {
        false
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
}

fn store_with_account() -> (tempfile::TempDir, Keystore) {
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init");
    let store = Keystore::open(dir.path()).expect("open");
    (dir, store)
}

/// Validate a role's chain against the store's account key, as a receiver that pinned it would.
fn validates(
    store: &Keystore,
    chain: &[synapse::certificate::AgentCertificate],
    now: DateTime<Utc>,
) -> Result<synapse::certificate::VerifiedChain, synapse::certificate::ChainError> {
    let account_key_id = store.account().key_id;
    let account_key = store.account_public_key();
    validate_chain(
        chain,
        &move |kid: &str| (kid == account_key_id).then_some(account_key),
        &NoRevocations,
        now,
    )
}

#[test]
fn a_role_is_stable_across_loads() {
    let (_dir, store) = store_with_account();
    let first = store.role("synapse", t0()).expect("role");
    let second = store
        .role("synapse", t0() + Duration::minutes(5))
        .expect("role again");
    assert_eq!(first.global_id, "synapse@acct");
    assert_eq!(second.global_id, first.global_id);
    assert_eq!(second.signing_key_id, first.signing_key_id);
    assert_eq!(second.sealing_key_id, first.sealing_key_id);
    assert_eq!(
        second.chain[0].serial, first.chain[0].serial,
        "a valid certificate is not reissued"
    );
}

#[test]
fn a_fresh_certificate_validates_against_the_account_key() {
    let (_dir, store) = store_with_account();
    let role = store.role("synapse", t0()).expect("role");
    let verified = validates(&store, &role.chain, t0()).expect("chain validates");
    assert_eq!(verified.subject_global_id, "synapse@acct");
    assert_eq!(verified.links, 1);
    let mut names: Vec<String> = verified
        .permissions
        .iter()
        .map(Permission::as_str)
        .collect();
    names.sort();
    assert_eq!(names, ["ack", "request-ack", "send", "state-write"]);
    assert_eq!(role.not_before, t0());
    assert_eq!(role.not_after, t0() + Duration::hours(24));
    assert_eq!(
        synapse::sender_auth::key_id(&verified.subject_signing_key),
        role.signing_key_id
    );
    assert_eq!(
        role.crypto.public_key_bytes().expect("signing key loaded"),
        verified.subject_signing_key
    );
}

#[test]
fn a_certificate_is_renewed_under_twelve_hours_and_not_before() {
    let (_dir, store) = store_with_account();
    let first = store.role("r", t0()).expect("role");

    let at_11h = store
        .role("r", t0() + Duration::hours(11))
        .expect("role at 11h");
    assert_eq!(
        at_11h.chain[0].serial, first.chain[0].serial,
        "12h+ left: keep"
    );

    let now = t0() + Duration::hours(12) + Duration::seconds(1);
    let renewed = store.role("r", now).expect("role past 12h");
    assert_ne!(
        renewed.chain[0].serial, first.chain[0].serial,
        "under 12h left: renew"
    );
    assert_eq!(renewed.not_before, now);
    assert_eq!(renewed.not_after, now + Duration::hours(24));
    assert_eq!(
        renewed.signing_key_id, first.signing_key_id,
        "renewal keeps the keys"
    );
    assert_eq!(
        renewed.sealing_key_id, first.sealing_key_id,
        "renewal keeps the keys"
    );
    validates(&store, &renewed.chain, now).expect("renewed chain validates");
}

#[test]
fn an_expired_certificate_is_renewed() {
    let (_dir, store) = store_with_account();
    let first = store.role("r", t0()).expect("role");
    let later = t0() + Duration::hours(48);
    let renewed = store.role("r", later).expect("role after expiry");
    assert_ne!(renewed.chain[0].serial, first.chain[0].serial);
    validates(&store, &renewed.chain, later).expect("renewed chain validates");
}

#[test]
fn concurrent_first_loads_agree_on_one_key() {
    let dir = tempfile::tempdir().unwrap();
    Keystore::init_account(dir.path(), "acct").expect("init");
    let home = dir.path().to_path_buf();
    let ids: Vec<(String, String)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let home = &home;
                s.spawn(move || {
                    let store = Keystore::open(home).expect("open");
                    let role = store.role("race", t0()).expect("role");
                    (role.signing_key_id, role.sealing_key_id)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(
        ids.windows(2).all(|w| w[0] == w[1]),
        "racing loaders disagree: {ids:?}"
    );
}

#[test]
fn a_garbage_role_key_is_corrupt_and_unnamed() {
    let (dir, store) = store_with_account();
    store.role("x", t0()).expect("role");
    let key = dir.path().join("roles").join("x").join("signing.key.pem");
    std::fs::write(&key, b"junk").unwrap();
    let err = store.role("x", t0()).expect_err("garbage must not load");
    assert_eq!(err, KeystoreError::Corrupt("role signing key"));
    for form in path_forms(dir.path()) {
        assert!(!err.to_string().contains(&form));
    }
}

#[test]
fn role_names_are_validated() {
    let (_dir, store) = store_with_account();
    assert!(matches!(
        store.role("../evil", t0()),
        Err(KeystoreError::InvalidName)
    ));
}

// ---- Task 3: Windows ACL check ----

#[cfg(windows)]
fn icacls_grant_read(path: &Path, sid: &str) {
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg(format!("*{sid}:R"))
        .stdout(std::process::Stdio::null())
        .status()
        .expect("icacls runs");
    assert!(
        status.success(),
        "icacls could not grant {sid} read: the mutation did not apply"
    );
}

#[cfg(windows)]
#[test]
fn a_fresh_store_passes_the_acl_check() {
    let (_dir, store) = store_with_account();
    store
        .role("r", t0())
        .expect("a fresh store under the user's temp dir is owner-only");
}

#[cfg(windows)]
#[test]
fn a_key_readable_by_a_broad_group_is_refused() {
    // S-1-1-0 Everyone, S-1-5-32-545 Users, S-1-5-11 Authenticated Users.
    for sid in ["S-1-1-0", "S-1-5-32-545", "S-1-5-11"] {
        let dir = tempfile::tempdir().unwrap();
        Keystore::init_account(dir.path(), "acct").expect("init");
        icacls_grant_read(&account_key_path(dir.path()), sid);
        let got = Keystore::open(dir.path());
        assert!(
            matches!(got, Err(KeystoreError::PermissionsTooOpen("account key"))),
            "{sid} can read the account key, yet open returned {got:?}"
        );
    }
}

#[cfg(windows)]
#[test]
fn a_role_key_readable_by_everyone_is_refused() {
    let (dir, store) = store_with_account();
    store.role("r", t0()).expect("role");
    icacls_grant_read(
        &dir.path().join("roles").join("r").join("signing.key.pem"),
        "S-1-1-0",
    );
    let got = store.role("r", t0());
    assert!(
        matches!(
            got,
            Err(KeystoreError::PermissionsTooOpen("role signing key"))
        ),
        "{got:?}"
    );
}

// ---- Final-review fixes ----

/// Review I1: a crash between init's two writes left a key with no name, and no command could
/// recover it ("an account already exists", yet `open` failed). The next init completes it.
#[test]
fn an_init_interrupted_before_the_name_is_completed_by_the_next_init() {
    let dir = tempfile::tempdir().unwrap();
    let first = Keystore::init_account(dir.path(), "acct").expect("init");
    let key_before = std::fs::read(account_key_path(dir.path())).unwrap();
    std::fs::remove_file(dir.path().join("account").join("name")).unwrap();

    let again = Keystore::init_account(dir.path(), "acct").expect("init completes the account");
    assert_eq!(again.key_id, first.key_id, "the existing key is kept");
    assert_eq!(
        std::fs::read(account_key_path(dir.path())).unwrap(),
        key_before
    );
    assert_eq!(
        Keystore::open(dir.path()).expect("open").account().account,
        "acct"
    );
}

/// Review I3: a reused certificate's signature was never checked, so a damaged cert.pem was
/// handed to every receiver until renewal. A certificate that does not verify is reissued.
#[test]
fn a_certificate_with_a_bad_signature_is_reissued() {
    let (dir, store) = store_with_account();
    let first = store.role("r", t0()).expect("role");
    let mut damaged = first.chain.clone();
    damaged[0].signature[0] ^= 1;
    std::fs::write(
        dir.path().join("roles").join("r").join("cert.pem"),
        synapse::certificate::chain_to_pem(&damaged),
    )
    .unwrap();

    let now = t0() + Duration::minutes(1);
    let again = store.role("r", now).expect("role");
    validates(&store, &again.chain, now).expect("a damaged certificate is not reused");
}

/// Review M1 (re-graded Important): a broad group that can WRITE a key can swap in its own key,
/// which the next load would certify. Unix refuses group/other write; Windows now does too.
#[cfg(windows)]
#[test]
fn a_key_writable_by_a_broad_group_is_refused() {
    let (dir, store) = store_with_account();
    store.role("r", t0()).expect("role");
    let key = dir.path().join("roles").join("r").join("signing.key.pem");
    let status = std::process::Command::new("icacls")
        .arg(&key)
        .arg("/grant")
        .arg("*S-1-5-32-545:W")
        .stdout(std::process::Stdio::null())
        .status()
        .expect("icacls runs");
    assert!(
        status.success(),
        "icacls could not grant Users write: the mutation did not apply"
    );
    let got = store.role("r", t0());
    assert!(
        matches!(
            got,
            Err(KeystoreError::PermissionsTooOpen("role signing key"))
        ),
        "{got:?}"
    );
}

/// #77 K1: a second writer of the account name is refused with `AccountExists`. Negative: the name
/// file is already present while the key is absent (so the key is created, then the create-only
/// name write loses). Positive: a fresh home is created.
#[test]
fn a_taken_account_name_is_refused_and_a_fresh_home_is_created() {
    let taken = tempfile::tempdir().unwrap();
    let account_dir = taken.path().join("account");
    std::fs::create_dir_all(&account_dir).unwrap();
    // Owner-only, as the keystore creates it; otherwise it refuses the directory before the name
    // write is ever reached.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&account_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(account_dir.join("name"), b"someone").unwrap();
    assert!(!account_key_path(taken.path()).exists());
    let got = Keystore::init_account(taken.path(), "acct");
    assert!(
        matches!(got, Err(KeystoreError::AccountExists)),
        "init_account over a taken name must fail with AccountExists (it succeeded: {})",
        got.is_ok()
    );
    assert_eq!(
        std::fs::read(account_dir.join("name")).unwrap(),
        b"someone",
        "the existing name is untouched"
    );

    let fresh = tempfile::tempdir().unwrap();
    let created = Keystore::init_account(fresh.path(), "acct").expect("a fresh home is created");
    assert_eq!(created.account, "acct");
}

/// #77 K2 (best effort): threads race `init_account` on fresh homes, all released together, and
/// exactly one wins per home while every loser gets `AccountExists`. Only a real race can reach
/// the "key file created between the check and the write" branch, so this test cannot guarantee
/// it executes; it guarantees the outcome is right whichever branch the race takes.
#[test]
fn racing_init_account_has_exactly_one_winner_per_home() {
    const THREADS: usize = 8;
    for round in 0..40 {
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(THREADS);
        let results: Vec<Result<_, KeystoreError>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        Keystore::init_account(dir.path(), "acct")
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "round {round}: {results:?}");
        for loser in results.iter().filter_map(|r| r.as_ref().err()) {
            assert!(
                matches!(loser, KeystoreError::AccountExists),
                "round {round}: {loser:?}"
            );
        }
        Keystore::open(dir.path()).expect("the winner's account opens");
    }
}
