// SPDX-License-Identifier: MIT OR Apache-2.0
//! The mailbox's needs, as PersistAnt's registry asks for them, and the stores it lists for them.
//!
//! Synapse names no backend here: [`provider_needs`] turns [`MailboxNeeds`] into capability ids and
//! a durability class, and [`listing`] is whatever `persistant::registry::providers` answers, best
//! first. An operator may record one listed id in Synapse's configuration; `open_named` turns it
//! back into a store at start-up.

use persistant::capability::CapabilityId;
use persistant::capability::choose::Durability;
use persistant::capability::provider::{ProviderNeeds, Unmet};
use persistant::registry::{self, AnyKv, Endpoint, Listing, OpenOptions};
use std::path::Path;
use std::time::Duration;
use synapse::mailbox::{DurabilityClass, MailboxNeeds};

use super::{
    PersistantMailStore, StoreError, create_owner_only_if_unix, lock_exclusive, new_runtime, se,
    wait,
};

fn ids(names: &[&str]) -> Vec<CapabilityId> {
    names
        .iter()
        .map(|n| CapabilityId::new(*n).expect("a literal capability id is well formed"))
        .collect()
}

/// `needs` as PersistAnt capability ids and the least durability class. Each field of
/// [`MailboxNeeds`] adds the ids its rows of `docs/MAILBOX_STORE_NEEDS.md` rest on; the key-value
/// basics the store always uses are always included.
pub fn provider_needs(needs: &MailboxNeeds) -> ProviderNeeds {
    let mut want = vec![
        "kv.get",
        "kv.put",
        "kv.delete",
        "kv.put_if_absent",
        "kv.compare_and_swap",
        "kv.compare_and_delete",
        "kv.prefix_list",
    ];
    if needs.atomic_batch {
        want.extend([
            "kv.batch_atomic.absent_race",
            "kv.batch_atomic.concurrent_read",
            "kv.batch_atomic.optimistic_sequence",
            "kv.batch_atomic.rollback",
        ]);
    }
    if needs.ordered_scan {
        want.extend(["kv.ordered_scan", "kv.ordered_scan_values"]);
    }
    if needs.lease_ttl {
        want.extend(["kv.ttl", "kv.ttl_remaining", "kv.purge_expired"]);
    }
    if needs.bounded_calls {
        want.push("kv.bounded_call");
    }
    let durability = match needs.durability {
        DurabilityClass::Process => Durability::Process,
        DurabilityClass::Machine => Durability::Machine,
    };
    ProviderNeeds::new(ids(&want), durability)
}

/// Whether `listing` is a server, opened from a connection URL, rather than a file.
#[must_use]
pub fn wants_url(listing: &Listing) -> bool {
    matches!(
        listing.endpoint,
        persistant::capability::provider::EndpointSpec::Url { .. }
    )
}

/// The best listed store that lives in a file under the home: the one a fresh home can be given
/// with nothing from the operator. A server needs a connection URL only the operator has.
#[must_use]
pub fn first_file_store(listed: &[Listing]) -> Option<&Listing> {
    listed.iter().find(|l| !wants_url(l))
}

/// The stores this build can offer for `needs`, best first, each with the reasons it ranks where it
/// does. `Err` names, for every store considered, what it lacks; no closest match is offered.
///
/// # Errors
/// When no store has every need.
pub fn listing(needs: &MailboxNeeds) -> Result<Vec<Listing>, Unmet> {
    registry::providers(&provider_needs(needs))
}

/// A mailbox store over whichever PersistAnt provider was opened by id.
pub type RegistryMailStore = PersistantMailStore<AnyKv>;

impl RegistryMailStore {
    /// Open the store `choice` records, under `home`: a file store as [`Self::open_named`], a server
    /// store as [`Self::open_named_url`].
    ///
    /// # Errors
    /// As those two.
    pub fn open_choice(
        choice: &StoreChoice,
        home: &Path,
        needs: &MailboxNeeds,
        call_bound: Duration,
    ) -> Result<Self, StoreError> {
        match (&choice.file, &choice.url_env) {
            (Some(file), _) => Self::open_named(&choice.id, home.join(file), needs, call_bound),
            (None, Some(var)) => Self::open_named_url(&choice.id, var, needs, call_bound),
            (None, None) => Err(StoreError("the store choice names no file or URL".into())),
        }
    }

    /// Open the server provider `id` with the connection URL held in the environment variable
    /// `url_env` (read now, never printed), gated against `needs` with every call bounded by
    /// `call_bound`. A server has no file to lock, so the store takes a **lease** in itself
    /// ([`PersistantMailStore::hold_lease`]): a second daemon on the same database is refused.
    ///
    /// # Errors
    /// When PersistAnt refuses the id, the URL is missing or wrong, the server cannot be reached, or
    /// another process holds the store.
    pub fn open_named_url(
        id: &str,
        url_env: &str,
        needs: &MailboxNeeds,
        call_bound: Duration,
    ) -> Result<Self, StoreError> {
        Self::open_named_url_in(id, url_env, needs, call_bound, "mail.v3")
    }

    /// As [`Self::open_named_url`], keeping the mailbox under key namespace `ns` (several mailboxes
    /// can share one database; each takes its own lease).
    ///
    /// # Errors
    /// As [`Self::open_named_url`].
    pub fn open_named_url_in(
        id: &str,
        url_env: &str,
        needs: &MailboxNeeds,
        call_bound: Duration,
        ns: &str,
    ) -> Result<Self, StoreError> {
        let rt = new_runtime()?;
        // Two processes opening a database that has no tables yet both run `CREATE TABLE IF NOT
        // EXISTS`, and PostgreSQL lets one of them fail with a unique violation on its catalog.
        // The tables exist by then, so the open is tried again: the loser then meets the lease
        // and is refused for the right reason instead of failing on a catalog race.
        let mut tries = 0;
        let kv = loop {
            tries += 1;
            let opened = {
                let (id, var, needs) = (id.to_string(), url_env.to_string(), provider_needs(needs));
                rt.handle().clone().spawn(async move {
                    let options = OpenOptions::new().call_bound(call_bound);
                    registry::open_named_with(&id, &Endpoint::url_env(var), &needs, &options)
                        .await
                        .map(registry::Handle::into_kv)
                        .map_err(|e| se("open", e))
                })
            };
            match wait(&rt, opened) {
                Ok(kv) => break kv,
                Err(e) if tries < 4 && e.to_string().contains("unique violation") => {
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(e) => {
                    rt.shutdown_background();
                    return Err(e);
                }
            }
        };
        let mut store = Self::from_runtime(rt, kv, ns.into());
        store.hold_lease()?;
        Ok(store)
    }

    /// Open provider `id` (an id from [`listing`], as recorded in Synapse's configuration) at the
    /// file `path`, gated again against `needs` by PersistAnt, with every call bounded by
    /// `call_bound`. The file is owner-only, as for the SQLite store, and one process holds it.
    ///
    /// # Errors
    /// When PersistAnt refuses the id (unknown, unmet needs, a wrong kind of endpoint), the file is
    /// too open, another process holds it, or the backend cannot be opened.
    pub fn open_named(
        id: &str,
        path: impl AsRef<Path>,
        needs: &MailboxNeeds,
        call_bound: Duration,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        create_owner_only_if_unix(&path)?;
        if path.exists() {
            synapse::keystore::check_owner_only(&path, "mail store")
                .map_err(|e| se("permissions", e))?;
        }
        let lock = lock_exclusive(&path)?;
        let rt = new_runtime()?;
        let opened = {
            let (id, path, needs) = (id.to_string(), path.clone(), provider_needs(needs));
            rt.handle().clone().spawn(async move {
                let options = OpenOptions::new().call_bound(call_bound);
                registry::open_named_with(&id, &Endpoint::path(&path), &needs, &options)
                    .await
                    .map(registry::Handle::into_kv)
                    .map_err(|e| se("open", e))
            })
        };
        let kv = match wait(&rt, opened) {
            Ok(kv) => kv,
            Err(e) => {
                rt.shutdown_background();
                return Err(e);
            }
        };
        if let Err(e) = synapse::keystore::check_owner_only(&path, "mail store") {
            rt.shutdown_background();
            return Err(se("permissions", e));
        }
        let mut store = Self::from_runtime(rt, kv, "mail.v3".into());
        store._lock = Some(lock);
        Ok(store)
    }
}

/// The file under a Synapse home that records the operator's chosen store.
pub const CHOICE_FILE: &str = "mailbox-store.json";

/// The store the operator picked from [`listing`]: a PersistAnt provider id and where it is: a file
/// under the home, or the name of an environment variable that holds the connection URL (the URL is
/// read when the store opens and is never written to the home, printed or logged). Synapse code
/// names no id; it only keeps the one it was given.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoreChoice {
    /// A [`Listing::id`] from PersistAnt's registry.
    pub id: String,
    /// The file name under the home, a bare name with no separators. Absent for a server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The environment variable holding the connection URL. Absent for a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_env: Option<String>,
}

fn valid_env_name(n: &str) -> bool {
    let mut c = n.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

impl StoreChoice {
    /// A choice of `id` held in `file` (default `mailbox.<id>`).
    ///
    /// # Errors
    /// When `file` is not a bare file name.
    pub fn new(id: &str, file: Option<&str>) -> Result<Self, StoreError> {
        let file = file.map_or_else(|| format!("mailbox.{id}"), str::to_string);
        Self {
            id: id.to_string(),
            file: Some(file),
            url_env: None,
        }
        .checked()
    }

    /// A choice of the server provider `id`, its connection URL in the variable `url_env`.
    ///
    /// # Errors
    /// When `url_env` is not an environment variable name.
    pub fn server(id: &str, url_env: &str) -> Result<Self, StoreError> {
        Self {
            id: id.to_string(),
            file: None,
            url_env: Some(url_env.to_string()),
        }
        .checked()
    }

    /// Exactly one of file and URL variable, each well formed.
    fn checked(self) -> Result<Self, StoreError> {
        match (&self.file, &self.url_env) {
            (Some(f), None)
                if !f.is_empty() && !f.contains(['/', '\\']) && f != "." && f != ".." =>
            {
                Ok(self)
            }
            (Some(f), None) => Err(StoreError(format!(
                "store file {f:?} is not a bare file name"
            ))),
            (None, Some(v)) if valid_env_name(v) => Ok(self),
            (None, Some(v)) => Err(StoreError(format!(
                "{v:?} is not an environment variable name"
            ))),
            _ => Err(StoreError(
                "a store choice names a file or a URL variable, not both and not neither".into(),
            )),
        }
    }

    /// The recorded choice in `home`, or `None` when the operator has recorded none.
    ///
    /// # Errors
    /// When the file exists but cannot be read or understood: the daemon must not guess a store.
    pub fn read(home: &Path) -> Result<Option<Self>, StoreError> {
        let text = match std::fs::read_to_string(home.join(CHOICE_FILE)) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(se("read store choice", e)),
        };
        let c: StoreChoice =
            serde_json::from_str(&text).map_err(|e| se("parse store choice", e))?;
        c.checked().map(Some)
    }

    /// Record this choice in `home`. Takes effect at the next daemon start.
    ///
    /// # Errors
    /// When the file cannot be written.
    pub fn write(&self, home: &Path) -> Result<(), StoreError> {
        let text = serde_json::to_string_pretty(self).map_err(|e| se("encode store choice", e))?;
        std::fs::write(home.join(CHOICE_FILE), text + "\n").map_err(|e| se("write store choice", e))
    }

    /// Where the store is, in words: the file name, or `url from $VAR`.
    #[must_use]
    pub fn describe(&self) -> String {
        match (&self.file, &self.url_env) {
            (Some(f), _) => f.clone(),
            (None, Some(v)) => format!("connection URL from ${v}"),
            (None, None) => String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mailbox_needs_ask_for_machine_durability_and_each_stated_need() {
        let n = provider_needs(&MailboxNeeds::MAILBOX);
        assert_eq!(n.min_durability(), Durability::Machine);
        let has = |s: &str| n.ids().iter().any(|i| i.as_str() == s);
        assert!(has("kv.batch_atomic.rollback"));
        assert!(has("kv.ordered_scan"));
        assert!(has("kv.ttl"));
        assert!(has("kv.bounded_call"));
    }

    #[test]
    fn a_fresh_home_is_never_given_a_server() {
        let listed = listing(&MailboxNeeds::MAILBOX).expect("a store qualifies");
        let server = listed.iter().find(|l| wants_url(l)).map(|l| l.id);
        assert!(
            server.is_some(),
            "control: this build lists a server: {listed:?}"
        );
        let file = first_file_store(&listed).expect("a file store qualifies");
        assert!(!wants_url(file), "{}", file.id);
    }

    #[test]
    fn a_need_left_off_asks_for_nothing_extra() {
        let mut m = MailboxNeeds::MAILBOX;
        m.bounded_calls = false;
        let n = provider_needs(&m);
        assert!(n.ids().iter().all(|i| i.as_str() != "kv.bounded_call"));
    }

    #[test]
    fn machine_durability_lists_the_power_loss_safe_store_and_not_the_default_one() {
        let ids: Vec<_> = listing(&MailboxNeeds::MAILBOX)
            .expect("a store qualifies")
            .iter()
            .map(|l| l.id)
            .collect();
        assert!(ids.contains(&"sqlite-full"), "{ids:?}");
        assert!(!ids.contains(&"sqlite"), "{ids:?}");
        assert!(!ids.contains(&"memory"), "{ids:?}");
        assert!(!ids.contains(&"fs"), "{ids:?}");
    }

    #[test]
    fn open_named_opens_the_top_listed_store_declares_machine_and_reopens() {
        use synapse::mailbox::MailStore;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mail.db");
        let listed = listing(&MailboxNeeds::MAILBOX).expect("a store qualifies");
        let top = first_file_store(&listed)
            .expect("a file store qualifies")
            .id;
        let bound = Duration::from_secs(10);
        let store = RegistryMailStore::open_named(top, &path, &MailboxNeeds::MAILBOX, bound)
            .expect("opens");
        assert_eq!(store.durability(), DurabilityClass::Machine);
        drop(store);
        RegistryMailStore::open_named(top, &path, &MailboxNeeds::MAILBOX, bound).expect("reopens");
    }

    #[test]
    fn an_id_that_does_not_meet_the_needs_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mail.db");
        let err = RegistryMailStore::open_named(
            "memory",
            &path,
            &MailboxNeeds::MAILBOX,
            Duration::from_secs(10),
        )
        .err()
        .expect("memory is volatile");
        assert!(err.to_string().contains("open"), "{err}");
    }

    #[test]
    fn a_choice_round_trips_and_refuses_a_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(StoreChoice::read(dir.path()).expect("reads"), None);
        let c = StoreChoice::new("sqlite-full", Some("mailbox.sqlite")).expect("bare name");
        c.write(dir.path()).expect("writes");
        assert_eq!(StoreChoice::read(dir.path()).expect("reads"), Some(c));
        assert!(StoreChoice::new("x", Some("../evil")).is_err());
        assert_eq!(
            StoreChoice::new("x", None)
                .expect("default")
                .file
                .as_deref(),
            Some("mailbox.x")
        );
    }

    #[test]
    fn a_server_choice_keeps_the_variable_name_and_never_a_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = StoreChoice::server("postgres", "SYNAPSE_DB_URL").expect("a variable name");
        c.write(dir.path()).expect("writes");
        let text = std::fs::read_to_string(dir.path().join(CHOICE_FILE)).expect("reads");
        assert!(
            text.contains("SYNAPSE_DB_URL") && !text.contains("file"),
            "{text}"
        );
        assert_eq!(StoreChoice::read(dir.path()).expect("reads"), Some(c));
        assert!(StoreChoice::server("postgres", "postgres://u:p@h/db").is_err());
    }

    #[test]
    fn a_choice_with_both_or_neither_is_refused() {
        let both = r#"{"id":"x","file":"f","url_env":"V"}"#;
        let neither = r#"{"id":"x"}"#;
        for text in [both, neither] {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(CHOICE_FILE), text).expect("writes");
            assert!(StoreChoice::read(dir.path()).is_err(), "{text}");
        }
    }

    #[test]
    fn an_unreadable_choice_file_is_an_error_not_a_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CHOICE_FILE), "{ not json").expect("writes");
        assert!(StoreChoice::read(dir.path()).is_err());
    }
}
