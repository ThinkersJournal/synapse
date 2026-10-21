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

/// The store the operator picked from [`listing`]: a PersistAnt provider id and the file under the
/// home that holds it. Synapse code names no id; it only keeps the one it was given.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoreChoice {
    /// A [`Listing::id`] from PersistAnt's registry.
    pub id: String,
    /// The file name under the home. A bare name: no separators.
    pub file: String,
}

impl StoreChoice {
    /// A choice of `id`, held in `file` (default `mailbox.<id>`).
    ///
    /// # Errors
    /// When `file` is not a bare file name.
    pub fn new(id: &str, file: Option<&str>) -> Result<Self, StoreError> {
        let file = file.map_or_else(|| format!("mailbox.{id}"), str::to_string);
        if file.is_empty() || file.contains(['/', '\\']) || file == "." || file == ".." {
            return Err(StoreError(format!(
                "store file {file:?} is not a bare file name"
            )));
        }
        Ok(StoreChoice {
            id: id.to_string(),
            file,
        })
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
        Self::new(&c.id, Some(&c.file)).map(Some)
    }

    /// Record this choice in `home`. Takes effect at the next daemon start.
    ///
    /// # Errors
    /// When the file cannot be written.
    pub fn write(&self, home: &Path) -> Result<(), StoreError> {
        let text = serde_json::to_string_pretty(self).map_err(|e| se("encode store choice", e))?;
        std::fs::write(home.join(CHOICE_FILE), text + "\n").map_err(|e| se("write store choice", e))
    }

    /// The path of the store file under `home`.
    #[must_use]
    pub fn path(&self, home: &Path) -> std::path::PathBuf {
        home.join(&self.file)
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
    }

    #[test]
    fn open_named_opens_the_top_listed_store_declares_machine_and_reopens() {
        use synapse::mailbox::MailStore;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mail.db");
        let top = listing(&MailboxNeeds::MAILBOX).expect("a store qualifies")[0].id;
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
            StoreChoice::new("x", None).expect("default").file,
            "mailbox.x"
        );
    }

    #[test]
    fn an_unreadable_choice_file_is_an_error_not_a_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CHOICE_FILE), "{ not json").expect("writes");
        assert!(StoreChoice::read(dir.path()).is_err());
    }
}
