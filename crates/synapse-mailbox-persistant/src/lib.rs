// SPDX-License-Identifier: MIT OR Apache-2.0
//! A Synapse [`MailStore`] over PersistAnt's key-value kind (adoption-fit note step 2; board 229).
//!
//! One `write` is optimistic: read the store version `m/ver`, run the closure against a read
//! cache plus write overlay, then commit one `batch` that `Require`s `m/ver` unchanged, applies
//! the writes and bumps `m/ver`. A lost race (`Ok(false)`) reruns the closure. Every writer
//! requires the one version key, so writers serialise and `next_seq` cannot hand out a duplicate
//! (measured in the spike: without the `Require`, 70 of 80 sequence numbers duplicated).
//!
//! **Durability is read from PersistAnt, never assumed.** [`MailStore::durability`] reports
//! `Machine` only when PersistAnt's own table declares it for the backend name the opened store
//! carries; [`SqliteMailStore::open`] opens SQLite with `open_durable` (WAL, `synchronous=FULL`),
//! which is the name declared `Machine`. A plain `SqliteBackend::open` declares `Process` and
//! `Mailbox::open` refuses it.
//!
//! **Blocking.** `write` blocks the calling thread, like the redb store. The async work runs on
//! this store's own runtime and the caller waits on a std channel, so it is safe to call from
//! inside another tokio runtime (a `block_on` there would panic). Every backend call is bounded by
//! [`PersistantMailStore::with_timeout`] (default 30 s): MySQL was measured to *stall*, not fail,
//! on a full disk, so a store without its own timeout could hang a daemon.
use chrono::{DateTime, Utc};
use persistant_kv::choose::{Durability, declared_durability};
use persistant_kv::{BatchOp, KvBackend, KvOnRelational};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use synapse::mailbox::{DurabilityClass, MailError, MailStore, MailTxn, StoreError, Stored};
use synapse::roles::RolesState;
use tokio::runtime::Runtime;

/// How many lost races one `write` tolerates before giving up.
const MAX_RACES: usize = 10_000;
/// Default bound on any one backend call.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn se(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError(format!("{what}: {e}"))
}

/// A mailbox store over any PersistAnt [`KvBackend`] with `batch` and `Require`.
pub struct PersistantMailStore<K: KvBackend + Send + Sync + 'static> {
    rt: Runtime,
    kv: Arc<K>,
    ns: String,
    timeout: Duration,
}

/// The SQLite store, opened for power-loss durability.
pub type SqliteMailStore = PersistantMailStore<KvOnRelational<persistant_sqlx::SqliteBackend>>;

impl SqliteMailStore {
    /// Open (creating if missing) a SQLite file with WAL and `synchronous=FULL`
    /// (`SqliteBackend::open_durable`), declared `Machine` by PersistAnt.
    ///
    /// # Errors
    /// When the database cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let rt = new_runtime()?;
        let path = path.as_ref().to_path_buf();
        let kv = rt
            .block_on(async move {
                let db = persistant_sqlx::SqliteBackend::open_durable(path)
                    .await
                    .map_err(|e| se("open sqlite", e))?;
                KvOnRelational::open(db).await.map_err(|e| se("open kv", e))
            })
            .map_err(|e: StoreError| e)?;
        Ok(Self::from_runtime(rt, kv, "mail".into()))
    }
}

fn new_runtime() -> Result<Runtime, StoreError> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_time()
        .build()
        .map_err(|e| se("runtime", e))
}

impl<K: KvBackend + Send + Sync + 'static> PersistantMailStore<K> {
    /// Wrap an already-opened backend under key namespace `ns`. The declared durability is
    /// whatever PersistAnt declares for `kv.backend()`, so the caller must have opened the
    /// backend the way that name implies.
    ///
    /// # Errors
    /// When the runtime cannot be built.
    pub fn new(kv: K, ns: impl Into<String>) -> Result<Self, StoreError> {
        Ok(Self::from_runtime(new_runtime()?, kv, ns.into()))
    }

    fn from_runtime(rt: Runtime, kv: K, ns: String) -> Self {
        PersistantMailStore {
            rt,
            kv: Arc::new(kv),
            ns,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Bound every backend call by `timeout` (a stall becomes an `Err`, nothing changed).
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Run `fut` on the store's runtime and wait for it on a std channel, bounded by the timeout.
    fn run<T: Send + 'static>(
        &self,
        what: &'static str,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (tx, rx) = mpsc::channel();
        let timeout = self.timeout;
        self.rt.spawn(async move {
            let out = tokio::time::timeout(timeout, fut).await;
            let _ = tx.send(out);
        });
        match rx.recv() {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(_)) => Err(StoreError(format!(
                "{what}: no answer from the backend within {timeout:?}"
            ))),
            Err(_) => Err(StoreError(format!("{what}: the backend task died"))),
        }
    }
}

struct Tx<'a, K: KvBackend + Send + Sync + 'static> {
    st: &'a PersistantMailStore<K>,
    writes: BTreeMap<String, Option<Vec<u8>>>,
}

impl<K: KvBackend + Send + Sync + 'static> Tx<'_, K> {
    fn qprefix(&self, role: &str) -> String {
        format!("{}/q/{}/", self.st.ns, hex(role))
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        if let Some(w) = self.writes.get(key) {
            return Ok(w.clone());
        }
        let kv = Arc::clone(&self.st.kv);
        let key = key.to_string();
        self.st
            .run("get", async move { kv.get(&key).await })?
            .map_err(|e| se("get", e))
    }

    /// Every entry under `prefix`, the overlay applied on top of what the backend holds.
    fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut after: Option<String> = None;
        loop {
            let kv = Arc::clone(&self.st.kv);
            let (p, a) = (prefix.to_string(), after.clone());
            let page = self
                .st
                .run("scan", async move {
                    kv.ordered_scan_values(&p, a.as_deref(), 200).await
                })?
                .map_err(|e| se("scan", e))?;
            out.extend(page.entries);
            match page.next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        for (k, w) in self.writes.range(prefix.to_string()..) {
            if !k.starts_with(prefix) {
                break;
            }
            match w {
                Some(v) => {
                    out.insert(k.clone(), v.clone());
                }
                None => {
                    out.remove(k);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    fn stage(&mut self, key: String, v: Vec<u8>) {
        self.writes.insert(key, Some(v));
    }

    fn del(&mut self, key: String) {
        self.writes.insert(key, None);
    }

    fn stored_of(raw: &[u8]) -> Result<Stored, StoreError> {
        serde_json::from_slice(raw).map_err(|e| se("decode", e))
    }
}

impl<K: KvBackend + Send + Sync + 'static> MailTxn for Tx<'_, K> {
    fn stats(&self, role: &str) -> Result<(usize, u64), StoreError> {
        let mut n = 0;
        let mut bytes = 0u64;
        for (_, raw) in self.scan_prefix(&self.qprefix(role))? {
            n += 1;
            bytes += Self::stored_of(&raw)?.envelope.body.len() as u64;
        }
        Ok((n, bytes))
    }

    fn scan(&self, role: &str, visit: &mut dyn FnMut(&Stored) -> bool) -> Result<(), StoreError> {
        let mut all = Vec::new();
        for (_, raw) in self.scan_prefix(&self.qprefix(role))? {
            all.push(Self::stored_of(&raw)?);
        }
        all.sort_by_key(|s| s.seq);
        for s in &all {
            if !visit(s) {
                break;
            }
        }
        Ok(())
    }

    fn queued(&self, role: &str, id: &str) -> Result<Option<Stored>, StoreError> {
        let key = format!("{}{}", self.qprefix(role), hex(id));
        self.get(&key)?.map(|r| Self::stored_of(&r)).transpose()
    }

    fn put(&mut self, role: &str, stored: Stored) -> Result<(), StoreError> {
        let key = format!("{}{}", self.qprefix(role), hex(&stored.envelope.message_id));
        let raw = serde_json::to_vec(&stored).map_err(|e| se("encode", e))?;
        self.stage(key, raw);
        Ok(())
    }

    fn remove(&mut self, role: &str, id: &str) -> Result<(), StoreError> {
        let key = format!("{}{}", self.qprefix(role), hex(id));
        self.del(key);
        Ok(())
    }

    fn acked_at(&self, role: &str, id: &str) -> Result<Option<DateTime<Utc>>, StoreError> {
        let key = format!("{}/a/{}/{}", self.st.ns, hex(role), hex(id));
        self.get(&key)?
            .map(|r| serde_json::from_slice(&r).map_err(|e| se("decode", e)))
            .transpose()
    }

    fn record_ack(&mut self, role: &str, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        let key = format!("{}/a/{}/{}", self.st.ns, hex(role), hex(id));
        let raw = serde_json::to_vec(&at).map_err(|e| se("encode", e))?;
        self.stage(key, raw);
        Ok(())
    }

    fn sweep_acked(&mut self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let mut n = 0;
        for (k, raw) in self.scan_prefix(&format!("{}/a/", self.st.ns))? {
            let at: DateTime<Utc> = serde_json::from_slice(&raw).map_err(|e| se("decode", e))?;
            if at < before {
                self.del(k);
                n += 1;
            }
        }
        Ok(n)
    }

    fn next_seq(&mut self) -> Result<u64, StoreError> {
        let key = format!("{}/c/seq", self.st.ns);
        let next = match self.get(&key)? {
            Some(r) => serde_json::from_slice::<u64>(&r).map_err(|e| se("decode", e))? + 1,
            None => 1,
        };
        self.stage(key, serde_json::to_vec(&next).map_err(|e| se("encode", e))?);
        Ok(next)
    }

    fn roles(&self) -> Result<RolesState, StoreError> {
        match self.get(&format!("{}/r/state", self.st.ns))? {
            Some(r) => serde_json::from_slice(&r).map_err(|e| se("decode", e)),
            None => Ok(RolesState::default()),
        }
    }

    fn set_roles(&mut self, state: &RolesState) -> Result<(), StoreError> {
        let raw = serde_json::to_vec(state).map_err(|e| se("encode", e))?;
        self.stage(format!("{}/r/state", self.st.ns), raw);
        Ok(())
    }
}

impl<K: KvBackend + Send + Sync + 'static> MailStore for PersistantMailStore<K> {
    /// `Machine` only when PersistAnt declares `Machine` for this backend's name; an unknown or
    /// weaker backend reports `Process`, which `Mailbox::open` refuses.
    fn durability(&self) -> DurabilityClass {
        match declared_durability(self.kv.backend()) {
            Some(d) if d.class == Durability::Machine => DurabilityClass::Machine,
            _ => DurabilityClass::Process,
        }
    }

    fn write(
        &self,
        f: &mut dyn FnMut(&mut dyn MailTxn) -> Result<(), MailError>,
    ) -> Result<(), MailError> {
        let ver_key = format!("{}/m/ver", self.ns);
        for _ in 0..MAX_RACES {
            let kv = Arc::clone(&self.kv);
            let k = ver_key.clone();
            let ver = self
                .run("ver", async move { kv.get(&k).await })
                .map_err(MailError::Store)?
                .map_err(|e| MailError::Store(se("ver", e)))?;
            let mut tx = Tx {
                st: self,
                writes: BTreeMap::new(),
            };
            f(&mut tx)?;
            let n: u64 = match &ver {
                Some(r) => {
                    serde_json::from_slice::<u64>(r)
                        .map_err(|e| MailError::Store(se("decode ver", e)))?
                        + 1
                }
                None => 1,
            };
            let mut ops = Vec::with_capacity(tx.writes.len() + 2);
            ops.push(BatchOp::require(ver_key.clone(), ver.clone()));
            for (k, w) in &tx.writes {
                ops.push(match w {
                    Some(v) => BatchOp::put(k.clone(), v.clone()),
                    None => BatchOp::delete(k.clone()),
                });
            }
            ops.push(BatchOp::put(
                ver_key.clone(),
                serde_json::to_vec(&n).map_err(|e| MailError::Store(se("encode ver", e)))?,
            ));
            let kv = Arc::clone(&self.kv);
            let committed = self
                .run("batch", async move { kv.batch(&ops).await })
                .map_err(MailError::Store)?
                .map_err(|e| MailError::Store(se("batch", e)))?;
            if committed {
                return Ok(());
            }
        }
        Err(MailError::Store(StoreError(format!(
            "write: gave up after {MAX_RACES} lost races"
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stalled_backend_call_becomes_an_error_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteMailStore::open(dir.path().join("m.db"))
            .unwrap()
            .with_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        let err = store
            .run("stall", async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            })
            .unwrap_err();
        assert!(err.0.contains("no answer"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn it_can_be_called_from_inside_another_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteMailStore::open(dir.path().join("m.db")).unwrap();
        let outer = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .unwrap();
        outer.block_on(async {
            store.write(&mut |_txn| Ok(())).unwrap();
        });
    }
}
