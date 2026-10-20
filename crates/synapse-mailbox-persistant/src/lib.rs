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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use synapse::mailbox::{
    DurabilityClass, Envelope, Lease, MailError, MailStore, MailTxn, QueueDepth, StoreError,
    Stored, is_free,
};
use synapse::roles::RolesState;
use tokio::runtime::Runtime;

/// How many lost races one `write` tolerates before giving up.
const MAX_RACES: usize = 10_000;
/// Default bound on any one backend call.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<String, StoreError> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| StoreError("bad hex key".into()))?;
    String::from_utf8(bytes).map_err(|_| StoreError("bad hex key".into()))
}

fn se(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError(format!("{what}: {e}"))
}

/// A mailbox store over any PersistAnt [`KvBackend`] with `batch` and `Require`.
pub struct PersistantMailStore<K: KvBackend + Send + Sync + 'static> {
    /// `Some` until drop, which must not block (see the `Drop` impl).
    rt: Option<Runtime>,
    kv: Arc<K>,
    ns: String,
    timeout: Duration,
    /// Held for the store's life by [`SqliteMailStore::open`]: one process per database file.
    _lock: Option<std::fs::File>,
}

/// The SQLite store, opened for power-loss durability.
pub type SqliteMailStore =
    PersistantMailStore<KvOnRelational<persistant_sqlx::Bounded<persistant_sqlx::SqliteBackend>>>;

impl SqliteMailStore {
    /// Open (creating if missing) a SQLite file with WAL and `synchronous=FULL`
    /// (`SqliteBackend::open_durable`), declared `Machine` by PersistAnt. Like the redb store, a new
    /// file is created owner-only (Unix `0600`; on Windows it inherits the profile's ACL) and every
    /// open refuses a file broader than its owner. Safe to call from inside a tokio runtime.
    ///
    /// # Errors
    /// When the file is too open, or the database cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        #[cfg(unix)]
        create_owner_only(&path).map_err(|e| se("create", e))?;
        if path.exists() {
            synapse::keystore::check_owner_only(&path, "mail store")
                .map_err(|e| se("permissions", e))?;
        }
        let lock = lock_exclusive(&path)?;
        let rt = new_runtime()?;
        let opened = {
            let p = path.clone();
            rt.handle().clone().spawn(async move {
                let db = persistant_sqlx::SqliteBackend::open_durable(p)
                    .await
                    .map_err(|e| se("open sqlite", e))?;
                // PersistAnt 0.8.20's call bound: a call that times out poisons its transaction,
                // so a timed-out batch is rolled back rather than left half-open.
                KvOnRelational::open(persistant_sqlx::Bounded::new(db, DEFAULT_TIMEOUT))
                    .await
                    .map_err(|e| se("open kv", e))
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

/// An exclusive lock on `<path>.lock`, held until the returned handle drops. The mailbox keeps its
/// role epochs in memory, so two processes serving one database would hand out clashing epochs;
/// redb's own file lock gives the redb store this, SQLite has none.
fn lock_exclusive(path: &Path) -> Result<std::fs::File, StoreError> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let lock_path = std::path::PathBuf::from(name);
    #[cfg(unix)]
    create_owner_only(&lock_path).map_err(|e| se("create lock", e))?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| se("open lock", e))?;
    file.try_lock().map_err(|e| {
        StoreError(format!(
            "another process holds the mail store ({}): {e}",
            lock_path.display()
        ))
    })?;
    Ok(file)
}

/// Wait for a task on `rt` without `block_on`, so this works inside another tokio runtime.
fn wait<T: Send + 'static>(
    rt: &Runtime,
    task: tokio::task::JoinHandle<Result<T, StoreError>>,
) -> Result<T, StoreError> {
    let (tx, rx) = mpsc::channel();
    rt.spawn(async move {
        let _ = tx.send(task.await);
    });
    match rx.recv() {
        Ok(Ok(r)) => r,
        _ => Err(StoreError("open: the backend task died".into())),
    }
}

/// A new file starts owner-only (`0600`); an existing one is left as it is.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map(drop)
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
            rt: Some(rt),
            ns,
            // Past the backend's own bound, if it has one, so the backend's error (and its
            // rollback) comes first and this is only the backstop.
            timeout: kv
                .call_bound()
                .map_or(DEFAULT_TIMEOUT, |b| b + Duration::from_secs(5)),
            kv: Arc::new(kv),
            _lock: None,
        }
    }

    fn rt(&self) -> &Runtime {
        self.rt.as_ref().expect("the runtime lives until drop")
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
        self.rt().spawn(async move {
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

/// Dropping a tokio runtime blocks, which panics inside another runtime (a daemon drops its store
/// while shutting down on one). `shutdown_background` does not wait for tasks, and every `write`
/// has already returned, so nothing of ours is in flight.
impl<K: KvBackend + Send + Sync + 'static> Drop for PersistantMailStore<K> {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

/// A stored message without its body. The body lives under its own key, so scanning a queue for
/// depth, leases or the next free message never reads a body (the redb store keeps the same split).
#[derive(Serialize, Deserialize)]
struct Meta {
    message_id: String,
    to: String,
    from: String,
    seq: u64,
    enqueued_at: DateTime<Utc>,
    lease: Option<Lease>,
    attempts: u32,
    body_len: u64,
}

impl Meta {
    fn with_body(self, body: Vec<u8>) -> Stored {
        Stored {
            envelope: Envelope {
                message_id: self.message_id,
                to: self.to,
                from: self.from,
                body,
            },
            seq: self.seq,
            enqueued_at: self.enqueued_at,
            lease: self.lease,
            attempts: self.attempts,
        }
    }
}

/// Called with each entry's key and value; `false` stops the scan.
type Emit<'a> = dyn FnMut(&str, &[u8]) -> Result<bool, StoreError> + 'a;

/// How many metas one backend call returns while scanning a queue.
const PAGE: usize = 500;

/// How many index entries `fetch` reads at a time: it usually wants the first few.
const FREE_PAGE: usize = 64;

/// A pull-based, paged scan of one key prefix with a transaction's pending writes applied on top
/// (a pending put replaces or adds an entry, a pending delete hides one), in key order.
struct Cursor<'a, K: KvBackend + Send + Sync + 'static> {
    st: &'a PersistantMailStore<K>,
    prefix: String,
    page: usize,
    after: Option<String>,
    buf: VecDeque<(String, Vec<u8>)>,
    exhausted: bool,
    overlay: Vec<(String, Option<Vec<u8>>)>,
    oi: usize,
}

impl<K: KvBackend + Send + Sync + 'static> Cursor<'_, K> {
    fn refill(&mut self) -> Result<(), StoreError> {
        let kv = Arc::clone(&self.st.kv);
        let (p, a, n) = (self.prefix.clone(), self.after.clone(), self.page);
        let page = self
            .st
            .run("scan", async move {
                kv.ordered_scan_values(&p, a.as_deref(), n).await
            })?
            .map_err(|e| se("scan", e))?;
        self.buf.extend(page.entries);
        match page.next {
            Some(n) => self.after = Some(n),
            None => self.exhausted = true,
        }
        Ok(())
    }

    fn next(&mut self) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        loop {
            while self.buf.is_empty() && !self.exhausted {
                self.refill()?;
            }
            let backend = self.buf.front().map(|(k, _)| k.as_str());
            let pending = self.overlay.get(self.oi).map(|(k, _)| k.as_str());
            match (backend, pending) {
                (None, None) => return Ok(None),
                (Some(_), None) => return Ok(self.buf.pop_front()),
                (Some(b), Some(o)) if b < o => return Ok(self.buf.pop_front()),
                (b, Some(o)) => {
                    // The pending write comes first, or replaces the backend entry of the same key.
                    if b == Some(o) {
                        self.buf.pop_front();
                    }
                    let (k, v) = self.overlay[self.oi].clone();
                    self.oi += 1;
                    if let Some(v) = v {
                        return Ok(Some((k, v)));
                    }
                }
            }
        }
    }
}

/// Key layout, all under `<ns>/` (the namespace carries the layout version, so a store written by
/// an earlier layout is never read as this one):
/// `q/<role>/<seq:020>` meta, `b/<role>/<seq:020>` body, `i/<role>/<hex id>` seq of that id,
/// `f/<role>/<seq:020>` a marker for each message with no lease, `l/<role>/<seq:020>` the
/// `Lease` of each message that has one (so `fetch` and `depths` read only what they need),
/// `s/<role>` (count, bytes), `a/<role>/<hex id>` ack time, `c/seq`, `r/state`.
/// Zero-padded `seq` makes the backend's key order the queue's order.
struct Tx<'a, K: KvBackend + Send + Sync + 'static> {
    st: &'a PersistantMailStore<K>,
    writes: BTreeMap<String, Option<Vec<u8>>>,
}

impl<K: KvBackend + Send + Sync + 'static> Tx<'_, K> {
    fn key(&self, kind: char, role: &str, tail: &str) -> String {
        format!("{}/{kind}/{}/{tail}", self.st.ns, hex(role))
    }

    fn qkey(&self, role: &str, seq: u64) -> String {
        self.key('q', role, &format!("{seq:020}"))
    }

    fn bkey(&self, role: &str, seq: u64) -> String {
        self.key('b', role, &format!("{seq:020}"))
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

    fn cursor(&self, prefix: String, page: usize) -> Cursor<'_, K> {
        let overlay: Vec<(String, Option<Vec<u8>>)> = self
            .writes
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(prefix.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Cursor {
            st: self.st,
            prefix,
            page,
            after: None,
            buf: VecDeque::new(),
            exhausted: false,
            overlay,
            oi: 0,
        }
    }

    /// Every entry under `prefix` in key order, this transaction's writes applied on top of what
    /// the backend holds, stopping when `emit` returns `false` (so a caller that needs the first
    /// few entries reads one page, not the queue).
    fn for_each(&self, prefix: &str, emit: &mut Emit<'_>) -> Result<(), StoreError> {
        let mut cursor = self.cursor(prefix.to_string(), PAGE);
        while let Some((k, v)) = cursor.next()? {
            if !emit(&k, &v)? {
                break;
            }
        }
        Ok(())
    }

    fn for_each_meta(&self, role: &str, f: &mut dyn FnMut(Meta) -> bool) -> Result<(), StoreError> {
        self.for_each(&self.key('q', role, ""), &mut |_, raw| {
            let meta: Meta = serde_json::from_slice(raw).map_err(|e| se("decode", e))?;
            Ok(f(meta))
        })
    }

    /// The first `limit` metas of the role's queue, one backend call.
    fn for_each_meta_limit(
        &self,
        role: &str,
        limit: usize,
        f: &mut dyn FnMut(Meta),
    ) -> Result<(), StoreError> {
        let mut cursor = self.cursor(self.key('q', role, ""), limit.max(1));
        for _ in 0..limit {
            let Some((_, raw)) = cursor.next()? else {
                break;
            };
            f(serde_json::from_slice(&raw).map_err(|e| se("decode", e))?);
        }
        Ok(())
    }

    fn meta(&self, role: &str, seq: u64) -> Result<Option<Meta>, StoreError> {
        self.get(&self.qkey(role, seq))?
            .map(|r| serde_json::from_slice(&r).map_err(|e| se("decode", e)))
            .transpose()
    }

    fn body(&self, role: &str, seq: u64) -> Result<Vec<u8>, StoreError> {
        self.get(&self.bkey(role, seq))?
            .ok_or_else(|| StoreError(format!("body missing for seq {seq}")))
    }

    fn seq_of(&self, role: &str, id: &str) -> Result<Option<u64>, StoreError> {
        self.get(&self.key('i', role, &hex(id)))?
            .map(|r| {
                std::str::from_utf8(&r)
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .ok_or_else(|| StoreError("bad index entry".into()))
            })
            .transpose()
    }

    fn counts(&self, role: &str) -> Result<(u64, u64), StoreError> {
        match self.get(&format!("{}/s/{}", self.st.ns, hex(role)))? {
            Some(r) => serde_json::from_slice(&r).map_err(|e| se("decode", e)),
            None => Ok((0, 0)),
        }
    }

    fn set_counts(&mut self, role: &str, count: u64, bytes: u64) -> Result<(), StoreError> {
        let raw = serde_json::to_vec(&(count, bytes)).map_err(|e| se("encode", e))?;
        self.stage(format!("{}/s/{}", self.st.ns, hex(role)), raw);
        Ok(())
    }

    fn stage(&mut self, key: String, v: Vec<u8>) {
        self.writes.insert(key, Some(v));
    }

    fn del(&mut self, key: String) {
        self.writes.insert(key, None);
    }
}

impl<K: KvBackend + Send + Sync + 'static> MailTxn for Tx<'_, K> {
    fn stats(&self, role: &str) -> Result<(usize, u64), StoreError> {
        let (count, bytes) = self.counts(role)?;
        Ok((usize::try_from(count).unwrap_or(usize::MAX), bytes))
    }

    fn scan(&self, role: &str, visit: &mut dyn FnMut(&Stored) -> bool) -> Result<(), StoreError> {
        let mut failed = None;
        self.for_each_meta(role, &mut |meta| match self.body(role, meta.seq) {
            Ok(body) => visit(&meta.with_body(body)),
            Err(e) => {
                failed = Some(e);
                false
            }
        })?;
        failed.map_or(Ok(()), Err)
    }

    fn scan_leases(
        &self,
        role: &str,
        visit: &mut dyn FnMut(DateTime<Utc>, Option<&Lease>),
    ) -> Result<(), StoreError> {
        self.for_each_meta(role, &mut |meta| {
            visit(meta.enqueued_at, meta.lease.as_ref());
            true
        })
    }

    fn scan_free(
        &self,
        role: &str,
        epoch: u64,
        now: DateTime<Utc>,
        visit: &mut dyn FnMut(&Stored) -> bool,
    ) -> Result<(), StoreError> {
        // Two ordered streams, merged by seq: messages never leased (all free) and leased ones
        // (free only when expired or held by an older epoch). Neither reads a message's metadata
        // or body until it is chosen, and the scan stops at the first `false`.
        let fprefix = self.key('f', role, "");
        let lprefix = self.key('l', role, "");
        let mut free = self.cursor(fprefix.clone(), FREE_PAGE);
        let mut leased = self.cursor(lprefix.clone(), FREE_PAGE);
        let mut next_free = free.next()?;
        let mut next_leased = leased.next()?;
        loop {
            let take_free = match (&next_free, &next_leased) {
                (None, None) => break,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (Some((f, _)), Some((l, _))) => f[fprefix.len()..] < l[lprefix.len()..],
            };
            let seq: u64 = if take_free {
                let (k, _) = next_free.take().expect("checked above");
                next_free = free.next()?;
                k[fprefix.len()..]
                    .parse()
                    .map_err(|_| StoreError("bad free key".into()))?
            } else {
                let (k, v) = next_leased.take().expect("checked above");
                next_leased = leased.next()?;
                let lease: Lease = serde_json::from_slice(&v).map_err(|e| se("decode", e))?;
                if !is_free(Some(&lease), epoch, now) {
                    continue;
                }
                k[lprefix.len()..]
                    .parse()
                    .map_err(|_| StoreError("bad lease key".into()))?
            };
            let Some(meta) = self.meta(role, seq)? else {
                continue;
            };
            // The metadata is the authority; the indexes only say where to look.
            if !is_free(meta.lease.as_ref(), epoch, now) {
                continue;
            }
            let body = self.body(role, seq)?;
            if !visit(&meta.with_body(body)) {
                break;
            }
        }
        Ok(())
    }

    fn queue_depth(
        &self,
        role: &str,
        epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<QueueDepth, StoreError> {
        let (total, _) = self.counts(role)?;
        let total = usize::try_from(total).unwrap_or(usize::MAX);
        // Only the leased messages are read: those held by this epoch and unexpired are `leased`,
        // everything else is `queued`.
        let mut leased = 0_usize;
        let mut cursor = self.cursor(self.key('l', role, ""), PAGE);
        while let Some((_, v)) = cursor.next()? {
            let lease: Lease = serde_json::from_slice(&v).map_err(|e| se("decode", e))?;
            if lease.epoch == epoch && lease.until > now {
                leased += 1;
            }
        }
        // Sequence numbers rise with enqueue time, so the oldest arrival is the first row's.
        let mut oldest = None;
        self.for_each_meta_limit(role, 1, &mut |meta| {
            oldest = Some(meta.enqueued_at);
        })?;
        Ok(QueueDepth {
            queued: total.saturating_sub(leased),
            leased,
            oldest_enqueued_at: oldest,
        })
    }

    fn queued(&self, role: &str, id: &str) -> Result<Option<Stored>, StoreError> {
        let Some(seq) = self.seq_of(role, id)? else {
            return Ok(None);
        };
        let Some(meta) = self.meta(role, seq)? else {
            return Ok(None);
        };
        let body = self.body(role, seq)?;
        Ok(Some(meta.with_body(body)))
    }

    fn put(&mut self, role: &str, stored: Stored) -> Result<(), StoreError> {
        let id = stored.envelope.message_id.clone();
        let existing = match self.seq_of(role, &id)? {
            Some(seq) => self.meta(role, seq)?,
            None => None,
        };
        // A replace keeps the stored body and its size (as the redb store does): leasing a
        // message must not rewrite it.
        let body_len = existing
            .as_ref()
            .map_or(stored.envelope.body.len() as u64, |m| m.body_len);
        let seq = existing.as_ref().map_or(stored.seq, |m| m.seq);
        let meta = Meta {
            message_id: id.clone(),
            to: stored.envelope.to.clone(),
            from: stored.envelope.from.clone(),
            seq,
            enqueued_at: stored.enqueued_at,
            lease: stored.lease.clone(),
            attempts: stored.attempts,
            body_len,
        };
        let raw = serde_json::to_vec(&meta).map_err(|e| se("encode", e))?;
        let qkey = self.qkey(role, seq);
        self.stage(qkey, raw);
        let (fkey, lkey) = (
            self.key('f', role, &format!("{seq:020}")),
            self.key('l', role, &format!("{seq:020}")),
        );
        match &stored.lease {
            Some(lease) => {
                let raw = serde_json::to_vec(lease).map_err(|e| se("encode", e))?;
                self.stage(lkey, raw);
                self.del(fkey);
            }
            None => {
                self.stage(fkey, b"1".to_vec());
                self.del(lkey);
            }
        }
        if existing.is_none() {
            let bkey = self.bkey(role, seq);
            self.stage(bkey, stored.envelope.body);
            let ikey = self.key('i', role, &hex(&id));
            self.stage(ikey, seq.to_string().into_bytes());
            let (count, bytes) = self.counts(role)?;
            self.set_counts(role, count + 1, bytes + body_len)?;
        }
        Ok(())
    }

    fn remove(&mut self, role: &str, id: &str) -> Result<(), StoreError> {
        let Some(seq) = self.seq_of(role, id)? else {
            return Ok(());
        };
        let body_len = self.meta(role, seq)?.map_or(0, |m| m.body_len);
        let (qkey, bkey, ikey) = (
            self.qkey(role, seq),
            self.bkey(role, seq),
            self.key('i', role, &hex(id)),
        );
        let (fkey, lkey) = (
            self.key('f', role, &format!("{seq:020}")),
            self.key('l', role, &format!("{seq:020}")),
        );
        self.del(qkey);
        self.del(bkey);
        self.del(ikey);
        self.del(fkey);
        self.del(lkey);
        let (count, bytes) = self.counts(role)?;
        self.set_counts(
            role,
            count.saturating_sub(1),
            bytes.saturating_sub(body_len),
        )
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
        let mut old = Vec::new();
        self.for_each(&format!("{}/a/", self.st.ns), &mut |k, raw| {
            let at: DateTime<Utc> = serde_json::from_slice(raw).map_err(|e| se("decode", e))?;
            if at < before {
                old.push(k.to_string());
            }
            Ok(true)
        })?;
        let n = old.len();
        for k in old {
            self.del(k);
        }
        Ok(n)
    }

    fn queue_roles(&self) -> Result<Vec<String>, StoreError> {
        // A count row exists for every role that ever held a message; keep those that hold some.
        let prefix = format!("{}/s/", self.st.ns);
        let mut roles = Vec::new();
        self.for_each(&prefix, &mut |k, raw| {
            let (count, _): (u64, u64) =
                serde_json::from_slice(raw).map_err(|e| se("decode", e))?;
            if count > 0 {
                roles.push(unhex(&k[prefix.len()..])?);
            }
            Ok(true)
        })?;
        Ok(roles)
    }

    fn all_acked(&self) -> Result<Vec<(String, String, DateTime<Utc>)>, StoreError> {
        let prefix = format!("{}/a/", self.st.ns);
        let mut out = Vec::new();
        self.for_each(&prefix, &mut |k, raw| {
            let (role, id) = k[prefix.len()..]
                .split_once('/')
                .ok_or_else(|| StoreError("bad acked key".into()))?;
            let at = serde_json::from_slice(raw).map_err(|e| se("decode", e))?;
            out.push((unhex(role)?, unhex(id)?, at));
            Ok(true)
        })?;
        Ok(out)
    }

    fn seq_counter(&self) -> Result<u64, StoreError> {
        match self.get(&format!("{}/c/seq", self.st.ns))? {
            Some(r) => serde_json::from_slice(&r).map_err(|e| se("decode", e)),
            None => Ok(0),
        }
    }

    fn set_seq_counter(&mut self, value: u64) -> Result<(), StoreError> {
        let raw = serde_json::to_vec(&value).map_err(|e| se("encode", e))?;
        self.stage(format!("{}/c/seq", self.st.ns), raw);
        Ok(())
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
