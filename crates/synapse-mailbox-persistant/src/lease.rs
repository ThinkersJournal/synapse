// SPDX-License-Identifier: MIT OR Apache-2.0
//! One daemon per server-backed store. A file store is held by a file lock; a store on a server has
//! no file, so the holder keeps a **lease** in the store itself: a key written with a time to live,
//! renewed every few seconds, deleted on a clean stop. A second opener finds it held and refuses;
//! after a crash the lease lapses within [`LEASE_TTL`]. The mailbox keeps its role epochs in memory,
//! so two daemons on one store would hand out clashing epochs and deliver twice.
//!
//! Only key-value calls are used (`put_if_absent`, `compare_and_swap`, `compare_and_delete` with a
//! time to live), so any backend that passes the mailbox's needs can hold one.
//!
//! If a renewal cannot be made good for longer than the lease lasts, the lease is lost: the holder
//! can no longer say nobody else has the store, and every `write` returns an error from then on.

use persistant_kv::KvBackend;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::{PersistantMailStore, StoreError, se};

/// How long a lease lasts without a renewal.
pub const LEASE_TTL: Duration = Duration::from_secs(20);
/// How often it is renewed.
const BEAT: Duration = Duration::from_secs(5);
/// How often the renewing task looks for a stop request.
const TICK: Duration = Duration::from_millis(100);
/// The longest a clean stop waits for the lease to be deleted.
const RELEASE_WAIT: Duration = Duration::from_secs(3);

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A held lease: set `stop` to end it, wait on `ended` for the delete.
pub(crate) struct Lease {
    lost: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    ended: Mutex<mpsc::Receiver<()>>,
}

impl Lease {
    pub(crate) fn is_lost(&self) -> bool {
        self.lost.load(Ordering::SeqCst)
    }

    /// Ask the renewing task to delete the lease and wait (bounded) for it to do so.
    pub(crate) fn release(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(rx) = self.ended.lock() {
            let _ = rx.recv_timeout(RELEASE_WAIT);
        }
    }
}

fn token() -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{}.{nanos}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    )
    .into_bytes()
}

impl<K: KvBackend + Send + Sync + 'static> PersistantMailStore<K> {
    /// Take this store's lease, or refuse because another holder has it. The lease is renewed in the
    /// background until the store drops.
    ///
    /// # Errors
    /// When another process holds the lease (it is free again [`LEASE_TTL`] after that process dies
    /// without a clean stop), or the backend cannot be reached.
    pub fn hold_lease(&mut self) -> Result<(), StoreError> {
        let key = format!("{}/lease", self.ns);
        let mut current = token();
        let (kv, k, v) = (Arc::clone(&self.kv), key.clone(), current.clone());
        let got = self
            .run("lease", async move {
                kv.put_if_absent(&k, v, Some(LEASE_TTL)).await
            })?
            .map_err(|e| se("lease", e))?;
        if !got {
            return Err(StoreError(format!(
                "another process holds this mail store (lease {key}); it frees {} s after that process stops",
                LEASE_TTL.as_secs()
            )));
        }
        let lost = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (done, ended) = mpsc::channel();
        let (kv, lost2, stop2) = (Arc::clone(&self.kv), Arc::clone(&lost), Arc::clone(&stop));
        self.rt().spawn(async move {
            let mut last_ok = Instant::now();
            let mut last_beat = Instant::now();
            while !stop2.load(Ordering::SeqCst) {
                tokio::time::sleep(TICK).await;
                if last_beat.elapsed() < BEAT {
                    continue;
                }
                last_beat = Instant::now();
                let next = token();
                match kv
                    .compare_and_swap(&key, &current, next.clone(), Some(LEASE_TTL))
                    .await
                {
                    Ok(true) => {
                        current = next;
                        last_ok = Instant::now();
                    }
                    // Someone else holds it now, or it lapsed: we no longer have the store alone.
                    Ok(false) => {
                        lost2.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(_) if last_ok.elapsed() >= LEASE_TTL => {
                        lost2.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(_) => {}
                }
            }
            if !lost2.load(Ordering::SeqCst) {
                let _ = kv.compare_and_delete(&key, &current).await;
            }
            let _ = done.send(());
        });
        self.lease = Some(Lease {
            lost,
            stop,
            ended: Mutex::new(ended),
        });
        Ok(())
    }

    /// An error once the lease is lost; `Ok` for a store that holds none.
    pub(crate) fn check_lease(&self) -> Result<(), StoreError> {
        match &self.lease {
            Some(l) if l.is_lost() => Err(StoreError(
                "the mail store's lease was lost: another process may be serving it; restart"
                    .into(),
            )),
            _ => Ok(()),
        }
    }
}
