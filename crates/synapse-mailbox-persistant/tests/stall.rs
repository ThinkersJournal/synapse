// SPDX-License-Identifier: MIT OR Apache-2.0
//! Need 9 (`docs/MAILBOX_STORE_NEEDS.md`): a backend that stops answering becomes an `Err` from
//! `write` within the bound, and nothing is lost or doubled. MySQL stalled rather than failed on a
//! full disk (PersistAnt run 39325665814); this wraps a real SQLite key-value backend in one that
//! can be made to behave the same way.
use persistant_kv::{BatchOp, KvBackend, KvError, KvOnRelational, ValuePage};
use std::time::Duration;
use synapse::mailbox::conformance::{Stall, a_stalled_backend_returns_an_error_not_a_hang};
use synapse_mailbox_persistant::PersistantMailStore;

type Inner = KvOnRelational<persistant_sqlx::SqliteBackend>;

/// Delegates to `inner`; while `stall` is set a call never answers. With `after`, the call runs
/// first and only its answer is withheld: the write was applied but the caller cannot know.
struct StallKv {
    inner: Inner,
    stall: Stall,
    after: bool,
}

impl StallKv {
    async fn hold(&self) {
        while self.stall.is_set() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn call<T>(&self, f: impl std::future::Future<Output = T>) -> T {
        if self.after {
            let out = f.await;
            self.hold().await;
            out
        } else {
            self.hold().await;
            f.await
        }
    }
}

impl KvBackend for StallKv {
    fn backend(&self) -> &str {
        self.inner.backend()
    }

    fn version(&self) -> &str {
        self.inner.version()
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        self.call(self.inner.get(key)).await
    }

    async fn put(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> Result<(), KvError> {
        self.call(self.inner.put(key, value, ttl)).await
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        self.call(self.inner.delete(key)).await
    }

    async fn batch(&self, ops: &[BatchOp]) -> Result<bool, KvError> {
        self.call(self.inner.batch(ops)).await
    }

    async fn ordered_scan_values(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ValuePage, KvError> {
        self.call(self.inner.ordered_scan_values(prefix, after, limit))
            .await
    }
}

fn store(stall: Stall, after: bool) -> PersistantMailStore<StallKv> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mail.db");
    // The directory outlives the store for the length of the test process.
    std::mem::forget(dir);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let inner = rt.block_on(async {
        let db = persistant_sqlx::SqliteBackend::open_durable(&path)
            .await
            .unwrap();
        KvOnRelational::open(db).await.unwrap()
    });
    rt.shutdown_background();
    PersistantMailStore::new(
        StallKv {
            inner,
            stall,
            after,
        },
        "mail",
    )
    .unwrap()
    .with_timeout(Duration::from_millis(300))
}

#[test]
fn a_backend_that_never_answers_is_an_error_and_loses_nothing() {
    a_stalled_backend_returns_an_error_not_a_hang(|s| store(s, false), Duration::from_secs(10));
}

/// The nastier case: the write was applied and only the answer is lost.
#[test]
fn a_write_applied_but_never_acknowledged_is_not_doubled_by_the_retry() {
    a_stalled_backend_returns_an_error_not_a_hang(|s| store(s, true), Duration::from_secs(10));
}
