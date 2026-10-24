// SPDX-License-Identifier: MIT OR Apache-2.0
//! The durable [`Backend`](super::Backend): one redb file, owner-only like the mailbox's.

use redb::{ReadableTable, TableDefinition};

use super::{
    Backend, DerivedFlags, FactObservation, FactSpec, HistoryEntry, Notice, Record, StateError,
    Txn, TxnRead,
};

/// `id` -> serde_json [`Record`].
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("records");
/// `(id, revision)` -> serde_json [`HistoryEntry`].
const HISTORY: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("history");
/// `seq` -> serde_json [`Notice`]: not yet delivered.
const NOTICES: TableDefinition<u64, &[u8]> = TableDefinition::new("notices");
/// fact spec -> serde_json [`FactObservation`].
const FACTS: TableDefinition<&str, &[u8]> = TableDefinition::new("facts");
/// record id -> serde_json [`DerivedFlags`]: what was last notified.
const FLAGS: TableDefinition<&str, &[u8]> = TableDefinition::new("derived_flags");
/// `"record"` -> the last record number issued; `"notice"` -> the last notice seq; `"format"` -> the file format stamp.
const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");
const FORMAT: u64 = 1;

fn err(what: &str) -> impl Fn(&dyn std::fmt::Display) -> StateError + '_ {
    move |e| StateError::Store(format!("{what}: {e}"))
}

/// A durable store. The file is created owner-only (Unix `0600`; on Windows it inherits the user
/// profile's ACL) and every open refuses a file broader than its owner.
pub struct RedbBackend {
    db: redb::Database,
}

impl RedbBackend {
    pub fn open(path: &std::path::Path) -> Result<Self, StateError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(|e| err("create")(&e))?;
        }
        let db = redb::Database::create(path).map_err(|e| err("open")(&e))?;
        crate::keystore::check_owner_only(path, "state store")
            .map_err(|e| err("permissions")(&e))?;
        let txn = db.begin_write().map_err(|e| err("begin")(&e))?;
        {
            txn.open_table(RECORDS).map_err(|e| err("table")(&e))?;
            txn.open_table(HISTORY).map_err(|e| err("table")(&e))?;
            txn.open_table(NOTICES).map_err(|e| err("table")(&e))?;
            txn.open_table(FACTS).map_err(|e| err("table")(&e))?;
            txn.open_table(FLAGS).map_err(|e| err("table")(&e))?;
            let mut counters = txn.open_table(COUNTERS).map_err(|e| err("table")(&e))?;
            let stamped = counters
                .get("format")
                .map_err(|e| err("format")(&e))?
                .map(|v| v.value());
            match stamped {
                None => {
                    counters
                        .insert("format", FORMAT)
                        .map_err(|e| err("format")(&e))?;
                }
                Some(FORMAT) => {}
                Some(newer) => {
                    return Err(StateError::Store(format!(
                        "state store format {newer} is newer than this binary knows ({FORMAT})"
                    )));
                }
            }
        }
        txn.commit().map_err(|e| err("commit")(&e))?;
        Ok(RedbBackend { db })
    }
}

struct RedbTxn {
    txn: redb::WriteTransaction,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, StateError> {
    serde_json::from_slice(bytes).map_err(|e| err("decode")(&e))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec(value).map_err(|e| err("encode")(&e))
}

impl TxnRead for RedbTxn {
    fn record(&self, id: &str) -> Result<Option<Record>, StateError> {
        let table = self.txn.open_table(RECORDS).map_err(|e| err("table")(&e))?;
        let got = table.get(id).map_err(|e| err("read")(&e))?;
        got.map(|v| decode(v.value())).transpose()
    }

    fn all(&self) -> Result<Vec<Record>, StateError> {
        let table = self.txn.open_table(RECORDS).map_err(|e| err("table")(&e))?;
        let mut out = Vec::new();
        for row in table.iter().map_err(|e| err("scan")(&e))? {
            let (_, value) = row.map_err(|e| err("scan")(&e))?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }

    fn history(&self, id: &str) -> Result<Vec<HistoryEntry>, StateError> {
        let table = self.txn.open_table(HISTORY).map_err(|e| err("table")(&e))?;
        let mut out = Vec::new();
        for row in table
            .range((id, 0)..=(id, u64::MAX))
            .map_err(|e| err("scan")(&e))?
        {
            let (_, value) = row.map_err(|e| err("scan")(&e))?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }

    fn notices(&self, max: usize) -> Result<Vec<Notice>, StateError> {
        let table = self.txn.open_table(NOTICES).map_err(|e| err("table")(&e))?;
        let mut out = Vec::new();
        for row in table.iter().map_err(|e| err("scan")(&e))?.take(max) {
            let (_, value) = row.map_err(|e| err("scan")(&e))?;
            out.push(decode(value.value())?);
        }
        Ok(out)
    }

    fn fact(&self, spec: &FactSpec) -> Result<Option<FactObservation>, StateError> {
        let table = self.txn.open_table(FACTS).map_err(|e| err("table")(&e))?;
        let got = table.get(spec.as_str()).map_err(|e| err("read")(&e))?;
        got.map(|v| decode(v.value())).transpose()
    }

    fn derived_flags(&self, id: &str) -> Result<Option<DerivedFlags>, StateError> {
        let table = self.txn.open_table(FLAGS).map_err(|e| err("table")(&e))?;
        let got = table.get(id).map_err(|e| err("read")(&e))?;
        got.map(|v| decode(v.value())).transpose()
    }
}

impl Txn for RedbTxn {
    fn next_number(&mut self) -> Result<u64, StateError> {
        let mut table = self
            .txn
            .open_table(COUNTERS)
            .map_err(|e| err("table")(&e))?;
        let next = table
            .get("record")
            .map_err(|e| err("counter")(&e))?
            .map_or(0, |v| v.value())
            + 1;
        table
            .insert("record", next)
            .map_err(|e| err("counter")(&e))?;
        Ok(next)
    }

    fn put_record(&mut self, record: &Record) -> Result<(), StateError> {
        let mut table = self.txn.open_table(RECORDS).map_err(|e| err("table")(&e))?;
        table
            .insert(record.id.as_str(), encode(record)?.as_slice())
            .map_err(|e| err("write")(&e))?;
        Ok(())
    }

    fn push_notice(&mut self, notice: &Notice) -> Result<(), StateError> {
        let seq = {
            let mut table = self
                .txn
                .open_table(COUNTERS)
                .map_err(|e| err("table")(&e))?;
            let next = table
                .get("notice")
                .map_err(|e| err("counter")(&e))?
                .map_or(0, |v| v.value())
                + 1;
            table
                .insert("notice", next)
                .map_err(|e| err("counter")(&e))?;
            next
        };
        let mut stored = notice.clone();
        stored.seq = seq;
        let mut table = self.txn.open_table(NOTICES).map_err(|e| err("table")(&e))?;
        table
            .insert(seq, encode(&stored)?.as_slice())
            .map_err(|e| err("write")(&e))?;
        Ok(())
    }

    fn put_fact(&mut self, fact: &FactObservation) -> Result<(), StateError> {
        let mut table = self.txn.open_table(FACTS).map_err(|e| err("table")(&e))?;
        table
            .insert(fact.fact.as_str(), encode(fact)?.as_slice())
            .map_err(|e| err("write")(&e))?;
        Ok(())
    }

    fn put_derived_flags(&mut self, id: &str, flags: &DerivedFlags) -> Result<(), StateError> {
        let mut table = self.txn.open_table(FLAGS).map_err(|e| err("table")(&e))?;
        table
            .insert(id, encode(flags)?.as_slice())
            .map_err(|e| err("write")(&e))?;
        Ok(())
    }

    fn remove_notice(&mut self, seq: u64) -> Result<(), StateError> {
        let mut table = self.txn.open_table(NOTICES).map_err(|e| err("table")(&e))?;
        table.remove(seq).map_err(|e| err("write")(&e))?;
        Ok(())
    }

    fn append(&mut self, entry: &HistoryEntry) -> Result<(), StateError> {
        let mut table = self.txn.open_table(HISTORY).map_err(|e| err("table")(&e))?;
        table
            .insert(
                (entry.id.as_str(), entry.revision),
                encode(entry)?.as_slice(),
            )
            .map_err(|e| err("write")(&e))?;
        Ok(())
    }
}

impl Backend for RedbBackend {
    fn write<R>(
        &self,
        f: impl FnOnce(&mut dyn Txn) -> Result<R, StateError>,
    ) -> Result<R, StateError> {
        let mut txn = RedbTxn {
            txn: self.db.begin_write().map_err(|e| err("begin")(&e))?,
        };
        // Dropping an uncommitted write transaction discards it.
        let out = f(&mut txn)?;
        txn.txn.commit().map_err(|e| err("commit")(&e))?;
        Ok(out)
    }

    fn read<R>(
        &self,
        f: impl FnOnce(&dyn TxnRead) -> Result<R, StateError>,
    ) -> Result<R, StateError> {
        let txn = RedbTxn {
            txn: self.db.begin_write().map_err(|e| err("begin")(&e))?,
        };
        f(&txn)
    }
}
