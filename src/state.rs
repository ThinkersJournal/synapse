// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared state between lanes: one [`Record`] per cross-lane thread, written by compare-and-set on
//! a revision, with an append-only, hash-chained history. Design:
//! `docs/superpowers/specs/2026-10-23-shared-state-design.md` (slice S1).
//!
//! Everything here is transport-neutral: the [`StateStore`] trait takes a [`Caller`] (the verified
//! role and what its certificate grants, resolved by whoever binds this to a transport) and returns
//! plain values. Access, compare-and-set, validation and the hash chain live in [`StateEngine`], so
//! no binding can bypass them; a [`Backend`] only stores rows.
//!
//! Free text (`title`, `notes`, condition values) is data: stored as given, bounded, never executed.
//! A [`FactSpec`] is parsed against a closed registry; text that does not parse is refused.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keystore::valid_name;

#[cfg(feature = "mailbox-redb")]
mod redb_backend;
#[cfg(feature = "mailbox-redb")]
pub use redb_backend::RedbBackend;

/// Largest `title`, in bytes.
pub const MAX_TITLE: usize = 200;
/// Largest `notes`, in bytes.
pub const MAX_NOTES: usize = 8 * 1024;
/// Most conditions in `verify` plus `blocked_on`, each.
pub const MAX_CONDITIONS: usize = 32;
/// Most parties on one record.
pub const MAX_PARTIES: usize = 16;
/// Largest condition value, in bytes.
pub const MAX_VALUE: usize = 200;
/// Hash of the (nonexistent) entry before revision 1.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// A thread's lifecycle. `Done` and `Cancelled` are terminal: only an admin patches a terminal record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Open,
    Blocked,
    Waiting,
    Done,
    Cancelled,
}

impl State {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Done | State::Cancelled)
    }
}

/// How a condition's observed value is compared with its `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    /// Semver `>=`; only for `crate_version`.
    Ge,
    Exists,
    Absent,
}

/// A fact the forge can answer, named from a closed registry. S1 validates the text; S4 evaluates it.
///
/// | kind | text |
/// |---|---|
/// | `crate_version` | `crate_version:<crate>` |
/// | `pr_state` | `pr_state:<owner>/<repo>#<n>` |
/// | `ref_sha` | `ref_sha:<owner>/<repo>@<branch>` |
/// | `check_state` | `check_state:<owner>/<repo>@<sha>` |
/// | `file_at_ref` | `file_at_ref:<owner>/<repo>@<ref>:<path>` |
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FactSpec(String);

fn slug(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn repo_ok(s: &str) -> bool {
    matches!(s.split_once('/'), Some((o, r)) if slug(o, 64) && slug(r, 100))
}

fn refname_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
}

impl FactSpec {
    /// Parse `text` against the registry.
    pub fn parse(text: &str) -> Result<FactSpec, StateError> {
        let bad = || StateError::Malformed(format!("not a known fact: {}", clip(text)));
        let (kind, rest) = text.split_once(':').ok_or_else(bad)?;
        let ok = match kind {
            "crate_version" => slug(rest, 64),
            "pr_state" => matches!(rest.split_once('#'),
                Some((repo, n)) if repo_ok(repo) && !n.is_empty() && n.len() <= 9
                    && n.bytes().all(|b| b.is_ascii_digit())),
            "ref_sha" => matches!(rest.split_once('@'),
                Some((repo, branch)) if repo_ok(repo) && refname_ok(branch)),
            "check_state" => matches!(rest.split_once('@'),
                Some((repo, sha)) if repo_ok(repo) && (7..=64).contains(&sha.len())
                    && sha.bytes().all(|b| b.is_ascii_hexdigit())),
            "file_at_ref" => matches!(rest.split_once('@'),
                Some((repo, tail)) if repo_ok(repo) && matches!(tail.split_once(':'),
                    Some((r, path)) if refname_ok(r) && refname_ok(path))),
            _ => false,
        };
        if ok {
            Ok(FactSpec(text.to_string()))
        } else {
            Err(bad())
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        self.0.split_once(':').map_or("", |(k, _)| k)
    }
}

impl TryFrom<String> for FactSpec {
    type Error = StateError;
    fn try_from(text: String) -> Result<Self, StateError> {
        FactSpec::parse(&text)
    }
}

impl From<FactSpec> for String {
    fn from(spec: FactSpec) -> String {
        spec.0
    }
}

fn clip(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(60).collect()
}

/// A fact, how to compare it, and the value to compare with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub fact: FactSpec,
    pub op: Op,
    #[serde(default)]
    pub value: String,
}

impl Condition {
    fn validate(&self) -> Result<(), StateError> {
        if self.value.len() > MAX_VALUE || self.value.chars().any(char::is_control) {
            return Err(StateError::Malformed("condition value".into()));
        }
        match self.op {
            Op::Ge if self.fact.kind() != "crate_version" => {
                return Err(StateError::Malformed(
                    "`ge` applies only to crate_version".into(),
                ));
            }
            Op::Eq | Op::Ge if self.value.is_empty() => {
                return Err(StateError::Malformed(
                    "this comparison needs a value".into(),
                ));
            }
            Op::Exists | Op::Absent if !self.value.is_empty() => {
                return Err(StateError::Malformed("exists/absent take no value".into()));
            }
            _ => {}
        }
        Ok(())
    }
}

/// What a blocked record waits on: another record, or a fact condition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blocker {
    Record(String),
    Condition(Condition),
}

/// `T-<n>`: the id shape this slice allocates.
fn id_ok(id: &str) -> bool {
    id.strip_prefix("T-").is_some_and(|n| {
        !n.is_empty()
            && n.len() <= 12
            && n.bytes().all(|b| b.is_ascii_digit())
            && !n.starts_with('0')
    })
}

/// One cross-lane thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// `T-<n>`, allocated by the store, never reused.
    pub id: String,
    /// Reserved for a ULID that may replace `id` later (CireSnave/PM, 2026-10-23). Always `None` now.
    #[serde(default)]
    pub uid: Option<String>,
    pub title: String,
    pub parties: Vec<String>,
    pub owner: String,
    pub state: State,
    pub blocked_on: Vec<Blocker>,
    pub verify: Vec<Condition>,
    pub notes: String,
    /// 1 at creation, +1 per accepted write.
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The fields a writer supplies to create a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRecord {
    pub title: String,
    pub parties: Vec<String>,
    pub owner: String,
    #[serde(default = "default_state")]
    pub state: State,
    #[serde(default)]
    pub blocked_on: Vec<Blocker>,
    #[serde(default)]
    pub verify: Vec<Condition>,
    #[serde(default)]
    pub notes: String,
}

fn default_state() -> State {
    State::Open
}

/// A field-level change: a `Some` field replaces the whole field, a `None` field is left alone.
/// Unknown fields are refused, not ignored; derived fields are not patchable.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parties: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_on: Option<Vec<Blocker>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<Vec<Condition>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl Patch {
    /// The names of the fields this patch sets, for notifications and the history.
    #[must_use]
    pub fn fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.title.is_some() {
            out.push("title");
        }
        if self.parties.is_some() {
            out.push("parties");
        }
        if self.owner.is_some() {
            out.push("owner");
        }
        if self.state.is_some() {
            out.push("state");
        }
        if self.blocked_on.is_some() {
            out.push("blocked_on");
        }
        if self.verify.is_some() {
            out.push("verify");
        }
        if self.notes.is_some() {
            out.push("notes");
        }
        out
    }
}

/// What one history entry did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Create(NewRecord),
    Patch(Patch),
}

/// One accepted write. `hash` covers every other field and `prev_hash`, so removing or altering an
/// entry is detected by [`verify_chain`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub revision: u64,
    /// The writer's verified role.
    pub writer: String,
    pub written_at: DateTime<Utc>,
    pub change: Change,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Serialize)]
struct HashInput<'a> {
    id: &'a str,
    revision: u64,
    writer: &'a str,
    written_micros: i64,
    change: &'a Change,
    prev_hash: &'a str,
}

impl HistoryEntry {
    fn compute_hash(&self) -> String {
        let input = HashInput {
            id: &self.id,
            revision: self.revision,
            writer: &self.writer,
            written_micros: self.written_at.timestamp_micros(),
            change: &self.change,
            prev_hash: &self.prev_hash,
        };
        // Struct field order is fixed, so this serialisation is deterministic.
        let bytes = serde_json::to_vec(&input).expect("history entries always serialise");
        Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Check a record's history end to end: revisions run 1.. without a gap, each `prev_hash` is the
/// previous `hash`, and every `hash` matches its entry. `Err(revision)` names the first bad entry
/// (0 for an empty history).
pub fn verify_chain(history: &[HistoryEntry]) -> Result<(), u64> {
    if history.is_empty() {
        return Err(0);
    }
    let mut prev = GENESIS_HASH.to_string();
    for (i, entry) in history.iter().enumerate() {
        if entry.revision != i as u64 + 1
            || entry.prev_hash != prev
            || entry.hash != entry.compute_hash()
        {
            return Err(entry.revision);
        }
        prev.clone_from(&entry.hash);
    }
    Ok(())
}

/// Rebuild a record from its history: the check that the history is the whole story.
pub fn fold(history: &[HistoryEntry]) -> Result<Record, StateError> {
    let mut record: Option<Record> = None;
    for entry in history {
        record = Some(match (&entry.change, record) {
            (Change::Create(new), None) => from_new(&entry.id, new, entry.written_at),
            (Change::Patch(patch), Some(mut r)) => {
                apply(&mut r, patch);
                r.revision = entry.revision;
                r.updated_at = entry.written_at;
                r
            }
            _ => {
                return Err(StateError::Store(
                    "history does not start with a create".into(),
                ));
            }
        });
    }
    record.ok_or_else(|| StateError::Store("empty history".into()))
}

fn from_new(id: &str, new: &NewRecord, now: DateTime<Utc>) -> Record {
    Record {
        id: id.to_string(),
        uid: None,
        title: new.title.clone(),
        parties: new.parties.clone(),
        owner: new.owner.clone(),
        state: new.state,
        blocked_on: new.blocked_on.clone(),
        verify: new.verify.clone(),
        notes: new.notes.clone(),
        revision: 1,
        created_at: now,
        updated_at: now,
    }
}

fn apply(r: &mut Record, p: &Patch) {
    if let Some(v) = &p.title {
        r.title.clone_from(v);
    }
    if let Some(v) = &p.parties {
        r.parties.clone_from(v);
    }
    if let Some(v) = &p.owner {
        r.owner.clone_from(v);
    }
    if let Some(v) = p.state {
        r.state = v;
    }
    if let Some(v) = &p.blocked_on {
        r.blocked_on.clone_from(v);
    }
    if let Some(v) = &p.verify {
        r.verify.clone_from(v);
    }
    if let Some(v) = &p.notes {
        r.notes.clone_from(v);
    }
}

/// "Record `id` changed": what a party is told, and nothing more. It carries ids and field names,
/// never a title, note or value, so no free text reaches a channel and a party whose access was
/// withdrawn learns nothing it can read. The store writes one per party (but the writer) in the same
/// transaction as the write; a delivery task hands them on and then marks them delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Assigned by the store, in write order; 0 until stored.
    pub seq: u64,
    pub id: String,
    pub revision: u64,
    /// The party told.
    pub to: String,
    pub changed_by: String,
    /// `["created"]` for a new record, else the patched field names.
    pub fields: Vec<String>,
}

impl Notice {
    /// The mail body: compact JSON of the ids and field names.
    #[must_use]
    pub fn body(&self) -> String {
        serde_json::json!({
            "kind": "state",
            "id": self.id,
            "revision": self.revision,
            "changed_by": self.changed_by,
            "fields": self.fields,
        })
        .to_string()
    }

    /// The mailbox message id: stable for one (record, revision, party), so a notice handed over
    /// twice after a crash is one message.
    #[must_use]
    pub fn message_id(&self) -> String {
        format!("state:{}:{}:{}", self.id, self.revision, self.to)
    }
}

/// Why a store call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// The caller may not do this to this record.
    Forbidden,
    NotFound,
    /// The write named a revision that is no longer current. Nothing changed; the current record is
    /// attached so the writer decides again without another round trip.
    StaleRevision(Box<Record>),
    /// A terminal record is patched only by an admin.
    Terminal,
    /// A `blocked_on` record id names no record.
    UnknownBlocker(String),
    Malformed(String),
    /// The backing store failed.
    Store(String),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Forbidden => write!(f, "forbidden"),
            StateError::NotFound => write!(f, "no such record"),
            StateError::StaleRevision(current) => {
                write!(
                    f,
                    "stale revision: {} is at {}",
                    current.id, current.revision
                )
            }
            StateError::Terminal => write!(f, "the record is done or cancelled"),
            StateError::UnknownBlocker(id) => {
                write!(f, "blocked on an unknown record {}", clip(id))
            }
            StateError::Malformed(what) => write!(f, "malformed: {what}"),
            StateError::Store(what) => write!(f, "store: {what}"),
        }
    }
}

impl std::error::Error for StateError {}

/// Who is calling and what its certificate grants. The binding (daemon, CLI, a tool server) fills this from
/// the verified session; a request never supplies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The verified role name (no account suffix), as the mailbox's `from`.
    pub role: String,
    /// `state-write`: may create records and patch those it is a party to.
    pub write: bool,
    /// `state-admin`: reads and patches any record, changes owners, patches terminal records.
    pub admin: bool,
    /// Reads every record (the PM and the export role); grants no write.
    pub read_all: bool,
}

impl Caller {
    fn sees(&self, r: &Record) -> bool {
        self.admin || self.read_all || r.parties.contains(&self.role)
    }
}

/// Which records `list` returns, beyond what the caller may see.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    /// Empty: any state.
    pub states: Vec<State>,
    pub party: Option<String>,
}

/// The transport-neutral API. The daemon, the CLI, agent tool servers and a future Commy binding all call this.
pub trait StateStore {
    fn create(
        &self,
        caller: &Caller,
        new: NewRecord,
        now: DateTime<Utc>,
    ) -> Result<Record, StateError>;
    fn get(&self, caller: &Caller, id: &str) -> Result<Option<Record>, StateError>;
    fn list(&self, caller: &Caller, filter: &Filter) -> Result<Vec<Record>, StateError>;
    /// Apply `patch` iff the record is still at `expected`; see [`StateError::StaleRevision`].
    fn patch(
        &self,
        caller: &Caller,
        id: &str,
        expected: u64,
        patch: Patch,
        now: DateTime<Utc>,
    ) -> Result<Record, StateError>;
    fn history(&self, caller: &Caller, id: &str) -> Result<Vec<HistoryEntry>, StateError>;
    /// Up to `max` notices not yet delivered, oldest first.
    fn pending_notices(&self, max: usize) -> Result<Vec<Notice>, StateError>;
    /// Mark a notice delivered. Idempotent.
    fn notice_delivered(&self, seq: u64) -> Result<(), StateError>;
}

/// The read side of one transaction.
pub trait TxnRead {
    fn record(&self, id: &str) -> Result<Option<Record>, StateError>;
    fn all(&self) -> Result<Vec<Record>, StateError>;
    fn history(&self, id: &str) -> Result<Vec<HistoryEntry>, StateError>;
    fn notices(&self, max: usize) -> Result<Vec<Notice>, StateError>;
}

/// One write transaction: everything done through it commits together or not at all.
pub trait Txn: TxnRead {
    /// The next record number, never repeated.
    fn next_number(&mut self) -> Result<u64, StateError>;
    fn put_record(&mut self, record: &Record) -> Result<(), StateError>;
    fn append(&mut self, entry: &HistoryEntry) -> Result<(), StateError>;
    /// Store `notice`, giving it the next `seq`.
    fn push_notice(&mut self, notice: &Notice) -> Result<(), StateError>;
    fn remove_notice(&mut self, seq: u64) -> Result<(), StateError>;
}

/// Storage for the engine: rows and atomicity, nothing else.
pub trait Backend {
    /// Run `f` in a transaction; commit if it returns `Ok`, discard everything if `Err`.
    fn write<R>(
        &self,
        f: impl FnOnce(&mut dyn Txn) -> Result<R, StateError>,
    ) -> Result<R, StateError>;
    fn read<R>(
        &self,
        f: impl FnOnce(&dyn TxnRead) -> Result<R, StateError>,
    ) -> Result<R, StateError>;
}

/// The shared logic over any [`Backend`].
pub struct StateEngine<B: Backend> {
    backend: B,
}

impl<B: Backend> StateEngine<B> {
    pub fn new(backend: B) -> Self {
        StateEngine { backend }
    }
}

/// An in-memory engine, for tests and for stores that need no durability.
pub type MemoryState = StateEngine<MemoryBackend>;

impl MemoryState {
    #[must_use]
    pub fn in_memory() -> Self {
        StateEngine::new(MemoryBackend::default())
    }
}

fn check_text(label: &str, text: &str, max: usize, multiline: bool) -> Result<(), StateError> {
    let bad_char = |c: char| c.is_control() && !(multiline && matches!(c, '\n' | '\t'));
    if text.len() > max || text.chars().any(bad_char) {
        Err(StateError::Malformed(format!(
            "{label} is too long or has control characters"
        )))
    } else {
        Ok(())
    }
}

/// Everything a record must satisfy, checked on the post-state of every write.
fn validate(r: &Record, txn: &dyn TxnRead) -> Result<(), StateError> {
    check_text("title", &r.title, MAX_TITLE, false)?;
    if r.title.is_empty() {
        return Err(StateError::Malformed("title is empty".into()));
    }
    check_text("notes", &r.notes, MAX_NOTES, true)?;
    if r.parties.is_empty() || r.parties.len() > MAX_PARTIES {
        return Err(StateError::Malformed(format!("1 to {MAX_PARTIES} parties")));
    }
    if !r.parties.iter().all(|p| valid_name(p)) {
        return Err(StateError::Malformed("a party is not a role name".into()));
    }
    let mut sorted = r.parties.clone();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != r.parties.len() {
        return Err(StateError::Malformed("a party is listed twice".into()));
    }
    if !r.parties.contains(&r.owner) {
        return Err(StateError::Malformed("the owner must be a party".into()));
    }
    if r.verify.len() > MAX_CONDITIONS || r.blocked_on.len() > MAX_CONDITIONS {
        return Err(StateError::Malformed(format!(
            "at most {MAX_CONDITIONS} conditions"
        )));
    }
    if !r.blocked_on.is_empty() && r.state != State::Blocked {
        return Err(StateError::Malformed(
            "blocked_on is set only while blocked".into(),
        ));
    }
    for c in &r.verify {
        c.validate()?;
    }
    for b in &r.blocked_on {
        match b {
            Blocker::Condition(c) => c.validate()?,
            Blocker::Record(id) => {
                if !id_ok(id) || *id == r.id {
                    return Err(StateError::Malformed(
                        "a record cannot block on that id".into(),
                    ));
                }
                if txn.record(id)?.is_none() {
                    return Err(StateError::UnknownBlocker(id.clone()));
                }
            }
        }
    }
    Ok(())
}

fn append_entry(
    txn: &mut dyn Txn,
    record: &Record,
    writer: &str,
    change: Change,
    now: DateTime<Utc>,
) -> Result<(), StateError> {
    let prev_hash = txn
        .history(&record.id)?
        .last()
        .map_or_else(|| GENESIS_HASH.to_string(), |e| e.hash.clone());
    let mut entry = HistoryEntry {
        id: record.id.clone(),
        revision: record.revision,
        writer: writer.to_string(),
        written_at: now,
        change,
        prev_hash,
        hash: String::new(),
    };
    entry.hash = entry.compute_hash();
    txn.append(&entry)?;
    txn.put_record(record)?;
    let fields: Vec<String> = match &entry.change {
        Change::Create(_) => vec!["created".to_string()],
        Change::Patch(patch) => patch.fields().into_iter().map(String::from).collect(),
    };
    for party in record.parties.iter().filter(|p| p.as_str() != writer) {
        txn.push_notice(&Notice {
            seq: 0,
            id: record.id.clone(),
            revision: record.revision,
            to: party.clone(),
            changed_by: writer.to_string(),
            fields: fields.clone(),
        })?;
    }
    Ok(())
}

impl<B: Backend> StateStore for StateEngine<B> {
    fn create(
        &self,
        caller: &Caller,
        new: NewRecord,
        now: DateTime<Utc>,
    ) -> Result<Record, StateError> {
        if !(caller.write || caller.admin) {
            return Err(StateError::Forbidden);
        }
        if !caller.admin && !new.parties.contains(&caller.role) {
            return Err(StateError::Forbidden);
        }
        self.backend.write(|txn| {
            let id = format!("T-{}", txn.next_number()?);
            let record = from_new(&id, &new, now);
            validate(&record, txn)?;
            append_entry(txn, &record, &caller.role, Change::Create(new), now)?;
            Ok(record)
        })
    }

    fn get(&self, caller: &Caller, id: &str) -> Result<Option<Record>, StateError> {
        self.backend
            .read(|txn| Ok(txn.record(id)?.filter(|r| caller.sees(r))))
    }

    fn list(&self, caller: &Caller, filter: &Filter) -> Result<Vec<Record>, StateError> {
        self.backend.read(|txn| {
            let mut out: Vec<Record> = txn
                .all()?
                .into_iter()
                .filter(|r| caller.sees(r))
                .filter(|r| filter.states.is_empty() || filter.states.contains(&r.state))
                .filter(|r| filter.party.as_ref().is_none_or(|p| r.parties.contains(p)))
                .collect();
            out.sort_by_key(|r| id_number(&r.id));
            Ok(out)
        })
    }

    fn patch(
        &self,
        caller: &Caller,
        id: &str,
        expected: u64,
        patch: Patch,
        now: DateTime<Utc>,
    ) -> Result<Record, StateError> {
        if patch.fields().is_empty() {
            return Err(StateError::Malformed(
                "an empty patch changes nothing".into(),
            ));
        }
        self.backend.write(|txn| {
            let current = txn.record(id)?.ok_or(StateError::NotFound)?;
            let party = current.parties.contains(&caller.role);
            if !(caller.admin || (caller.write && party)) {
                return Err(StateError::Forbidden);
            }
            // Who may reshape the record itself: its owner, or an admin.
            if (patch.parties.is_some() || patch.owner.is_some())
                && !(caller.admin || current.owner == caller.role)
            {
                return Err(StateError::Forbidden);
            }
            if current.state.is_terminal() && !caller.admin {
                return Err(StateError::Terminal);
            }
            if current.revision != expected {
                return Err(StateError::StaleRevision(Box::new(current)));
            }
            let mut next = current;
            apply(&mut next, &patch);
            next.revision = expected + 1;
            next.updated_at = now;
            validate(&next, txn)?;
            append_entry(txn, &next, &caller.role, Change::Patch(patch), now)?;
            Ok(next)
        })
    }

    fn pending_notices(&self, max: usize) -> Result<Vec<Notice>, StateError> {
        self.backend.read(|txn| txn.notices(max))
    }

    fn notice_delivered(&self, seq: u64) -> Result<(), StateError> {
        self.backend.write(|txn| txn.remove_notice(seq))
    }

    fn history(&self, caller: &Caller, id: &str) -> Result<Vec<HistoryEntry>, StateError> {
        self.backend.read(|txn| {
            let record = txn.record(id)?.ok_or(StateError::NotFound)?;
            if !caller.sees(&record) {
                return Err(StateError::Forbidden);
            }
            txn.history(id)
        })
    }
}

fn id_number(id: &str) -> u64 {
    id.strip_prefix("T-")
        .and_then(|n| n.parse().ok())
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Default)]
struct MemoryData {
    records: BTreeMap<String, Record>,
    history: BTreeMap<String, Vec<HistoryEntry>>,
    counter: u64,
    notices: BTreeMap<u64, Notice>,
    notice_counter: u64,
}

impl TxnRead for MemoryData {
    fn record(&self, id: &str) -> Result<Option<Record>, StateError> {
        Ok(self.records.get(id).cloned())
    }
    fn all(&self) -> Result<Vec<Record>, StateError> {
        Ok(self.records.values().cloned().collect())
    }
    fn history(&self, id: &str) -> Result<Vec<HistoryEntry>, StateError> {
        Ok(self.history.get(id).cloned().unwrap_or_default())
    }
    fn notices(&self, max: usize) -> Result<Vec<Notice>, StateError> {
        Ok(self.notices.values().take(max).cloned().collect())
    }
}

impl Txn for MemoryData {
    fn next_number(&mut self) -> Result<u64, StateError> {
        self.counter += 1;
        Ok(self.counter)
    }
    fn put_record(&mut self, record: &Record) -> Result<(), StateError> {
        self.records.insert(record.id.clone(), record.clone());
        Ok(())
    }
    fn append(&mut self, entry: &HistoryEntry) -> Result<(), StateError> {
        self.history
            .entry(entry.id.clone())
            .or_default()
            .push(entry.clone());
        Ok(())
    }
    fn push_notice(&mut self, notice: &Notice) -> Result<(), StateError> {
        self.notice_counter += 1;
        let mut stored = notice.clone();
        stored.seq = self.notice_counter;
        self.notices.insert(stored.seq, stored);
        Ok(())
    }
    fn remove_notice(&mut self, seq: u64) -> Result<(), StateError> {
        self.notices.remove(&seq);
        Ok(())
    }
}

/// Rows in memory. A write works on a copy and swaps it in only on success, so a failed write
/// changes nothing.
#[derive(Default)]
pub struct MemoryBackend {
    data: Mutex<MemoryData>,
}

impl MemoryBackend {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryData>, StateError> {
        self.data
            .lock()
            .map_err(|_| StateError::Store("poisoned".into()))
    }
}

impl Backend for MemoryBackend {
    fn write<R>(
        &self,
        f: impl FnOnce(&mut dyn Txn) -> Result<R, StateError>,
    ) -> Result<R, StateError> {
        let mut guard = self.lock()?;
        let mut work = guard.clone();
        let out = f(&mut work)?;
        *guard = work;
        Ok(out)
    }

    fn read<R>(
        &self,
        f: impl FnOnce(&dyn TxnRead) -> Result<R, StateError>,
    ) -> Result<R, StateError> {
        f(&*self.lock()?)
    }
}
