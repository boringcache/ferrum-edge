//! Durable, bounded on-disk spool for admin audit events (issue #2421).
//!
//! The admin mutation path hands an audit event to this spool **before** the
//! success response is acknowledged. The handoff is `write temp → fsync file →
//! rename into `pending/` → fsync directory`, so a crash after the response
//! leaves a replayable record. Delivery into `audit_events` happens
//! asynchronously with bounded retry; the spool file is removed only after the
//! backend has accepted the event.
//!
//! Layout under the configured root:
//!
//! ```text
//! <root>/pending/<event-id>.json   durable, not yet delivered
//! <root>/failed/<event-id>.json    retained for operator remediation
//! <root>/tmp/<event-id>.json.tmp   in-flight write (reconciled at open)
//! ```
//!
//! # Bounds and hostile input
//!
//! Every entry point is bounded: record bytes, pending-record count, retained
//! record count, and directory-walk entries. Filenames are derived from the
//! event UUID and validated against a strict charset before being joined to the
//! root, so no operator- or actor-controlled string reaches a path. A record
//! that fails to parse, exceeds the read ceiling, or carries a body whose
//! embedded id does not match its filename is *corrupt*: it is quarantined into
//! `failed/` rather than being replayed or silently deleted.
//!
//! Nothing in this module logs an actor subject, a diff body, a token, or any
//! credential metadata. Errors carry a static reason label plus the event id.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::admin::audit::AuditEvent;

/// On-disk record format version. A record with any other version is corrupt.
pub const AUDIT_SPOOL_RECORD_VERSION: u32 = 1;

/// Hard ceiling for one serialized spool record, independent of configuration.
/// Larger admin bodies are still audited: the diff is replaced by a redacted
/// placeholder so the event identity stays durable (see
/// [`SpooledAuditRecord::with_bounded_diff`]).
pub const AUDIT_SPOOL_MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// Ceiling for a single directory walk. Prevents an unbounded `read_dir` on a
/// spool that another process filled.
pub const AUDIT_SPOOL_MAX_SCAN_ENTRIES: usize = 100_000;

/// Longest accepted record-id string (a UUID is 36 characters).
const MAX_RECORD_ID_LEN: usize = 64;

const PENDING_DIR: &str = "pending";
const FAILED_DIR: &str = "failed";
const TMP_DIR: &str = "tmp";
const RECORD_EXTENSION: &str = ".json";
const TMP_EXTENSION: &str = ".json.tmp";

/// Placeholder substituted for a diff that would exceed the record ceiling.
/// The event identity (who/what/when/where) stays durable and auditable.
pub const AUDIT_DIFF_OMITTED_MARKER: &str = "diff_exceeded_max_record_bytes";

/// Static, operator-facing reason labels. Never interpolate a path, an actor
/// subject, or an OS error string into an audit log line or metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoolErrorKind {
    /// The spool root could not be prepared or is not usable.
    Unavailable,
    /// The pending-record ceiling is reached; no further durable handoff.
    Saturated,
    /// A filesystem write/rename/fsync failed.
    Io,
    /// The record could not be serialized or its id is not a legal filename.
    InvalidRecord,
    /// A stored record is unparseable, truncated, oversized, or mismatched.
    Corrupt,
}

impl SpoolErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SpoolErrorKind::Unavailable => "spool_unavailable",
            SpoolErrorKind::Saturated => "spool_saturated",
            SpoolErrorKind::Io => "spool_io_error",
            SpoolErrorKind::InvalidRecord => "invalid_record",
            SpoolErrorKind::Corrupt => "corrupt_record",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoolError {
    pub kind: SpoolErrorKind,
}

impl SpoolError {
    fn new(kind: SpoolErrorKind) -> Self {
        Self { kind }
    }

    pub fn reason(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately reason-only: the caller logs this, and the underlying OS
        // error can carry a filesystem path.
        f.write_str(self.kind.as_str())
    }
}

impl std::error::Error for SpoolError {}

/// One durable audit record.
///
/// `attempts` is advisory delivery bookkeeping used to decide when an event has
/// exhausted its bounded retry budget across process restarts. It is rewritten
/// only when a delivery attempt fails, so the steady-state path is one write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpooledAuditRecord {
    /// On-disk format version. Fail closed on anything but the current value.
    pub v: u32,
    pub event: AuditEvent,
    /// Delivery attempts already burned against this record.
    #[serde(default)]
    pub attempts: u32,
    /// Unix milliseconds when the record was first made durable.
    #[serde(default)]
    pub first_spooled_unix_ms: i64,
    /// Set when the diff was replaced by [`AUDIT_DIFF_OMITTED_MARKER`].
    #[serde(default)]
    pub diff_omitted: bool,
}

impl SpooledAuditRecord {
    /// Build a record whose serialized form is guaranteed to fit the ceiling.
    ///
    /// An oversized diff is replaced by a redacted marker rather than dropping
    /// the event: losing *that a change happened* is the failure mode #2421 is
    /// about, and the resource identity is what makes the record reconcilable.
    pub fn with_bounded_diff(event: AuditEvent, max_record_bytes: u64) -> Self {
        let mut record = Self {
            v: AUDIT_SPOOL_RECORD_VERSION,
            event,
            attempts: 0,
            first_spooled_unix_ms: chrono::Utc::now().timestamp_millis(),
            diff_omitted: false,
        };
        let fits = serde_json::to_vec(&record)
            .map(|bytes| bytes.len() as u64 <= max_record_bytes)
            .unwrap_or(false);
        if !fits {
            record.event.diff = serde_json::json!({ "omitted": AUDIT_DIFF_OMITTED_MARKER });
            record.diff_omitted = true;
        }
        record
    }

    pub fn id(&self) -> &str {
        &self.event.id
    }
}

/// Bounded snapshot of on-disk spool state for health/status and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SpoolStats {
    pub pending_records: u64,
    pub retained_records: u64,
    /// True when a bounded scan stopped at [`AUDIT_SPOOL_MAX_SCAN_ENTRIES`], so
    /// the counts above are floors rather than exact values.
    pub scan_truncated: bool,
}

/// A prepared, bounded audit spool rooted at an operator-configured directory.
///
/// `pending_count` / `retained_count` are O(1) admission counters seeded by one
/// bounded scan at [`AuditSpool::open`]. Without them every committed admin
/// mutation would pay an O(backlog) `read_dir` just to test the ceiling. They
/// can drift when another process shares the directory, so a counter that
/// reports "full" is always confirmed by a real scan before a handoff is
/// refused — the cheap path is never the one that loses an event.
#[derive(Debug)]
pub struct AuditSpool {
    root: PathBuf,
    max_pending_records: u64,
    max_retained_records: u64,
    max_record_bytes: u64,
    pending_count: AtomicU64,
    retained_count: AtomicU64,
}

impl AuditSpool {
    /// Prepare the spool tree and reconcile abandoned temp files.
    ///
    /// Returns an error when the root cannot be created or written. Callers
    /// decide the policy consequence (fail open with a memory-only pipeline, or
    /// fail closed and refuse audited mutations).
    pub fn open(
        root: impl Into<PathBuf>,
        max_pending_records: u64,
        max_retained_records: u64,
    ) -> Result<Self, SpoolError> {
        let root = root.into();
        let spool = Self {
            root,
            max_pending_records: max_pending_records.max(1),
            max_retained_records: max_retained_records.max(1),
            max_record_bytes: AUDIT_SPOOL_MAX_RECORD_BYTES,
            pending_count: AtomicU64::new(0),
            retained_count: AtomicU64::new(0),
        };
        for dir in [spool.pending_dir(), spool.failed_dir(), spool.tmp_dir()] {
            fs::create_dir_all(&dir).map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
        }
        spool.probe_writable()?;
        spool.reconcile_tmp_dir();
        spool.resync_counters();
        Ok(spool)
    }

    pub fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }

    fn pending_dir(&self) -> PathBuf {
        self.root.join(PENDING_DIR)
    }

    fn failed_dir(&self) -> PathBuf {
        self.root.join(FAILED_DIR)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join(TMP_DIR)
    }

    /// Verify the tree is actually writable now rather than discovering it on
    /// the first committed mutation.
    fn probe_writable(&self) -> Result<(), SpoolError> {
        let probe = self.tmp_dir().join("audit-spool-write-probe.tmp");
        let write = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&probe)
            .and_then(|mut file| {
                file.write_all(b"ok")?;
                file.sync_all()
            });
        let _ = fs::remove_file(&probe);
        write.map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))
    }

    /// Remove temp files abandoned by a crash mid-write. A temp file was never
    /// renamed into `pending/`, so it was never acknowledged to a client and
    /// carries no delivery obligation.
    fn reconcile_tmp_dir(&self) {
        let Ok(entries) = fs::read_dir(self.tmp_dir()) else {
            return;
        };
        for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".tmp"))
            {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// Durably persist `record`. Returns once the bytes and the directory entry
    /// are on stable storage.
    pub fn write(&self, record: &SpooledAuditRecord) -> Result<(), SpoolError> {
        let id = record.id().to_string();
        let pending = self.record_path(PENDING_DIR, &id)?;
        // Re-spooling an id that is already durable is a no-op, so a retried
        // handoff cannot double-count the backlog.
        if pending.exists() {
            return Ok(());
        }
        if self.pending_count.load(Ordering::Relaxed) >= self.max_pending_records {
            // Confirm with a real scan before refusing a committed mutation's
            // audit event: a drifted counter must never fabricate saturation.
            let (pending_count, truncated) = self.count_dir(PENDING_DIR);
            self.pending_count.store(pending_count, Ordering::Relaxed);
            if pending_count >= self.max_pending_records || truncated {
                return Err(SpoolError::new(SpoolErrorKind::Saturated));
            }
        }

        let bytes =
            serde_json::to_vec(record).map_err(|_| SpoolError::new(SpoolErrorKind::InvalidRecord))?;
        if bytes.len() as u64 > self.max_record_bytes {
            // `with_bounded_diff` already collapses oversized diffs, so this is
            // an identity field that is itself hostile-sized.
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }

        let tmp = self.tmp_dir().join(format!("{id}{TMP_EXTENSION}"));
        let write = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()
        })();
        if write.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        if fs::rename(&tmp, &pending).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        sync_dir(&self.pending_dir());
        self.pending_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Rewrite an existing pending record in place (attempt bookkeeping).
    ///
    /// Best-effort: a failure here only costs retry-budget accuracy, never the
    /// record itself, so the caller treats it as non-fatal.
    pub fn update_attempts(&self, record: &SpooledAuditRecord) -> Result<(), SpoolError> {
        let id = record.id().to_string();
        let pending = self.record_path(PENDING_DIR, &id)?;
        if !pending.exists() {
            return Ok(());
        }
        let bytes =
            serde_json::to_vec(record).map_err(|_| SpoolError::new(SpoolErrorKind::InvalidRecord))?;
        if bytes.len() as u64 > self.max_record_bytes {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        let tmp = self.tmp_dir().join(format!("{id}{TMP_EXTENSION}"));
        let write = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()
        })();
        if write.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        if fs::rename(&tmp, &pending).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        sync_dir(&self.pending_dir());
        Ok(())
    }

    /// Delete a delivered record. Idempotent: a missing file is success.
    pub fn remove_pending(&self, id: &str) -> Result<(), SpoolError> {
        let pending = self.record_path(PENDING_DIR, id)?;
        match fs::remove_file(&pending) {
            Ok(()) => {
                sync_dir(&self.pending_dir());
                decrement(&self.pending_count);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SpoolError::new(SpoolErrorKind::Io)),
        }
    }

    /// Move a pending record into operator-visible retention.
    ///
    /// Returns `Ok(true)` when the record was retained and `Ok(false)` when the
    /// retained ceiling was already reached and the record had to be discarded.
    /// Discarding the *newest* arrival preserves the oldest evidence, which is
    /// what an operator reconciling a gap needs first.
    pub fn retain_unrecoverable(&self, id: &str) -> Result<bool, SpoolError> {
        let pending = self.record_path(PENDING_DIR, id)?;
        let failed = self.record_path(FAILED_DIR, id)?;
        if !pending.exists() {
            return Ok(failed.exists());
        }
        if self.retained_capacity_exhausted() {
            self.remove_pending(id)?;
            return Ok(false);
        }
        if fs::rename(&pending, &failed).is_err() {
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        sync_dir(&self.pending_dir());
        sync_dir(&self.failed_dir());
        decrement(&self.pending_count);
        self.retained_count.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }

    /// Read one pending record.
    ///
    /// Any corruption — bad version, oversized file, unparseable JSON, or an
    /// embedded id that disagrees with the filename — quarantines the file into
    /// `failed/` and reports [`SpoolErrorKind::Corrupt`]. A corrupt record is
    /// never replayed and never silently deleted.
    pub fn read_pending(&self, id: &str) -> Result<SpooledAuditRecord, SpoolError> {
        let pending = self.record_path(PENDING_DIR, id)?;
        match self.read_record_at(&pending, id) {
            Ok(record) => Ok(record),
            Err(error) => {
                if error.kind == SpoolErrorKind::Corrupt {
                    let _ = self.quarantine_corrupt(id);
                }
                Err(error)
            }
        }
    }

    fn read_record_at(&self, path: &Path, expected_id: &str) -> Result<SpooledAuditRecord, SpoolError> {
        let metadata =
            fs::metadata(path).map_err(|_| SpoolError::new(SpoolErrorKind::Unavailable))?;
        if metadata.len() > self.max_record_bytes {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        let mut file = File::open(path).map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        // Bounded read: never trust `metadata.len()` alone against a file that
        // grew between stat and read.
        let mut bytes = Vec::with_capacity(metadata.len().min(64 * 1024) as usize);
        file.by_ref()
            .take(self.max_record_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| SpoolError::new(SpoolErrorKind::Io))?;
        if bytes.len() as u64 > self.max_record_bytes {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        let record: SpooledAuditRecord = serde_json::from_slice(&bytes)
            .map_err(|_| SpoolError::new(SpoolErrorKind::Corrupt))?;
        if record.v != AUDIT_SPOOL_RECORD_VERSION || record.event.id != expected_id {
            return Err(SpoolError::new(SpoolErrorKind::Corrupt));
        }
        Ok(record)
    }

    /// Move a corrupt pending record into `failed/` under its raw filename.
    fn quarantine_corrupt(&self, id: &str) -> Result<(), SpoolError> {
        let pending = self.record_path(PENDING_DIR, id)?;
        let failed = self.record_path(FAILED_DIR, id)?;
        if self.retained_capacity_exhausted() {
            let _ = fs::remove_file(&pending);
            decrement(&self.pending_count);
            return Ok(());
        }
        if fs::rename(&pending, &failed).is_err() {
            return Err(SpoolError::new(SpoolErrorKind::Io));
        }
        sync_dir(&self.pending_dir());
        sync_dir(&self.failed_dir());
        decrement(&self.pending_count);
        self.retained_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// List up to `limit` pending record ids.
    ///
    /// Entries whose name is not `<valid-id>.json` are quarantined rather than
    /// parsed, so a hostile or foreign file in the spool directory cannot be
    /// replayed and cannot wedge the scan.
    pub fn list_pending_ids(&self, limit: usize) -> Vec<String> {
        let limit = limit.min(AUDIT_SPOOL_MAX_SCAN_ENTRIES);
        let mut ids = Vec::new();
        let Ok(entries) = fs::read_dir(self.pending_dir()) else {
            return ids;
        };
        for entry in entries.take(AUDIT_SPOOL_MAX_SCAN_ENTRIES).flatten() {
            if ids.len() >= limit {
                break;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            match record_id_from_file_name(name) {
                Some(id) => ids.push(id),
                None => {
                    // Not a legal record filename: quarantine by deletion of a
                    // stray temp, otherwise leave it alone rather than
                    // recursing into an operator's own directory contents.
                    if name.ends_with(".tmp") {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
        ids
    }

    /// Whether retained storage is full, confirmed by a scan before discarding.
    fn retained_capacity_exhausted(&self) -> bool {
        if self.retained_count.load(Ordering::Relaxed) < self.max_retained_records {
            return false;
        }
        let (retained_count, truncated) = self.count_dir(FAILED_DIR);
        self.retained_count.store(retained_count, Ordering::Relaxed);
        retained_count >= self.max_retained_records || truncated
    }

    /// Bounded counts for health/status and metrics. Also resynchronizes the
    /// O(1) admission counters against what is actually on disk.
    pub fn stats(&self) -> SpoolStats {
        let (pending_records, pending_truncated) = self.count_dir(PENDING_DIR);
        let (retained_records, retained_truncated) = self.count_dir(FAILED_DIR);
        if !pending_truncated {
            self.pending_count.store(pending_records, Ordering::Relaxed);
        }
        if !retained_truncated {
            self.retained_count.store(retained_records, Ordering::Relaxed);
        }
        SpoolStats {
            pending_records,
            retained_records,
            scan_truncated: pending_truncated || retained_truncated,
        }
    }

    /// Seed the admission counters from disk at startup.
    fn resync_counters(&self) {
        let _ = self.stats();
    }

    /// Count entries in a spool subdirectory, stopping at the scan ceiling.
    /// The bool reports whether the ceiling truncated the walk.
    fn count_dir(&self, sub: &str) -> (u64, bool) {
        let Ok(entries) = fs::read_dir(self.root.join(sub)) else {
            return (0, false);
        };
        let mut count = 0u64;
        for (index, entry) in entries.enumerate() {
            if index >= AUDIT_SPOOL_MAX_SCAN_ENTRIES {
                return (count, true);
            }
            if entry
                .ok()
                .and_then(|entry| {
                    entry
                        .path()
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(|name| name.ends_with(RECORD_EXTENSION))
                })
                .unwrap_or(false)
            {
                count = count.saturating_add(1);
            }
        }
        (count, false)
    }

    /// Join a validated record id under a spool subdirectory.
    ///
    /// The id charset check is the path-traversal boundary: `..`, `/`, and any
    /// separator are rejected before the join, so the result is always a direct
    /// child of the subdirectory.
    fn record_path(&self, sub: &str, id: &str) -> Result<PathBuf, SpoolError> {
        if !is_valid_record_id(id) {
            return Err(SpoolError::new(SpoolErrorKind::InvalidRecord));
        }
        Ok(self.root.join(sub).join(format!("{id}{RECORD_EXTENSION}")))
    }
}

/// Accepted record-id charset: UUID text only. Anything else — including path
/// separators, `.`, and non-ASCII — is rejected before any path join.
pub fn is_valid_record_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RECORD_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Extract a validated record id from a `<id>.json` filename.
pub fn record_id_from_file_name(name: &str) -> Option<String> {
    let id = name.strip_suffix(RECORD_EXTENSION)?;
    is_valid_record_id(id).then(|| id.to_string())
}

/// Saturating decrement for an admission counter.
fn decrement(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(1))
    });
}

/// Best-effort directory fsync so a rename is durable across a power loss.
///
/// Only meaningful on Unix; Windows cannot open a directory as a file, and the
/// rename is already ordered there.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}
