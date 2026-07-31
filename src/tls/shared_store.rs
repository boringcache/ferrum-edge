//! Cross-instance coherent persistence for file-backed TLS material stores.
//!
//! Managed TLS records, ACME certificates/orders/accounts, and renewal leases
//! are all small JSON documents that several gateway replicas may share through
//! one writable volume. Each document is wrapped in a [`SharedStoreFile`],
//! which provides the three properties a process-local `OnceLock` cache plus a
//! whole-map rewrite cannot (issue #2409):
//!
//! * **Authoritative reads.** [`SharedStoreFile::snapshot`] revalidates the
//!   cached document against the file's identity stamp on every call, so a
//!   record another replica committed becomes visible without a restart and
//!   without a bespoke watcher. The existing `managed://` / `acme://` material
//!   poll loops (`tls::source::subscription`) therefore observe cross-instance
//!   rotations through their ordinary refresh path.
//! * **Conflict-safe writes.** [`SharedStoreFile::mutate`] takes an exclusive
//!   advisory file lock, re-reads the document *under that lock*, applies the
//!   caller's mutation to that fresh state, and only then republishes. The
//!   read-modify-write is serialized across processes, so a concurrent writer's
//!   committed record can never be erased by a stale in-memory map, and
//!   existence decisions (create-without-overwrite, kind conflicts, lease
//!   ownership) are evaluated against authoritative state.
//! * **Fail-closed ambiguity.** A lock that cannot be taken within
//!   `FERRUM_TLS_STORE_LOCK_TIMEOUT_SECONDS`, an unreadable or unparseable
//!   file, or a poisoned in-process guard is an error — never a silent
//!   local-only write.
//!
//! Nothing here logs document contents. Managed records and ACME accounts hold
//! private key material, so errors carry only the operator-configured store
//! path (local configuration, not a secret-provider reference) and an
//! I/O/parse failure class.

use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

/// How close to "now" a store file's modification time may be before the cached
/// snapshot is treated as possibly stale regardless of the recorded stamp.
///
/// Filesystems with coarse timestamp granularity can record two distinct writes
/// with the same `mtime`, and inode numbers can in principle be reused, so a
/// freshly written file is always re-read. Outside that window an unchanged
/// stamp is trusted and a read costs one `stat`.
const COARSE_MTIME_WINDOW: Duration = Duration::from_secs(2);

/// Retry cadence while waiting for a contended advisory lock.
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Fixed diagnostic for a poisoned in-process guard. Never includes contents.
const POISONED_GUARD: &str = "in-process store guard is poisoned";

#[derive(Debug, Error)]
pub enum SharedStoreError {
    #[error("failed to read shared TLS store '{path}': {details}")]
    Read { path: String, details: String },
    #[error("failed to write shared TLS store '{path}': {details}")]
    Write { path: String, details: String },
    #[error("failed to parse shared TLS store '{path}': {details}")]
    Parse { path: String, details: String },
    #[error(
        "timed out after {seconds}s waiting for exclusive access to shared TLS store '{path}'; another instance may be holding it"
    )]
    LockTimeout { path: String, seconds: u64 },
}

impl SharedStoreError {
    fn read(path: &Path, details: impl fmt::Display) -> Self {
        Self::Read {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }

    fn write(path: &Path, details: impl fmt::Display) -> Self {
        Self::Write {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }

    fn parse(path: &Path, details: impl fmt::Display) -> Self {
        Self::Parse {
            path: path.display().to_string(),
            details: details.to_string(),
        }
    }
}

/// A JSON document that carries a monotonic store version.
///
/// The version is bumped by every committed write. Correctness does not depend
/// on it — the exclusive-lock read-modify-write is what prevents lost updates —
/// but it gives operators and tests a cheap, non-secret way to observe that a
/// write landed and to tell two generations of a document apart.
pub trait VersionedStoreFile:
    Default + Clone + Serialize + DeserializeOwned + Send + Sync + 'static
{
    fn store_version(&self) -> u64;
    fn set_store_version(&mut self, version: u64);
}

/// Identity of the on-disk document at the moment it was last loaded.
///
/// Publication is temp-file + rename, so on Unix the inode changes on every
/// commit and is an exact change detector; length and modification time cover
/// platforms without inode identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    device: u64,
}

impl FileStamp {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                inode: metadata.ino(),
                device: metadata.dev(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
            }
        }
    }

    /// Whether the file was written recently enough that timestamp granularity
    /// could hide a subsequent change.
    fn written_recently(&self, now: SystemTime) -> bool {
        let Some(modified) = self.modified else {
            return true;
        };
        match now.duration_since(modified) {
            Ok(age) => age < COARSE_MTIME_WINDOW,
            // Modified in the future (clock skew): treat as freshly written.
            Err(_) => true,
        }
    }
}

struct Cached<T> {
    value: Arc<T>,
    /// `None` means the document did not exist at the last load.
    stamp: Option<FileStamp>,
}

/// Releases an advisory file lock on drop.
struct FileLockGuard {
    file: File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        // Best effort: the lock is also released when the handle closes.
        let _ = self.file.unlock();
    }
}

/// One shared JSON document with cross-process coherent reads and writes.
pub struct SharedStoreFile<T: VersionedStoreFile> {
    path: PathBuf,
    lock_path: PathBuf,
    lock_timeout: Duration,
    cached: RwLock<Cached<T>>,
    /// Serializes writers inside this process before they contend for the
    /// cross-process advisory lock.
    write_gate: Mutex<()>,
}

impl<T: VersionedStoreFile> fmt::Debug for SharedStoreFile<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedStoreFile")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl<T: VersionedStoreFile> SharedStoreFile<T> {
    /// Open (or adopt) the shared document at `path`.
    ///
    /// A missing document is an empty store; an unreadable or unparseable one
    /// is an error, so a corrupt shared volume is never silently replaced by an
    /// empty local map.
    pub fn open(path: PathBuf) -> Result<Self, SharedStoreError> {
        let lock_path = lock_path_for(&path)?;
        let store = Self {
            path,
            lock_path,
            lock_timeout: crate::config::env_config::tls_store_lock_timeout_from_env(),
            cached: RwLock::new(Cached {
                value: Arc::new(T::default()),
                stamp: None,
            }),
            write_gate: Mutex::new(()),
        };
        store.reload()?;
        Ok(store)
    }

    /// Committed version of the current authoritative document.
    ///
    /// Diagnostic surface only; the store's correctness comes from the
    /// exclusive-lock read-modify-write, not from this counter.
    #[allow(dead_code)]
    pub fn version(&self) -> Result<u64, SharedStoreError> {
        Ok(self.snapshot()?.store_version())
    }

    /// The authoritative document, re-read whenever the file changed.
    pub fn snapshot(&self) -> Result<Arc<T>, SharedStoreError> {
        if let Some(value) = self.cached_if_fresh()? {
            return Ok(value);
        }
        self.reload()
    }

    /// Serialized read-modify-write against authoritative shared state.
    ///
    /// `apply` runs under the exclusive cross-process lock and sees the current
    /// committed document, so its decisions are made against what every other
    /// instance has actually written. The result is published only after the
    /// durable replacement succeeds; a failed publish leaves both readers and
    /// the on-disk document on the prior committed state.
    pub fn mutate<R, E>(&self, apply: impl FnOnce(&mut T) -> Result<R, E>) -> Result<R, E>
    where
        E: From<SharedStoreError>,
    {
        self.mutate_if(|document| apply(document).map(|outcome| (true, outcome)))
    }

    /// [`Self::mutate`] for callers whose decision may be "no change".
    ///
    /// `apply` returns `(committed, outcome)`; a `false` flag republishes
    /// nothing, which keeps read-only outcomes (a denied lease acquisition, a
    /// renewal for a claim already taken over) from rewriting the shared
    /// document on every attempt. The exclusive lock still covers the whole
    /// decision, so it is made against authoritative state either way.
    pub fn mutate_if<R, E>(
        &self,
        apply: impl FnOnce(&mut T) -> Result<(bool, R), E>,
    ) -> Result<R, E>
    where
        E: From<SharedStoreError>,
    {
        let _local = self.write_gate.lock().map_err(|_| self.poisoned())?;
        let _lock = self.lock(/*exclusive=*/ true)?;
        let current = self.reload_locked()?;
        let mut candidate = (*current).clone();
        let (committed, outcome) = apply(&mut candidate)?;
        if !committed {
            return Ok(outcome);
        }
        let next = current.store_version().saturating_add(1);
        candidate.set_store_version(next);
        self.persist_locked(&candidate)?;
        Ok(outcome)
    }

    fn poisoned(&self) -> SharedStoreError {
        SharedStoreError::write(&self.path, POISONED_GUARD)
    }

    /// Cached document when the on-disk identity still matches it.
    fn cached_if_fresh(&self) -> Result<Option<Arc<T>>, SharedStoreError> {
        let cached = self.cached.read().map_err(|_| self.poisoned())?;
        let current = match std::fs::metadata(&self.path) {
            Ok(metadata) => Some(FileStamp::from_metadata(&metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(SharedStoreError::read(&self.path, error)),
        };
        let unchanged = match (cached.stamp, current) {
            (None, None) => true,
            (Some(previous), Some(current)) => {
                previous == current && !current.written_recently(SystemTime::now())
            }
            _ => false,
        };
        if unchanged {
            Ok(Some(cached.value.clone()))
        } else {
            Ok(None)
        }
    }

    fn reload(&self) -> Result<Arc<T>, SharedStoreError> {
        let _lock = self.lock(/*exclusive=*/ false)?;
        self.reload_locked()
    }

    /// Read the authoritative document. The caller must already hold the lock.
    fn reload_locked(&self) -> Result<Arc<T>, SharedStoreError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let value = Arc::new(T::default());
                self.publish_cached(value.clone(), None)?;
                return Ok(value);
            }
            Err(error) => return Err(SharedStoreError::read(&self.path, error)),
        };
        // Stamp from the open handle so it describes exactly the bytes read.
        let stamp = file.metadata().ok();
        let stamp = stamp.as_ref().map(FileStamp::from_metadata);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| SharedStoreError::read(&self.path, error))?;
        let parsed = serde_json::from_slice::<T>(&bytes)
            .map_err(|error| SharedStoreError::parse(&self.path, error))?;
        let value = Arc::new(parsed);
        self.publish_cached(value.clone(), stamp)?;
        Ok(value)
    }

    fn persist_locked(&self, value: &T) -> Result<(), SharedStoreError> {
        let payload = serde_json::to_vec_pretty(value)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        crate::tls::private_file::replace_private_file(&self.path, &payload)
            .map_err(|error| SharedStoreError::write(&self.path, error))?;
        let stamp = std::fs::metadata(&self.path).ok();
        let stamp = stamp.as_ref().map(FileStamp::from_metadata);
        self.publish_cached(Arc::new(value.clone()), stamp)
    }

    fn publish_cached(
        &self,
        value: Arc<T>,
        stamp: Option<FileStamp>,
    ) -> Result<(), SharedStoreError> {
        let mut cached = self.cached.write().map_err(|_| self.poisoned())?;
        *cached = Cached { value, stamp };
        Ok(())
    }

    fn lock(&self, exclusive: bool) -> Result<FileLockGuard, SharedStoreError> {
        let file = self.open_lock_file()?;
        let deadline = Instant::now() + self.lock_timeout;
        loop {
            let attempt = if exclusive {
                file.try_lock()
            } else {
                file.try_lock_shared()
            };
            match attempt {
                Ok(()) => return Ok(FileLockGuard { file }),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(self.lock_timed_out());
                    }
                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(TryLockError::Error(error)) => {
                    return Err(SharedStoreError::write(&self.lock_path, error));
                }
            }
        }
    }

    fn lock_timed_out(&self) -> SharedStoreError {
        SharedStoreError::LockTimeout {
            path: self.path.display().to_string(),
            seconds: self.lock_timeout.as_secs(),
        }
    }

    fn open_lock_file(&self) -> Result<File, SharedStoreError> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(&self.lock_path)
            .map_err(|error| SharedStoreError::write(&self.lock_path, error))
    }
}

/// Sidecar advisory-lock path for a store document.
///
/// The lock lives beside the document rather than on it because publication
/// replaces the document by rename: a lock taken on the old inode would not be
/// seen by a writer that opened the new one.
fn lock_path_for(path: &Path) -> Result<PathBuf, SharedStoreError> {
    let missing_parent = || SharedStoreError::write(path, "store path has no parent directory");
    let missing_name = || SharedStoreError::write(path, "store path has no file name");
    let parent = path.parent().ok_or_else(missing_parent)?;
    let file_name = path.file_name().ok_or_else(missing_name)?;
    Ok(parent.join(format!(".{}.lock", file_name.to_string_lossy())))
}
