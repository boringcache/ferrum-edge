//! Private, durable file publication for TLS material stores.
//!
//! Writes use `0600` on Unix, `create_new` temps, fsync, rename, and a parent
//! directory fsync so readers observe either the prior durable file or the fully
//! committed replacement. Temporary files are removed on every failure path
//! without masking the primary error. Post-rename durability failures roll the
//! visible destination back and fsync the parent directory so the rollback is
//! itself durable.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use uuid::Uuid;

#[cfg(test)]
use std::cell::Cell;

/// Injectable failure points for durable private-file publication.
///
/// Available only in unit tests. Arm a single fault through
/// [`inject_private_file_fault_for_tests`]. [`PrivateFileFault::DirSync`] is
/// one-shot: after the initial post-rename parent sync fails, the fault clears
/// so rollback can attempt a real parent-directory durability sync.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PrivateFileFault {
    #[default]
    None,
    Create,
    Write,
    Sync,
    Rename,
    DirSync,
}

#[cfg(test)]
thread_local! {
    static INJECTED_FAULT: Cell<PrivateFileFault> = const { Cell::new(PrivateFileFault::None) };
}

#[cfg(test)]
fn injected_fault() -> PrivateFileFault {
    INJECTED_FAULT.with(Cell::get)
}

/// Arm a one-thread private-file fault until the returned guard drops.
#[cfg(test)]
pub(crate) fn inject_private_file_fault_for_tests(fault: PrivateFileFault) -> PrivateFileFaultGuard {
    INJECTED_FAULT.with(|cell| cell.set(fault));
    PrivateFileFaultGuard { active: true }
}

/// Clears an injected [`PrivateFileFault`] on drop.
#[cfg(test)]
#[must_use = "the fault is cleared when this guard is dropped"]
pub(crate) struct PrivateFileFaultGuard {
    active: bool,
}

#[cfg(test)]
impl PrivateFileFaultGuard {
    /// Disarm early so subsequent writes in the same test run for real.
    pub(crate) fn disarm(mut self) {
        self.clear();
        self.active = false;
    }

    fn clear(&self) {
        INJECTED_FAULT.with(|cell| cell.set(PrivateFileFault::None));
    }
}

#[cfg(test)]
impl Drop for PrivateFileFaultGuard {
    fn drop(&mut self) {
        if self.active {
            self.clear();
        }
    }
}

/// Write `bytes` to a new private file at `path` (typically a temp name).
///
/// On create/write/sync failure the path is removed when present, and the
/// original I/O error is preserved.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match write_private_file_inner(path, bytes) {
        Ok(()) => Ok(()),
        Err(error) => remove_path_preserving_primary(path, error),
    }
}

fn write_private_file_inner(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    match injected_fault() {
        PrivateFileFault::Create => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "injected fault: failed to create private temp file '{}'",
                    path.display()
                ),
            ));
        }
        PrivateFileFault::Write => {
            // Create the file so cleanup paths can be exercised, then fail the write.
            create_private_file(path)?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "injected fault: failed to write private temp file '{}'",
                    path.display()
                ),
            ));
        }
        PrivateFileFault::Sync => {
            let mut file = create_private_file(path)?;
            file.write_all(bytes)?;
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "injected fault: failed to fsync private temp file '{}'",
                    path.display()
                ),
            ));
        }
        PrivateFileFault::None | PrivateFileFault::Rename | PrivateFileFault::DirSync => {}
    }

    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create_new(true).write(true).open(path)
    }
}

/// Atomically publish `bytes` at `final_path`.
///
/// Sequence: private temp → write → fsync → rename → parent-directory fsync.
/// Temporary files are removed on every failure. If rename succeeded but the
/// parent-directory fsync failed, the prior durable contents of `final_path`
/// are restored (or the new file is removed on create) and the parent directory
/// is fsynced again so the rollback itself is durable, before returning the
/// primary error.
pub(crate) fn replace_private_file(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = final_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no parent directory",
        )
    })?;
    let file_name = final_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private file path has no file name",
        )
    })?;
    let tmp_path = parent.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        Uuid::new_v4().simple()
    ));

    let previous = read_previous_snapshot(final_path)?;

    if let Err(error) = write_private_file(&tmp_path, bytes) {
        return Err(error);
    }

    if let Err(error) = rename_temp_into_place(&tmp_path, final_path) {
        return remove_path_preserving_primary(&tmp_path, error);
    }

    if let Err(error) = sync_parent_dir(parent) {
        return restore_previous_after_publish_failure(final_path, previous.as_deref(), error);
    }

    Ok(())
}

fn read_previous_snapshot(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn rename_temp_into_place(tmp_path: &Path, final_path: &Path) -> io::Result<()> {
    #[cfg(test)]
    if injected_fault() == PrivateFileFault::Rename {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "injected fault: failed to rename private temp file '{}' to '{}'",
                tmp_path.display(),
                final_path.display()
            ),
        ));
    }
    fs::rename(tmp_path, final_path)
}

fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    sync_parent_dir_inner(parent, /*allow_injected_fault=*/ true)
}

/// Parent-directory durability sync used after rollback. Never consults the
/// injected DirSync fault so a one-shot publish failure can still exercise a
/// real rollback durability attempt.
fn sync_parent_dir_after_rollback(parent: &Path) -> io::Result<()> {
    sync_parent_dir_inner(parent, /*allow_injected_fault=*/ false)
}

fn sync_parent_dir_inner(parent: &Path, allow_injected_fault: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        #[cfg(test)]
        if allow_injected_fault && take_dir_sync_fault() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "injected fault: failed to fsync parent directory '{}' after rename",
                    parent.display()
                ),
            ));
        }
        #[cfg(not(test))]
        let _ = allow_injected_fault;
        let dir = File::open(parent)?;
        dir.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        #[cfg(test)]
        if allow_injected_fault && take_dir_sync_fault() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "injected fault: failed to fsync parent directory after rename",
            ));
        }
        #[cfg(not(test))]
        let _ = allow_injected_fault;
        // Directory fsync is not available; file sync + rename is the durability
        // boundary on these platforms.
        Ok(())
    }
}

/// Consume a pending DirSync fault (one-shot) so rollback can sync for real.
#[cfg(test)]
fn take_dir_sync_fault() -> bool {
    INJECTED_FAULT.with(|cell| {
        if cell.get() == PrivateFileFault::DirSync {
            cell.set(PrivateFileFault::None);
            true
        } else {
            false
        }
    })
}

fn restore_previous_after_publish_failure(
    final_path: &Path,
    previous: Option<&[u8]>,
    primary: io::Error,
) -> io::Result<()> {
    let restore_result = match previous {
        Some(bytes) => restore_private_file_best_effort(final_path, bytes),
        None => match fs::remove_file(final_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    };

    let mut extras = Vec::new();
    match restore_result {
        Ok(()) => {}
        Err(restore_error) => extras.push(format!(
            "also failed to restore prior state: {restore_error}"
        )),
    }

    if let Some(parent) = final_path.parent() {
        if let Err(sync_error) = sync_parent_dir_after_rollback(parent) {
            extras.push(format!(
                "also failed to fsync parent directory after rollback: {sync_error}"
            ));
        }
    }

    if extras.is_empty() {
        Err(primary)
    } else {
        Err(io::Error::new(
            primary.kind(),
            format!("{primary}; {}", extras.join("; ")),
        ))
    }
}

/// Best-effort rewrite used only to undo a post-rename durability failure.
///
/// Does not consult injected faults: the caller is already returning the
/// primary durability error. Parent-directory durability sync is performed by
/// [`restore_previous_after_publish_failure`] after this restore (or a create
/// rollback removal) so both paths share one durable rollback contract.
fn restore_private_file_best_effort(final_path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = match final_path.parent() {
        Some(parent) => parent,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path has no parent directory",
            ));
        }
    };
    let file_name = match final_path.file_name() {
        Some(name) => name,
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path has no file name",
            ));
        }
    };
    let tmp_path = parent.join(format!(
        ".{}.restore-{}",
        file_name.to_string_lossy(),
        Uuid::new_v4().simple()
    ));
    match restore_write_private_file(&tmp_path, bytes) {
        Ok(()) => {}
        Err(error) => return remove_path_preserving_primary(&tmp_path, error),
    }
    match fs::rename(&tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(error) => remove_path_preserving_primary(&tmp_path, error),
    }
}

fn restore_write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_path_preserving_primary(path: &Path, primary: io::Error) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Err(primary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(primary),
        Err(cleanup_error) => Err(io::Error::new(
            primary.kind(),
            format!("{primary}; also failed to remove temporary file: {cleanup_error}"),
        )),
    }
}

/// Return paths under `dir` whose names look like private-file temps.
#[cfg(test)]
pub(crate) fn private_temp_artifacts_for_tests(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.contains(".tmp-") || name.contains(".restore-") {
            artifacts.push(entry.path());
        }
    }
    artifacts.sort();
    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn with_fault<T>(fault: PrivateFileFault, f: impl FnOnce() -> T) -> T {
        let guard = inject_private_file_fault_for_tests(fault);
        let result = f();
        guard.disarm();
        result
    }

    #[test]
    fn dir_sync_failure_restores_prior_file_and_syncs_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("material.json");
        replace_private_file(&path, b"version-a").expect("seed");

        let err = with_fault(PrivateFileFault::DirSync, || {
            replace_private_file(&path, b"version-b")
        })
        .expect_err("dir sync fault must fail publish");
        assert!(
            err.to_string().contains("injected fault: failed to fsync parent directory"),
            "primary dir-sync error must be preserved: {err}"
        );
        assert!(
            !err.to_string().contains("also failed to"),
            "successful rollback must not append secondary errors: {err}"
        );
        assert_eq!(fs::read(&path).expect("restored"), b"version-a");
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty()
        );
        // DirSync is one-shot: a subsequent publish must succeed with a real
        // parent sync (proving the rollback path cleared the injected fault).
        replace_private_file(&path, b"version-c").expect("publish after one-shot dir sync");
        assert_eq!(fs::read(&path).expect("updated"), b"version-c");
    }

    #[test]
    fn dir_sync_failure_removes_new_create_and_syncs_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new-material.json");
        assert!(!path.exists());

        let err = with_fault(PrivateFileFault::DirSync, || {
            replace_private_file(&path, b"brand-new")
        })
        .expect_err("dir sync fault must fail create");
        assert!(
            err.to_string().contains("injected fault: failed to fsync parent directory"),
            "primary dir-sync error must be preserved: {err}"
        );
        assert!(
            !err.to_string().contains("also failed to"),
            "successful create-rollback must not append secondary errors: {err}"
        );
        assert!(
            !path.exists(),
            "failed create must remove the visible destination"
        );
        assert!(
            private_temp_artifacts_for_tests(dir.path())
                .expect("list temps")
                .is_empty()
        );
    }

    #[test]
    fn fault_injection_apis_are_crate_private_test_only() {
        // Compiling this module under `cfg(test)` is the seam: production builds
        // omit PrivateFileFault / inject / artifact helpers entirely.
        let _ = PrivateFileFault::None;
        let guard = inject_private_file_fault_for_tests(PrivateFileFault::None);
        guard.disarm();
        let _ = private_temp_artifacts_for_tests(std::path::Path::new("."));
    }
}
