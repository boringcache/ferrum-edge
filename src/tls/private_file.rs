//! Private, durable file publication for TLS material stores.
//!
//! Writes use `0600` on Unix, `create_new` temps, fsync, rename, and a parent
//! directory fsync so readers observe either the prior durable file or the fully
//! committed replacement. Temporary files are removed on every failure path
//! without masking the primary error.

use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Injectable failure points for durable private-file publication.
///
/// Production always uses [`PrivateFileFault::None`]. External unit tests arm a
/// single fault through [`inject_private_file_fault_for_tests`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[doc(hidden)]
pub enum PrivateFileFault {
    #[default]
    None,
    Create,
    Write,
    Sync,
    Rename,
    DirSync,
}

thread_local! {
    static INJECTED_FAULT: Cell<PrivateFileFault> = const { Cell::new(PrivateFileFault::None) };
}

fn injected_fault() -> PrivateFileFault {
    INJECTED_FAULT.with(Cell::get)
}

/// Arm a one-thread private-file fault until the returned guard drops.
#[doc(hidden)]
pub fn inject_private_file_fault_for_tests(fault: PrivateFileFault) -> PrivateFileFaultGuard {
    INJECTED_FAULT.with(|cell| cell.set(fault));
    PrivateFileFaultGuard { active: true }
}

/// Clears an injected [`PrivateFileFault`] on drop.
#[doc(hidden)]
#[must_use = "the fault is cleared when this guard is dropped"]
pub struct PrivateFileFaultGuard {
    active: bool,
}

impl PrivateFileFaultGuard {
    /// Disarm early so subsequent writes in the same test run for real.
    pub fn disarm(mut self) {
        self.clear();
        self.active = false;
    }

    fn clear(&self) {
        INJECTED_FAULT.with(|cell| cell.set(PrivateFileFault::None));
    }
}

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
/// are restored (or the new file is removed on create) before returning the
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
    #[cfg(unix)]
    {
        if injected_fault() == PrivateFileFault::DirSync {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "injected fault: failed to fsync parent directory '{}' after rename",
                    parent.display()
                ),
            ));
        }
        let dir = File::open(parent)?;
        dir.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        // Directory fsync is not available; file sync + rename is the durability
        // boundary on these platforms.
        if injected_fault() == PrivateFileFault::DirSync {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "injected fault: failed to fsync parent directory after rename",
            ));
        }
        Ok(())
    }
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
    match restore_result {
        Ok(()) => Err(primary),
        Err(restore_error) => Err(io::Error::new(
            primary.kind(),
            format!("{primary}; also failed to restore prior state: {restore_error}"),
        )),
    }
}

/// Best-effort rewrite used only to undo a post-rename durability failure.
///
/// Does not consult injected faults or require a parent-directory fsync: the
/// caller is already returning the primary durability error, and this path
/// exists only to keep live and on-disk snapshots aligned.
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
#[doc(hidden)]
pub fn private_temp_artifacts_for_tests(dir: &Path) -> io::Result<Vec<PathBuf>> {
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
