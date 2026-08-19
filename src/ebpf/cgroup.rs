#![allow(dead_code)]
//! cgroup v2 path resolution for Kubernetes pods.
//!
//! Kubernetes uses two cgroup drivers — `systemd` and `cgroupfs` — each
//! placing pod cgroups at different paths. The node agent must resolve
//! the correct path before attaching BPF programs.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Single-entry memo for [`resolve_pod_cgroup_path_cached`].
///
/// Deliberately one slot, not a map: exactly one NodeWaypoint relay pod is
/// resolved on a timer at any moment, so a single `(cgroup_root, pod_uid,
/// path)` tuple is inherently bounded and cannot grow as pods churn.
static RELAY_POD_CGROUP_PATH_MEMO: OnceLock<Mutex<Option<(String, String, PathBuf)>>> =
    OnceLock::new();

/// [`resolve_pod_cgroup_path`] for callers that resolve the SAME pod on a
/// timer rather than once per pod event.
///
/// `resolve_pod_cgroup_path`'s six fast paths only cover the plain
/// `kubepods.slice` / `kubepods` layouts. On the kubeadm/kind systemd layout
/// (`kubelet.slice/kubelet-kubepods.slice/...`, pinned by
/// `resolve_pod_cgroup_path_finds_kubelet_slice_systemd_pod`) every call falls
/// through to `discover_pod_cgroup_paths`, a breadth-first walk bounded at
/// `POD_CGROUP_DISCOVERY_MAX_DIRS` directories that does not early-exit on a
/// match. The NodeWaypoint relay reconcile runs every
/// `UDP_CAPTURE_READINESS_POLL` (250 ms), so calling the uncached resolver
/// there costs thousands of directory reads per second, forever, on a
/// steady-state node.
///
/// The memo is validated by a single `exists()` check before reuse. That is
/// sound because the resolved path embeds the pod UID: if the pod's cgroup
/// moves to a different parent slice the cached path stops existing and the
/// walk is redone. Callers still re-run [`collect_cgroup_tree`] on the
/// returned path every poll, so a container leaf that moves WITHIN the pod
/// subtree is still detected — only the discovery is cached, never the inode
/// set.
pub fn resolve_pod_cgroup_path_cached(cgroup_root: &str, pod_uid: &str) -> Option<PathBuf> {
    let memo = RELAY_POD_CGROUP_PATH_MEMO.get_or_init(|| Mutex::new(None));
    let mut slot = match memo.lock() {
        Ok(slot) => slot,
        // A poisoned memo is a cache, not state: recover and keep serving.
        Err(poisoned) => poisoned.into_inner(),
    };
    resolve_pod_cgroup_path_with_memo(
        &mut slot,
        cgroup_root,
        pod_uid,
        resolve_pod_cgroup_path,
        |path| path.exists(),
    )
}

/// Memo policy for [`resolve_pod_cgroup_path_cached`], with the slot, the
/// resolver, and the liveness probe injected so the cache-hit, stale-path, and
/// changed-identity transitions are testable without touching the process
/// global or the real filesystem.
fn resolve_pod_cgroup_path_with_memo(
    slot: &mut Option<(String, String, PathBuf)>,
    cgroup_root: &str,
    pod_uid: &str,
    mut resolve: impl FnMut(&str, &str) -> Option<PathBuf>,
    mut still_exists: impl FnMut(&Path) -> bool,
) -> Option<PathBuf> {
    if let Some((cached_root, cached_uid, cached_path)) = slot.as_ref()
        && cached_root == cgroup_root
        && cached_uid == pod_uid
        && still_exists(cached_path)
    {
        return Some(cached_path.clone());
    }
    let resolved = resolve(cgroup_root, pod_uid)?;
    *slot = Some((
        cgroup_root.to_string(),
        pod_uid.to_string(),
        resolved.clone(),
    ));
    Some(resolved)
}

/// Resolve the cgroup v2 path for a Kubernetes pod.
///
/// Tries systemd driver paths first (`kubepods.slice/...`), then falls back to
/// cgroupfs driver paths (`kubepods/pod{uid}/`).
pub fn resolve_pod_cgroup_path(cgroup_root: &str, pod_uid: &str) -> Option<PathBuf> {
    let sanitized_uid = pod_uid.replace('-', "_");

    if let Some(path) = systemd_pod_cgroup_paths(cgroup_root, &sanitized_uid)
        .into_iter()
        .chain(cgroupfs_pod_cgroup_paths(cgroup_root, pod_uid))
        .find(|path| path.exists())
    {
        return Some(path);
    }

    discover_pod_cgroup_paths(cgroup_root, pod_uid, &sanitized_uid)
        .into_iter()
        .find(|path| path.exists())
}

fn systemd_pod_cgroup_paths(cgroup_root: &str, sanitized_uid: &str) -> [PathBuf; 3] {
    let root = Path::new(cgroup_root).join("kubepods.slice");
    [
        root.join(format!("kubepods-pod{sanitized_uid}.slice")),
        root.join(format!(
            "kubepods-burstable.slice/kubepods-burstable-pod{sanitized_uid}.slice"
        )),
        root.join(format!(
            "kubepods-besteffort.slice/kubepods-besteffort-pod{sanitized_uid}.slice"
        )),
    ]
}

fn cgroupfs_pod_cgroup_paths(cgroup_root: &str, pod_uid: &str) -> [PathBuf; 3] {
    let root = Path::new(cgroup_root).join("kubepods");
    [
        root.join(format!("pod{pod_uid}")),
        root.join(format!("burstable/pod{pod_uid}")),
        root.join(format!("besteffort/pod{pod_uid}")),
    ]
}

const POD_CGROUP_DISCOVERY_MAX_DEPTH: usize = 8;
const POD_CGROUP_DISCOVERY_MAX_DIRS: usize = 4096;

fn discover_pod_cgroup_paths(
    cgroup_root: &str,
    pod_uid: &str,
    sanitized_uid: &str,
) -> Vec<PathBuf> {
    let root = Path::new(cgroup_root);
    let raw_cgroupfs = format!("pod{pod_uid}");
    let systemd_suffix = format!("pod{sanitized_uid}.slice");
    let mut matches = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0usize));
    let mut scanned = 0usize;

    while let Some((dir, depth)) = queue.pop_front() {
        if scanned >= POD_CGROUP_DISCOVERY_MAX_DIRS {
            // A cap-hit is a miss for [`resolve_pod_cgroup_path`] (None), not a
            // partial authorization set. Unlike [`collect_cgroup_tree`], this
            // walk is a name search: failing to find the pod fail-closes.
            break;
        }
        scanned += 1;

        let name_matches = dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == raw_cgroupfs || name.ends_with(&systemd_suffix));
        if name_matches {
            matches.push(dir.clone());
            continue;
        }
        if depth >= POD_CGROUP_DISCOVERY_MAX_DEPTH {
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
            if descend {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }

    matches
}

/// Build the expected cgroup path for a given QoS class (for testing/validation).
pub fn cgroup_path_for_qos(cgroup_root: &str, pod_uid: &str, qos_class: &str) -> PathBuf {
    match qos_class {
        "Guaranteed" => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
        "Burstable" => Path::new(cgroup_root).join(format!("kubepods/burstable/pod{pod_uid}")),
        "BestEffort" => Path::new(cgroup_root).join(format!("kubepods/besteffort/pod{pod_uid}")),
        _ => Path::new(cgroup_root).join(format!("kubepods/pod{pod_uid}")),
    }
}

/// Bounds for [`collect_cgroup_tree`]. Kubernetes pod cgroups nest only a
/// level or two deep (the pod slice plus a `.scope`/dir per container, plus
/// the pause container), so these are generous; they exist solely to keep a
/// pathological or adversarial cgroup tree from turning enrollment into an
/// unbounded directory walk.
///
/// Exactly [`CGROUP_TREE_MAX_INODES`] complete directory inodes remain
/// representable. Observing a further unique directory, a descendant past
/// [`CGROUP_TREE_MAX_DEPTH`], or a child that cannot be fully enumerated is
/// reported via [`CgroupTreeWalkStatus`] rather than silently truncated.
pub const CGROUP_TREE_MAX_DEPTH: usize = 8;
pub const CGROUP_TREE_MAX_INODES: usize = 256;
const CGROUP_TREE_MAX_DIR_ENTRIES: usize = 512;
const CGROUP_TREE_MAX_VISITS: usize = 512;

/// Why a bounded cgroup-tree walk could not prove the inode set complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupTreeWalkStatus {
    /// Every reachable descendant directory was enumerated; [`CgroupTreeWalk::inodes`]
    /// is the full set.
    Complete,
    /// A unique directory inode past [`CGROUP_TREE_MAX_INODES`] was observed, or
    /// the pending-visit queue could not be extended without exceeding that bound.
    ExceededEntryBound,
    /// A directory at [`CGROUP_TREE_MAX_DEPTH`] has a descendant that would
    /// require walking deeper.
    ExceededDepthBound,
    /// A descendant could not be `stat`ed or `read_dir`ed, so remaining
    /// children may exist unseen.
    IncompleteEnumeration,
}

/// Bounded walk of a pod cgroup subtree.
///
/// `inodes` is the pod directory first, then descendants in breadth-first
/// order, capped at [`CGROUP_TREE_MAX_INODES`]. It is an authorization set
/// only when [`Self::status`] is [`CgroupTreeWalkStatus::Complete`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupTreeWalk {
    pub inodes: Vec<u64>,
    pub status: CgroupTreeWalkStatus,
}

impl CgroupTreeWalk {
    pub fn is_complete(&self) -> bool {
        self.status == CgroupTreeWalkStatus::Complete
    }

    fn complete(inodes: Vec<u64>) -> Self {
        Self {
            inodes,
            status: CgroupTreeWalkStatus::Complete,
        }
    }
}

#[cfg(unix)]
fn record_incomplete(status: &mut CgroupTreeWalkStatus, reason: CgroupTreeWalkStatus) {
    // A Complete "reason" is not a failure and must not clobber a prior one.
    // Callers only pass incomplete statuses; ignore Complete rather than
    // panicking in debug builds over an internal invariant with no extra
    // diagnostic value.
    if reason == CgroupTreeWalkStatus::Complete {
        return;
    }
    if *status == CgroupTreeWalkStatus::Complete {
        *status = reason;
    }
}

/// Collect the inode of `pod_cgroup_path` plus every descendant cgroup
/// directory inode, breadth-first and bounded by [`CGROUP_TREE_MAX_DEPTH`] /
/// [`CGROUP_TREE_MAX_INODES`]. The pod inode is returned first.
///
/// This is the best-effort prefix used by workload-identity and
/// includeOutboundPorts enrollment: a truncated or incomplete walk still
/// enrolls the inodes that were observed, and a missed container leaf fails
/// closed at the connect hook. Authorization callers that must publish a
/// whole set (NodeWaypoint UDP relay cgroups) must use [`collect_cgroup_tree`]
/// and refuse unless [`CgroupTreeWalk::is_complete`] is true.
///
/// Returns an empty Vec on a missing/unreadable root or on non-Unix builds;
/// those callers treat empty as "nothing enrolled".
pub fn collect_cgroup_tree_inodes(pod_cgroup_path: &Path) -> Vec<u64> {
    collect_cgroup_tree(pod_cgroup_path).inodes
}

/// Collect the inode of `pod_cgroup_path` plus every descendant cgroup
/// directory inode, and report whether the walk proved that set complete.
///
/// This exists because the `connect4`/`connect6` hooks read
/// `bpf_get_current_cgroup_id()`, which returns the *leaf* cgroup the calling
/// task belongs to. On Kubernetes the connecting task is a container process
/// living in a child cgroup *below* the pod cgroup
/// (`.../kubepods-pod<uid>.slice/cri-containerd-<id>.scope`,
/// `.../pod<uid>/<container-id>`), so the pod cgroup inode alone never matches
/// the hook's lookup key — per-cgroup maps keyed only by the pod inode miss and
/// the hook falls back to its sentinel. Enrolling every descendant inode (the
/// container leaves) as well as the pod inode keys those maps with the same id
/// the hook reads.
///
/// A missing or non-directory root returns an empty complete walk (nothing to
/// enroll). Stat or `read_dir` failures on descendants, a unique directory
/// past [`CGROUP_TREE_MAX_INODES`], or a child past [`CGROUP_TREE_MAX_DEPTH`]
/// return the inodes observed so far with a non-complete status. The walk
/// itself stays bounded against hostile trees.
#[cfg(unix)]
pub fn collect_cgroup_tree(pod_cgroup_path: &Path) -> CgroupTreeWalk {
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    let mut inodes: Vec<u64> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    let mut status = CgroupTreeWalkStatus::Complete;
    queue.push_back((pod_cgroup_path.to_path_buf(), 0));
    let mut visits = 0usize;

    while let Some((path, depth)) = queue.pop_front() {
        visits += 1;
        if visits > CGROUP_TREE_MAX_VISITS {
            record_incomplete(&mut status, CgroupTreeWalkStatus::IncompleteEnumeration);
            break;
        }

        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(_) if inodes.is_empty() => {
                // Missing or unreadable root: nothing enrolled, not a truncated
                // descendant set.
                return CgroupTreeWalk::complete(Vec::new());
            }
            Err(_) => {
                record_incomplete(&mut status, CgroupTreeWalkStatus::IncompleteEnumeration);
                continue;
            }
        };
        // Only directories are cgroups; the files inside a cgroup dir
        // (`cgroup.procs`, `cgroup.controllers`, ...) are not.
        if !meta.is_dir() {
            continue;
        }
        let inode = meta.ino();
        if seen.insert(inode) {
            if inodes.len() >= CGROUP_TREE_MAX_INODES {
                record_incomplete(&mut status, CgroupTreeWalkStatus::ExceededEntryBound);
                break;
            }
            inodes.push(inode);
        } else {
            // Already walked this cgroup (bind-mount / duplicate path). Do not
            // re-descend: a cycle must not restart the bound.
            continue;
        }

        if depth >= CGROUP_TREE_MAX_DEPTH {
            match directory_has_directory_children(&path) {
                Ok(true) => {
                    record_incomplete(&mut status, CgroupTreeWalkStatus::ExceededDepthBound);
                }
                Ok(false) => {}
                Err(()) => {
                    record_incomplete(&mut status, CgroupTreeWalkStatus::IncompleteEnumeration);
                }
            }
            continue;
        }

        match std::fs::read_dir(&path) {
            Ok(entries) => {
                enqueue_directory_children(&mut queue, entries, depth, &mut status);
            }
            Err(_) => {
                record_incomplete(&mut status, CgroupTreeWalkStatus::IncompleteEnumeration);
            }
        }
    }

    CgroupTreeWalk { inodes, status }
}

/// Enqueue directory children of one cgroup dir. Stops enqueueing once the
/// pending queue would exceed [`CGROUP_TREE_MAX_INODES`], which is itself
/// evidence the tree is over the entry bound.
#[cfg(unix)]
fn enqueue_directory_children(
    queue: &mut VecDeque<(PathBuf, usize)>,
    entries: std::fs::ReadDir,
    depth: usize,
    status: &mut CgroupTreeWalkStatus,
) {
    let mut inspected = 0usize;
    for entry in entries {
        inspected += 1;
        if inspected > CGROUP_TREE_MAX_DIR_ENTRIES {
            record_incomplete(status, CgroupTreeWalkStatus::IncompleteEnumeration);
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                record_incomplete(status, CgroupTreeWalkStatus::IncompleteEnumeration);
                continue;
            }
        };
        // Use the readdir `d_type` when available (cgroupfs/kernfs supplies it
        // without a stat); if it's unknown, enqueue anyway and let the loop's
        // own `is_dir` check filter it out, so a child cgroup is never skipped.
        let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
        if !descend {
            continue;
        }
        if queue.len() >= CGROUP_TREE_MAX_INODES {
            record_incomplete(status, CgroupTreeWalkStatus::ExceededEntryBound);
            return;
        }
        queue.push_back((entry.path(), depth + 1));
    }
}

/// Whether `path` (already at [`CGROUP_TREE_MAX_DEPTH`]) has a directory child
/// that would require walking deeper. Unknown `d_type` is treated as a possible
/// directory so a child cgroup is never mistaken for a leaf.
#[cfg(unix)]
fn directory_has_directory_children(path: &Path) -> Result<bool, ()> {
    let entries = std::fs::read_dir(path).map_err(|_| ())?;
    let mut inspected = 0usize;
    for entry in entries {
        inspected += 1;
        if inspected > CGROUP_TREE_MAX_DIR_ENTRIES {
            return Err(());
        }
        let entry = entry.map_err(|_| ())?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(true) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(not(unix))]
pub fn collect_cgroup_tree(_pod_cgroup_path: &Path) -> CgroupTreeWalk {
    CgroupTreeWalk::complete(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_for_qos_guaranteed() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Guaranteed");
        assert_eq!(path, PathBuf::from("/sys/fs/cgroup/kubepods/podabc-123"));
    }

    #[test]
    fn cgroup_path_for_qos_burstable() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "Burstable");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/burstable/podabc-123")
        );
    }

    #[test]
    fn cgroup_path_for_qos_besteffort() {
        let path = cgroup_path_for_qos("/sys/fs/cgroup", "abc-123", "BestEffort");
        assert_eq!(
            path,
            PathBuf::from("/sys/fs/cgroup/kubepods/besteffort/podabc-123")
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_nonexistent() {
        assert!(resolve_pod_cgroup_path("/nonexistent/cgroup", "abc-123").is_none());
    }

    #[test]
    fn systemd_path_sanitizes_dashes_to_underscores() {
        let sanitized = "abc-def-123".replace('-', "_");
        assert_eq!(sanitized, "abc_def_123");
    }

    #[test]
    fn resolve_pod_cgroup_path_finds_systemd_burstable_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc_def.slice");
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_finds_systemd_besteffort_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podabc_def.slice");
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }

    #[test]
    fn resolve_pod_cgroup_path_finds_kubelet_slice_systemd_pod() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(
            "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/\
             kubelet-kubepods-burstable-podabc_def.slice",
        );
        std::fs::create_dir_all(&path).unwrap();

        assert_eq!(
            resolve_pod_cgroup_path(dir.path().to_str().unwrap(), "abc-def"),
            Some(path)
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_cgroup_tree_inodes_includes_pod_and_container_leaves() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        // Simulate a systemd-driver pod slice with two container scopes below
        // it — the leaf cgroups a container process's connect() actually runs
        // in, and whose inode `bpf_get_current_cgroup_id()` returns.
        let pod = dir.path().join("kubepods-pod_abc.slice");
        let c1 = pod.join("cri-containerd-aaaa.scope");
        let c2 = pod.join("cri-containerd-bbbb.scope");
        std::fs::create_dir_all(&c1).unwrap();
        std::fs::create_dir_all(&c2).unwrap();
        // A regular file inside a cgroup dir must NOT be treated as a cgroup.
        std::fs::write(pod.join("cgroup.procs"), b"").unwrap();

        let inodes = collect_cgroup_tree_inodes(&pod);

        let pod_ino = std::fs::metadata(&pod).unwrap().ino();
        let c1_ino = std::fs::metadata(&c1).unwrap().ino();
        let c2_ino = std::fs::metadata(&c2).unwrap().ino();
        let file_ino = std::fs::metadata(pod.join("cgroup.procs")).unwrap().ino();

        // Pod inode first, both container leaves present (the ids the
        // pod-inode-only enrollment used to miss), the file excluded.
        assert_eq!(inodes.first(), Some(&pod_ino));
        assert!(inodes.contains(&c1_ino));
        assert!(inodes.contains(&c2_ino));
        assert!(
            !inodes.contains(&file_ino),
            "files inside a cgroup dir are not cgroups"
        );
        assert_eq!(inodes.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn collect_cgroup_tree_inodes_empty_for_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(collect_cgroup_tree_inodes(&dir.path().join("does-not-exist")).is_empty());
    }

    /// The relay reconcile calls this on a 250 ms timer, and the uncached
    /// resolver walks up to 4096 directories on the kubeadm/kind
    /// `kubelet.slice` layout. A repeat call for the same live pod must not
    /// re-walk.
    #[test]
    fn memoized_relay_path_reuses_a_live_entry_without_re_resolving() {
        let mut slot = None;
        let mut resolves = 0usize;
        let mut resolve = |_root: &str, _uid: &str| {
            resolves += 1;
            Some(PathBuf::from("/sys/fs/cgroup/kubelet.slice/pod-a"))
        };

        let first = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/sys/fs/cgroup",
            "uid-a",
            &mut resolve,
            |_| true,
        );
        let second = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/sys/fs/cgroup",
            "uid-a",
            &mut resolve,
            |_| true,
        );

        assert_eq!(first, second);
        assert_eq!(resolves, 1, "a live cached path must not be re-walked");
    }

    /// The cached path embeds the pod UID, so it stopping existing means the
    /// pod's cgroup moved to a different parent slice. That must re-walk.
    #[test]
    fn memoized_relay_path_rewalks_when_the_cached_path_is_gone() {
        let mut slot = Some((
            "/sys/fs/cgroup".to_string(),
            "uid-a".to_string(),
            PathBuf::from("/sys/fs/cgroup/kubepods.slice/old"),
        ));
        let mut resolves = 0usize;
        let resolved = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/sys/fs/cgroup",
            "uid-a",
            |_root, _uid| {
                resolves += 1;
                Some(PathBuf::from("/sys/fs/cgroup/kubelet.slice/new"))
            },
            |_| false,
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from("/sys/fs/cgroup/kubelet.slice/new"))
        );
        assert_eq!(resolves, 1);
        assert_eq!(
            slot.as_ref().map(|(_, _, path)| path.clone()),
            Some(PathBuf::from("/sys/fs/cgroup/kubelet.slice/new")),
            "the memo must adopt the new path"
        );
    }

    /// A different relay identity (pod restart mints a new UID) must never be
    /// served the previous pod's cgroup path, even while that path still
    /// exists.
    #[test]
    fn memoized_relay_path_never_serves_a_different_identity() {
        let mut slot = Some((
            "/sys/fs/cgroup".to_string(),
            "uid-a".to_string(),
            PathBuf::from("/sys/fs/cgroup/kubepods.slice/pod-a"),
        ));
        let resolved = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/sys/fs/cgroup",
            "uid-b",
            |_root, uid| {
                Some(PathBuf::from(format!(
                    "/sys/fs/cgroup/kubepods.slice/{uid}"
                )))
            },
            |_| true,
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from("/sys/fs/cgroup/kubepods.slice/uid-b"))
        );

        // Same UID, different cgroup root, is also a different identity.
        let mut slot = Some((
            "/sys/fs/cgroup".to_string(),
            "uid-a".to_string(),
            PathBuf::from("/sys/fs/cgroup/kubepods.slice/pod-a"),
        ));
        let resolved = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/host/sys/fs/cgroup",
            "uid-a",
            |root, uid| Some(PathBuf::from(format!("{root}/kubepods.slice/{uid}"))),
            |_| true,
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from("/host/sys/fs/cgroup/kubepods.slice/uid-a"))
        );
    }

    /// A resolver miss must not poison the memo with a stale entry.
    #[test]
    fn memoized_relay_path_leaves_the_slot_untouched_on_a_miss() {
        let mut slot = None;
        let resolved = resolve_pod_cgroup_path_with_memo(
            &mut slot,
            "/sys/fs/cgroup",
            "uid-a",
            |_root, _uid| None,
            |_| true,
        );
        assert_eq!(resolved, None);
        assert!(slot.is_none(), "a miss must not cache anything");
    }
}
