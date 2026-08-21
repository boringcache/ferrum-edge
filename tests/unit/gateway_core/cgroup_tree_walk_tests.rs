//! Completeness contract for the bounded pod-cgroup walk used by NodeWaypoint
//! UDP relay authorization (PR #3957).
//!
//! `collect_cgroup_tree_inodes` used to stop at 256 entries with no overflow
//! signal, so a subsequent `len() > 256` check was unreachable. These tests
//! pin that a complete 256-inode tree stays representable, a 257th unique
//! directory is detected, a depth overflow is detected, and an unreadable
//! descendant is not mistaken for a complete set.

use std::path::{Path, PathBuf};

use ferrum_edge::ebpf::cgroup::{
    CGROUP_TREE_MAX_DEPTH, CGROUP_TREE_MAX_INODES, CgroupTreeWalkStatus, collect_cgroup_tree,
    collect_cgroup_tree_inodes,
};

fn pod_tree() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("cgroup root");
    let pod = dir.path().join("kubepods-pod_abc.slice");
    std::fs::create_dir_all(&pod).expect("pod cgroup");
    (dir, pod)
}

fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).expect("stat").ino()
}

#[test]
fn a_small_complete_tree_reports_every_directory_inode() {
    let (_dir, pod) = pod_tree();
    let c1 = pod.join("cri-containerd-aaaa.scope");
    let c2 = pod.join("cri-containerd-bbbb.scope");
    std::fs::create_dir_all(&c1).expect("container 1");
    std::fs::create_dir_all(&c2).expect("container 2");
    std::fs::write(pod.join("cgroup.procs"), b"").expect("cgroup file");

    let walk = collect_cgroup_tree(&pod);
    assert!(
        walk.is_complete(),
        "a fully readable pod + two container leaves must be a complete walk"
    );
    assert_eq!(walk.inodes.first(), Some(&inode_of(&pod)));
    assert!(walk.inodes.contains(&inode_of(&c1)));
    assert!(walk.inodes.contains(&inode_of(&c2)));
    assert_eq!(walk.inodes.len(), 3);
    assert_eq!(collect_cgroup_tree_inodes(&pod), walk.inodes);
}

#[test]
fn a_missing_root_is_empty_and_complete() {
    let dir = tempfile::tempdir().expect("cgroup root");
    let walk = collect_cgroup_tree(&dir.path().join("does-not-exist"));
    assert!(walk.inodes.is_empty());
    assert_eq!(walk.status, CgroupTreeWalkStatus::Complete);
}

#[test]
fn exactly_the_entry_bound_stays_complete() {
    let (_dir, pod) = pod_tree();
    // Root plus (MAX - 1) children = MAX unique directory inodes, all readable.
    for index in 0..(CGROUP_TREE_MAX_INODES - 1) {
        std::fs::create_dir(pod.join(format!("cri-containerd-{index:03}.scope")))
            .expect("container cgroup");
    }

    let walk = collect_cgroup_tree(&pod);
    assert_eq!(
        walk.status,
        CgroupTreeWalkStatus::Complete,
        "exactly {CGROUP_TREE_MAX_INODES} unique directories must remain representable"
    );
    assert_eq!(walk.inodes.len(), CGROUP_TREE_MAX_INODES);
    assert_eq!(walk.inodes.first(), Some(&inode_of(&pod)));
}

#[test]
fn a_257th_unique_directory_is_detected_as_entry_overflow() {
    let (_dir, pod) = pod_tree();
    for index in 0..CGROUP_TREE_MAX_INODES {
        std::fs::create_dir(pod.join(format!("cri-containerd-{index:03}.scope")))
            .expect("container cgroup");
    }

    let walk = collect_cgroup_tree(&pod);
    assert_eq!(walk.status, CgroupTreeWalkStatus::ExceededEntryBound);
    assert_eq!(
        walk.inodes.len(),
        CGROUP_TREE_MAX_INODES,
        "the observed prefix stays at the map/walk bound; the 257th is signalled, not stored"
    );
    assert_eq!(
        collect_cgroup_tree_inodes(&pod).len(),
        CGROUP_TREE_MAX_INODES,
        "identity/include-ports callers still receive the bounded prefix"
    );
}

#[test]
fn a_tree_at_the_depth_bound_stays_complete() {
    let (_dir, pod) = pod_tree();
    let mut path = pod.clone();
    for index in 0..CGROUP_TREE_MAX_DEPTH {
        path.push(format!("n{index}"));
        std::fs::create_dir(&path).expect("depth chain");
    }

    let walk = collect_cgroup_tree(&pod);
    assert_eq!(
        walk.status,
        CgroupTreeWalkStatus::Complete,
        "a chain whose deepest directory is at CGROUP_TREE_MAX_DEPTH with no children is complete"
    );
    assert_eq!(walk.inodes.len(), CGROUP_TREE_MAX_DEPTH + 1);
}

#[test]
fn a_child_past_the_depth_bound_is_detected() {
    let (_dir, pod) = pod_tree();
    let mut path = pod.clone();
    for index in 0..=CGROUP_TREE_MAX_DEPTH {
        path.push(format!("n{index}"));
        std::fs::create_dir(&path).expect("depth chain");
    }

    let walk = collect_cgroup_tree(&pod);
    assert_eq!(walk.status, CgroupTreeWalkStatus::ExceededDepthBound);
    assert_eq!(
        walk.inodes.len(),
        CGROUP_TREE_MAX_DEPTH + 1,
        "directories at depths 0..=MAX are collected; the deeper child is the overflow signal"
    );
    assert!(
        !walk.is_complete(),
        "a depth overflow must not be publishable as a complete relay cgroup set"
    );
}

#[test]
fn an_unreadable_descendant_is_not_a_complete_set() {
    use std::os::unix::fs::PermissionsExt as _;

    // SAFETY: `geteuid` is a pure read of this process's credentials.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let (_dir, pod) = pod_tree();
    let readable = pod.join("cri-containerd-aaaa.scope");
    let hidden = pod.join("cri-containerd-bbbb.scope");
    std::fs::create_dir(&readable).expect("readable container");
    std::fs::create_dir(&hidden).expect("hidden container");
    std::fs::create_dir(hidden.join("nested-leaf")).expect("nested leaf");
    std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    struct RestoreMode<'a>(&'a Path);
    impl Drop for RestoreMode<'_> {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o755));
        }
    }
    let _restore = RestoreMode(&hidden);

    let walk = collect_cgroup_tree(&pod);

    assert_eq!(
        walk.status,
        CgroupTreeWalkStatus::IncompleteEnumeration,
        "a descendant whose children cannot be listed must not look complete"
    );
    assert!(walk.inodes.contains(&inode_of(&pod)));
    assert!(walk.inodes.contains(&inode_of(&readable)));
    assert!(
        !walk.is_complete(),
        "authorization must refuse this walk rather than publish a truncated sender set"
    );
}
