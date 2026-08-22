//! Completeness contract for the bounded pod-cgroup walk used by NodeWaypoint
//! UDP relay authorization (PR #3957).
//!
//! `collect_cgroup_tree_inodes` used to stop at 256 entries with no overflow
//! signal, so a subsequent `len() > 256` check was unreachable. These tests
//! pin that a complete 256-inode tree stays representable, a 257th unique
//! directory is detected, a depth overflow is detected, and an unreadable
//! descendant is not mistaken for a complete set.
//!
//! Issue #4021 adds the other half of that contract: a descendant that VANISHED
//! (`ENOENT`) is evidence the tree shrank, not an inability to enumerate it, so
//! the walk re-runs (bounded) and reports the smaller tree as complete rather
//! than blacking out every NodeWaypoint UDP relay datagram on the node. It also
//! pins the walk bound to the `FERRUM_UDP_RELAY_CGROUPS` map bound.

use std::cell::Cell;
use std::path::{Path, PathBuf};

use ferrum_edge::ebpf::cgroup::{
    CGROUP_TREE_MAX_DEPTH, CGROUP_TREE_MAX_INODES, CgroupTreeWalkStatus, collect_cgroup_tree,
    collect_cgroup_tree_inodes, collect_cgroup_tree_with_vanished,
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

/// Issue #4021 split `NotFound` (the tree shrank — re-walk) out of every other
/// failure. This is the doctrine that must NOT have moved: an inability to
/// PROVE the tree's shape is still not evidence about it, so `EACCES` remains a
/// refusal.
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

/// A descendant that VANISHED mid-walk must not refuse the generation
/// (issue #4021, follow-up 1).
///
/// A container exiting removes its cgroup directory, and it can do so between
/// the pod's `readdir` and that child's `stat`. Recording that as
/// `IncompleteEnumeration` made `resolve_node_waypoint_relay_cgroups` return
/// `Err`, which clears the acknowledgement, closes the shared BPF gate, and
/// revokes the relay cgroups AND the reply sources — every NodeWaypoint UDP
/// relay datagram on the node, plus a steering teardown/reinstall cycle, for
/// one transient `ENOENT`.
///
/// The vanish predicate performs the REAL removal on first sight, so the
/// re-walk observes a genuinely smaller tree rather than a synthetic one.
#[test]
fn a_descendant_that_vanished_mid_walk_is_absent_not_a_refusal() {
    let (_dir, pod) = pod_tree();
    let alive = pod.join("cri-containerd-aaaa.scope");
    let doomed = pod.join("cri-containerd-bbbb.scope");
    std::fs::create_dir(&alive).expect("surviving container");
    std::fs::create_dir(&doomed).expect("exiting container");
    std::fs::create_dir(doomed.join("nested-leaf")).expect("nested leaf");
    let doomed_inode = inode_of(&doomed);

    let removed = Cell::new(false);
    let walk = collect_cgroup_tree_with_vanished(&pod, &|path: &Path| {
        if path != doomed || removed.get() {
            return false;
        }
        removed.set(true);
        std::fs::remove_dir_all(path).expect("stage the vanished subtree");
        true
    });

    assert!(removed.get(), "the vanish seam must have fired");
    assert!(
        walk.is_complete(),
        "a re-walk that observed one coherent smaller tree is complete, not a refusal"
    );
    assert_eq!(walk.inodes.first(), Some(&inode_of(&pod)));
    assert!(walk.inodes.contains(&inode_of(&alive)));
    assert!(
        !walk.inodes.contains(&doomed_inode),
        "the vanished subtree is absent, never stitched in from the first pass"
    );
    assert_eq!(walk.inodes.len(), 2);
}

/// The re-walk is BOUNDED: a tree that keeps shrinking is still refused, and
/// the walk terminates (issue #4021, follow-up 1).
///
/// No pass ever observed one coherent set here, so publishing a stitched set
/// would be exactly the truncation the completeness contract exists to
/// prevent. This test also proves the re-walk cannot spin: it only returns if
/// the bound is enforced.
#[test]
fn a_tree_that_keeps_shrinking_is_still_refused() {
    let (_dir, pod) = pod_tree();
    let doomed = pod.join("cri-containerd-bbbb.scope");
    std::fs::create_dir(&doomed).expect("churning container");

    let observations = Cell::new(0usize);
    let walk = collect_cgroup_tree_with_vanished(&pod, &|path: &Path| {
        if path != doomed {
            return false;
        }
        observations.set(observations.get() + 1);
        true
    });

    assert!(
        observations.get() > 1,
        "a shrinking tree must be re-walked, not accepted on the first pass"
    );
    assert_eq!(
        walk.status,
        CgroupTreeWalkStatus::IncompleteEnumeration,
        "a tree still shrinking after the last re-walk was never observed coherently"
    );
    assert!(!walk.is_complete());
}

/// An `ENOENT` on the ROOT is still "nothing enrolled", not a re-walk
/// (issue #4021, follow-up 1).
#[test]
fn a_vanished_root_stays_empty_and_complete() {
    let (_dir, pod) = pod_tree();
    let observations = Cell::new(0usize);
    let walk = collect_cgroup_tree_with_vanished(&pod, &|path: &Path| {
        if path != pod {
            return false;
        }
        observations.set(observations.get() + 1);
        true
    });

    assert!(walk.inodes.is_empty());
    assert_eq!(walk.status, CgroupTreeWalkStatus::Complete);
    assert_eq!(
        observations.get(),
        1,
        "an absent root is answered on the first pass; it is not a shrinking tree"
    );
}

/// The walk bound and the relay-cgroup BPF map bound are ONE number
/// (issue #4021, follow-up 4).
///
/// `src/ebpf/cgroup.rs` carries a `const _: () = assert!(...)` so a drift is a
/// compile error; this test exists so the FAILURE NAMES the coupling instead
/// of pointing at an anonymous const. Raise only the map and complete-looking
/// sets are silently short of a container leaf; raise only the walk and the
/// node-agent's `cgroups.len() > UDP_RELAY_CGROUP_MAX_ENTRIES` check starts
/// refusing legitimate generations.
#[test]
fn the_walk_bound_and_the_relay_cgroup_map_bound_are_one_number() {
    assert_eq!(
        CGROUP_TREE_MAX_INODES,
        ferrum_ebpf_common::UDP_RELAY_CGROUP_MAX_ENTRIES as usize,
        "CGROUP_TREE_MAX_INODES (src/ebpf/cgroup.rs) and UDP_RELAY_CGROUP_MAX_ENTRIES \
         (ebpf/ferrum-ebpf-common/src/lib.rs) are coupled: the walk produces the set the \
         node-agent publishes into FERRUM_UDP_RELAY_CGROUPS, and the node-agent refuses \
         any set larger than the map bound. Change both or neither."
    );
}
