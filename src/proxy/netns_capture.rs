//! In-pod-network-namespace outbound capture listeners (node-waypoint).
//!
//! # Why this exists
//!
//! In node-waypoint topology the eBPF `connect4` hook rewrites a captured pod's
//! outbound `connect()` to `127.0.0.1:15001` (the outbound capture port). That
//! destination is **pod loopback** — it never leaves the pod's network
//! namespace — so the connection can only be accepted by a socket that lives
//! *inside that pod's netns*. A single listener bound on `127.0.0.1:15001` in
//! the host/proxy netns (the default outbound listener) can therefore never
//! receive captured traffic from any pod: there is nothing listening on the
//! pod's own loopback.
//!
//! The GAP-2M `sock_ops` cookie bridge has the same requirement from the other
//! direction: it re-keys the orig-dst record by `(netns cookie, 4-tuple)` at
//! active-established and recovers it at passive-established using the
//! accept-side socket's netns cookie. That only matches when the accepting
//! socket shares the connecting socket's netns — i.e. when the proxy accepts
//! *in the pod netns*.
//!
//! # What this does
//!
//! For each pod the node-agent has enrolled for capture, the mesh proxy opens a
//! `127.0.0.1:15001` listener **inside that pod's network namespace** (entering
//! via `setns(CLONE_NEWNET)` on a dedicated OS thread — the same pattern as
//! [`crate::ebpf::veth`]) and runs the normal proxy accept loop on the returned
//! socket. The listening socket's fd is process-global once created, so the
//! accept loop runs on the shared tokio runtime in the host netns; only the
//! `bind()` happens in the pod netns. The accepted connection then resolves its
//! source pod identity through the same cookie path as before — which now
//! succeeds because the bridge's same-netns assumption holds.
//!
//! The node-agent (which watches pods and holds their cgroup paths) publishes
//! the enrolled-pod set to a pinned registry directory; this manager polls it
//! and reconciles **one listener per pod netns** (deduplicated by netns inode,
//! since a pod's sandbox + containers share one netns). Pods that come and go
//! drive listener open/close.
//!
//! # Verification
//!
//! Linux-only (`setns`, `/proc/<pid>/ns/net`); non-Linux targets compile to a
//! stub that reports unsupported. The reconcile bookkeeping and the registry
//! parser are unit-tested with a mock backend; the `setns`/`bind` path and the
//! full pod-loopback datapath are **not** unit- or CI-testable (they need a live
//! multi-pod node) and are exercised only in a real cluster. Gated behind
//! `FERRUM_MESH_NODE_WAYPOINT_IN_NETNS_LISTENERS_ENABLED` (default off).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::{ListenerTlsSource, ProxyState, run_accept_loop};

/// A pod the node-agent has enrolled for node-waypoint capture. `cgroup_path`
/// is the pod cgroup directory the node-agent resolved; the manager walks it to
/// find a live PID and, through `/proc/<pid>/ns/net`, the pod's network
/// namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCaptureTarget {
    pub pod_uid: String,
    pub cgroup_path: String,
}

/// Source of the current enrolled-pod set. Production reads a directory the
/// node-agent publishes; tests inject a fake.
pub trait PodCaptureSource: Send + Sync {
    fn list_targets(&self) -> Vec<PodCaptureTarget>;
}

/// Filesystem registry source: the node-agent writes one file per enrolled pod,
/// named `<pod_uid>`, whose single line is the pod cgroup path. Removing the
/// file (on pod teardown) drops the pod from the set. This mirrors the existing
/// "pinned path is the entire node-agent ↔ mesh-proxy IPC surface" contract.
pub struct DirectoryCaptureSource {
    dir: PathBuf,
}

impl DirectoryCaptureSource {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl PodCaptureSource for DirectoryCaptureSource {
    fn list_targets(&self) -> Vec<PodCaptureTarget> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            // Registry dir absent (node-agent not up yet, or no enrolled pods):
            // an empty set is the correct steady state, not an error.
            return Vec::new();
        };
        let mut targets = Vec::new();
        for entry in entries.flatten() {
            let pod_uid = entry.file_name().to_string_lossy().to_string();
            if pod_uid.is_empty() || pod_uid.starts_with('.') {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            let cgroup_path = contents.trim().to_string();
            if cgroup_path.is_empty() {
                continue;
            }
            targets.push(PodCaptureTarget {
                pod_uid,
                cgroup_path,
            });
        }
        targets
    }
}

/// Opens/closes the actual in-netns listeners. Abstracted so the manager's
/// reconcile diff is unit-testable with a mock; production uses
/// [`ProxyNetnsBackend`].
pub trait NetnsBackend: Send + Sync + 'static {
    /// Stable per-netns key for the pod (the netns inode). `None` when no live
    /// PID can be found in the cgroup (pod terminating, race) or the platform
    /// can't resolve it — the pod is skipped this round and retried next poll.
    fn netns_key(&self, target: &PodCaptureTarget) -> Option<u64>;

    /// Open a `capture_addr` listener inside the pod's netns and spawn its
    /// accept loop. Returns a stop handle (setting it `true` shuts the loop
    /// down) or `None` if the listener could not be created.
    fn open_listener(
        &self,
        target: &PodCaptureTarget,
        capture_addr: SocketAddr,
    ) -> Option<watch::Sender<bool>>;
}

/// One open in-netns listener, keyed in the manager by netns inode.
struct ActiveListener {
    stop: watch::Sender<bool>,
    /// Pods sharing this netns (normally exactly one; a pod's sandbox and
    /// containers share its netns). Kept for observability and so a netns stays
    /// open while any of its pods is still enrolled.
    pod_uids: HashSet<String>,
}

impl ActiveListener {
    fn close(&self) {
        let _ = self.stop.send(true);
    }
}

/// Reconciles in-netns capture listeners against the enrolled-pod set.
pub struct NetnsCaptureManager<B: NetnsBackend> {
    capture_addr: SocketAddr,
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    /// netns inode → its open listener.
    active: HashMap<u64, ActiveListener>,
}

impl<B: NetnsBackend> NetnsCaptureManager<B> {
    pub fn new(
        capture_addr: SocketAddr,
        source: Arc<dyn PodCaptureSource>,
        backend: B,
        poll_interval: Duration,
    ) -> Self {
        Self {
            capture_addr,
            source,
            backend,
            poll_interval,
            active: HashMap::new(),
        }
    }

    /// Poll-and-reconcile until `shutdown` flips to `true`, then close every
    /// listener.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        info!(
            capture_addr = %self.capture_addr,
            poll_secs = self.poll_interval.as_secs_f64(),
            "Node-waypoint in-netns capture manager started"
        );
        loop {
            self.reconcile_once();
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        self.shutdown_all();
    }

    /// One reconcile pass: open listeners for newly enrolled pod netns, close
    /// listeners whose pods are all gone. Returns the count of currently active
    /// listeners (used by tests).
    fn reconcile_once(&mut self) -> usize {
        let targets = self.source.list_targets();

        // Desired state: netns inode → pods in it. A target whose netns can't be
        // resolved right now is simply skipped (retried next poll); it never
        // tears down an existing listener.
        let mut desired: HashMap<u64, HashSet<String>> = HashMap::new();
        for target in &targets {
            if let Some(netns) = self.backend.netns_key(target) {
                desired
                    .entry(netns)
                    .or_default()
                    .insert(target.pod_uid.clone());
            } else {
                debug!(
                    pod_uid = %target.pod_uid,
                    cgroup = %target.cgroup_path,
                    "Node-waypoint capture: pod netns not resolvable yet; will retry"
                );
            }
        }

        // Close listeners whose netns no longer has any enrolled pod.
        let gone: Vec<u64> = self
            .active
            .keys()
            .filter(|netns| !desired.contains_key(netns))
            .copied()
            .collect();
        for netns in gone {
            if let Some(listener) = self.active.remove(&netns) {
                listener.close();
                info!(
                    netns_inode = netns,
                    "Closed node-waypoint in-netns capture listener"
                );
            }
        }

        // Open listeners for newly-seen netns; refresh membership for existing.
        for (netns, pod_uids) in desired {
            if let Some(existing) = self.active.get_mut(&netns) {
                existing.pod_uids = pod_uids;
                continue;
            }
            // Any target in this netns can open it — they share the namespace.
            let Some(target) = targets.iter().find(|t| pod_uids.contains(&t.pod_uid)) else {
                continue;
            };
            match self.backend.open_listener(target, self.capture_addr) {
                Some(stop) => {
                    info!(
                        netns_inode = netns,
                        pod_uid = %target.pod_uid,
                        "Opened node-waypoint in-netns capture listener"
                    );
                    self.active.insert(netns, ActiveListener { stop, pod_uids });
                }
                None => {
                    warn!(
                        netns_inode = netns,
                        pod_uid = %target.pod_uid,
                        "Failed to open node-waypoint in-netns capture listener; will retry"
                    );
                }
            }
        }

        self.active.len()
    }

    fn shutdown_all(&mut self) {
        for (_, listener) in self.active.drain() {
            listener.close();
        }
    }
}

/// Production backend: resolves pod netns from its cgroup and opens a real
/// capture listener inside it, feeding accepted connections into the shared
/// proxy accept loop.
pub struct ProxyNetnsBackend {
    state: ProxyState,
    conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
    mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
    global_shutdown: watch::Receiver<bool>,
}

impl ProxyNetnsBackend {
    pub fn new(
        state: ProxyState,
        conn_semaphore: Option<Arc<tokio::sync::Semaphore>>,
        mesh_direction: Option<crate::modes::mesh::MeshTrafficDirection>,
        global_shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state,
            conn_semaphore,
            mesh_direction,
            global_shutdown,
        }
    }
}

impl NetnsBackend for ProxyNetnsBackend {
    fn netns_key(&self, target: &PodCaptureTarget) -> Option<u64> {
        imp::netns_inode_for_cgroup(&target.cgroup_path)
    }

    fn open_listener(
        &self,
        target: &PodCaptureTarget,
        capture_addr: SocketAddr,
    ) -> Option<watch::Sender<bool>> {
        let std_listener =
            match imp::bind_capture_listener_in_pod_netns(&target.cgroup_path, capture_addr) {
                Ok(listener) => listener,
                Err(error) => {
                    warn!(
                        pod_uid = %target.pod_uid,
                        cgroup = %target.cgroup_path,
                        %error,
                        "Node-waypoint in-netns bind failed"
                    );
                    return None;
                }
            };
        let listener = match tokio::net::TcpListener::from_std(std_listener) {
            Ok(listener) => listener,
            Err(error) => {
                warn!(pod_uid = %target.pod_uid, %error, "Adopting in-netns listener fd failed");
                return None;
            }
        };

        // Per-listener stop signal. A forwarder flips it when the global
        // shutdown fires, so the accept loop stops on either signal.
        let (stop_tx, stop_rx) = watch::channel(false);
        let forwarder_stop = stop_tx.clone();
        let mut global = self.global_shutdown.clone();
        tokio::spawn(async move {
            while global.changed().await.is_ok() {
                if *global.borrow() {
                    let _ = forwarder_stop.send(true);
                    break;
                }
            }
        });

        let state = self.state.clone();
        let conn_semaphore = self.conn_semaphore.clone();
        let mesh_direction = self.mesh_direction;
        tokio::spawn(async move {
            run_accept_loop(
                listener,
                state,
                ListenerTlsSource::Static {
                    tls_config: None,
                    record_mesh_mtls_metric: false,
                },
                conn_semaphore,
                stop_rx,
                mesh_direction,
                0,
            )
            .await;
        });

        Some(stop_tx)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs::File;
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    /// Resolve the pod's netns identity (the `net` namespace inode) from a live
    /// PID in its cgroup. The inode is stable for the life of the netns and is a
    /// good dedup key across the pod sandbox + container cgroups.
    pub(super) fn netns_inode_for_cgroup(cgroup_path: &str) -> Option<u64> {
        let pid = first_pid_in_cgroup(cgroup_path)?;
        let meta = std::fs::metadata(format!("/proc/{pid}/ns/net")).ok()?;
        Some(meta.ino())
    }

    /// Bind `addr` (the capture loopback endpoint) inside the pod's network
    /// namespace and return the listening socket.
    ///
    /// `setns(CLONE_NEWNET)` changes the **calling thread's** netns, so it must
    /// NOT run on a tokio worker (it would corrupt unrelated tasks). We run it
    /// on a dedicated OS thread that restores its netns before exiting; the
    /// returned socket fd is process-global and outlives the thread.
    pub(super) fn bind_capture_listener_in_pod_netns(
        cgroup_path: &str,
        addr: SocketAddr,
    ) -> std::io::Result<std::net::TcpListener> {
        let pid = first_pid_in_cgroup(cgroup_path).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no live PID in pod cgroup (pod terminating or not yet started)",
            )
        })?;
        std::thread::spawn(move || -> std::io::Result<std::net::TcpListener> {
            let _guard = NetnsGuard::enter(pid)?;
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            socket.set_reuse_address(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&addr.into())?;
            socket.listen(1024)?;
            Ok(socket.into())
            // `_guard` drops here, on this thread, restoring the original netns
            // before the thread exits.
        })
        .join()
        .map_err(|_| std::io::Error::other("in-netns bind thread panicked"))?
    }

    /// Breadth-first walk of the pod cgroup subtree, returning the first PID
    /// from any `cgroup.procs`. Mirrors the discovery used by
    /// `crate::ebpf::veth`. Bounded to avoid runaway traversal.
    fn first_pid_in_cgroup(cgroup_path: &str) -> Option<u32> {
        let mut dirs = vec![PathBuf::from(cgroup_path)];
        let mut scanned = 0usize;
        while let Some(dir) = dirs.pop() {
            scanned += 1;
            if scanned > 1024 {
                break;
            }
            if let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs"))
                && let Some(pid) = procs.split_whitespace().find_map(|raw| raw.parse().ok())
            {
                return Some(pid);
            }
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
                        dirs.push(entry.path());
                    }
                }
            }
        }
        None
    }

    /// RAII netns switch: enters the target PID's net namespace on construction
    /// and restores the caller's on drop. Must live only on a dedicated thread.
    struct NetnsGuard {
        original: File,
    }

    impl NetnsGuard {
        fn enter(pid: u32) -> std::io::Result<Self> {
            let original = File::open("/proc/self/ns/net")?;
            let target = File::open(format!("/proc/{pid}/ns/net"))?;
            setns_net(target.as_raw_fd())?;
            Ok(Self { original })
        }
    }

    impl Drop for NetnsGuard {
        fn drop(&mut self) {
            let _ = setns_net(self.original.as_raw_fd());
        }
    }

    fn setns_net(fd: std::os::fd::RawFd) -> std::io::Result<()> {
        // Safety: `fd` is an open `/proc/.../ns/net` handle owned by the caller
        // for the duration of the call; `setns` only reads it.
        if unsafe { libc::setns(fd, libc::CLONE_NEWNET) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::net::SocketAddr;

    pub(super) fn netns_inode_for_cgroup(_cgroup_path: &str) -> Option<u64> {
        None
    }

    pub(super) fn bind_capture_listener_in_pod_netns(
        _cgroup_path: &str,
        _addr: SocketAddr,
    ) -> std::io::Result<std::net::TcpListener> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "in-netns capture listeners are Linux-only",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock backend: maps each pod's cgroup path to a caller-provided netns
    /// inode and records every open/close so the reconcile diff can be asserted
    /// without a real netns.
    struct MockBackend {
        // cgroup_path → netns inode (None = unresolvable this round)
        netns_by_cgroup: Mutex<HashMap<String, Option<u64>>>,
        opened: Mutex<Vec<u64>>,
    }

    impl MockBackend {
        fn new(mapping: &[(&str, Option<u64>)]) -> Self {
            Self {
                netns_by_cgroup: Mutex::new(
                    mapping.iter().map(|(c, n)| (c.to_string(), *n)).collect(),
                ),
                opened: Mutex::new(Vec::new()),
            }
        }
    }

    impl NetnsBackend for MockBackend {
        fn netns_key(&self, target: &PodCaptureTarget) -> Option<u64> {
            self.netns_by_cgroup
                .lock()
                .unwrap()
                .get(&target.cgroup_path)
                .copied()
                .flatten()
        }

        fn open_listener(
            &self,
            target: &PodCaptureTarget,
            _addr: SocketAddr,
        ) -> Option<watch::Sender<bool>> {
            let netns = self.netns_key(target)?;
            self.opened.lock().unwrap().push(netns);
            // The manager records closes by dropping the listener from `active`;
            // tests assert on `mgr.active` membership, so the mock just hands
            // back a live stop handle.
            let (tx, _rx) = watch::channel(false);
            Some(tx)
        }
    }

    fn target(uid: &str, cgroup: &str) -> PodCaptureTarget {
        PodCaptureTarget {
            pod_uid: uid.to_string(),
            cgroup_path: cgroup.to_string(),
        }
    }

    struct StaticSource(Vec<PodCaptureTarget>);
    impl PodCaptureSource for StaticSource {
        fn list_targets(&self) -> Vec<PodCaptureTarget> {
            self.0.clone()
        }
    }

    #[test]
    fn directory_source_parses_pod_uid_and_cgroup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("pod-a"), "/sys/fs/cgroup/kubepods/pod-a\n").unwrap();
        std::fs::write(
            dir.path().join("pod-b"),
            "  /sys/fs/cgroup/kubepods/pod-b  ",
        )
        .unwrap();
        std::fs::write(dir.path().join(".hidden"), "ignored").unwrap();
        std::fs::write(dir.path().join("empty"), "   ").unwrap();

        let source = DirectoryCaptureSource::new(dir.path());
        let mut targets = source.list_targets();
        targets.sort_by(|a, b| a.pod_uid.cmp(&b.pod_uid));

        assert_eq!(targets.len(), 2, "hidden + empty-cgroup files are skipped");
        assert_eq!(targets[0].pod_uid, "pod-a");
        assert_eq!(targets[0].cgroup_path, "/sys/fs/cgroup/kubepods/pod-a");
        assert_eq!(targets[1].pod_uid, "pod-b");
        assert_eq!(targets[1].cgroup_path, "/sys/fs/cgroup/kubepods/pod-b");
    }

    #[test]
    fn directory_source_absent_dir_is_empty_not_error() {
        let source = DirectoryCaptureSource::new("/definitely/not/a/dir");
        assert!(source.list_targets().is_empty());
    }

    #[tokio::test]
    async fn reconcile_opens_one_listener_per_netns_and_dedupes_shared_netns() {
        // pod-a and pod-b share netns 100 (e.g. sandbox + container); pod-c is
        // its own netns 200.
        let source = Arc::new(StaticSource(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
            target("pod-c", "/cg/c"),
        ]));
        let backend = MockBackend::new(&[
            ("/cg/a", Some(100)),
            ("/cg/b", Some(100)),
            ("/cg/c", Some(200)),
        ]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );
        let active = mgr.reconcile_once();
        assert_eq!(active, 2, "two distinct netns → two listeners, not three");
        let opened = mgr.backend.opened.lock().unwrap().clone();
        assert_eq!(opened.len(), 2);
        assert!(opened.contains(&100) && opened.contains(&200));
    }

    #[tokio::test]
    async fn reconcile_is_idempotent_and_closes_removed_pods() {
        let targets = Arc::new(Mutex::new(vec![
            target("pod-a", "/cg/a"),
            target("pod-c", "/cg/c"),
        ]));

        struct DynSource(Arc<Mutex<Vec<PodCaptureTarget>>>);
        impl PodCaptureSource for DynSource {
            fn list_targets(&self) -> Vec<PodCaptureTarget> {
                self.0.lock().unwrap().clone()
            }
        }

        let backend = MockBackend::new(&[("/cg/a", Some(100)), ("/cg/c", Some(200))]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            Arc::new(DynSource(targets.clone())),
            backend,
            Duration::from_secs(1),
        );

        assert_eq!(mgr.reconcile_once(), 2);
        // Second pass with the SAME set opens nothing new.
        assert_eq!(mgr.reconcile_once(), 2);
        assert_eq!(mgr.backend.opened.lock().unwrap().len(), 2, "no re-open");

        // pod-c goes away → its netns listener closes.
        targets.lock().unwrap().retain(|t| t.pod_uid != "pod-c");
        assert_eq!(mgr.reconcile_once(), 1);
        assert!(!mgr.active.contains_key(&200));
        assert!(mgr.active.contains_key(&100));
    }

    #[tokio::test]
    async fn reconcile_skips_unresolvable_netns_without_tearing_down() {
        // pod-a resolves; pod-b's netns is unresolvable this round (terminating
        // / race). The unresolvable pod is skipped, never affecting pod-a.
        let source = Arc::new(StaticSource(vec![
            target("pod-a", "/cg/a"),
            target("pod-b", "/cg/b"),
        ]));
        let backend = MockBackend::new(&[("/cg/a", Some(100)), ("/cg/b", None)]);
        let mut mgr = NetnsCaptureManager::new(
            "127.0.0.1:15001".parse().unwrap(),
            source,
            backend,
            Duration::from_secs(1),
        );
        assert_eq!(mgr.reconcile_once(), 1, "only the resolvable pod opens");
        assert!(mgr.active.contains_key(&100));
    }
}

/// Privileged functional tests for the in-netns capture primitive
/// ([`imp::bind_capture_listener_in_pod_netns`]). They create and enter network
/// namespaces, which needs `CAP_SYS_ADMIN`/root, so they are `#[ignore]`d and
/// run only by the dedicated `netns-capture-live` CI job. Each self-skips
/// (returns, passing) when it lacks root or `unshare` — mirroring
/// `ebpf::loader::live_kernel_tests`.
///
/// No eBPF here: this layer proves the OS mechanism the whole design rests on —
/// a `127.0.0.1:15001` listener bound *inside* a pod's netns is reachable from a
/// client in that netns and **unreachable from the host netns** (the per-pod
/// loopback isolation that makes a single host-netns listener insufficient).
#[cfg(all(test, target_os = "linux"))]
mod live_netns_tests {
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command};
    use std::time::{Duration, Instant};

    const CAPTURE_PORT: u16 = 15001;

    fn is_root() -> bool {
        // Safety: `geteuid` is always sound and never fails.
        unsafe { libc::geteuid() == 0 }
    }

    /// Spawn a child living in a fresh network namespace (loopback brought up),
    /// then sleeping. `/proc/<pid>/ns/net` is the synthetic "pod" netns.
    /// `None` if `unshare` is unavailable. `unshare --net` does not fork, so the
    /// spawned PID is the process living in the new netns.
    fn spawn_pod_netns_child() -> Option<Child> {
        Command::new("unshare")
            .args([
                "--net",
                "sh",
                "-c",
                "ip link set lo up 2>/dev/null || true; exec sleep 30",
            ])
            .spawn()
            .ok()
    }

    /// Reaps the child netns process on drop so the test never leaks it.
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Connect to `127.0.0.1:port` from inside `pid`'s network namespace, on a
    /// throwaway thread (setns mutates only the calling thread, and the thread
    /// exits immediately so no restore is needed). Returns whether it connected.
    fn connect_inside_netns(pid: u32, port: u16) -> bool {
        std::thread::spawn(move || -> bool {
            let Ok(target) = std::fs::File::open(format!("/proc/{pid}/ns/net")) else {
                return false;
            };
            // Safety: `target` is an open netns handle owned for the call.
            if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return false;
            }
            match TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                Duration::from_secs(2),
            ) {
                Ok(mut stream) => {
                    let _ = stream.write_all(b"ping");
                    true
                }
                Err(_) => false,
            }
        })
        .join()
        .unwrap_or(false)
    }

    #[test]
    #[ignore = "requires root + CAP_SYS_ADMIN to create/enter network namespaces"]
    fn in_netns_listener_reachable_inside_pod_and_isolated_from_host() {
        if !is_root() {
            eprintln!("SKIP: not root; cannot create network namespaces");
            return;
        }
        let Some(child) = spawn_pod_netns_child() else {
            eprintln!("SKIP: `unshare --net` unavailable");
            return;
        };
        let pid = child.id();
        let _child = ChildGuard(child);
        // Let the child unshare its netns and bring loopback up.
        std::thread::sleep(Duration::from_millis(400));

        // Synthetic pod cgroup: `first_pid_in_cgroup` only reads `cgroup.procs`,
        // so a tempdir holding the child PID is enough — no real cgroupfs.
        let cgdir = tempfile::tempdir().unwrap();
        std::fs::write(cgdir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        let cgroup_path = cgdir.path().to_string_lossy().to_string();

        let listener = super::imp::bind_capture_listener_in_pod_netns(
            &cgroup_path,
            SocketAddr::from((Ipv4Addr::LOCALHOST, CAPTURE_PORT)),
        )
        .expect("bind capture listener inside the pod netns");
        listener
            .set_nonblocking(true)
            .expect("listener set_nonblocking");

        // (1) A client INSIDE the pod netns must reach the in-netns listener.
        assert!(
            connect_inside_netns(pid, CAPTURE_PORT),
            "a client inside the pod netns must reach the in-netns capture listener"
        );

        // Poll accept with a deadline so a missed connection can never hang CI.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut accepted = false;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok(_) => {
                    accepted = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("in-netns listener accept failed: {e}"),
            }
        }
        assert!(
            accepted,
            "the in-netns listener must accept the pod's loopback connection"
        );

        // (2) The HOST netns must NOT reach 127.0.0.1:15001 — the listener lives
        // only in the pod netns. This loopback isolation is exactly why a single
        // host-netns listener can never serve captured pods.
        let host_reach = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, CAPTURE_PORT)),
            Duration::from_millis(500),
        );
        assert!(
            host_reach.is_err(),
            "host netns must not reach a pod-netns-only loopback listener (got {host_reach:?})"
        );
    }
}
