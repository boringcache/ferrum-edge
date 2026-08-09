//! Host-network UDP capture for the Ambient mesh proxy (issue #3288).
//!
//! # Why this exists
//!
//! Ambient's proxy runs `hostNetwork: true`, OUTSIDE the workload pods' network
//! namespaces. Until now the only UDP capture producer was
//! [`super::netns_udp_capture`], which `setns(CLONE_NEWNET)`s into each enrolled
//! pod to install rules and bind a socket there. That needs `hostPID`,
//! `SYS_ADMIN`, and `SYS_PTRACE` — privileges some clusters will not grant — and
//! the host-namespace alternative did not exist: the pod-netns rule generator
//! splits inbound from outbound with `-m addrtype --dst-type LOCAL`, which is
//! meaningless in the host namespace (pod IPs are forwarded there, not local), so
//! it deliberately emitted NOTHING for `host_netns`.
//!
//! # The safe host-namespace discriminator
//!
//! This module captures from the host namespace using the INGRESS INTERFACE as
//! the direction discriminator, which is exact rather than heuristic:
//!
//! * A pod's egress is the only traffic that enters the host namespace on THAT
//!   pod's host-side interface. `-i <iface>` in `mangle PREROUTING` selects it
//!   and nothing else.
//! * Traffic destined FOR a pod arrives on the node uplink and is forwarded out
//!   the pod interface; it never matches an `-i <pod iface>` rule.
//! * The node's own traffic (kubelet, CNI, DNS, the mesh proxy's own relay
//!   egress, every `hostNetwork` pod) is locally generated and traverses
//!   `OUTPUT`. This path installs no `mangle OUTPUT` chain at all, so host
//!   traffic is structurally incapable of being captured.
//!
//! # Per-datagram identity
//!
//! One transparent socket serves every enrolled pod on the node, so evidence
//! cannot be fixed per producer the way the pod-netns path fixes it per netns.
//! Each datagram carries two independent kernel-provided facts:
//!
//! * `IP_RECVORIGDSTADDR` — the original destination, un-rewritten by TPROXY.
//! * `IP_PKTINFO` / `IPV6_PKTINFO` — the ingress interface index.
//!
//! [`HostUdpIdentityIndex`] maps the ingress interface index to exactly one
//! enrolled pod and then requires the datagram's SOURCE address to be one of that
//! pod's registry-published addresses. Both facts come from the kernel, never
//! from the datagram payload, so a workload cannot assert another tenant's
//! identity: forging a source IP does not change which interface the packet
//! entered on, and an interface belongs to one pod. Anything that fails either
//! check is dropped — the path never falls back to an unattested or mesh-wide
//! identity, which on a shared socket would be exactly the cross-tenant
//! confusion this design exists to prevent.
//!
//! An interface that more than one enrolled pod claims makes attribution
//! ambiguous, so BOTH pods are refused (never captured under a guessed
//! identity). In practice that is the "shared bridge CNI" case: such a
//! deployment must use the per-pod-netns producer instead.
//!
//! # Lifecycle
//!
//! The manager polls the same node-agent-published registry the pod-netns
//! producer uses, and holds the datapath at one of three postures, never between
//! them:
//!
//! 1. **Guarded** — a scope-exact DROP guard is jumped from `PREROUTING`. Used
//!    while rules are rebuilt and whenever setup fails. Enrolled UDP egress is
//!    dropped, never leaked as plaintext.
//! 2. **Live** — guard released, capture chain populated, socket bound.
//! 3. **Absent** — every Ferrum-owned host object removed by exact name.
//!
//! Linux-only. The reconcile/attribution logic is platform-independent and unit
//! tested with a mock backend; the socket/iptables datapath is exercised on a
//! live node.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use super::netns_capture::{PodCaptureSource, PodCaptureTarget};
use crate::capture::IptablesPlan;
use crate::modes::mesh::hbone::UdpSourceIdentity;

/// How long shutdown waits for the node-agent to acknowledge that its BPF UDP
/// gate closed before giving up and leaving the datapath fail-closed. Mirrors the
/// pod-netns producer's bounded handshake window.
const GATE_CLOSE_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval for the gate-close acknowledgement.
const GATE_CLOSE_ACK_POLL: Duration = Duration::from_millis(100);

/// One enrolled pod's host-side capture binding: the interface its egress enters
/// the host namespace on, the addresses it is allowed to source from, and the
/// attested identity every datagram it sends is relayed under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUdpPodBinding {
    pub pod_uid: String,
    pub iface: String,
    pub ifindex: u32,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub identity: UdpSourceIdentity,
}

impl HostUdpPodBinding {
    /// Whether `addr` is an address this pod is registered to source from.
    /// IPv4-mapped IPv6 senders are canonicalized by the caller, so a plain
    /// family comparison is exact here.
    fn owns_source(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => self.ipv4 == Some(v4),
            IpAddr::V6(v6) => self.ipv6 == Some(v6),
        }
    }
}

/// Why one enrolled pod is not covered by host UDP capture. Every variant is a
/// FAIL-CLOSED outcome: the pod's UDP egress is not captured, and (because the
/// node-agent's readiness marker is withheld) its tc guard keeps that egress
/// closed rather than letting it out in plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUdpRefusal {
    /// The registry entry carried no attested SPIFFE identity. On a shared
    /// capture socket an unattested datagram would be relayed with no source
    /// principal beside a sibling pod's attested one.
    MissingIdentity,
    /// The registry entry published no pod address for any family, so a
    /// datagram's source could not be bound to this pod.
    MissingPodAddress,
    /// The pod's host-side interface could not be resolved.
    UnresolvedInterface,
    /// The resolved interface name is not a name this path will place in an
    /// `iptables -i` argument (see `capture::validate_host_capture_interface`).
    InvalidInterface,
    /// More than one enrolled pod resolved to this interface, so a datagram
    /// arriving on it cannot be attributed to a single workload.
    AmbiguousInterface,
    /// The node has more enrolled pods than the supported host capture interface
    /// bound.
    InterfaceCapacity,
}

impl HostUdpRefusal {
    /// Stable, closed-set reason label. Safe for logs and metrics: it is a
    /// `&'static str` from this enum, never operator- or registry-supplied text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingIdentity => "missing_identity",
            Self::MissingPodAddress => "missing_pod_address",
            Self::UnresolvedInterface => "unresolved_interface",
            Self::InvalidInterface => "invalid_interface",
            Self::AmbiguousInterface => "ambiguous_interface",
            Self::InterfaceCapacity => "interface_capacity",
        }
    }
}

/// A resolved host-side interface for one pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInterface {
    pub name: String,
    pub ifindex: u32,
}

/// The reconciled host capture state for one poll: which pods are captured, on
/// which interfaces, and which are refused and why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostUdpDesiredState {
    /// Captured pods, ordered by interface name so the rendered ruleset is
    /// deterministic across polls (an unordered set would rewrite the chain on
    /// every reconcile even when nothing changed).
    pub bindings: Vec<HostUdpPodBinding>,
    /// Refused pods, ordered by pod UID.
    pub refused: Vec<(String, HostUdpRefusal)>,
}

impl HostUdpDesiredState {
    /// Interface names in rule order.
    pub fn ifaces(&self) -> Vec<String> {
        self.bindings.iter().map(|b| b.iface.clone()).collect()
    }

    /// Pod UIDs whose capture is live.
    pub fn bound_uids(&self) -> HashSet<String> {
        self.bindings.iter().map(|b| b.pod_uid.clone()).collect()
    }

    /// Whether the RULESET this state renders differs from `other`'s. Only the
    /// interface set feeds the ruleset, so an identity-only change is NOT a rule
    /// change (it is handled by [`Self::identity_changed_from`], which is the
    /// stronger, listener-restarting condition).
    pub fn rules_differ_from(&self, other: &Self) -> bool {
        self.ifaces() != other.ifaces()
    }

    /// Whether any interface's ATTRIBUTION changed — a different pod, identity,
    /// or source-address set behind the same interface. That is the one change a
    /// running capture loop cannot absorb safely, because sessions admitted under
    /// the previous evidence would keep relaying under it, so the caller restarts
    /// the loop. A pure add/remove is not an attribution change.
    pub fn identity_changed_from(&self, other: &Self) -> bool {
        let previous: HashMap<&str, &HostUdpPodBinding> = other
            .bindings
            .iter()
            .map(|b| (b.iface.as_str(), b))
            .collect();
        self.bindings.iter().any(|binding| {
            previous
                .get(binding.iface.as_str())
                .is_some_and(|prior| *prior != binding)
        })
    }
}

/// Build the desired host capture state from the enrolled-pod registry and the
/// per-pod interface resolution.
///
/// Pure and platform-independent: every effect (procfs reads, `iptables`,
/// sockets) is the caller's. `resolved` maps pod UID to its host-side interface;
/// a missing entry means resolution failed for that pod.
pub fn plan_host_udp_bindings(
    targets: &[PodCaptureTarget],
    resolved: &HashMap<String, ResolvedInterface>,
) -> HostUdpDesiredState {
    let mut refused: Vec<(String, HostUdpRefusal)> = Vec::new();
    let mut candidates: Vec<HostUdpPodBinding> = Vec::new();

    for target in targets {
        // Attested identity is mandatory on the shared host socket. The
        // pod-netns producer tolerates its absence because its socket is already
        // scoped to one pod; here absence would mean relaying one tenant's
        // datagrams with no principal alongside another's attested ones.
        let Some(identity) = target.source_identity.clone() else {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::MissingIdentity));
            continue;
        };
        if target.source_ips.ipv4.is_none() && target.source_ips.ipv6.is_none() {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::MissingPodAddress));
            continue;
        }
        let Some(interface) = resolved.get(&target.pod_uid) else {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::UnresolvedInterface));
            continue;
        };
        if crate::capture::validate_host_capture_interface(&interface.name).is_err()
            || interface.ifindex == 0
        {
            refused.push((target.pod_uid.clone(), HostUdpRefusal::InvalidInterface));
            continue;
        }
        candidates.push(HostUdpPodBinding {
            pod_uid: target.pod_uid.clone(),
            iface: interface.name.clone(),
            ifindex: interface.ifindex,
            ipv4: target.source_ips.ipv4,
            ipv6: target.source_ips.ipv6,
            identity,
        });
    }

    // Ambiguity is fail-closed for EVERY claimant, not first-wins: a shared
    // interface (a bridge CNI, or a stale registry entry pointing at a recycled
    // veth) makes per-datagram attribution impossible, and capturing under a
    // guessed identity is precisely the cross-tenant confusion this path must
    // not have. Interface index and name are both checked so a rename between
    // resolutions cannot smuggle two pods onto one index.
    let mut iface_claims: HashMap<&str, usize> = HashMap::new();
    let mut index_claims: HashMap<u32, usize> = HashMap::new();
    for binding in &candidates {
        *iface_claims.entry(binding.iface.as_str()).or_insert(0) += 1;
        *index_claims.entry(binding.ifindex).or_insert(0) += 1;
    }

    let mut bindings: Vec<HostUdpPodBinding> = Vec::new();
    for binding in candidates {
        let shared = iface_claims
            .get(binding.iface.as_str())
            .is_some_and(|count| *count > 1)
            || index_claims
                .get(&binding.ifindex)
                .is_some_and(|count| *count > 1);
        if shared {
            refused.push((binding.pod_uid.clone(), HostUdpRefusal::AmbiguousInterface));
            continue;
        }
        bindings.push(binding);
    }

    // Deterministic rule order, and a deterministic overflow decision when a node
    // somehow exceeds the interface bound.
    bindings.sort_by(|left, right| left.iface.cmp(&right.iface));
    if bindings.len() > crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES {
        for binding in bindings.split_off(crate::capture::MAX_HOST_UDP_CAPTURE_INTERFACES) {
            refused.push((binding.pod_uid, HostUdpRefusal::InterfaceCapacity));
        }
    }
    refused.sort_by(|left, right| left.0.cmp(&right.0));

    HostUdpDesiredState { bindings, refused }
}

/// Ingress-interface keyed source-evidence index consulted on every captured
/// datagram.
///
/// A whole generation is published at once through [`ArcSwap`]: the reconcile
/// loop is the only writer and always replaces the complete mapping, so a reader
/// observes either the previous generation or the next one, never a half-applied
/// mix in which one pod's interface already points at its successor while another
/// still points at its predecessor. Its cardinality is bounded by
/// `capture::MAX_HOST_UDP_CAPTURE_INTERFACES`.
#[derive(Debug)]
pub struct HostUdpIdentityIndex {
    by_ifindex: ArcSwap<HashMap<u32, Arc<HostUdpPodBinding>>>,
}

impl Default for HostUdpIdentityIndex {
    fn default() -> Self {
        Self {
            by_ifindex: ArcSwap::from_pointee(HashMap::new()),
        }
    }
}

/// Why a captured datagram was refused by [`HostUdpIdentityIndex::authorize`].
/// Closed set, so it is safe to log and count without echoing untrusted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUdpDatagramRefusal {
    /// The kernel reported no ingress interface for the datagram (no
    /// `IP_PKTINFO`/`IPV6_PKTINFO` cmsg, or index 0). Without it the datagram
    /// cannot be attributed, so it is dropped rather than relayed unattributed.
    NoIngressInterface,
    /// The ingress interface belongs to no currently enrolled pod.
    UnenrolledInterface,
    /// The source address is not one the pod owning that interface is registered
    /// to use — a spoofed or stale source.
    SourceAddressMismatch,
}

impl HostUdpDatagramRefusal {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoIngressInterface => "no_ingress_interface",
            Self::UnenrolledInterface => "unenrolled_interface",
            Self::SourceAddressMismatch => "source_address_mismatch",
        }
    }
}

impl HostUdpIdentityIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a complete new generation of bindings.
    pub fn publish(&self, bindings: &[HostUdpPodBinding]) {
        let map: HashMap<u32, Arc<HostUdpPodBinding>> = bindings
            .iter()
            .map(|binding| (binding.ifindex, Arc::new(binding.clone())))
            .collect();
        self.by_ifindex.store(Arc::new(map));
    }

    /// Drop every binding (used when capture stops, so a socket still draining
    /// cannot attribute a late datagram to a pod that is no longer captured).
    pub fn clear(&self) {
        self.by_ifindex.store(Arc::new(HashMap::new()));
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.by_ifindex.load().len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Per-datagram admission check. Deliberately allocation-free and clone-free
    /// so it can run on the receive path for every datagram: one lock-free
    /// snapshot load, one hash lookup, one address comparison.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn authorize(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Result<(), HostUdpDatagramRefusal> {
        let Some(ifindex) = ingress_ifindex.filter(|index| *index != 0) else {
            return Err(HostUdpDatagramRefusal::NoIngressInterface);
        };
        let snapshot = self.by_ifindex.load();
        let Some(binding) = snapshot.get(&ifindex) else {
            return Err(HostUdpDatagramRefusal::UnenrolledInterface);
        };
        if !binding.owns_source(source) {
            return Err(HostUdpDatagramRefusal::SourceAddressMismatch);
        }
        Ok(())
    }

    /// Resolve the attested evidence for an ALREADY-authorized datagram. Called
    /// only when a new session is admitted, so the `Arc` clone stays off the
    /// per-datagram refresh path.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn identity_for(
        &self,
        ingress_ifindex: Option<u32>,
        source: IpAddr,
    ) -> Option<Arc<UdpSourceIdentity>> {
        let ifindex = ingress_ifindex.filter(|index| *index != 0)?;
        let snapshot = self.by_ifindex.load();
        let binding = snapshot.get(&ifindex)?;
        if !binding.owns_source(source) {
            return None;
        }
        Some(Arc::new(binding.identity.clone()))
    }
}

/// Effects the host capture manager performs, behind a trait so the reconcile
/// logic is testable without root, iptables, or a live node.
pub trait HostUdpCaptureBackend: Send + Sync + 'static {
    /// Resolve one pod's host-side interface. `Err` means "unresolved" and is
    /// treated as a refusal, never as "capture everything".
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String>;

    /// Install/refresh the scope-exact fail-closed DROP guard for `ifaces`.
    fn install_guard(&self, ifaces: &[String]) -> Result<(), String>;

    /// Rebuild the capture chain + transparent routing for `ifaces`.
    fn install_capture(&self, ifaces: &[String]) -> Result<(), String>;

    /// Remove the capture chain + routing, leaving any active guard in place.
    fn teardown_capture_rules(&self) -> Result<(), String>;

    /// Strictly release the fail-closed guard once capture is live.
    fn release_guard(&self) -> Result<(), String>;

    /// Remove every Ferrum-owned host UDP object (capture path and guards).
    fn teardown_all(&self) -> Result<(), String>;

    /// Bind the transparent capture socket and run the capture loop until the
    /// returned handle is stopped.
    fn start_listener(
        &self,
        index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String>;
}

/// Handle to a running host capture listener.
pub struct HostUdpListenerHandle {
    stop: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl HostUdpListenerHandle {
    pub fn new(stop: watch::Sender<bool>, task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            stop,
            task: Some(task),
        }
    }

    /// A handle with no task, for backends (and tests) that do not spawn one.
    #[allow(dead_code)]
    pub fn detached(stop: watch::Sender<bool>) -> Self {
        Self { stop, task: None }
    }

    async fn stop(mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// Reconciles host-network UDP capture against the enrolled-pod registry.
pub struct HostUdpCaptureManager<B: HostUdpCaptureBackend> {
    source: Arc<dyn PodCaptureSource>,
    backend: B,
    poll_interval: Duration,
    index: Arc<HostUdpIdentityIndex>,
    /// Producer-to-node-agent readiness handshake directory
    /// (`<registry>/.udp-ready`). The node-agent keeps each pod's BPF UDP gate
    /// closed until the marker exists, so publishing it is what admits a pod's
    /// UDP egress — and withholding it is what keeps a refused pod closed.
    ready_dir: Option<PathBuf>,
    /// The state whose ruleset is currently installed. `None` until the first
    /// successful apply, which is also the "nothing installed yet" posture.
    applied: Option<HostUdpDesiredState>,
    /// What the most recent poll DECIDED, whether or not it was installed. This
    /// is what `reconcile_once` reports, so refusals stay visible even on a poll
    /// that installed nothing (a node whose every enrolled pod is refused would
    /// otherwise look indistinguishable from a node with no enrolled pods).
    last_desired: HostUdpDesiredState,
    listener: Option<HostUdpListenerHandle>,
    /// How long shutdown waits for the node-agent's gate-close acknowledgement.
    gate_close_timeout: Duration,
    /// `true` when the fail-closed guard is installed and has not been released.
    /// A retained guard survives across polls so a failing node stays closed.
    guard_active: bool,
    /// The interface set the last guard/capture install was scoped to. Tracked
    /// SEPARATELY from `applied`, which a failed apply clears: shutdown still has
    /// to be able to (re)install a scope-exact guard for the pods whose readiness
    /// it published, and it cannot derive that scope from a cleared `applied`.
    guard_scope: Vec<String>,
    /// Pods whose readiness marker this process published and has not retracted.
    ///
    /// This — NOT `applied` — is what shutdown and retraction key on. A failed
    /// apply clears `applied` while the node-agent's UDP gate is still open for
    /// those pods (their egress is held by the retained DROP guard), so keying
    /// teardown on `applied` would let shutdown conclude "nothing was ready",
    /// remove the guard, and release their egress in plaintext.
    published_ready: HashSet<String>,
    /// Refusal reasons already logged, so a persistently unresolvable pod does
    /// not warn on every poll.
    logged_refusals: HashMap<String, HostUdpRefusal>,
}

impl<B: HostUdpCaptureBackend> HostUdpCaptureManager<B> {
    pub fn new(source: Arc<dyn PodCaptureSource>, backend: B, poll_interval: Duration) -> Self {
        Self {
            source,
            backend,
            poll_interval,
            index: Arc::new(HostUdpIdentityIndex::new()),
            ready_dir: None,
            applied: None,
            last_desired: HostUdpDesiredState::default(),
            listener: None,
            gate_close_timeout: GATE_CLOSE_ACK_TIMEOUT,
            guard_active: false,
            guard_scope: Vec::new(),
            published_ready: HashSet::new(),
            logged_refusals: HashMap::new(),
        }
    }

    pub fn with_ready_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.ready_dir = dir;
        self
    }

    /// Override the bounded wait for the node-agent's gate-close acknowledgement
    /// (tests use a short window; production uses [`GATE_CLOSE_ACK_TIMEOUT`]).
    #[allow(dead_code)]
    pub fn with_gate_close_timeout(mut self, timeout: Duration) -> Self {
        self.gate_close_timeout = timeout;
        self
    }

    /// The shared per-datagram evidence index (handed to the capture loop).
    pub fn index(&self) -> Arc<HostUdpIdentityIndex> {
        self.index.clone()
    }

    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        // Reap any state a previous generation of this process left behind
        // BEFORE the first apply. Running it unconditionally is what makes a
        // crash-restart converge: the current configuration may render a
        // different interface set, and a stale chain would keep steering the
        // pods it named into a socket this process has not bound yet.
        if let Err(error) = self.backend.teardown_all() {
            warn!(
                %error,
                "Host UDP capture: could not reap stale host capture state at startup; continuing"
            );
        }
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    self.reconcile_once().await;
                }
            }
        }
        self.shutdown().await;
    }

    /// One reconcile pass. Never panics and never leaves the datapath in a state
    /// that leaks plaintext: every failure path either keeps the previous live
    /// ruleset or retains the DROP guard.
    pub async fn reconcile_once(&mut self) -> &HostUdpDesiredState {
        let targets = self.source.list_targets();
        let mut resolved: HashMap<String, ResolvedInterface> = HashMap::new();
        for target in &targets {
            match self.backend.resolve_interface(target) {
                Ok(interface) => {
                    resolved.insert(target.pod_uid.clone(), interface);
                }
                Err(error) => {
                    debug!(
                        pod_uid = %target.pod_uid,
                        %error,
                        "Host UDP capture: could not resolve host-side interface for pod"
                    );
                }
            }
        }
        let desired = plan_host_udp_bindings(&targets, &resolved);
        self.log_refusals(&desired);
        self.last_desired = desired.clone();

        let rules_changed = self
            .applied
            .as_ref()
            .is_none_or(|applied| desired.rules_differ_from(applied));
        let identity_changed = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.identity_changed_from(applied));
        let listener_needed = !desired.bindings.is_empty();
        let listener_missing = listener_needed && self.listener.is_none();

        // Nothing enrolled and nothing installed: install no chain, no jump, and
        // no routing. A node with no mesh-enrolled pods keeps a completely
        // untouched datapath.
        if desired.bindings.is_empty()
            && self.applied.is_none()
            && self.listener.is_none()
            && !self.guard_active
        {
            return &self.last_desired;
        }
        if !rules_changed && !identity_changed && !listener_missing && !self.guard_active {
            return &self.last_desired;
        }

        self.apply(desired).await;
        &self.last_desired
    }

    async fn apply(&mut self, desired: HostUdpDesiredState) {
        let ifaces = desired.ifaces();

        // 1. Guard first. Enrolled egress is dropped for the duration of the
        //    rebuild rather than briefly escaping capture. A guard failure keeps
        //    the previous live ruleset (which is still correct for the pods it
        //    covers) and retries next poll; it must NOT proceed to flush the
        //    capture chain, because that would open the very window the guard
        //    exists to close.
        if !ifaces.is_empty() {
            if let Err(error) = self.backend.install_guard(&ifaces) {
                warn!(
                    %error,
                    interfaces = ifaces.len(),
                    "Host UDP capture: fail-closed guard install failed; keeping the previous \
                     ruleset and retrying"
                );
                return;
            }
            self.guard_active = true;
            self.guard_scope = ifaces.clone();
        }

        // 2. An attribution change cannot be absorbed by a running loop: its
        //    admitted sessions still carry the previous evidence. Stop the loop
        //    (which drains and cancels its sessions) before republishing.
        let identity_changed = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.identity_changed_from(applied));
        if identity_changed && let Some(listener) = self.listener.take() {
            info!("Host UDP capture: pod attribution changed; restarting the capture listener");
            listener.stop().await;
            self.index.clear();
        }

        // 3. Retract readiness for pods that are no longer captured BEFORE their
        //    rules disappear, so the node-agent's tc guard closes first.
        let now_bound = desired.bound_uids();
        let stale: Vec<String> = self
            .published_ready
            .difference(&now_bound)
            .cloned()
            .collect();
        for uid in stale {
            self.retract_readiness(&uid);
        }

        // 4. Rebuild the capture chain.
        if let Err(error) = self.backend.install_capture(&ifaces) {
            warn!(
                %error,
                interfaces = ifaces.len(),
                "Host UDP capture: capture rule install failed; removing partial capture state \
                 and retaining the fail-closed guard"
            );
            if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                warn!(
                    error = %cleanup_error,
                    "Host UDP capture: partial capture cleanup failed; guard retained"
                );
            }
            // The previously applied ruleset is gone, so do not keep claiming it.
            self.applied = None;
            self.index.clear();
            return;
        }

        // 5. Publish evidence BEFORE the guard is released, so the very first
        //    datagram the socket can receive is already attributable.
        self.index.publish(&desired.bindings);

        // 6. Start the listener if capture is wanted and none is running. A bind
        //    failure keeps the guard: rules without a socket are a black hole,
        //    and a black hole plus a released guard would look like capture while
        //    silently discarding traffic.
        if !desired.bindings.is_empty() && self.listener.is_none() {
            match self.backend.start_listener(self.index.clone()) {
                Ok(handle) => self.listener = Some(handle),
                Err(error) => {
                    warn!(
                        %error,
                        "Host UDP capture: transparent socket bind failed; retaining the \
                         fail-closed guard and retrying"
                    );
                    if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                        warn!(
                            error = %cleanup_error,
                            "Host UDP capture: capture cleanup after bind failure did not complete"
                        );
                    }
                    self.index.clear();
                    self.applied = None;
                    return;
                }
            }
        }

        // 7. Stop a listener nobody needs (every pod unenrolled or refused).
        if desired.bindings.is_empty() && let Some(listener) = self.listener.take() {
            listener.stop().await;
            self.index.clear();
        }

        // 8. Guarded → live. A release failure keeps the guard AND removes the
        //    capture rules: dropping is a correct posture, capturing behind a
        //    DROP is not.
        // Released unconditionally, not only when THIS pass installed a guard: a
        // previous pass may have retained one (its release failed, or the pod set
        // has since emptied), and that retained DROP must not outlive the rebuild
        // that fixed it. The release script tolerates absent chains and stays
        // strict about resource errors.
        if let Err(error) = self.backend.release_guard() {
            warn!(
                %error,
                "Host UDP capture: could not release the fail-closed guard; removing capture \
                 rules and retrying with enrolled egress still closed"
            );
            if let Err(cleanup_error) = self.backend.teardown_capture_rules() {
                warn!(
                    error = %cleanup_error,
                    "Host UDP capture: capture cleanup after guard-release failure did not complete"
                );
            }
            self.index.clear();
            self.applied = None;
            self.guard_active = true;
            return;
        }
        self.guard_active = false;

        // 9. Only now is each captured pod's egress genuinely going through the
        //    mesh, so publish its readiness marker and open the BPF gate.
        if let Some(ready_dir) = self.ready_dir.clone() {
            for binding in &desired.bindings {
                super::netns_udp_capture::write_udp_ready_marker(&ready_dir, &binding.pod_uid);
            }
        }
        self.published_ready = desired.bound_uids();

        info!(
            captured_pods = desired.bindings.len(),
            refused_pods = desired.refused.len(),
            "Host UDP capture reconciled"
        );
        self.applied = Some(desired);
    }

    fn retract_readiness(&mut self, pod_uid: &str) {
        if let Some(ready_dir) = &self.ready_dir {
            super::netns_udp_capture::remove_udp_ready_marker(ready_dir, pod_uid);
        }
        self.published_ready.remove(pod_uid);
    }

    /// Graceful shutdown: retract readiness, wait (bounded) for the node-agent to
    /// confirm the BPF gates are closed, then remove Ferrum-owned host state.
    ///
    /// If the acknowledgement does not arrive, the fail-closed guard is installed
    /// and only the capture rules are removed. That leaves the node dropping
    /// enrolled UDP egress instead of releasing it as plaintext while the
    /// node-agent still believes capture is live.
    pub async fn shutdown(&mut self) {
        let bound = self.published_ready.clone();
        let ifaces = self.guard_scope.clone();

        let acknowledged = if bound.is_empty() {
            true
        } else {
            self.request_gate_close(&bound).await
        };

        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
        self.index.clear();

        if acknowledged {
            if let Err(error) = self.backend.teardown_all() {
                warn!(%error, "Host UDP capture: shutdown teardown did not complete");
            }
            if let Some(ready_dir) = &self.ready_dir {
                super::netns_udp_capture::clear_udp_ack_requirement(ready_dir, &bound);
            }
            self.published_ready.clear();
        } else {
            warn!(
                pods = bound.len(),
                "Host UDP capture: node-agent did not acknowledge closing its UDP gates; \
                 retaining the fail-closed guard and removing only the capture rules"
            );
            if !ifaces.is_empty()
                && let Err(error) = self.backend.install_guard(&ifaces)
            {
                warn!(
                    %error,
                    "Host UDP capture: could not install the shutdown fail-closed guard; \
                     removing capture rules anyway (a socketless TPROXY jump is worse)"
                );
            }
            if let Err(error) = self.backend.teardown_capture_rules() {
                warn!(%error, "Host UDP capture: shutdown capture cleanup did not complete");
            }
        }
        self.applied = None;
        self.guard_active = false;
        self.guard_scope.clear();
    }

    async fn request_gate_close(&self, bound: &HashSet<String>) -> bool {
        let Some(ready_dir) = &self.ready_dir else {
            // No handshake configured: nothing gates this node's UDP egress on
            // our readiness marker, so there is no acknowledgement to await.
            return true;
        };
        if !super::netns_udp_capture::request_udp_gate_close(ready_dir, bound) {
            return false;
        }
        let deadline = Instant::now() + self.gate_close_timeout;
        loop {
            if self.gate_close_acknowledged(bound) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(GATE_CLOSE_ACK_POLL).await;
        }
    }

    fn gate_close_acknowledged(&self, bound: &HashSet<String>) -> bool {
        let Some(ready_dir) = &self.ready_dir else {
            return true;
        };
        let Some(registry_dir) = ready_dir.parent() else {
            return false;
        };
        let ack_dir = registry_dir.join(".udp-not-ready");
        bound.iter().all(|uid| {
            super::netns_udp_capture::udp_ready_marker_path(&ack_dir, uid)
                .is_some_and(|marker| marker.is_file())
        })
    }

    fn log_refusals(&mut self, desired: &HostUdpDesiredState) {
        for (pod_uid, reason) in &desired.refused {
            if self.logged_refusals.get(pod_uid) == Some(reason) {
                continue;
            }
            warn!(
                pod_uid = %pod_uid,
                reason = reason.as_str(),
                "Host UDP capture refused a pod; its UDP egress stays closed (the readiness \
                 marker is withheld) rather than bypassing the mesh"
            );
            self.logged_refusals.insert(pod_uid.clone(), *reason);
        }
        let still_refused: HashSet<&String> =
            desired.refused.iter().map(|(uid, _)| uid).collect();
        self.logged_refusals
            .retain(|uid, _| still_refused.contains(uid));
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Production backend
// ───────────────────────────────────────────────────────────────────────────

/// The production host capture backend: renders the plans from
/// `crate::capture`, runs them through `sh -c` in the process's OWN (host)
/// network namespace — no `setns` anywhere — and binds the transparent socket
/// here too.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ProxyHostUdpBackend {
    state: Arc<super::ProxyState>,
    capture_config: crate::capture::CaptureConfig,
    capture_port: u16,
    include_v6: bool,
    max_sessions: usize,
    cleanup_interval_seconds: u64,
    recvmmsg_batch_size: usize,
    session_shard_amount: usize,
    sysfs_net: PathBuf,
}

impl ProxyHostUdpBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: Arc<super::ProxyState>,
        capture_config: crate::capture::CaptureConfig,
        capture_port: u16,
        max_sessions: usize,
        cleanup_interval_seconds: u64,
        recvmmsg_batch_size: usize,
        session_shard_amount: usize,
    ) -> Self {
        let include_v6 = capture_config.ip6tables_mode != crate::capture::Ip6TablesMode::Disabled;
        Self {
            state,
            capture_config,
            capture_port,
            include_v6,
            max_sessions,
            cleanup_interval_seconds,
            recvmmsg_batch_size,
            session_shard_amount,
            sysfs_net: PathBuf::from("/sys/class/net"),
        }
    }

    /// Override the sysfs root used for interface-index lookups (tests).
    #[allow(dead_code)]
    pub fn with_sysfs_net(mut self, path: PathBuf) -> Self {
        self.sysfs_net = path;
        self
    }

    /// Read an interface's kernel index. The index is what every captured
    /// datagram is attributed by, so it is read from sysfs (authoritative) rather
    /// than derived from the name.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn ifindex_for(&self, name: &str) -> Result<u32, String> {
        crate::capture::validate_host_capture_interface(name)?;
        let path = self.sysfs_net.join(name).join("ifindex");
        let raw = std::fs::read_to_string(&path)
            .map_err(|error| format!("could not read {}: {error}", path.display()))?;
        raw.trim()
            .parse::<u32>()
            .map_err(|_| format!("{} does not contain an interface index", path.display()))
            .and_then(|index| {
                if index == 0 {
                    Err("interface index 0 is not a usable capture attribution key".to_string())
                } else {
                    Ok(index)
                }
            })
    }
}

#[cfg(target_os = "linux")]
impl HostUdpCaptureBackend for ProxyHostUdpBackend {
    fn resolve_interface(&self, target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        // Prefer the pod's own netns view (`iflink` → host peer index), which
        // identifies the veth peer directly. Fall back to the host route table
        // keyed on the registry-published pod IP, which needs neither `hostPID`
        // nor `setns` — that fallback is what lets this path run without the
        // per-pod-netns producer's elevated privileges.
        let name = crate::ebpf::veth::discover_veth_for_pod(None, Some(&target.cgroup_path))
            .or_else(|| {
                target
                    .source_ips
                    .ipv4
                    .and_then(crate::ebpf::veth::discover_veth_for_pod_ip)
            })
            .ok_or_else(|| "no host-side interface resolved for this pod".to_string())?;
        let ifindex = self.ifindex_for(&name)?;
        Ok(ResolvedInterface { name, ifindex })
    }

    fn install_guard(&self, ifaces: &[String]) -> Result<(), String> {
        let script = IptablesPlan::host_udp_guard_script(&self.capture_config, ifaces)?;
        if script.is_empty() {
            return Ok(());
        }
        run_host_script(&script)
    }

    fn install_capture(&self, ifaces: &[String]) -> Result<(), String> {
        let script = IptablesPlan::host_udp_setup_script(&self.capture_config, ifaces)?;
        run_host_script(&script)
    }

    fn teardown_capture_rules(&self) -> Result<(), String> {
        let script = IptablesPlan::host_udp_capture_rules_teardown_script(self.include_v6);
        run_host_script(&script)
    }

    fn release_guard(&self) -> Result<(), String> {
        run_host_script(&IptablesPlan::host_udp_guard_release_script())
    }

    fn teardown_all(&self) -> Result<(), String> {
        let script = IptablesPlan::host_udp_teardown_script(self.include_v6);
        run_host_script(&script)
    }

    fn start_listener(
        &self,
        index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String> {
        let wildcard = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let bind_addr = std::net::SocketAddr::new(wildcard, self.capture_port);
        // `true` requests the ingress-interface cmsg: on this shared socket the
        // interface index IS the identity key, so a bind that cannot report it
        // fails rather than serving unattributable datagrams.
        let (std_socket, bound_addr, v4_origdst, v6_origdst) =
            super::mesh_udp_capture::bind_mesh_udp_capture_socket_with_pktinfo(bind_addr, true)
                .map_err(|error| error.to_string())?;
        let frontend_socket =
            tokio::net::UdpSocket::from_std(std_socket).map_err(|error| error.to_string())?;
        let runtime = super::mesh_udp_capture::MeshUdpCaptureRuntime {
            state: self.state.clone(),
            cleanup_interval_seconds: self.cleanup_interval_seconds,
            recvmmsg_batch_size: self.recvmmsg_batch_size,
            session_shard_amount: self.session_shard_amount,
            session_limiter: Arc::new(super::mesh_udp_capture::MeshUdpSessionLimiter::new(
                self.max_sessions,
            )),
            source_identity: super::mesh_udp_capture::CapturedSourceEvidence::HostIngress(index),
            // The capture socket and its reply sockets must share a namespace.
            // Both live in the proxy's own (host) namespace here; a reply is
            // sourced from the captured VIP:port and reaches the pod over the
            // ordinary host route out its interface.
            reply_socket_factory: Arc::new(
                super::mesh_udp_capture::CurrentNetnsReplySocketFactory,
            ),
        };
        let (stop_tx, stop_rx) = watch::channel(false);
        info!(
            bound = %bound_addr,
            v4_origdst,
            v6_origdst,
            "Host UDP capture: transparent host-namespace capture socket bound"
        );
        let task = tokio::spawn(async move {
            let _ = super::mesh_udp_capture::run_mesh_udp_capture_on_socket(
                frontend_socket,
                bound_addr,
                v4_origdst,
                v6_origdst,
                runtime,
                stop_rx,
                None,
                None,
            )
            .await;
        });
        Ok(HostUdpListenerHandle::new(stop_tx, task))
    }
}

#[cfg(not(target_os = "linux"))]
impl HostUdpCaptureBackend for ProxyHostUdpBackend {
    fn resolve_interface(&self, _target: &PodCaptureTarget) -> Result<ResolvedInterface, String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn install_guard(&self, _ifaces: &[String]) -> Result<(), String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn install_capture(&self, _ifaces: &[String]) -> Result<(), String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }

    fn teardown_capture_rules(&self) -> Result<(), String> {
        Ok(())
    }

    fn release_guard(&self) -> Result<(), String> {
        Ok(())
    }

    fn teardown_all(&self) -> Result<(), String> {
        Ok(())
    }

    fn start_listener(
        &self,
        _index: Arc<HostUdpIdentityIndex>,
    ) -> Result<HostUdpListenerHandle, String> {
        Err("host-network UDP capture is Linux-only".to_string())
    }
}

/// Best-effort removal of every Ferrum-owned host-netns UDP object, for the
/// deployments that are NOT running the host capture path.
///
/// A node that once ran host capture and now runs the pod-netns producer (or has
/// UDP capture switched off entirely) would otherwise keep a `PREROUTING` jump
/// into a chain whose socket nobody binds — captured egress diverted into a black
/// hole, with nothing left to reap it, because both the shutdown teardown and the
/// setup path are owned by a code path that no longer runs. This is the same
/// unconditional pre-setup reap the node-agent performs for the pod-netns UDP
/// objects, applied to the host-netns ones.
///
/// Every command targets an exact Ferrum-owned object and is best-effort, so it
/// is a no-op when no host state exists.
pub fn reap_stale_host_udp_state(include_v6: bool) {
    if !cfg!(target_os = "linux") {
        return;
    }
    let script = IptablesPlan::host_udp_teardown_script(include_v6);
    if let Err(error) = run_host_script(&script) {
        debug!(
            %error,
            "Host UDP capture: stale host-namespace UDP state reap did not complete (expected \
             when no host capture state exists)"
        );
    }
}

/// Run one capture script in the process's own network namespace.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn run_host_script(script: &str) -> Result<(), String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|error| format!("could not run the host capture script: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    // Only the script's own diagnostics are surfaced, bounded in length. The
    // script text itself is not echoed: it embeds the node's capture scope and
    // would be noisy without adding diagnostic value.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail: String = stderr.trim().chars().take(512).collect();
    Err(format!(
        "host capture script failed with status {}: {detail}",
        output.status
    ))
}
