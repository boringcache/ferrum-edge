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
//! Two lifecycle rules keep a POD LEAVING capture from becoming a plaintext
//! window:
//!
//! * The guard's scope is the UNION of the interfaces the new generation
//!   captures and the interfaces of pods that still owe a transition, and a
//!   removed pod's capture rule is not rebuilt away until the node-agent
//!   acknowledges (over the durable `.udp-ack-required` → `.udp-not-ready`
//!   handshake) that it closed that pod's BPF gate. Removing a readiness marker
//!   does not close that gate synchronously.
//! * A removal, refusal, or attribution change stops the shared capture loop
//!   before the next evidence generation goes live, because an already-admitted
//!   session keeps its own [`UdpSourceIdentity`] and its transparent reply
//!   socket. A pure addition disturbs nothing and does not restart it.
//!
//! The capture loop is supervised: every reconcile checks whether it exited on
//! its own and, if it did, guards the datapath and restarts it rather than
//! leaving a published-ready node black-holing captured traffic.
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

/// How long ONE reconcile pass waits for a departing pod's gate-close
/// acknowledgement before leaving the protective guard up and retrying on the
/// next poll. Deliberately shorter than the shutdown budget: the reconcile loop
/// retries anyway, so a stalled node-agent must not stall reconciliation for
/// every other pod on the node. Waiting longer would not change the posture —
/// the departing pod's rules and guard are retained either way.
const RECONCILE_GATE_CLOSE_ACK_WAIT: Duration = Duration::from_secs(1);

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
    /// change (it is handled by [`Self::requires_listener_restart_from`], which
    /// is the stronger, listener-restarting condition).
    pub fn rules_differ_from(&self, other: &Self) -> bool {
        self.ifaces() != other.ifaces()
    }

    /// Whether the running capture loop must be stopped before this state
    /// becomes live. Two cases, and both leave an already-admitted session
    /// relaying under evidence this generation no longer vouches for:
    ///
    /// * An interface's ATTRIBUTION changed — a different pod, identity, or
    ///   source-address set behind the same interface.
    /// * A binding was REMOVED: the pod left the registry, became refused, or
    ///   moved to another interface. Per-datagram authorization stops new and
    ///   refreshed traffic the moment the next index generation is published,
    ///   but a session admitted earlier keeps its old [`UdpSourceIdentity`] and
    ///   its transparent reply socket, so a one-way return stream could keep
    ///   sending to a removed — or recycled — pod address until it idles out.
    ///
    /// A pure ADDITION is not a restart: no existing session's evidence changes,
    /// so the live sessions of the pods that stayed are left undisturbed.
    pub fn requires_listener_restart_from(&self, other: &Self) -> bool {
        let current: HashMap<&str, &HostUdpPodBinding> = self
            .bindings
            .iter()
            .map(|b| (b.iface.as_str(), b))
            .collect();
        other.bindings.iter().any(|prior| {
            current
                .get(prior.iface.as_str())
                .is_none_or(|binding| *binding != prior)
        })
    }

    /// Captured pod UID to the interface its capture rule is scoped to.
    fn bound_ifaces(&self) -> HashMap<String, String> {
        self.bindings
            .iter()
            .map(|binding| (binding.pod_uid.clone(), binding.iface.clone()))
            .collect()
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
    let mut iface_claims: HashMap<String, usize> = HashMap::new();
    let mut index_claims: HashMap<u32, usize> = HashMap::new();
    for binding in &candidates {
        *iface_claims.entry(binding.iface.clone()).or_insert(0) += 1;
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

    /// Whether the capture loop this handle owns has already returned. The
    /// manager polls it every reconcile: a loop that exits on its own is
    /// otherwise invisible (the handle stays `Some`), and the datapath would keep
    /// steering enrolled egress into a socket nobody reads. A handle carrying no
    /// task cannot exit on its own, so it is never reported as finished.
    fn is_finished(&self) -> bool {
        self.task.as_ref().is_some_and(|task| task.is_finished())
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
    /// Pods whose readiness marker this process published and has not retracted,
    /// mapped to the interface their capture rule is scoped to.
    ///
    /// This — NOT `applied` — is what shutdown and retraction key on. A failed
    /// apply clears `applied` while the node-agent's UDP gate is still open for
    /// those pods (their egress is held by the retained DROP guard), so keying
    /// teardown on `applied` would let shutdown conclude "nothing was ready",
    /// remove the guard, and release their egress in plaintext. The interface is
    /// carried alongside the UID because it is what a protective guard has to be
    /// scoped to once the pod is gone from the desired state.
    published_ready: HashMap<String, String>,
    /// Pods whose durable `.udp-ack-required` gate-close handshake this process
    /// has issued and whose `.udp-not-ready` acknowledgement has not arrived,
    /// mapped to the interface that must stay guarded until it does.
    ///
    /// Removing a readiness marker does NOT synchronously close the node-agent's
    /// BPF UDP gate, so a removed pod's capture rule may not disappear until the
    /// close is acknowledged — otherwise its egress leaves the node in plaintext
    /// for as long as the node-agent takes to notice. Reconcile keeps these pods
    /// inside the DROP guard's scope and refuses to rebuild the chain until the
    /// set drains.
    awaiting_gate_close: HashMap<String, String>,
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
            published_ready: HashMap::new(),
            awaiting_gate_close: HashMap::new(),
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
        self.supervise_listener().await;
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
        let restart_required = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.requires_listener_restart_from(applied));
        let listener_needed = !desired.bindings.is_empty();
        let listener_missing = listener_needed && self.listener.is_none();
        // A pod whose gate close is not yet acknowledged still owes this manager
        // a transition, so its poll can never be a no-op no matter how stable the
        // desired state looks.
        let gate_close_pending = !self.awaiting_gate_close.is_empty();

        // Nothing enrolled and nothing installed: install no chain, no jump, and
        // no routing. A node with no mesh-enrolled pods keeps a completely
        // untouched datapath.
        if desired.bindings.is_empty()
            && self.applied.is_none()
            && self.listener.is_none()
            && !self.guard_active
            && !gate_close_pending
            && self.published_ready.is_empty()
        {
            return &self.last_desired;
        }
        if !rules_changed
            && !restart_required
            && !listener_missing
            && !self.guard_active
            && !gate_close_pending
        {
            return &self.last_desired;
        }

        self.apply(desired).await;
        &self.last_desired
    }

    /// Detect a capture loop that returned on its own — a socket error, a bind
    /// that died under it, a panicked task.
    ///
    /// Nothing else notices: the handle stays `Some`, so no poll sees a missing
    /// listener, the ruleset keeps steering every enrolled pod's egress into a
    /// socket nobody reads, and readiness stays published. Clearing `applied`
    /// forces the next apply, which reinstalls the guard, rebuilds the chain, and
    /// restarts the loop through the ordinary guarded path. An operator-requested
    /// stop consumes the handle (both [`Self::shutdown`] and [`Self::apply`]
    /// `take()` it before stopping), so this can only ever observe an UNEXPECTED
    /// exit — a requested shutdown is never turned into a restart.
    async fn supervise_listener(&mut self) {
        if !self
            .listener
            .as_ref()
            .is_some_and(HostUdpListenerHandle::is_finished)
        {
            return;
        }
        warn!(
            "Host UDP capture: the transparent capture loop exited unexpectedly; guarding the \
             datapath and restarting it"
        );
        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
        // Stale evidence and the claim to a live ruleset both go: a late datagram
        // must not be attributed by a socket that is gone, and the next apply has
        // to rebuild from the guarded posture rather than short-circuit.
        self.index.clear();
        self.applied = None;
    }

    async fn apply(&mut self, desired: HostUdpDesiredState) {
        let ifaces = desired.ifaces();
        let now_bound = desired.bound_uids();

        // 1. Guard first, scoped to the UNION of what this generation captures
        //    and what still owes a transition (pods whose readiness this process
        //    published, pods awaiting a gate-close acknowledgement, and the scope
        //    the last guard was installed with). A desired-only guard would leave
        //    a removed pod's interface unprotected exactly while its capture rule
        //    is being rebuilt away. Enrolled egress is dropped for the duration of
        //    the rebuild rather than briefly escaping capture. A guard failure
        //    keeps the previous live ruleset (still correct for the pods it
        //    covers) and retries next poll; it must NOT proceed to flush the
        //    capture chain, because that would open the very window the guard
        //    exists to close.
        let guard_ifaces = self.guard_scope_for(&ifaces);
        if !guard_ifaces.is_empty() {
            if let Err(error) = self.backend.install_guard(&guard_ifaces) {
                warn!(
                    %error,
                    interfaces = guard_ifaces.len(),
                    "Host UDP capture: fail-closed guard install failed; keeping the previous \
                     ruleset and retrying"
                );
                return;
            }
            self.guard_active = true;
            self.guard_scope = guard_ifaces;
        }

        // 2. A restart-requiring change cannot be absorbed by a running loop: its
        //    admitted sessions still carry the previous evidence, and a removed
        //    pod's session still holds a transparent reply socket. Stop the loop
        //    (which drains and cancels its sessions) before republishing.
        let restart_required = self
            .applied
            .as_ref()
            .is_some_and(|applied| desired.requires_listener_restart_from(applied));
        if restart_required && let Some(listener) = self.listener.take() {
            info!(
                "Host UDP capture: a captured pod's attribution changed or was withdrawn; \
                 restarting the capture listener so no session keeps relaying under the previous \
                 evidence"
            );
            listener.stop().await;
            self.index.clear();
        }

        // 3. Retire the pods this generation drops through the DURABLE node-agent
        //    handshake before any rule of theirs can disappear. Removing a
        //    readiness marker does not synchronously close the node-agent's BPF
        //    gate, so an unacknowledged close plus a rebuilt chain is exactly the
        //    window in which a removed pod's UDP egress leaves the node in
        //    plaintext. Their interfaces stay inside the guard installed above
        //    until the acknowledgement lands, so waiting costs availability for
        //    the pods being retired, never confidentiality.
        self.cancel_gate_close_for_returning(&now_bound);
        let leaving: Vec<(String, String)> = self
            .published_ready
            .iter()
            .filter(|(uid, _)| !now_bound.contains(*uid))
            .map(|(uid, iface)| (uid.clone(), iface.clone()))
            .collect();
        let requested = self.begin_gate_close(&leaving);
        let budget = self.gate_close_timeout.min(RECONCILE_GATE_CLOSE_ACK_WAIT);
        let acknowledged = self.await_gate_close(budget).await;
        if !requested || !acknowledged {
            // Fail closed and retry: the guard installed above stays up, the live
            // ruleset is left alone, and nothing this pass would have removed is
            // removed.
            return;
        }

        // 4. Rebuild the capture chain. An empty interface set renders no rules
        //    at all (the generator refuses to emit an empty ruleset), so the
        //    chain contents are removed instead; the `PREROUTING` jump and the
        //    guard both stay until step 8.
        let rebuilt = if ifaces.is_empty() {
            self.backend.teardown_capture_rules()
        } else {
            self.backend.install_capture(&ifaces)
        };
        if let Err(error) = rebuilt {
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
            // The previously applied ruleset is gone, so do not keep claiming it
            // or leave sessions from that now-untracked generation alive. If the
            // listener survived while `applied` became `None`, a later removal
            // could not detect that it must restart the listener, and an admitted
            // session could keep its stale identity / transparent reply socket.
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
            }
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
        if desired.bindings.is_empty()
            && let Some(listener) = self.listener.take()
        {
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
            // Keep the listener generation and `applied` generation coupled on
            // every failure path. The guard remains fail-closed and the capture
            // rules are gone, so preserving live sessions provides no availability
            // benefit and would make their evidence impossible to compare during
            // the next withdrawal.
            if let Some(listener) = self.listener.take() {
                listener.stop().await;
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
        self.published_ready = desired.bound_ifaces();
        // Every retirement this pass owed is acknowledged (step 3 returned
        // otherwise), so the protective scope narrows back to what is captured.
        self.guard_scope = ifaces;

        info!(
            captured_pods = desired.bindings.len(),
            refused_pods = desired.refused.len(),
            "Host UDP capture reconciled"
        );
        self.applied = Some(desired);
    }

    /// The interface set the fail-closed guard must cover for one transition:
    /// what the new generation captures, plus every interface still carrying an
    /// obligation — a pod whose readiness this process published (the node-agent
    /// may still have its BPF gate open) or one awaiting a gate-close
    /// acknowledgement — plus whatever the last guard was scoped to (a failed
    /// apply clears `applied`, so it is the only remaining record of what an
    /// earlier pass protected).
    fn guard_scope_for(&self, desired: &[String]) -> Vec<String> {
        let mut scope: Vec<String> = desired.to_vec();
        for iface in self
            .published_ready
            .values()
            .chain(self.awaiting_gate_close.values())
            .chain(self.guard_scope.iter())
        {
            if !scope.contains(iface) {
                scope.push(iface.clone());
            }
        }
        // The generator refuses duplicates and the rendered ruleset should not
        // depend on map iteration order.
        scope.sort();
        scope.dedup();
        scope
    }

    /// A pod that re-entered capture is owned by the ordinary apply path again:
    /// this pass republishes its readiness once capture is live, so its pending
    /// handshake is cancelled rather than awaited. Awaiting it would stall every
    /// reconcile on an acknowledgement the node-agent has no reason to send.
    fn cancel_gate_close_for_returning(&mut self, bound: &HashSet<String>) {
        let returning: Vec<String> = self
            .awaiting_gate_close
            .keys()
            .filter(|uid| bound.contains(*uid))
            .cloned()
            .collect();
        for pod_uid in returning {
            self.clear_gate_close_requirement(&pod_uid);
            self.awaiting_gate_close.remove(&pod_uid);
        }
    }

    /// Start (or continue) the durable gate-close handshake for pods leaving
    /// capture. `false` means at least one requirement could not be persisted, so
    /// the caller must stay fail-closed: that pod keeps its published readiness,
    /// its interface stays in the guard scope, and no rule of its is removed.
    ///
    /// A pod already awaiting an acknowledgement is deliberately NOT re-requested.
    /// [`request_udp_gate_close`](super::netns_udp_capture::request_udp_gate_close)
    /// deletes any `.udp-not-ready` ack before retracting readiness — so a stale
    /// ack can never authorize a new handoff — and reissuing it every poll would
    /// delete the very acknowledgement this manager is waiting for.
    fn begin_gate_close(&mut self, leaving: &[(String, String)]) -> bool {
        let mut requested = true;
        for (pod_uid, iface) in leaving {
            if self.awaiting_gate_close.contains_key(pod_uid) {
                continue;
            }
            let Some(ready_dir) = self.ready_dir.clone() else {
                // No handshake directory: nothing gates this pod's UDP egress on
                // our readiness marker, so there is no acknowledgement to await.
                self.published_ready.remove(pod_uid);
                continue;
            };
            let one: HashSet<String> = std::iter::once(pod_uid.clone()).collect();
            if super::netns_udp_capture::request_udp_gate_close(&ready_dir, &one) {
                self.awaiting_gate_close
                    .insert(pod_uid.clone(), iface.clone());
            } else {
                warn!(
                    pod_uid = %pod_uid,
                    "Host UDP capture: could not persist the UDP gate-close handshake for a pod \
                     leaving capture; its fail-closed guard and capture rule are retained until \
                     it succeeds"
                );
                requested = false;
            }
        }
        requested
    }

    /// Wait (bounded by `budget`) for the node-agent to acknowledge every
    /// outstanding gate close. Each pod is retired individually the moment its
    /// `.udp-not-ready` marker appears — that marker is the proof its BPF gate is
    /// shut, and it is the only thing that makes clearing the durable requirement
    /// safe.
    async fn await_gate_close(&mut self, budget: Duration) -> bool {
        if self.awaiting_gate_close.is_empty() {
            return true;
        }
        let deadline = Instant::now() + budget;
        loop {
            self.reap_acknowledged_gate_closes();
            if self.awaiting_gate_close.is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                warn!(
                    pods = self.awaiting_gate_close.len(),
                    "Host UDP capture: the node-agent did not acknowledge closing its UDP gate \
                     for pods leaving capture; retaining their fail-closed guard and their \
                     capture rules, and retrying"
                );
                return false;
            }
            tokio::time::sleep(GATE_CLOSE_ACK_POLL).await;
        }
    }

    fn reap_acknowledged_gate_closes(&mut self) {
        let acknowledged: Vec<String> = self
            .awaiting_gate_close
            .keys()
            .filter(|pod_uid| self.gate_close_acknowledged(pod_uid.as_str()))
            .cloned()
            .collect();
        for pod_uid in acknowledged {
            self.clear_gate_close_requirement(&pod_uid);
            self.awaiting_gate_close.remove(&pod_uid);
            self.published_ready.remove(&pod_uid);
        }
    }

    fn clear_gate_close_requirement(&self, pod_uid: &str) {
        if let Some(ready_dir) = &self.ready_dir {
            let one: HashSet<String> = std::iter::once(pod_uid.to_string()).collect();
            super::netns_udp_capture::clear_udp_ack_requirement(ready_dir, &one);
        }
    }

    /// Graceful shutdown: retract readiness, wait (bounded) for the node-agent to
    /// confirm the BPF gates are closed, then remove Ferrum-owned host state.
    ///
    /// If the acknowledgement does not arrive, the fail-closed guard is installed
    /// and only the capture rules are removed. That leaves the node dropping
    /// enrolled UDP egress instead of releasing it as plaintext while the
    /// node-agent still believes capture is live.
    pub async fn shutdown(&mut self) {
        // Every pod this process ever published readiness for, INCLUDING the ones
        // a reconcile already moved onto the handshake but could not retire: both
        // still owe an acknowledgement, and both still need guard coverage.
        let leaving: Vec<(String, String)> = self
            .published_ready
            .iter()
            .map(|(uid, iface)| (uid.clone(), iface.clone()))
            .collect();
        let ifaces = self.guard_scope_for(&[]);
        // A pod awaiting an acknowledgement is still published, so this is the
        // whole set, not a subset of it.
        let pods = leaving.len();

        let budget = self.gate_close_timeout;
        let requested = self.begin_gate_close(&leaving);
        let acknowledged = requested && self.await_gate_close(budget).await;

        if let Some(listener) = self.listener.take() {
            listener.stop().await;
        }
        self.index.clear();

        if acknowledged {
            if let Err(error) = self.backend.teardown_all() {
                warn!(%error, "Host UDP capture: shutdown teardown did not complete");
            }
            self.published_ready.clear();
        } else {
            warn!(
                pods,
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

    /// Whether the node-agent published the durable `.udp-not-ready` marker that
    /// proves this pod's BPF UDP gate is shut. Without a handshake directory
    /// nothing gated the pod on our readiness marker in the first place.
    fn gate_close_acknowledged(&self, pod_uid: &str) -> bool {
        let Some(ready_dir) = &self.ready_dir else {
            return true;
        };
        let Some(registry_dir) = ready_dir.parent() else {
            return false;
        };
        let ack_dir = registry_dir.join(".udp-not-ready");
        super::netns_udp_capture::udp_ready_marker_path(&ack_dir, pod_uid)
            .is_some_and(|marker| marker.is_file())
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
        let still_refused: HashSet<&String> = desired.refused.iter().map(|(uid, _)| uid).collect();
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
            reply_socket_factory: Arc::new(super::mesh_udp_capture::CurrentNetnsReplySocketFactory),
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
