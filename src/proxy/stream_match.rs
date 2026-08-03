//! Precomputed VirtualService L4 (`tcp[]` / `tls[]`) match predicates.
//!
//! Cold-path translation admits `sourceLabels`, `sourceSubnets`,
//! `destinationSubnets`, `gateways`, and `sourceNamespace` onto a stream
//! [`Proxy`](crate::config::types::Proxy) as [`StreamMatchCriteria`]. Config
//! normalization compiles that carrier into [`CompiledStreamMatch`] so the
//! TCP/TLS accept path can evaluate AND-within-arm / OR-across-arms semantics
//! without allocating or re-parsing CIDRs, labels, or gateway names.
//!
//! Evidence always comes from trustworthy connection / workload metadata
//! (socket peer, `SO_ORIGINAL_DST`, peer SPIFFE, slice workload labels, and the
//! listener's configured gateway binding). Missing evidence denies any
//! predicate that requires it — never match by absence or client-controlled
//! headers.

use crate::config::types::validate_namespace;
use crate::identity::spiffe::SpiffeId;
use crate::util::cidr::CidrSet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Reserved Istio gateway token meaning "apply on the mesh / sidecar".
pub const MESH_GATEWAY_TOKEN: &str = "mesh";

/// Serializable L4 match carrier stored on a stream [`Proxy`](crate::config::types::Proxy).
///
/// An empty `arms` list means "no additional L4 predicates" (port / SNI alone).
/// Non-empty `arms` are OR'd; predicates inside one arm are AND'd. This mirrors
/// Istio `match[]` within one `tcp[]`/`tls[]` route block when multiple matches
/// collapse onto the same listen port (and SNI for TLS).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMatchCriteria {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arms: Vec<StreamMatchArm>,
}

/// One AND-combined L4 match arm (one Istio `L4MatchAttributes` object).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMatchArm {
    /// Exact source-workload label subset. Empty = unconstrained.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub source_labels: BTreeMap<String, String>,
    /// Exact source namespace (SPIFFE `ns/<ns>/…`). `None` = unconstrained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_namespace: Option<String>,
    /// Source IP CIDRs (Istio `sourceSubnets`). Empty = unconstrained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_subnets: Vec<String>,
    /// Destination IP CIDRs (Istio `destinationSubnets`). Empty = unconstrained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_subnets: Vec<String>,
    /// Effective gateway names for this arm (`mesh` and/or `ns/name`).
    /// Empty = unconstrained (caller already resolved inheritance).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateways: Vec<String>,
}

impl StreamMatchCriteria {
    /// True when no L4 predicate arms are configured.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.arms.is_empty()
    }

    /// Compile into the allocation-free hot-path matcher. Fails closed on any
    /// unrepresentable CIDR / empty gateway token that slipped past admission.
    pub fn compile(&self) -> Result<CompiledStreamMatch, String> {
        let mut arms = Vec::with_capacity(self.arms.len());
        for (index, arm) in self.arms.iter().enumerate() {
            arms.push(
                arm.compile()
                    .map_err(|e| format!("stream_match.arms[{index}]: {e}"))?,
            );
        }
        Ok(CompiledStreamMatch { arms })
    }
}

impl StreamMatchArm {
    fn compile(&self) -> Result<CompiledStreamMatchArm, String> {
        let source_subnets = compile_cidr_list(&self.source_subnets, "source_subnets")?;
        let destination_subnets =
            compile_cidr_list(&self.destination_subnets, "destination_subnets")?;
        for gateway in &self.gateways {
            if gateway.is_empty() {
                return Err("gateways entry must not be empty".to_string());
            }
        }
        // Labels / namespace are validated at translation; re-check empties so a
        // hand-authored Proxy cannot widen by omission.
        if self
            .source_labels
            .keys()
            .any(|k| k.is_empty() || k.chars().all(char::is_whitespace))
        {
            return Err("source_labels keys must be non-empty".to_string());
        }
        if let Some(ns) = self.source_namespace.as_deref() {
            validate_namespace(ns).map_err(|e| format!("source_namespace: {e}"))?;
        }
        Ok(CompiledStreamMatchArm {
            source_labels: self.source_labels.clone(),
            source_namespace: self.source_namespace.clone(),
            source_subnets,
            destination_subnets,
            gateways: self.gateways.clone(),
            requires_source_labels: !self.source_labels.is_empty(),
            requires_source_namespace: self.source_namespace.is_some(),
            requires_source_ip: !self.source_subnets.is_empty(),
            requires_destination_ip: !self.destination_subnets.is_empty(),
            requires_gateway: !self.gateways.is_empty(),
        })
    }
}

fn compile_cidr_list(entries: &[String], field: &str) -> Result<CidrSet, String> {
    if entries.is_empty() {
        return Ok(CidrSet::default());
    }
    // Join with commas so we reuse the shared strict parser (IPv4-mapped
    // folding included). Reject empty segments explicitly for field diagnostics.
    for (i, entry) in entries.iter().enumerate() {
        if entry.trim().is_empty() {
            return Err(format!("{field}[{i}] must be a non-empty CIDR or IP"));
        }
    }
    CidrSet::parse_strict(&entries.join(",")).map_err(|e| format!("{field}: {e}"))
}

/// Hot-path matcher compiled at config load / normalize time.
#[derive(Debug, Clone, Default)]
pub struct CompiledStreamMatch {
    arms: Vec<CompiledStreamMatchArm>,
}

#[derive(Debug, Clone)]
struct CompiledStreamMatchArm {
    source_labels: BTreeMap<String, String>,
    source_namespace: Option<String>,
    source_subnets: CidrSet,
    destination_subnets: CidrSet,
    gateways: Vec<String>,
    requires_source_labels: bool,
    requires_source_namespace: bool,
    requires_source_ip: bool,
    requires_destination_ip: bool,
    requires_gateway: bool,
}

impl CompiledStreamMatch {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.arms.is_empty()
    }

    /// Evaluate OR-across-arms against trustworthy connection evidence.
    ///
    /// Returns `true` when there are no arms (unconstrained) or when any arm
    /// matches. Missing evidence required by an arm causes that arm to fail;
    /// it never succeeds by absence.
    #[inline]
    pub fn matches(&self, evidence: &StreamMatchEvidence<'_>) -> bool {
        if self.arms.is_empty() {
            return true;
        }
        self.arms.iter().any(|arm| arm.matches(evidence))
    }
}

/// Pick the first candidate whose compiled stream_match accepts `evidence`.
/// Candidates with no configured matcher are treated as unconstrained; a
/// configured-but-uncompiled matcher fails the whole shared group closed.
/// Order is the caller-supplied candidate order (Istio first-match-wins).
pub fn resolve_proxy_by_stream_match_in_epoch(
    candidates: &[crate::config::db_backend::NamespacedResourceId],
    evidence: &StreamMatchEvidence<'_>,
    epoch: &crate::request_epoch::RequestEpoch,
) -> Option<crate::config::db_backend::NamespacedResourceId> {
    if has_configured_but_uncompiled_candidate(candidates, epoch) {
        return None;
    }
    for id in candidates {
        let Some(proxy) = epoch.proxy_by_namespaced_id(&id.namespace, &id.id) else {
            continue;
        };
        match proxy.compiled_stream_match.as_ref() {
            // Unconstrained proxy (no stream_match configured).
            None if proxy
                .stream_match
                .as_ref()
                .map(|m| m.is_empty())
                .unwrap_or(true) =>
            {
                return Some(id.clone());
            }
            // Configured but uncompiled = fail closed.
            None => continue,
            Some(matcher) if matcher.matches(evidence) => return Some(id.clone()),
            Some(_) => continue,
        }
    }
    None
}

/// Resolve among shared-port candidates using SNI (when `use_sni`) and/or
/// stream_match evidence. Preserves Istio first-match-wins ordering.
pub fn resolve_shared_stream_proxy_in_epoch(
    sni: Option<&str>,
    candidates: &[crate::config::db_backend::NamespacedResourceId],
    evidence: &StreamMatchEvidence<'_>,
    epoch: &crate::request_epoch::RequestEpoch,
    use_sni: bool,
) -> Option<crate::config::db_backend::NamespacedResourceId> {
    if use_sni {
        if has_configured_but_uncompiled_candidate(candidates, epoch) {
            return None;
        }
        // Mirror SNI priority: exact, then wildcard, then catch-all — but only
        // among candidates that also satisfy stream_match.
        let mut exact: Option<crate::config::db_backend::NamespacedResourceId> = None;
        let mut wildcard: Option<crate::config::db_backend::NamespacedResourceId> = None;
        let mut catch_all: Option<crate::config::db_backend::NamespacedResourceId> = None;
        for id in candidates {
            let Some(proxy) = epoch.proxy_by_namespaced_id(&id.namespace, &id.id) else {
                continue;
            };
            let configured = proxy.stream_match.as_ref().is_some_and(|c| !c.is_empty());
            if configured {
                match proxy.compiled_stream_match.as_ref() {
                    Some(matcher) if matcher.matches(evidence) => {}
                    // Missing compiled form or non-match → skip candidate.
                    _ => continue,
                }
            } else if proxy
                .compiled_stream_match
                .as_ref()
                .is_some_and(|m| !m.matches(evidence))
            {
                continue;
            }
            if proxy.hosts.is_empty() {
                if catch_all.is_none() {
                    catch_all = Some(id.clone());
                }
                continue;
            }
            let Some(hostname) = sni else {
                continue;
            };
            let mut matched_exact = false;
            let mut matched_wild = false;
            for host in &proxy.hosts {
                if host == hostname {
                    matched_exact = true;
                    break;
                }
                if crate::config::types::wildcard_matches(host, hostname) {
                    matched_wild = true;
                }
            }
            if matched_exact {
                exact = Some(id.clone());
                break;
            }
            if matched_wild && wildcard.is_none() {
                wildcard = Some(id.clone());
            }
        }
        exact.or(wildcard).or(catch_all)
    } else {
        resolve_proxy_by_stream_match_in_epoch(candidates, evidence, epoch)
    }
}

fn has_configured_but_uncompiled_candidate(
    candidates: &[crate::config::db_backend::NamespacedResourceId],
    epoch: &crate::request_epoch::RequestEpoch,
) -> bool {
    candidates.iter().any(|id| {
        epoch
            .proxy_by_namespaced_id(&id.namespace, &id.id)
            .is_some_and(|proxy| {
                proxy
                    .stream_match
                    .as_ref()
                    .is_some_and(|criteria| !criteria.is_empty())
                    && proxy.compiled_stream_match.is_none()
            })
    })
}

impl CompiledStreamMatchArm {
    fn matches(&self, evidence: &StreamMatchEvidence<'_>) -> bool {
        if self.requires_source_labels {
            let Some(labels) = evidence.source_labels else {
                return false;
            };
            if !self
                .source_labels
                .iter()
                .all(|(k, v)| labels.get(k.as_str()) == Some(v.as_str()))
            {
                return false;
            }
        }
        if self.requires_source_namespace {
            let Some(expected) = self.source_namespace.as_deref() else {
                return false;
            };
            let Some(actual) = evidence.source_namespace else {
                return false;
            };
            if actual != expected {
                return false;
            }
        }
        if self.requires_source_ip {
            let Some(ip) = evidence.source_ip else {
                return false;
            };
            if !self.source_subnets.contains(&ip) {
                return false;
            }
        }
        if self.requires_destination_ip {
            let Some(ip) = evidence.destination_ip else {
                return false;
            };
            if !self.destination_subnets.contains(&ip) {
                return false;
            }
        }
        if self.requires_gateway {
            let Some(binding) = evidence.trusted_gateway_ref else {
                return false;
            };
            if !self
                .gateways
                .iter()
                .any(|g| gateway_names_equal(g, binding))
            {
                return false;
            }
        }
        true
    }
}

/// Trustworthy connection / workload evidence for L4 match evaluation.
///
/// All fields are optional; predicates that need a missing field deny.
///
/// Manual [`Debug`]: `&dyn SourceLabelLookup` is not `Debug`, and deriving
/// would force an object-safe `Debug` supertrait on every label map.
#[derive(Clone, Copy, Default)]
pub struct StreamMatchEvidence<'a> {
    /// Socket-peer / direct client IP (`source.ip`). Never from client headers.
    pub source_ip: Option<IpAddr>,
    /// Original destination IP (`SO_ORIGINAL_DST` / capture metadata).
    pub destination_ip: Option<IpAddr>,
    /// Source workload namespace from peer SPIFFE (`ns/<ns>/…`).
    pub source_namespace: Option<&'a str>,
    /// Source workload labels from the mesh slice / local workload inventory.
    pub source_labels: Option<&'a dyn SourceLabelLookup>,
    /// Listener-configured gateway binding (`mesh` or `namespace/name`).
    /// Never inferred from untrusted wire data.
    pub trusted_gateway_ref: Option<&'a str>,
}

impl std::fmt::Debug for StreamMatchEvidence<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamMatchEvidence")
            .field("source_ip", &self.source_ip)
            .field("destination_ip", &self.destination_ip)
            .field("source_namespace", &self.source_namespace)
            .field(
                "source_labels",
                &self.source_labels.map(|_| "<SourceLabelLookup>"),
            )
            .field("trusted_gateway_ref", &self.trusted_gateway_ref)
            .finish()
    }
}

/// Label lookup used by `sourceLabels` matching without forcing a concrete map
/// type on the hot path.
pub trait SourceLabelLookup {
    fn get(&self, key: &str) -> Option<&str>;
}

impl SourceLabelLookup for BTreeMap<String, String> {
    #[inline]
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl SourceLabelLookup for std::collections::HashMap<String, String> {
    #[inline]
    fn get(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

/// Resolve source-label evidence without borrowing labels from an arbitrary
/// same-service-account workload.
///
/// An exact NodeWaypoint policy scope wins because it was derived from the
/// eBPF-resolved pod UID in the same slice generation as the authenticated
/// identity. Otherwise a canonical source IP narrows same-SPIFFE workloads by
/// their declared addresses. If ambiguity remains, labels are usable only when
/// every remaining candidate has an identical label map; divergent replicas
/// fail closed.
pub fn trustworthy_source_labels<'a>(
    workloads: &'a [crate::modes::mesh::config::Workload],
    peer_spiffe: &str,
    source_ip: Option<IpAddr>,
    exact_node_waypoint_scope: Option<&'a crate::modes::mesh::runtime::PolicyScopeCache>,
) -> Option<&'a std::collections::HashMap<String, String>> {
    if let Some(scope) = exact_node_waypoint_scope {
        return (scope.spiffe_id.as_str() == peer_spiffe).then_some(&scope.labels);
    }

    let canonical_source_ip = source_ip.map(crate::util::client_identity::canonical_ip);
    if let Some(source_ip) = canonical_source_ip {
        let by_address = workloads.iter().filter(|workload| {
            workload.spiffe_id.as_str() == peer_spiffe
                && workload.addresses.iter().any(|address| {
                    parse_workload_ip(address).is_some_and(|candidate| candidate == source_ip)
                })
        });
        if let Some(labels) = identical_candidate_labels(by_address) {
            return Some(labels);
        }
    }

    // The authenticated SPIFFE ID is trustworthy but may identify several
    // replicas. Ambiguity is harmless only when every such workload proves the
    // exact same labels; otherwise sourceLabels must deny.
    identical_candidate_labels(
        workloads
            .iter()
            .filter(|workload| workload.spiffe_id.as_str() == peer_spiffe),
    )
}

fn identical_candidate_labels<'a>(
    mut candidates: impl Iterator<Item = &'a crate::modes::mesh::config::Workload>,
) -> Option<&'a std::collections::HashMap<String, String>> {
    let first = candidates.next()?;
    candidates
        .all(|candidate| candidate.selector.labels == first.selector.labels)
        .then_some(&first.selector.labels)
}

fn parse_workload_ip(address: &str) -> Option<IpAddr> {
    let trimmed = address.trim();
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed);
    unbracketed
        .parse::<IpAddr>()
        .ok()
        .map(crate::util::client_identity::canonical_ip)
}

/// Compare Istio gateway name spellings. `mesh` is exact. Named gateways compare
/// as canonical `namespace/name` (case-sensitive, already normalized at parse).
#[inline]
pub fn gateway_names_equal(configured: &str, binding: &str) -> bool {
    configured == binding
}

/// Canonicalize an Istio gateway reference relative to the VirtualService
/// namespace. Accepts `mesh`, `name` (→ `{vs_namespace}/name`), or `ns/name`.
pub fn canonicalize_gateway_name(raw: &str, vs_namespace: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("gateway name must not be empty".to_string());
    }
    if trimmed == MESH_GATEWAY_TOKEN {
        return Ok(MESH_GATEWAY_TOKEN.to_string());
    }
    if let Some((ns, name)) = trimmed.split_once('/') {
        if ns.is_empty() || name.is_empty() || name.contains('/') {
            return Err(format!(
                "gateway '{trimmed}' must be 'mesh', '<name>', or '<namespace>/<name>'"
            ));
        }
        validate_namespace(ns).map_err(|e| format!("gateway namespace: {e}"))?;
        validate_gateway_name_segment(name)?;
        Ok(format!("{ns}/{name}"))
    } else {
        validate_gateway_name_segment(trimmed)?;
        validate_namespace(vs_namespace)
            .map_err(|e| format!("VirtualService namespace for gateway qualification: {e}"))?;
        Ok(format!("{vs_namespace}/{trimmed}"))
    }
}

fn validate_gateway_name_segment(name: &str) -> Result<(), String> {
    // Istio Gateway metadata.name is a DNS-1123 label.
    if name.is_empty() || name.len() > 63 {
        return Err(format!(
            "gateway name '{name}' must be a DNS-1123 label (1-63 chars)"
        ));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(format!(
            "gateway name '{name}' must start and end with alphanumeric"
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
    {
        return Err(format!(
            "gateway name '{name}' must be a lowercase DNS-1123 label"
        ));
    }
    Ok(())
}

/// Validate a Kubernetes label key (optional prefix `/` name).
pub fn valid_kubernetes_label_key(value: &str) -> bool {
    let (prefix, name) = match value.split_once('/') {
        Some((prefix, name)) => (Some(prefix), name),
        None => (None, value),
    };
    if !valid_kubernetes_label_name(name) {
        return false;
    }
    prefix.is_none_or(valid_kubernetes_dns_subdomain)
}

/// Validate a Kubernetes label value (empty is allowed).
pub fn valid_kubernetes_label_value(value: &str) -> bool {
    value.is_empty() || valid_kubernetes_label_name(value)
}

fn valid_kubernetes_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
        })
}

fn valid_kubernetes_label_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

/// Resolve the trusted VirtualService L4 gateway binding for this process.
///
/// Precedence:
/// 1. Explicit `FERRUM_STREAM_GATEWAY_REF` (`mesh` or `namespace/name`); an
///    empty value clears the binding (gateway predicates deny).
/// 2. Otherwise the reserved `mesh` token — Istio's default when gateways are
///    omitted. Named-gateway data planes must set `FERRUM_STREAM_GATEWAY_REF`
///    explicitly; the binding is never inferred from untrusted wire data.
pub fn trusted_stream_gateway_ref() -> Option<String> {
    if let Some(raw) = crate::config::conf_file::resolve_ferrum_var("FERRUM_STREAM_GATEWAY_REF") {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed.to_string());
    }
    Some(MESH_GATEWAY_TOKEN.to_string())
}

/// Extract the source namespace from a peer SPIFFE ID string when present.
pub fn source_namespace_from_spiffe(spiffe: &str) -> Option<String> {
    SpiffeId::new(spiffe)
        .ok()
        .and_then(|id| id.namespace().map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn evidence_ip(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn empty_criteria_matches() {
        let compiled = StreamMatchCriteria::default().compile().unwrap();
        assert!(compiled.matches(&StreamMatchEvidence::default()));
    }

    #[test]
    fn source_namespace_denies_when_missing() {
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_namespace: Some("prod".into()),
                ..Default::default()
            }],
        };
        let compiled = criteria.compile().unwrap();
        assert!(!compiled.matches(&StreamMatchEvidence::default()));
        assert!(compiled.matches(&StreamMatchEvidence {
            source_namespace: Some("prod"),
            ..Default::default()
        }));
        assert!(!compiled.matches(&StreamMatchEvidence {
            source_namespace: Some("other"),
            ..Default::default()
        }));
    }

    #[test]
    fn source_labels_require_evidence() {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "billing".into());
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_labels: labels.clone(),
                ..Default::default()
            }],
        };
        let compiled = criteria.compile().unwrap();
        assert!(!compiled.matches(&StreamMatchEvidence::default()));
        assert!(compiled.matches(&StreamMatchEvidence {
            source_labels: Some(&labels),
            ..Default::default()
        }));
        let mut other = BTreeMap::new();
        other.insert("app".into(), "other".into());
        assert!(!compiled.matches(&StreamMatchEvidence {
            source_labels: Some(&other),
            ..Default::default()
        }));
    }

    #[test]
    fn source_and_destination_subnets() {
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_subnets: vec!["10.0.0.0/8".into()],
                destination_subnets: vec!["192.168.1.0/24".into()],
                ..Default::default()
            }],
        };
        let compiled = criteria.compile().unwrap();
        assert!(!compiled.matches(&StreamMatchEvidence {
            source_ip: Some(evidence_ip("10.1.2.3")),
            ..Default::default()
        }));
        assert!(compiled.matches(&StreamMatchEvidence {
            source_ip: Some(evidence_ip("10.1.2.3")),
            destination_ip: Some(evidence_ip("192.168.1.50")),
            ..Default::default()
        }));
        assert!(!compiled.matches(&StreamMatchEvidence {
            source_ip: Some(evidence_ip("10.1.2.3")),
            destination_ip: Some(evidence_ip("10.0.0.1")),
            ..Default::default()
        }));
    }

    #[test]
    fn gateways_mesh_vs_named() {
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                gateways: vec!["mesh".into()],
                ..Default::default()
            }],
        };
        let compiled = criteria.compile().unwrap();
        assert!(!compiled.matches(&StreamMatchEvidence::default()));
        assert!(compiled.matches(&StreamMatchEvidence {
            trusted_gateway_ref: Some("mesh"),
            ..Default::default()
        }));
        assert!(!compiled.matches(&StreamMatchEvidence {
            trusted_gateway_ref: Some("istio-system/ingress"),
            ..Default::default()
        }));
    }

    #[test]
    fn or_across_arms() {
        let criteria = StreamMatchCriteria {
            arms: vec![
                StreamMatchArm {
                    source_namespace: Some("a".into()),
                    ..Default::default()
                },
                StreamMatchArm {
                    source_namespace: Some("b".into()),
                    ..Default::default()
                },
            ],
        };
        let compiled = criteria.compile().unwrap();
        assert!(compiled.matches(&StreamMatchEvidence {
            source_namespace: Some("b"),
            ..Default::default()
        }));
    }

    #[test]
    fn canonicalize_gateway_qualifies_short_name() {
        assert_eq!(
            canonicalize_gateway_name("ingress", "default").unwrap(),
            "default/ingress"
        );
        assert_eq!(
            canonicalize_gateway_name("istio-system/ingress", "default").unwrap(),
            "istio-system/ingress"
        );
        assert_eq!(
            canonicalize_gateway_name("mesh", "default").unwrap(),
            "mesh"
        );
    }

    #[test]
    fn rejects_bad_cidr_at_compile() {
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_subnets: vec!["not-a-cidr".into()],
                ..Default::default()
            }],
        };
        assert!(criteria.compile().is_err());
    }

    #[test]
    fn source_namespace_from_spiffe_path() {
        assert_eq!(
            source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/sa/web").as_deref(),
            Some("prod")
        );
        assert_eq!(source_namespace_from_spiffe("not-spiffe"), None);
    }

    #[test]
    fn label_key_validation() {
        assert!(valid_kubernetes_label_key("app"));
        assert!(valid_kubernetes_label_key("example.com/app"));
        assert!(!valid_kubernetes_label_key(""));
        assert!(!valid_kubernetes_label_key("/app"));
        assert!(valid_kubernetes_label_value("billing"));
        assert!(valid_kubernetes_label_value(""));
    }

    #[test]
    fn and_within_arm() {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "billing".into());
        let criteria = StreamMatchCriteria {
            arms: vec![StreamMatchArm {
                source_labels: labels.clone(),
                source_namespace: Some("prod".into()),
                source_subnets: vec!["10.0.0.0/8".into()],
                ..Default::default()
            }],
        };
        let compiled = criteria.compile().unwrap();
        assert!(!compiled.matches(&StreamMatchEvidence {
            source_labels: Some(&labels),
            source_namespace: Some("prod"),
            ..Default::default()
        }));
        assert!(compiled.matches(&StreamMatchEvidence {
            source_labels: Some(&labels),
            source_namespace: Some("prod"),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            ..Default::default()
        }));
    }
}
