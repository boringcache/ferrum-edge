//! Ferrum `UDPResponseAmplificationPolicy` Direct Policy Attachment.
//!
//! Ordinary Gateway API `UDPRoute` translation must never silently program an
//! unlimited amplification relay. This module collects the Ferrum-owned CRD,
//! resolves GEP-713 oldest-wins precedence, and projects a finite factor (or an
//! explicit dual-acknowledged unlimited override) onto every generated UDP
//! proxy before listener bind.
//!
//! Invalid, zero, negative, non-finite, or excessive factors never win. A
//! missing or unusable policy falls through to the next precedence level and
//! finally the controller default — never to unlimited.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;

use super::gateway_api::{self, parse_k8s_timestamp};
use super::{
    GatewayApiListenerParentKind, K8sAccumulator, K8sObject, K8sResourceKey, K8sTranslateError,
};
use crate::config::types::Proxy;
use crate::udp_amplification::{
    GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR, MAX_UDP_AMPLIFICATION_FACTOR,
    UDP_AMPLIFICATION_POLICY_GROUP, UDP_AMPLIFICATION_POLICY_KIND, factor_is_valid,
    record_policy_invalid,
};

const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";
const MAX_TARGET_REFS: usize = 16;

const ACCEPTED_OK: &str = "Ferrum accepted this UDPResponseAmplificationPolicy";
const REFS_OK: &str = "All UDPResponseAmplificationPolicy references accepted by Ferrum";
const CONFLICTED_MESSAGE: &str = "An older UDPResponseAmplificationPolicy already governs one or more of the same targets";
const REF_NOT_PERMITTED_MESSAGE: &str =
    "Cross-namespace UDPResponseAmplificationPolicy attachment is not permitted by ReferenceGrant";
const TARGET_NOT_FOUND_MESSAGE: &str =
    "UDPResponseAmplificationPolicy targetRef does not resolve to an observed Gateway or UDPRoute";

/// Effective protection posture projected onto a generated UDPRoute proxy and
/// published on `UDPRoute.status.parents[].conditions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpAmplificationPosture {
    /// Controller default (`8.0`). Protection is on.
    FiniteDefault,
    /// A valid finite policy won. Protection is on.
    FinitePolicy,
    /// Dual-acknowledged `mode: Unlimited`. Protection is off.
    ExplicitUnlimited,
}

impl UdpAmplificationPosture {
    pub fn condition_status(self) -> bool {
        !matches!(self, Self::ExplicitUnlimited)
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::FiniteDefault => "FiniteDefault",
            Self::FinitePolicy => "FinitePolicy",
            Self::ExplicitUnlimited => "ExplicitUnlimited",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::FiniteDefault => {
                "Ferrum applied the controller default UDP response-amplification limit"
            }
            Self::FinitePolicy => "Ferrum applied a finite UDPResponseAmplificationPolicy",
            Self::ExplicitUnlimited => {
                "Ferrum programmed this UDPRoute without a response-amplification limit because an attached policy acknowledged unsafe amplification"
            }
        }
    }
}

/// Translation outcome for one `UDPResponseAmplificationPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiUdpAmplificationPolicyStatus {
    pub policy: K8sResourceKey,
    pub accepted: bool,
    pub accepted_reason: String,
    pub accepted_message: String,
    pub resolved_refs: bool,
    pub resolved_refs_reason: String,
    pub resolved_refs_message: String,
    /// Named targets Ferrum will list as `status.ancestors` (Gateway / UDPRoute).
    pub ancestors: Vec<UdpAmplificationAncestorRef>,
}

/// One Direct Policy Attachment target for status `ancestorRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAmplificationAncestorRef {
    pub kind: String,
    pub namespace: String,
    pub name: String,
    pub section_name: Option<String>,
}

/// Per-parent UDPRoute protection posture for status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayApiUdpAmplificationRoutePosture {
    pub route: K8sResourceKey,
    pub parent_ref: String,
    pub posture: UdpAmplificationPosture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMode {
    Finite,
    Unlimited,
}

#[derive(Debug, Clone)]
struct ValidPolicyBody {
    factor: Option<f32>,
}

#[derive(Debug, Clone)]
struct IndexedPolicy {
    resource: K8sResourceKey,
    creation_timestamp: Option<DateTime<Utc>>,
    body: ValidPolicyBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AttachmentKey {
    Route { namespace: String, name: String },
    Gateway {
        namespace: String,
        name: String,
        section: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct TargetRef {
    kind: String,
    namespace: String,
    name: String,
    section_name: Option<String>,
    cross_namespace: bool,
}

#[derive(Debug, Default)]
pub(crate) struct UdpAmplificationPolicyIndex {
    by_attachment: HashMap<AttachmentKey, IndexedPolicy>,
    /// Valid policy bodies keyed by `(namespace, name)` for GatewayClass.parametersRef.
    by_name: HashMap<(String, String), IndexedPolicy>,
}

impl UdpAmplificationPolicyIndex {
    fn insert_winner(&mut self, key: AttachmentKey, candidate: IndexedPolicy) {
        match self.by_attachment.get(&key) {
            None => {
                self.by_attachment.insert(key, candidate);
            }
            Some(existing) => {
                if policy_is_preferred(&candidate, existing) {
                    self.by_attachment.insert(key, candidate);
                }
            }
        }
    }
}

fn policy_is_preferred(candidate: &IndexedPolicy, existing: &IndexedPolicy) -> bool {
    match (candidate.creation_timestamp, existing.creation_timestamp) {
        (Some(c), Some(e)) => match c.cmp(&e) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal => candidate.resource.cmp(&existing.resource).is_lt(),
        },
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => candidate.resource.cmp(&existing.resource).is_lt(),
    }
}

/// Collect every in-scope `UDPResponseAmplificationPolicy`. Invalid objects
/// record status and never occupy an attachment slot.
pub(crate) fn collect_all(
    acc: &mut K8sAccumulator,
    objects: &[&K8sObject],
) -> Result<(), K8sTranslateError> {
    let observed_udproutes: std::collections::HashSet<(String, String)> = objects
        .iter()
        .filter(|object| object.kind == "UDPRoute")
        .map(|object| {
            (
                object.metadata.namespace.clone(),
                object.metadata.name.clone(),
            )
        })
        .collect();

    for object in objects {
        if object.kind != UDP_AMPLIFICATION_POLICY_KIND {
            continue;
        }
        collect_one(acc, object, &observed_udproutes);
    }
    Ok(())
}

fn collect_one(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    observed_udproutes: &std::collections::HashSet<(String, String)>,
) {
    let parsed_targets = parse_target_refs(object);
    let parsed_body = parse_policy_body(object);

    let (body, targets, error) = match (parsed_body, parsed_targets) {
        (Err(error), targets) | (Ok(_), Err(error)) => {
            (None, targets.unwrap_or_default(), Some(error))
        }
        (Ok(body), Ok(targets)) => (Some(body), targets, None),
    };

    let mut resolved_error = error;
    if resolved_error.is_none() {
        for target in &targets {
            if let Some(error) =
                authorize_and_resolve_target(acc, object, target, observed_udproutes)
            {
                resolved_error = Some(error);
                break;
            }
        }
    }

    let ancestors: Vec<UdpAmplificationAncestorRef> = targets
        .iter()
        .map(|target| UdpAmplificationAncestorRef {
            kind: target.kind.clone(),
            namespace: target.namespace.clone(),
            name: target.name.clone(),
            section_name: target.section_name.clone(),
        })
        .collect();

    if let Some(error) = resolved_error {
        record_policy_invalid();
        acc.warnings.push(format!(
            "Gateway API UDPResponseAmplificationPolicy {}/{} is invalid: {}",
            object.metadata.namespace, object.metadata.name, error.message
        ));
        acc.record_udp_amplification_policy_status(GatewayApiUdpAmplificationPolicyStatus {
            policy: K8sResourceKey::from_object(object),
            accepted: false,
            accepted_reason: error.accepted_reason.to_string(),
            accepted_message: error.message.clone(),
            resolved_refs: false,
            resolved_refs_reason: error.refs_reason.to_string(),
            resolved_refs_message: error.message,
            ancestors,
        });
        return;
    }

    let Some(body) = body else {
        return;
    };

    let indexed = IndexedPolicy {
        resource: K8sResourceKey::from_object(object),
        creation_timestamp: object
            .metadata
            .creation_timestamp
            .as_deref()
            .and_then(parse_k8s_timestamp),
        body: body.clone(),
    };
    acc.udp_amplification_policies.by_name.insert(
        (
            object.metadata.namespace.clone(),
            object.metadata.name.clone(),
        ),
        indexed.clone(),
    );

    for target in &targets {
        let key = match target.kind.as_str() {
            "UDPRoute" => AttachmentKey::Route {
                namespace: target.namespace.clone(),
                name: target.name.clone(),
            },
            "Gateway" => AttachmentKey::Gateway {
                namespace: target.namespace.clone(),
                name: target.name.clone(),
                section: target.section_name.clone(),
            },
            _ => continue,
        };
        acc.udp_amplification_policies
            .insert_winner(key, indexed.clone());
    }

    // Conflicted losers are finalized after every policy is indexed so status
    // is stable under input reorder. Record a provisional Accepted here; finish()
    // flips policies that lost every attachment they named.
    acc.record_udp_amplification_policy_status(GatewayApiUdpAmplificationPolicyStatus {
        policy: K8sResourceKey::from_object(object),
        accepted: true,
        accepted_reason: "Accepted".to_string(),
        accepted_message: ACCEPTED_OK.to_string(),
        resolved_refs: true,
        resolved_refs_reason: "ResolvedRefs".to_string(),
        resolved_refs_message: REFS_OK.to_string(),
        ancestors,
    });
}

struct PolicyError {
    accepted_reason: &'static str,
    refs_reason: &'static str,
    message: String,
}

impl PolicyError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            accepted_reason: "Invalid",
            refs_reason: "Invalid",
            message: message.into(),
        }
    }

    fn ref_not_permitted() -> Self {
        Self {
            accepted_reason: "RefNotPermitted",
            refs_reason: "RefNotPermitted",
            message: REF_NOT_PERMITTED_MESSAGE.to_string(),
        }
    }

    fn target_not_found() -> Self {
        Self {
            accepted_reason: "TargetNotFound",
            refs_reason: "InvalidKind",
            message: TARGET_NOT_FOUND_MESSAGE.to_string(),
        }
    }
}

fn parse_target_refs(object: &K8sObject) -> Result<Vec<TargetRef>, PolicyError> {
    let Some(raw) = object.spec.get("targetRefs") else {
        return Ok(Vec::new());
    };
    let Some(entries) = raw.as_array() else {
        return Err(PolicyError::invalid("spec.targetRefs must be an array"));
    };
    if entries.len() > MAX_TARGET_REFS {
        return Err(PolicyError::invalid(format!(
            "spec.targetRefs must contain at most {MAX_TARGET_REFS} entries"
        )));
    }
    let mut targets = Vec::with_capacity(entries.len());
    for entry in entries {
        targets.push(parse_one_target(object, entry)?);
    }
    Ok(targets)
}

fn parse_one_target(object: &K8sObject, entry: &Value) -> Result<TargetRef, PolicyError> {
    if !entry.is_object() {
        return Err(PolicyError::invalid(
            "spec.targetRefs entries must be objects",
        ));
    }
    let group = entry
        .get("group")
        .and_then(Value::as_str)
        .unwrap_or(GATEWAY_API_GROUP);
    if group != GATEWAY_API_GROUP {
        return Err(PolicyError::invalid(
            "spec.targetRefs.group must be gateway.networking.k8s.io",
        ));
    }
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::invalid("spec.targetRefs.kind is required"))?;
    if kind != "Gateway" && kind != "UDPRoute" {
        return Err(PolicyError::invalid(
            "spec.targetRefs.kind must be Gateway or UDPRoute",
        ));
    }
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| PolicyError::invalid("spec.targetRefs.name is required"))?;
    if name.is_empty() {
        return Err(PolicyError::invalid("spec.targetRefs.name must not be empty"));
    }
    let target_namespace = entry
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(object.metadata.namespace.as_str());
    if target_namespace.is_empty() {
        return Err(PolicyError::invalid(
            "spec.targetRefs.namespace must not be empty",
        ));
    }
    let section_name = entry
        .get("sectionName")
        .and_then(Value::as_str)
        .map(str::to_string);
    if section_name.as_ref().is_some_and(|name| name.is_empty()) {
        return Err(PolicyError::invalid(
            "spec.targetRefs.sectionName must not be empty when set",
        ));
    }
    if kind == "UDPRoute" && section_name.is_some() {
        return Err(PolicyError::invalid(
            "spec.targetRefs.sectionName is not valid on a UDPRoute target",
        ));
    }
    let cross_namespace = target_namespace != object.metadata.namespace;
    Ok(TargetRef {
        kind: kind.to_string(),
        namespace: target_namespace.to_string(),
        name: name.to_string(),
        section_name,
        cross_namespace,
    })
}

fn parse_policy_body(object: &K8sObject) -> Result<ValidPolicyBody, PolicyError> {
    let mode = match object.spec.get("mode").and_then(Value::as_str) {
        None | Some("Finite") => PolicyMode::Finite,
        Some("Unlimited") => PolicyMode::Unlimited,
        Some(_) => {
            return Err(PolicyError::invalid(
                "spec.mode must be Finite or Unlimited",
            ));
        }
    };
    let ack = object
        .spec
        .get("acknowledgeUnsafeAmplification")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    match mode {
        PolicyMode::Unlimited => {
            if !ack {
                return Err(PolicyError::invalid(
                    "spec.acknowledgeUnsafeAmplification must be true when spec.mode is Unlimited",
                ));
            }
            Ok(ValidPolicyBody { factor: None })
        }
        PolicyMode::Finite => {
            if ack {
                return Err(PolicyError::invalid(
                    "spec.acknowledgeUnsafeAmplification must not be set when spec.mode is Finite",
                ));
            }
            let Some(raw) = object.spec.get("maxResponseAmplificationFactor") else {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor is required when spec.mode is Finite",
                ));
            };
            let factor = match raw {
                Value::Number(number) => number.as_f64(),
                _ => None,
            };
            let Some(factor) = factor else {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor must be a finite number",
                ));
            };
            if !factor.is_finite()
                || factor <= 0.0
                || factor > f64::from(MAX_UDP_AMPLIFICATION_FACTOR)
            {
                return Err(PolicyError::invalid(format!(
                    "spec.maxResponseAmplificationFactor must be a finite number greater than 0 and at most {MAX_UDP_AMPLIFICATION_FACTOR}"
                )));
            }
            let factor = factor as f32;
            if !factor_is_valid(factor) {
                return Err(PolicyError::invalid(
                    "spec.maxResponseAmplificationFactor must be a finite number greater than 0 and at most 1024",
                ));
            }
            Ok(ValidPolicyBody {
                factor: Some(factor),
            })
        }
    }
}

fn authorize_and_resolve_target(
    acc: &K8sAccumulator,
    object: &K8sObject,
    target: &TargetRef,
    observed_udproutes: &std::collections::HashSet<(String, String)>,
) -> Option<PolicyError> {
    if target.cross_namespace
        && !acc.reference_grant_allows(
            &object.metadata.namespace,
            UDP_AMPLIFICATION_POLICY_GROUP,
            UDP_AMPLIFICATION_POLICY_KIND,
            &target.namespace,
            GATEWAY_API_GROUP,
            &target.kind,
            Some(&target.name),
        )
    {
        return Some(PolicyError::ref_not_permitted());
    }
    let exists = match target.kind.as_str() {
        "Gateway" => acc
            .gateway_class_name_by_gateway
            .contains_key(&(target.namespace.clone(), target.name.clone())),
        "UDPRoute" => observed_udproutes.contains(&(target.namespace.clone(), target.name.clone())),
        _ => false,
    };
    if !exists {
        return Some(PolicyError::target_not_found());
    }
    None
}

/// Mark policies that lost any named attachment under GEP-713 oldest-wins
/// and withdraw them from every slot (atomic Direct attachment).
pub(crate) fn finalize_conflicts(acc: &mut K8sAccumulator) {
    let mut lost_any: std::collections::HashSet<K8sResourceKey> = std::collections::HashSet::new();
    for status in &acc.udp_amplification_policy_statuses {
        if !status.accepted || status.ancestors.is_empty() {
            continue;
        }
        let lost = status.ancestors.iter().any(|ancestor| {
            let key = match ancestor.kind.as_str() {
                "UDPRoute" => AttachmentKey::Route {
                    namespace: ancestor.namespace.clone(),
                    name: ancestor.name.clone(),
                },
                "Gateway" => AttachmentKey::Gateway {
                    namespace: ancestor.namespace.clone(),
                    name: ancestor.name.clone(),
                    section: ancestor.section_name.clone(),
                },
                _ => return false,
            };
            acc.udp_amplification_policies
                .by_attachment
                .get(&key)
                .is_some_and(|winner| winner.resource != status.policy)
        });
        if lost {
            lost_any.insert(status.policy.clone());
        }
    }
    if !lost_any.is_empty() {
        acc.udp_amplification_policies
            .by_attachment
            .retain(|_, policy| !lost_any.contains(&policy.resource));
        for status in &mut acc.udp_amplification_policy_statuses {
            if lost_any.contains(&status.policy) {
                status.accepted = false;
                status.accepted_reason = "Conflicted".to_string();
                status.accepted_message = CONFLICTED_MESSAGE.to_string();
            }
        }
    }
}

/// Project the effective amplification policy onto one generated UDPRoute proxy.
pub(crate) fn apply_to_generated_proxy(
    acc: &mut K8sAccumulator,
    object: &K8sObject,
    proxy: &mut Proxy,
    listen_port: u16,
) {
    let (factor, posture, parent_ref) = resolve_for_route(acc, object, listen_port);
    proxy.udp_max_response_amplification_factor = factor;
    acc.udp_amplification_route_postures
        .push(GatewayApiUdpAmplificationRoutePosture {
            route: K8sResourceKey::from_object(object),
            parent_ref,
            posture,
        });
}

fn resolve_for_route(
    acc: &K8sAccumulator,
    object: &K8sObject,
    listen_port: u16,
) -> (Option<f32>, UdpAmplificationPosture, String) {
    let claims = gateway_api::udp_route_listener_claims(object, acc);
    let claim = claims.iter().find(|claim| claim.port == listen_port);
    let parent_ref = claim
        .map(|claim| claim.parent_ref.clone())
        .unwrap_or_default();

    let route_key = AttachmentKey::Route {
        namespace: object.metadata.namespace.clone(),
        name: object.metadata.name.clone(),
    };
    if let Some(policy) = acc.udp_amplification_policies.by_attachment.get(&route_key) {
        return posture_from_body(&policy.body, parent_ref);
    }

    if let Some(claim) = claim {
        let (gateway_ns, gateway_name) = match claim.listener.parent_kind {
            GatewayApiListenerParentKind::Gateway => (
                claim.listener.namespace.clone(),
                claim.listener.gateway.clone(),
            ),
            GatewayApiListenerParentKind::ListenerSet => acc
                .gateway_api_listener_policies
                .get(&claim.listener)
                .and_then(|policy| policy.parent_gateway.clone())
                .unwrap_or_else(|| {
                    (
                        claim.listener.namespace.clone(),
                        claim.listener.gateway.clone(),
                    )
                }),
        };
        let section_key = AttachmentKey::Gateway {
            namespace: gateway_ns.clone(),
            name: gateway_name.clone(),
            section: Some(claim.listener.listener.clone()),
        };
        if let Some(policy) = acc
            .udp_amplification_policies
            .by_attachment
            .get(&section_key)
        {
            return posture_from_body(&policy.body, parent_ref);
        }
        let gateway_key = AttachmentKey::Gateway {
            namespace: gateway_ns.clone(),
            name: gateway_name.clone(),
            section: None,
        };
        if let Some(policy) = acc
            .udp_amplification_policies
            .by_attachment
            .get(&gateway_key)
        {
            return posture_from_body(&policy.body, parent_ref);
        }
        if let Some(class_name) = acc
            .gateway_class_name_by_gateway
            .get(&(gateway_ns, gateway_name))
            && let Some(factor) = class_default_factor(acc, class_name)
        {
            return posture_from_body(&ValidPolicyBody { factor }, parent_ref);
        }
    }

    (
        Some(GATEWAY_API_UDP_AMPLIFICATION_DEFAULT_FACTOR),
        UdpAmplificationPosture::FiniteDefault,
        parent_ref,
    )
}

fn class_default_factor(acc: &K8sAccumulator, class_name: &str) -> Option<Option<f32>> {
    let (namespace, name) = acc.gateway_class_parameters_ref.get(class_name)?;
    let policy = acc
        .udp_amplification_policies
        .by_name
        .get(&(namespace.clone(), name.clone()))?;
    Some(policy.body.factor)
}

fn posture_from_body(
    body: &ValidPolicyBody,
    parent_ref: String,
) -> (Option<f32>, UdpAmplificationPosture, String) {
    match body.factor {
        None => (
            None,
            UdpAmplificationPosture::ExplicitUnlimited,
            parent_ref,
        ),
        Some(factor) => (
            Some(factor),
            UdpAmplificationPosture::FinitePolicy,
            parent_ref,
        ),
    }
}

pub(crate) fn lookup_route_posture(
    postures: &[GatewayApiUdpAmplificationRoutePosture],
    route: &K8sResourceKey,
    parent_ref: &str,
) -> Option<UdpAmplificationPosture> {
    postures
        .iter()
        .find(|entry| entry.route == *route && entry.parent_ref == parent_ref)
        .map(|entry| entry.posture)
        .or_else(|| {
            postures
                .iter()
                .find(|entry| entry.route == *route)
                .map(|entry| entry.posture)
        })
}
