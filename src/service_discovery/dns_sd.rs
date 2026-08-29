//! DNS-SD service discovery using SRV records.
//!
//! Queries DNS SRV records for a service name and converts the results
//! into upstream targets. Reuses the gateway's existing DnsCache resolver
//! so that custom nameservers and DNS configuration are respected.
//!
//! RFC 2782 selection is split across two stages (issue #4291):
//!
//! * **Ingest (here).** Undialable records — the root target `.` and port `0`,
//!   the RFC 2782 "service decidedly not available" signals — are discarded.
//!   Every surviving tier is published, each target stamped with its priority
//!   in the reserved [`crate::service_discovery::SRV_PRIORITY_TAG`].
//! * **Selection (`LoadBalancer`).** The candidate filter keeps only the
//!   numerically-smallest tier that still has a HEALTHY target, and falls
//!   through to the next tier only when every lower tier is unhealthy.
//!
//! Discarding the disaster-recovery tiers at ingest (the earlier behavior)
//! stopped live primary/DR mixing but made the DR tier permanently
//! unreachable: once every primary target went unhealthy the load balancer had
//! nothing left to fail over to. RFC 2782 requires the client to use the
//! lowest-numbered priority it **can reach**, so reachability has to be a
//! runtime question, not a poll-time one.

use crate::config::types::{MAX_TARGETS_PER_UPSTREAM, UpstreamTarget};
use crate::dns::{DnsCache, SrvAnswer, normalize_srv_target_host};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use tracing::debug;

/// DNS-SD service discoverer.
///
/// Resolves SRV records for the configured service name and converts every
/// admissible RFC 2782 priority tier into `UpstreamTarget`s carrying their
/// priority tag.
pub struct DnsSdDiscoverer {
    dns_cache: DnsCache,
    service_name: String,
    default_weight: u32,
}

impl DnsSdDiscoverer {
    pub fn new(dns_cache: DnsCache, service_name: String, default_weight: u32) -> Self {
        Self {
            dns_cache,
            service_name,
            default_weight,
        }
    }
}

/// Convert SRV answers into DNS-SD upstream targets (issue #4291).
///
/// Admission order:
/// 1. Discard the RFC 2782 root target `.` (and the empty name left after
///    stripping the trailing root label) and ASCII-lowercase the host so it
///    matches `UpstreamTarget` admission.
/// 2. Admit ports through `admit_registry_port` — the same `1..=u16::MAX`
///    contract Kubernetes and Consul use. Port 0 is rejected.
/// 3. Deduplicate on the dial identity `host:port`, keeping the LOWEST
///    priority (and, at equal priority, the first record seen). A zone that
///    lists one endpoint in two tiers must not double its share of the tier it
///    actually serves, and must not be pinned to the DR tier by record order.
/// 4. Group the survivors into ascending priority tiers, keep at most
///    [`crate::service_discovery::MAX_SRV_PRIORITY_TIERS`] of them (lowest
///    first), and stamp each target with
///    [`crate::service_discovery::SRV_PRIORITY_TAG`]. Weights are preserved
///    per record; weight `0` becomes `default_weight` so published targets
///    match the static `1..=MAX_TARGET_WEIGHT` contract.
/// 5. Truncate to `MAX_TARGETS_PER_UPSTREAM`. Because the output is ordered by
///    ascending priority, truncation can only ever drop the LEAST preferred
///    records.
///
/// Invalid records are filtered **before** tiers are formed. A poisoned lowest
/// tier (every RR at that priority is `.` or port 0) therefore does not occupy
/// the live set at all: the next priority that still has a dialable host
/// becomes the best tier. Undialable RRs are not reachable, so they must not
/// block a numerically larger tier that *is*.
///
/// If no admissible records remain at any priority the snapshot is empty
/// (fail-closed) and the discovery manager's existing empty-after-filter
/// policy applies.
///
/// Returned targets are ordered by ascending priority; within each tier,
/// first-seen resolver order is preserved. Dedup on `host:port` keeps the first
/// equal-priority record and replaces it only for a lower numeric priority;
/// equal-priority duplicates also keep the first record's weight. Output is
/// deterministic for a given answer ordering but not invariant under permuting
/// same-tier answers.
pub(crate) fn targets_from_srv_records(
    records: impl IntoIterator<Item = SrvAnswer>,
    default_weight: u32,
) -> Vec<UpstreamTarget> {
    // Dial-identity dedup, lowest priority wins. `seen` maps `host:port` to the
    // slot in `admitted` so a later, better tier can replace an earlier one
    // in place without disturbing first-seen ordering.
    let mut admitted: Vec<SrvAnswer> = Vec::new();
    let mut seen: HashMap<(String, u16), usize> = HashMap::new();
    for answer in records {
        let Some(host) = normalize_srv_target_host(answer.host) else {
            continue;
        };
        let Some(port) = super::admit_registry_port(u64::from(answer.port)) else {
            continue;
        };
        let admitted_answer = SrvAnswer {
            host,
            port,
            weight: answer.weight,
            priority: answer.priority,
        };
        match seen.entry((admitted_answer.host.clone(), port)) {
            Entry::Occupied(existing) => {
                let slot = *existing.get();
                if admitted_answer.priority < admitted[slot].priority {
                    admitted[slot] = admitted_answer;
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(admitted.len());
                admitted.push(admitted_answer);
            }
        }
    }

    if admitted.is_empty() {
        return Vec::new();
    }

    // Ascending priority; `sort_by_key` is stable, so records inside one tier
    // keep their first-seen order.
    admitted.sort_by_key(|answer| answer.priority);

    // Bound the retained tier count. `admitted` is already ascending, so the
    // cutoff is the first record whose priority is not among the
    // `MAX_SRV_PRIORITY_TIERS` smallest.
    let mut retained_tiers = 0usize;
    let mut last_priority: Option<u16> = None;
    let mut cutoff = admitted.len();
    for (idx, answer) in admitted.iter().enumerate() {
        if last_priority != Some(answer.priority) {
            if retained_tiers == super::MAX_SRV_PRIORITY_TIERS {
                cutoff = idx;
                break;
            }
            retained_tiers += 1;
            last_priority = Some(answer.priority);
        }
    }
    admitted.truncate(cutoff.min(MAX_TARGETS_PER_UPSTREAM));

    admitted
        .into_iter()
        .map(|answer| {
            let mut tags = HashMap::with_capacity(1);
            tags.insert(
                super::SRV_PRIORITY_TAG.to_string(),
                super::format_srv_priority(answer.priority),
            );
            UpstreamTarget {
                host: answer.host,
                port: answer.port,
                service_port_policy_key: None,
                weight: if answer.weight > 0 {
                    u32::from(answer.weight)
                } else {
                    default_weight
                },
                tags,
                locality: None,
                path: None,
            }
        })
        .collect()
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for DnsSdDiscoverer {
    async fn discover(&self) -> Result<super::DiscoverySnapshot, anyhow::Error> {
        let srv_results = self.dns_cache.resolve_srv(&self.service_name).await?;
        let answers = srv_results.len();
        let targets = targets_from_srv_records(srv_results, self.default_weight);
        if targets.len() != answers {
            debug!(
                service = %self.service_name,
                answers,
                published = targets.len(),
                "DNS-SD dropped undialable, duplicate, or over-cardinality RFC 2782 SRV records"
            );
        }
        Ok(super::DiscoverySnapshot::from_targets(targets))
    }

    fn provider_name(&self) -> &str {
        "dns_sd"
    }
}
