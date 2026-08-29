//! DNS-SD service discovery using SRV records.
//!
//! Queries DNS SRV records for a service name and converts the results
//! into upstream targets. Reuses the gateway's existing DnsCache resolver
//! so that custom nameservers and DNS configuration are respected.
//!
//! RFC 2782 selection happens at ingest, not on the request path: undialable
//! records (root target `.`, port 0) are dropped first, then only the
//! numerically-smallest remaining priority is published. Lower-priority
//! disaster-recovery tiers are never load-balanced with the live tier.

use crate::config::types::UpstreamTarget;
use crate::dns::{DnsCache, SrvAnswer, is_rfc2782_root_target};
use std::collections::HashMap;

/// DNS-SD service discoverer.
///
/// Resolves SRV records for the configured service name and converts
/// admissible records at the lowest RFC 2782 priority into `UpstreamTarget`s.
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
///    stripping the trailing root label).
/// 2. Admit ports through `admit_registry_port` — the same `1..=u16::MAX`
///    contract Kubernetes and Consul use. Port 0 is rejected.
/// 3. Among remaining admissible records, keep only the numerically-smallest
///    RFC 2782 priority, preserving each record's weight (weight `0` is
///    remapped to `default_weight` so published targets match the static
///    `1..=MAX_TARGET_WEIGHT` contract).
///
/// Invalid records are filtered **before** min-priority. A poisoned lowest
/// tier (every RR is `.` or port 0) therefore does not occupy the live set:
/// the next priority that still has a dialable host is used. That is the
/// ingest-time reading of RFC 2782's "lowest-numbered priority it can reach"
/// — undialable RRs are not reachable, so they must not block a higher
/// (numerically larger) disaster-recovery tier that *is* dialable, and they
/// also must not be published *alongside* a valid live tier.
///
/// If no admissible records remain at any priority, the snapshot is empty
/// (fail-closed). The discovery manager's existing empty-after-filter policy
/// then applies; live traffic is not balanced onto leftover junk.
///
/// Runtime unreachability of an admitted live-tier host is health-check /
/// load-balancer failover, not "include the DR tier in this poll's snapshot".
pub(crate) fn targets_from_srv_records(
    records: impl IntoIterator<Item = SrvAnswer>,
    default_weight: u32,
) -> Vec<UpstreamTarget> {
    let admitted: Vec<SrvAnswer> = records
        .into_iter()
        .filter(|answer| !is_rfc2782_root_target(&answer.host))
        .filter_map(|answer| {
            super::admit_registry_port(u64::from(answer.port))
                .map(|port| SrvAnswer { port, ..answer })
        })
        .collect();

    let Some(min_priority) = admitted.iter().map(|answer| answer.priority).min() else {
        return Vec::new();
    };

    admitted
        .into_iter()
        .filter(|answer| answer.priority == min_priority)
        .map(|answer| UpstreamTarget {
            host: answer.host,
            port: answer.port,
            service_port_policy_key: None,
            weight: if answer.weight > 0 {
                u32::from(answer.weight)
            } else {
                default_weight
            },
            tags: HashMap::new(),
            locality: None,
            path: None,
        })
        .collect()
}

#[async_trait::async_trait]
impl super::ServiceDiscoverer for DnsSdDiscoverer {
    async fn discover(&self) -> Result<super::DiscoverySnapshot, anyhow::Error> {
        let srv_results = self.dns_cache.resolve_srv(&self.service_name).await?;
        Ok(super::DiscoverySnapshot::from_targets(
            targets_from_srv_records(srv_results, self.default_weight),
        ))
    }

    fn provider_name(&self) -> &str {
        "dns_sd"
    }
}
