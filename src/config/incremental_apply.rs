//! Shared incremental config application helpers.
//!
//! CP mode, ConfigSync, and xDS stream-local snapshots all consume the same
//! database delta shape. Keep the retain/upsert behavior centralized so those
//! paths cannot drift as resource types evolve.

use std::collections::{HashMap, HashSet};

use crate::config::db_loader::IncrementalResult;
use crate::config::types::GatewayConfig;

/// Apply an incremental result to a config snapshot in-place.
///
/// Removes deleted resources by `(namespace, id)`, upserts added/modified
/// resources, and updates `loaded_at` to the delta's poll timestamp.
pub(crate) fn apply_incremental_to_config_snapshot(
    config: &mut GatewayConfig,
    result: IncrementalResult,
) {
    let poll_timestamp = result.poll_timestamp;
    apply_incremental_resources(config, result);
    config.loaded_at = poll_timestamp;
}

fn apply_incremental_resources(config: &mut GatewayConfig, result: IncrementalResult) {
    let removed_proxies: HashSet<(&str, &str)> = result
        .removed_proxy_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_consumers: HashSet<(&str, &str)> = result
        .removed_consumer_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_plugins: HashSet<(&str, &str)> = result
        .removed_plugin_config_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();
    let removed_upstreams: HashSet<(&str, &str)> = result
        .removed_upstream_ids
        .iter()
        .map(|key| (key.namespace.as_str(), key.id.as_str()))
        .collect();

    config.proxies.retain(|proxy| {
        !removed_proxies.contains(&(proxy.namespace.as_str(), proxy.id.as_str()))
    });
    config.consumers.retain(|consumer| {
        !removed_consumers.contains(&(consumer.namespace.as_str(), consumer.id.as_str()))
    });
    config.plugin_configs.retain(|plugin| {
        !removed_plugins.contains(&(plugin.namespace.as_str(), plugin.id.as_str()))
    });
    config.upstreams.retain(|upstream| {
        !removed_upstreams.contains(&(upstream.namespace.as_str(), upstream.id.as_str()))
    });

    // Plugin associations are scoped by the owning proxy's namespace.
    for proxy in &mut config.proxies {
        proxy.plugins.retain(|assoc| {
            !removed_plugins.contains(&(proxy.namespace.as_str(), assoc.plugin_config_id.as_str()))
        });
    }

    upsert_by_id(
        &mut config.proxies,
        result.added_or_modified_proxies,
        |proxy| proxy.id.as_str(),
    );
    upsert_consumers_by_namespace_and_id(&mut config.consumers, result.added_or_modified_consumers);
    upsert_by_id(
        &mut config.plugin_configs,
        result.added_or_modified_plugin_configs,
        |plugin| plugin.id.as_str(),
    );
    upsert_by_id(
        &mut config.upstreams,
        result.added_or_modified_upstreams,
        |upstream| upstream.id.as_str(),
    );
}

fn upsert_consumers_by_namespace_and_id(
    existing: &mut Vec<crate::config::types::Consumer>,
    updates: Vec<crate::config::types::Consumer>,
) {
    let mut index: HashMap<(String, String), usize> = existing
        .iter()
        .enumerate()
        .map(|(i, consumer)| ((consumer.namespace.clone(), consumer.id.clone()), i))
        .collect();

    for consumer in updates {
        let key = (consumer.namespace.clone(), consumer.id.clone());
        if let Some(&pos) = index.get(&key) {
            existing[pos] = consumer;
        } else {
            let pos = existing.len();
            existing.push(consumer);
            index.insert(key, pos);
        }
    }
}

/// Upsert items into a vec by ID: replace existing entries, append new ones.
pub(crate) fn upsert_by_id<T, F>(existing: &mut Vec<T>, updates: Vec<T>, get_id: F)
where
    F: Fn(&T) -> &str,
{
    let mut index: HashMap<String, usize> = existing
        .iter()
        .enumerate()
        .map(|(i, item)| (get_id(item).to_string(), i))
        .collect();

    for item in updates {
        let id = get_id(&item).to_string();
        if let Some(&pos) = index.get(id.as_str()) {
            existing[pos] = item;
        } else {
            let pos = existing.len();
            existing.push(item);
            index.insert(id, pos);
        }
    }
}
