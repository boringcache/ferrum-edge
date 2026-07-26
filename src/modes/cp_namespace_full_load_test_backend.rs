//! Map-backed `DatabaseBackend` for CP `load_full_config_multi` unit tests.
//! Every method except [`CpNamespaceFullLoadTestBackend::load_full_config_for_purpose`]
//! panics so regressions stay narrowly scoped to the multi-namespace full-load loop.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::config::db_backend::{
    ApiSpecListFilter, AtomicBatchCounts, AtomicBatchGraph, AtomicBatchUnsupported,
    DatabaseBackend, DeleteAllResourcesError, DeleteMode, FullConfigLoadPurpose,
    IncrementalResult, NamespaceConfigAdmissionLeaseBackend, NamespaceResourceCounts,
    PaginatedResult,
};
use crate::config::types::{
    ApiSpec, BatchConfigWriteMode, Consumer, GatewayConfig, PluginConfig, PluginHttpClient, Proxy,
    Upstream,
};

#[track_caller]
fn cp_namespace_full_load_test_backend_not_used() -> ! {
    panic!("CpNamespaceFullLoadTestBackend method not used by load_full_config_multi tests")
}

#[track_caller]
fn cp_namespace_full_load_test_backend_not_used_sync() -> ! {
    cp_namespace_full_load_test_backend_not_used()
}

#[track_caller]
fn cp_namespace_full_load_test_backend_not_used_bool() -> bool {
    cp_namespace_full_load_test_backend_not_used()
}

#[track_caller]
fn cp_namespace_full_load_test_backend_not_used_refstr() -> &'static str {
    cp_namespace_full_load_test_backend_not_used()
}

/// Namespace-keyed full-load responses for deterministic CP multi-load tests.
#[allow(dead_code)]
pub struct CpNamespaceFullLoadTestBackend {
    responses: Mutex<HashMap<String, Result<GatewayConfig, anyhow::Error>>>,
}

impl CpNamespaceFullLoadTestBackend {
    pub fn new(responses: HashMap<String, Result<GatewayConfig, anyhow::Error>>) -> Self {
        Self {
            responses: Mutex::new(responses),
        }
    }
}

#[async_trait]
impl NamespaceConfigAdmissionLeaseBackend for CpNamespaceFullLoadTestBackend {
    async fn try_acquire_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<Option<u64>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn renew_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn release_namespace_config_admission_lease(
        &self,
        namespace: &str,
        owner: &str,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
}

#[async_trait]
impl DatabaseBackend for CpNamespaceFullLoadTestBackend {
    async fn load_full_config_for_purpose(
        &self,
        namespace: &str,
        purpose: FullConfigLoadPurpose,
    ) -> Result<GatewayConfig, anyhow::Error> {
        assert_eq!(
            purpose,
            FullConfigLoadPurpose::ControlPlane,
            "load_full_config_multi always loads with ControlPlane purpose"
        );
        self.responses
            .lock()
            .expect("CpNamespaceFullLoadTestBackend responses lock")
            .get(namespace)
            .cloned()
            .unwrap_or_else(|| Err(anyhow::anyhow!("missing namespace load stub for '{namespace}'")))
    }

    async fn health_check(&self) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    fn db_type(&self) -> &str { cp_namespace_full_load_test_backend_not_used_refstr() }
    fn has_read_replica(&self) -> bool { cp_namespace_full_load_test_backend_not_used_bool() }
    fn set_slow_query_threshold(&mut self, threshold_ms: Option<u64>) { cp_namespace_full_load_test_backend_not_used_sync() }
    fn set_full_load_page_size(&mut self, page_size: u64) { cp_namespace_full_load_test_backend_not_used_sync() }
    fn set_cert_expiry_warning_days(&mut self, days: u64) { cp_namespace_full_load_test_backend_not_used_sync() }
    fn set_backend_allow_ips(&mut self, policy: crate::config::BackendEgressPolicy) { cp_namespace_full_load_test_backend_not_used_sync() }
    fn set_audit_retention_policy(&mut self, policy: crate::admin::audit::AuditRetentionPolicy) { cp_namespace_full_load_test_backend_not_used_sync() }
    async fn load_namespace_snapshot(
        &self,
        namespace: &str,
    ) -> Result<GatewayConfig, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn count_namespace_resources(
        &self,
        namespace: &str,
    ) -> Result<NamespaceResourceCounts, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn latest_change_sequence(&self, namespace: &str) -> Result<u64, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn load_incremental_config(
        &self,
        namespace: &str,
        after_sequence: u64,
    ) -> Result<IncrementalResult, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn create_proxy(&self, proxy: &Proxy) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn update_proxy(&self, proxy: &Proxy) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_proxy(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_proxy(&self, namespace: &str, id: &str) -> Result<Option<Proxy>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_proxy_exists(
        &self,
        proxy_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_proxies_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Proxy>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn create_consumer(&self, consumer: &Consumer) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn update_consumer(
        &self,
        consumer: &Consumer,
        mode: &BatchConfigWriteMode,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_consumer(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_consumer(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Consumer>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_consumers_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Consumer>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn create_plugin_config(&self, pc: &PluginConfig) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn update_plugin_config(&self, pc: &PluginConfig) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_plugin_config(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_plugin_config(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<PluginConfig>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_plugin_configs_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<PluginConfig>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn create_upstream(&self, upstream: &Upstream) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn update_upstream(&self, upstream: &Upstream) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_upstream(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_upstream(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<Upstream>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn cleanup_orphaned_upstream(
        &self,
        namespace: &str,
        upstream_id: &str,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_upstreams_paginated(
        &self,
        namespace: &str,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<Upstream>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_listen_path_unique(
        &self,
        namespace: &str,
        listen_path: Option<&str>,
        hosts: &[String],
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_proxy_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_upstream_name_unique(
        &self,
        namespace: &str,
        name: &str,
        exclude_upstream_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_consumer_identity_unique(
        &self,
        namespace: &str,
        consumer_id: &str,
        username: &str,
        custom_id: Option<&str>,
        exclude_consumer_id: Option<&str>,
    ) -> Result<Option<String>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_keyauth_key_unique(
        &self,
        namespace: &str,
        key: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_mtls_identity_unique(
        &self,
        namespace: &str,
        identity: &str,
        exclude_consumer_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_listen_port_unique(
        &self,
        namespace: &str,
        port: u16,
        exclude_proxy_id: Option<&str>,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn check_upstream_exists(
        &self,
        upstream_id: &str,
        namespace: &str,
    ) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn validate_proxy_plugin_associations(
        &self,
        proxy_id: &str,
        namespace: &str,
        plugins: &[crate::config::types::PluginAssociation],
    ) -> Result<Vec<String>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_config_graph_atomically(
        &self,
        graph: &AtomicBatchGraph<'_>,
        mode: &BatchConfigWriteMode,
    ) -> Result<AtomicBatchCounts, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_proxies(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_proxies_without_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_attach_proxy_plugins(
        &self,
        proxies: &[Proxy],
        mode: &BatchConfigWriteMode,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_consumers(
        &self,
        consumers: &[Consumer],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_plugin_configs(
        &self,
        configs: &[PluginConfig],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn batch_create_upstreams(
        &self,
        upstreams: &[Upstream],
        mode: &BatchConfigWriteMode,
    ) -> Result<usize, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_all_resources(
        &self,
        namespace: &str,
        mode: &BatchConfigWriteMode,
    ) -> Result<DeleteMode, DeleteAllResourcesError> { cp_namespace_full_load_test_backend_not_used() }
    async fn acquire_mtls_dns_admission_guard(
        &self,
        namespace: &str,
    ) -> Result<String, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn release_mtls_dns_admission_guard(
        &self,
        namespace: &str,
        guard_owner: &str,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn reconnect(&self, db_url: &str) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn reconnect_read_replica(&self, replica_url: &str) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn try_failover_reconnect(&self, primary_url: &str) -> Result<String, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn run_migrations(&self) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_namespaces(&self) -> Result<Vec<String>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_namespaces_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<PaginatedResult<String>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn submit_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn restore_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
        additional_upstreams: &[Upstream],
        additional_plugins: &[PluginConfig],
        validation_http_client: &PluginHttpClient,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn replace_api_spec_bundle(
        &self,
        bundle: &crate::admin::api_specs::ExtractedBundle,
        spec: &ApiSpec,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_api_spec(
        &self,
        namespace: &str,
        id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn get_api_spec_by_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Result<Option<ApiSpec>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_api_specs(
        &self,
        namespace: &str,
        filter: &ApiSpecListFilter,
    ) -> Result<PaginatedResult<ApiSpec>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn count_api_specs(&self, namespace: &str) -> Result<u64, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn delete_api_spec(&self, namespace: &str, id: &str) -> Result<bool, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_spec_owned_plugin_configs(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::PluginConfig>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_spec_owned_upstreams(
        &self,
        namespace: &str,
        spec_id: &str,
    ) -> Result<Vec<crate::config::types::Upstream>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn insert_audit_event(
        &self,
        event: &crate::admin::audit::AuditEvent,
    ) -> Result<(), anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn list_audit_events(
        &self,
        namespace: &str,
        filter: &crate::admin::audit::AuditListFilter,
    ) -> Result<PaginatedResult<crate::admin::audit::AuditEvent>, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
    async fn prune_audit_events(&self, namespace: &str) -> Result<u64, anyhow::Error> { cp_namespace_full_load_test_backend_not_used() }
}
