use ferrum_edge::config::config_backup::load_config_backup;
use ferrum_edge::config::types::CURRENT_CONFIG_VERSION;
use std::io::Write;

fn write_tmp_file(content: &str) -> (tempfile::NamedTempFile, String) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(content.as_bytes()).unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_str().unwrap().to_string();
    (tmp, path)
}

#[test]
fn test_load_config_backup_valid_json() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path)
        .expect("valid backup must succeed")
        .expect("valid backup must return Some");
    assert_eq!(loaded.proxies.len(), 1);
    assert_eq!(loaded.proxies[0].id, "proxy-1");
    assert_eq!(loaded.proxies[0].listen_path.as_deref(), Some("/api"));
    assert_eq!(loaded.proxies[0].backend_host, "localhost");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
}

#[test]
fn test_load_config_backup_file_not_found() {
    let result = load_config_backup("/tmp/nonexistent-ferrum-backup-12345.json")
        .expect("missing file is Ok(None), not Err");
    assert!(result.is_none(), "should return None for missing file");
}

#[test]
fn test_load_config_backup_invalid_json() {
    let (_tmp, path) = write_tmp_file("{ not valid json }}}");
    let err = load_config_backup(&path).expect_err("invalid JSON must be Err, not Ok(None)");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to parse config backup"),
        "parse failure must be actionable, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_empty_config() {
    let json = r#"{
        "version": "1",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path)
        .expect("empty valid backup must succeed")
        .expect("empty valid backup must return Some");
    assert!(loaded.proxies.is_empty());
    assert!(loaded.consumers.is_empty());
    assert!(loaded.upstreams.is_empty());
}

#[test]
fn test_load_config_backup_stream_proxy_has_no_listen_path() {
    // Stream proxies route on listen_port and never carry a listen_path.
    // The loader accepts backups that omit the field entirely — serde(default)
    // deserializes to None.
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "tcp-proxy-1",
            "name": "tcp-test",
            "backend_host": "10.0.0.1",
            "backend_port": 5432,
            "backend_scheme": "tcp",
            "listen_port": 9999
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path)
        .expect("stream proxy backup must succeed")
        .expect("stream proxy backup must return Some");
    assert_eq!(
        loaded.proxies[0].listen_path, None,
        "stream proxy backups must deserialize to listen_path=None"
    );
    assert_eq!(loaded.proxies[0].listen_port, Some(9999));
}

#[test]
fn test_load_config_backup_preserves_multiple_resources() {
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "listen_path": "/one",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_scheme": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "listen_path": "/two",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_scheme": "http"
            }
        ],
        "consumers": [{
            "id": "c1",
            "username": "user1",
            "custom_id": "cust1"
        }],
        "plugin_configs": [],
        "upstreams": [{
            "id": "u1",
            "name": "upstream-1",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        }]
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let loaded = load_config_backup(&path)
        .expect("multi-resource backup must succeed")
        .expect("multi-resource backup must return Some");
    assert_eq!(loaded.proxies.len(), 2);
    assert_eq!(loaded.consumers.len(), 1);
    assert_eq!(loaded.upstreams.len(), 1);
    assert_eq!(loaded.consumers[0].username, "user1");
    assert_eq!(loaded.upstreams[0].name, Some("upstream-1".into()));
}

#[test]
fn test_load_config_backup_empty_file() {
    let (_tmp, path) = write_tmp_file("");
    let err = load_config_backup(&path).expect_err("empty file must be Err, not Ok(None)");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to parse config backup"),
        "empty-file parse failure must be actionable, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_invalid_regex_listen_path() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "bad-regex",
            "name": "bad-regex",
            "listen_path": "~(invalid[regex",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path).expect_err("invalid regex must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("invalid regex listen_path"),
        "must name the regex failure, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_duplicate_listen_path() {
    let json = r#"{
        "version": "1",
        "proxies": [
            {
                "id": "p1",
                "name": "proxy-one",
                "listen_path": "/same",
                "backend_host": "host1",
                "backend_port": 3000,
                "backend_scheme": "http"
            },
            {
                "id": "p2",
                "name": "proxy-two",
                "listen_path": "/same",
                "backend_host": "host2",
                "backend_port": 3001,
                "backend_scheme": "http"
            }
        ],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path).expect_err("duplicate listen path must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("/same") || msg.to_lowercase().contains("duplicate"),
        "must identify the duplicate listen path, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_dangling_upstream_reference() {
    let json = r#"{
        "version": "1",
        "proxies": [{
            "id": "p1",
            "name": "proxy-one",
            "listen_path": "/api",
            "backend_host": "localhost",
            "backend_port": 3000,
            "backend_scheme": "http",
            "upstream_id": "missing-upstream"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path).expect_err("dangling upstream_id must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("failed runtime validation"),
        "must surface runtime validation, got: {msg}"
    );
    assert!(
        msg.contains("non-existent upstream_id") && msg.contains("missing-upstream"),
        "must name the dangling reference, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_accepts_current_version_integer_form() {
    let json = format!(
        r#"{{
        "version": {},
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }}"#,
        CURRENT_CONFIG_VERSION
    );

    let (_tmp, path) = write_tmp_file(&json);
    let loaded = load_config_backup(&path)
        .expect("integer current version must succeed")
        .expect("integer current version must return Some");
    assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
}

#[test]
fn test_load_config_backup_rejects_unsupported_version() {
    let json = r#"{
        "version": "0",
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path).expect_err("unsupported version must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("version")
            && (msg.contains("No config migration path") || msg.contains("unsupported version")),
        "must report unsupported version without legacy shims, got: {msg}"
    );
}

#[test]
fn test_load_config_backup_rejects_missing_version() {
    let json = r#"{
        "proxies": [],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": []
    }"#;

    let (_tmp, path) = write_tmp_file(json);
    let err = load_config_backup(&path).expect_err("missing version must reject backup");
    let msg = err.to_string();
    assert!(
        msg.contains("version"),
        "must mention missing version, got: {msg}"
    );
}

#[test]
fn backup_bootstrap_uses_rejecting_runtime_contract_not_node_local_files() {
    let source = include_str!("../../../src/config/config_backup.rs");
    assert!(
        source.contains("collect_rejecting_runtime_config_errors"),
        "backup bootstrap must run the shared rejecting runtime contract"
    );
    assert!(
        source.contains("normalize_fields()"),
        "backup bootstrap must normalize before validation"
    );
    assert!(
        source.contains("resolve_upstream_tls()"),
        "backup bootstrap must resolve upstream TLS before validation"
    );
    assert!(
        !source.contains("validate_plugin_file_dependencies"),
        "backup bootstrap must keep node-local plugin file checks separate"
    );
    assert!(
        source.contains("CURRENT_CONFIG_VERSION") && source.contains("migrate_in_memory"),
        "backup bootstrap must validate/migrate version under the build-out policy"
    );

    let database = include_str!("../../../src/modes/database.rs");
    let backup_start = database
        .find("match load_config_backup(path)")
        .expect("database mode must call load_config_backup");
    let reserved_ports = database[backup_start..]
        .find("validate_stream_proxy_port_conflicts")
        .map(|offset| backup_start + offset)
        .expect("reserved-port check follows backup load");
    assert!(
        database[backup_start..reserved_ports].contains("Ok(Some(cfg))"),
        "database mode must only serve Ok(Some) backup snapshots"
    );
    assert!(
        database[backup_start..reserved_ports].contains("was rejected"),
        "database mode must surface actionable backup rejection errors"
    );
}
