use std::path::PathBuf;
use std::str::FromStr;

use ferrum_edge::_test_support::SqlTlsSnapshot;
use ferrum_edge::config::{DbTlsMode, EnvConfig, OperatingMode};
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};
use sqlx::postgres::{PgConnectOptions, PgSslMode};

use crate::unit::env_lock::with_env_vars;

fn material_path(snapshot: &SqlTlsSnapshot, key: &str) -> PathBuf {
    url::Url::parse(snapshot.url())
        .unwrap()
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| PathBuf::from(value.as_ref()))
        .unwrap()
}

#[test]
fn sql_tls_modes_match_native_drivers_for_every_database_consumer() {
    with_env_vars(&[], || {
        for mode in [
            OperatingMode::Database,
            OperatingMode::ControlPlane,
            OperatingMode::Migrate,
        ] {
            for (tls, pg, mysql) in [
                (
                    DbTlsMode::Disable,
                    PgSslMode::Disable,
                    MySqlSslMode::Disabled,
                ),
                (
                    DbTlsMode::Prefer,
                    PgSslMode::Prefer,
                    MySqlSslMode::Preferred,
                ),
                (
                    DbTlsMode::Require,
                    PgSslMode::Require,
                    MySqlSslMode::Required,
                ),
                (
                    DbTlsMode::VerifyCa,
                    PgSslMode::VerifyCa,
                    MySqlSslMode::VerifyCa,
                ),
                (
                    DbTlsMode::VerifyFull,
                    PgSslMode::VerifyFull,
                    MySqlSslMode::VerifyIdentity,
                ),
            ] {
                for db_type in ["postgres", "mysql"] {
                    let base = format!("{db_type}://localhost/ferrum");
                    let env = EnvConfig {
                        mode: mode.clone(),
                        db_type: Some(db_type.into()),
                        db_url: Some(base.clone()),
                        db_failover_urls: vec![base.clone()],
                        db_read_replica_url: Some(base),
                        db_tls_mode: Some(tls),
                        ..EnvConfig::default()
                    };
                    let mut urls = env.effective_db_failover_urls().unwrap();
                    urls.push(env.effective_db_url().unwrap().unwrap());
                    urls.push(env.effective_db_read_replica_url().unwrap().unwrap());
                    for url in urls {
                        // The driver ssl-mode enums do not implement `PartialEq`;
                        // compare their `Debug` renderings instead.
                        if db_type == "postgres" {
                            let actual = PgConnectOptions::from_str(&url).unwrap().get_ssl_mode();
                            assert_eq!(format!("{actual:?}"), format!("{pg:?}"));
                        } else {
                            let actual =
                                MySqlConnectOptions::from_str(&url).unwrap().get_ssl_mode();
                            assert_eq!(format!("{actual:?}"), format!("{mysql:?}"));
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn sql_tls_snapshot_keeps_all_accepted_material_after_source_replacement() {
    with_env_vars(&[], || {
        for (db_type, ca_key, cert_key, key_key) in [
            ("postgres", "sslrootcert", "sslcert", "sslkey"),
            ("mysql", "ssl-ca", "ssl-cert", "ssl-key"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut url = url::Url::parse(&format!("{db_type}://localhost/ferrum")).unwrap();
            for key in [ca_key, cert_key, key_key] {
                let path = dir.path().join(format!("{key} & material.pem"));
                std::fs::write(&path, format!("accepted {key}")).unwrap();
                url.query_pairs_mut()
                    .append_pair(key, path.to_str().unwrap());
            }
            let accepted = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            let retained = material_path(&accepted, ca_key);
            for key in [ca_key, cert_key, key_key] {
                std::fs::write(
                    dir.path().join(format!("{key} & material.pem")),
                    format!("candidate {key}"),
                )
                .unwrap();
                assert_eq!(
                    std::fs::read_to_string(material_path(&accepted, key)).unwrap(),
                    format!("accepted {key}"),
                );
            }
            let candidate = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            assert_eq!(
                std::fs::read_to_string(material_path(&candidate, ca_key)).unwrap(),
                format!("candidate {ca_key}"),
            );
            let rejected_path = material_path(&candidate, ca_key);
            drop(candidate);
            assert!(!rejected_path.exists());
            assert!(retained.exists());
            std::fs::remove_dir_all(dir.path()).unwrap();
            assert!(SqlTlsSnapshot::load(url.as_str(), db_type).is_err());
            assert_eq!(
                std::fs::read_to_string(&retained).unwrap(),
                format!("accepted {ca_key}"),
            );
            drop(accepted);
            assert!(!retained.exists());
        }
    });
}

#[test]
fn sql_tls_snapshot_selects_last_driver_alias_without_reading_shadowed_paths() {
    with_env_vars(&[], || {
        for (db_type, first, last) in [
            ("postgres", "sslrootcert", "ssl-ca"),
            ("mysql", "sslca", "ssl-ca"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ca.pem");
            std::fs::write(&path, "accepted CA").unwrap();
            let mut url = url::Url::parse(&format!("{db_type}://localhost/ferrum")).unwrap();
            url.query_pairs_mut()
                .append_pair(first, "/missing/shadowed.pem")
                .append_pair(last, path.to_str().unwrap());
            let snapshot = SqlTlsSnapshot::load(url.as_str(), db_type).unwrap();
            assert_eq!(
                std::fs::read_to_string(material_path(&snapshot, last)).unwrap(),
                "accepted CA",
            );
            assert!(!snapshot.url().contains("shadowed"));
        }
        let url = "sqlite::memory:";
        assert_eq!(SqlTlsSnapshot::load(url, "sqlite").unwrap().url(), url);
    });
}
