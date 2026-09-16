//! Pool-owned SQL TLS material. SQLx's Any driver parses the URL again for
//! every new connection, so retaining a pool alone does not retain its trust.
//! Private PEM copies keep both CA and client identity fixed for that pool's
//! entire lifetime, including idle eviction and server-initiated disconnects.

use std::io::Write;
use std::sync::Arc;

use sqlx::any::AnyPoolOptions;
use tempfile::NamedTempFile;

use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

pub struct SqlTlsSnapshot {
    url: String,
    files: Vec<NamedTempFile>,
}

impl SqlTlsSnapshot {
    /// Snapshot URL-owned and EnvConfig-derived PEM paths alike. No files are
    /// created for SQLite. Errors drop every partially prepared private file.
    pub fn load(db_url: &str, db_type: &str) -> Result<Self, sqlx::Error> {
        if !matches!(db_type, "postgres" | "mysql") {
            return Ok(Self {
                url: db_url.to_string(),
                files: Vec::new(),
            });
        }

        let mut url =
            url::Url::parse(db_url).map_err(|error| sqlx::Error::Configuration(error.into()))?;
        let pairs: Vec<_> = url.query_pairs().into_owned().collect();
        let mut files = Vec::new();
        // Preserve driver precedence for duplicate aliases: only the final
        // value of each material kind is used by the driver and snapshotted.
        let mut selected = std::collections::BTreeMap::new();
        for (index, (key, _)) in pairs.iter().enumerate() {
            if let Some(kind) = material_kind(db_type, key) {
                selected.insert(kind, index);
            }
        }

        if selected.is_empty() {
            return Ok(Self {
                url: db_url.to_string(),
                files,
            });
        }

        url.set_query(None);
        for (index, (key, value)) in pairs.iter().enumerate() {
            let Some(kind) = material_kind(db_type, key) else {
                url.query_pairs_mut().append_pair(key, value);
                continue;
            };
            if selected.get(&kind) != Some(&index) {
                continue;
            }
            let source = CertSource::parse(value, kind);
            let material = load_material_blocking(&source, kind)
                .map_err(|error| sqlx::Error::Configuration(error.into()))?;
            let mut file = tempfile::Builder::new()
                .prefix("ferrum-sql-tls-")
                .suffix(".pem")
                .tempfile()?;
            file.write_all(material.bytes.expose_secret())?;
            let path = file.path().to_str().ok_or_else(|| {
                sqlx::Error::Configuration("SQL TLS snapshot path is not UTF-8".into())
            })?;
            url.query_pairs_mut().append_pair(key, path);
            files.push(file);
        }
        Ok(Self {
            url: url.into(),
            files,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The pool owns its callbacks as long as it can establish connections.
    /// This default-true release hook only pins the private files; it leaves
    /// the existing after_connect session setup and checkout checks intact.
    pub(crate) fn pin(self, options: AnyPoolOptions) -> (AnyPoolOptions, String) {
        let url = self.url().to_string();
        let snapshot = Arc::new(self);
        let options = options.after_release(move |_, _| {
            let _keep_material_alive = &snapshot.files;
            Box::pin(async { Ok(true) })
        });
        (options, url)
    }
}

fn material_kind(db_type: &str, key: &str) -> Option<MaterialKind> {
    match (db_type, key) {
        ("postgres", "sslrootcert" | "ssl-root-cert" | "ssl-ca")
        | ("mysql", "sslca" | "ssl-ca") => Some(MaterialKind::CaBundle),
        ("postgres" | "mysql", "sslcert" | "ssl-cert") => Some(MaterialKind::Cert),
        ("postgres" | "mysql", "sslkey" | "ssl-key") => Some(MaterialKind::Key),
        _ => None,
    }
}
