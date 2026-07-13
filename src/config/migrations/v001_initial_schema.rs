use sha2::{Digest, Sha256};
use sqlx::AnyConnection;
use std::sync::OnceLock;

use super::Migration;
use super::sql_dialect::V001SqlBuilder;

/// V1: Initial schema — creates the baseline tables.
/// This matches the original inline schema from db_loader.rs.
pub struct V001InitialSchema;

impl Migration for V001InitialSchema {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "initial_schema"
    }

    fn checksum(&self) -> &str {
        static CHECKSUM: OnceLock<String> = OnceLock::new();
        CHECKSUM.get_or_init(|| {
            let mut hasher = Sha256::new();
            hasher.update(include_bytes!("v001_initial_schema.rs"));
            hasher.update(include_bytes!("sql_dialect.rs"));
            format!("sha256:{}", hex::encode(hasher.finalize()))
        })
    }
}

impl V001InitialSchema {
    pub async fn up(
        &self,
        connection: &mut AnyConnection,
        db_type: &str,
    ) -> Result<(), anyhow::Error> {
        V001SqlBuilder::new(db_type).apply(connection).await
    }
}
