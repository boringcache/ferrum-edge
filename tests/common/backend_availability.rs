//! Shared fail-closed / local-skip gate for external database backends.
//!
//! Hosted CI sets `FERRUM_DB_BACKENDS_REQUIRED=1` (and, for TLS containers,
//! `FERRUM_DB_TLS_REQUIRED=1`) so a missing PostgreSQL/MySQL/MongoDB fixture
//! fails the job instead of returning success after a silent skip.
//!
//! Local developers keep the historical opt-out: leave those variables unset
//! and tests that need an absent backend print a skip message and return.

/// True when hosted CI (or a local fail-closed run) requires network DB backends.
pub fn db_backends_required() -> bool {
    env_flag_enabled("FERRUM_DB_BACKENDS_REQUIRED")
}

/// True when TLS database containers are required for this run.
pub fn db_tls_required() -> bool {
    env_flag_enabled("FERRUM_DB_TLS_REQUIRED")
}

fn env_flag_enabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            !(trimmed.is_empty()
                || trimmed == "0"
                || trimmed.eq_ignore_ascii_case("false")
                || trimmed.eq_ignore_ascii_case("no"))
        }
        Err(_) => false,
    }
}

/// Skip locally when `available` is false; panic when backends are required.
///
/// Returns `true` when the caller should continue running the test body.
#[must_use]
pub fn continue_if_backend_available(backend: &str, available: bool, detail: &str) -> bool {
    if available {
        return true;
    }
    if db_backends_required() {
        panic!("{backend} is required (FERRUM_DB_BACKENDS_REQUIRED) but unavailable: {detail}");
    }
    eprintln!("SKIPPED {backend}: {detail}");
    false
}

/// Skip locally when a TLS container/fixture is missing; panic when TLS is required.
#[must_use]
pub fn continue_if_tls_fixture_available(backend: &str, available: bool, detail: &str) -> bool {
    if available {
        return true;
    }
    if db_tls_required() {
        panic!("{backend} TLS fixture is required (FERRUM_DB_TLS_REQUIRED) but unavailable: {detail}");
    }
    eprintln!("SKIPPED {backend} TLS: {detail}");
    false
}

/// Resolve `FERRUM_TEST_POSTGRES_URL`, failing closed when backends are required.
pub fn postgres_test_url() -> Option<String> {
    match std::env::var("FERRUM_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ if db_backends_required() => {
            panic!(
                "PostgreSQL is required (FERRUM_DB_BACKENDS_REQUIRED) but FERRUM_TEST_POSTGRES_URL is unset"
            );
        }
        _ => {
            eprintln!("SKIPPED postgres: FERRUM_TEST_POSTGRES_URL is unset");
            None
        }
    }
}

/// Resolve `FERRUM_TEST_MYSQL_URL`, failing closed when backends are required.
pub fn mysql_test_url() -> Option<String> {
    match std::env::var("FERRUM_TEST_MYSQL_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ if db_backends_required() => {
            panic!(
                "MySQL is required (FERRUM_DB_BACKENDS_REQUIRED) but FERRUM_TEST_MYSQL_URL is unset"
            );
        }
        _ => {
            eprintln!("SKIPPED mysql: FERRUM_TEST_MYSQL_URL is unset");
            None
        }
    }
}

/// Probe TCP reachability for `host:port` extracted from a postgres/mysql/mongodb URL.
pub async fn tcp_endpoint_reachable(host_port: &str) -> bool {
    tokio::net::TcpStream::connect(host_port).await.is_ok()
}

/// Extract `host:port` from a SQL or MongoDB connection URL for a readiness probe.
pub fn host_port_from_db_url(url: &str) -> String {
    let stripped = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .or_else(|| url.strip_prefix("mysql://"))
        .or_else(|| url.strip_prefix("mongodb://"))
        .or_else(|| url.strip_prefix("mongodb+srv://"))
        .unwrap_or(url);

    let authority = stripped
        .split(['/', '?'])
        .next()
        .unwrap_or(stripped);

    let host_port = if authority.contains('@') {
        authority.split('@').next_back().unwrap_or(authority)
    } else {
        authority
    };

    if host_port.starts_with('[') {
        // IPv6 literal — keep bracket form as tokio accepts it for connect.
        host_port.to_string()
    } else if host_port.contains(':') {
        host_port.to_string()
    } else if url.starts_with("mysql://") {
        format!("{host_port}:3306")
    } else if url.starts_with("mongodb://") || url.starts_with("mongodb+srv://") {
        format!("{host_port}:27017")
    } else {
        format!("{host_port}:5432")
    }
}
