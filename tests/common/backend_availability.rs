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
        panic!(
            "{backend} TLS fixture is required (FERRUM_DB_TLS_REQUIRED) but unavailable: {detail}"
        );
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

/// Best-effort resume of shared CI database containers.
///
/// Connectivity-recovery cells intentionally `docker pause` the shared MySQL /
/// PostgreSQL fixtures. If a prior attempt is interrupted before `Drop`
/// unpauses, later cells see a frozen backend and fail gateway health waits.
/// Calling this at the start of each SQL-backed cell keeps the matrix
/// deterministic without weakening required-backend flags.
pub fn ensure_shared_sql_containers_resumed() {
    for container in [
        "ferrum-ci-mysql",
        "ferrum-ci-postgres",
        "ferrum-test-mysql-tls",
        "ferrum-test-pg-tls",
    ] {
        let _ = std::process::Command::new("docker")
            .args(["unpause", container])
            .output();
    }
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

    let authority = stripped.split(['/', '?']).next().unwrap_or(stripped);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IsolatedSqlKind {
    Postgres,
    Mysql,
}

/// Owns a per-cell PostgreSQL/MySQL database created against a known CI
/// container. Dropped after the gateway process so later cells cannot load
/// poison rows left by a prior shared-database failure.
pub struct IsolatedSqlDatabase {
    container: String,
    db_name: String,
    kind: IsolatedSqlKind,
    user: String,
    password: String,
}

impl Drop for IsolatedSqlDatabase {
    fn drop(&mut self) {
        // MySQL rejects DROP DATABASE while sessions still hold the schema;
        // gateway Drop kills the child, but server-side cleanup can lag briefly.
        // Postgres uses WITH (FORCE); MySQL gets a short sync retry loop.
        let attempts = match self.kind {
            IsolatedSqlKind::Postgres => 1,
            IsolatedSqlKind::Mysql => 5,
        };
        let mut last_stderr = String::new();
        for attempt in 0..attempts {
            let output = match self.kind {
                IsolatedSqlKind::Postgres => std::process::Command::new("docker")
                    .args([
                        "exec",
                        &self.container,
                        "psql",
                        "-U",
                        &self.user,
                        "-d",
                        "postgres",
                        "-v",
                        "ON_ERROR_STOP=1",
                        "-c",
                        &format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE);", self.db_name),
                    ])
                    .output(),
                IsolatedSqlKind::Mysql => std::process::Command::new("docker")
                    .env("MYSQL_PWD", &self.password)
                    .args([
                        "exec",
                        "-e",
                        "MYSQL_PWD",
                        &self.container,
                        "mysql",
                        &format!("-u{}", self.user),
                        "-e",
                        &format!("DROP DATABASE IF EXISTS `{}`;", self.db_name),
                    ])
                    .output(),
            };
            match output {
                Ok(output) if output.status.success() => return,
                Ok(output) => {
                    last_stderr =
                        scrub_secret(&String::from_utf8_lossy(&output.stderr), &self.password);
                }
                Err(error) => {
                    last_stderr = scrub_secret(&error.to_string(), &self.password);
                }
            }
            if attempt + 1 < attempts {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        eprintln!(
            "WARN: failed to drop isolated {} database {} in {}: {}",
            match self.kind {
                IsolatedSqlKind::Postgres => "postgres",
                IsolatedSqlKind::Mysql => "mysql",
            },
            self.db_name,
            self.container,
            last_stderr
        );
    }
}

fn ci_sql_container(host_port: &str) -> Option<(&'static str, IsolatedSqlKind)> {
    let normalized = host_port
        .strip_prefix("127.0.0.1:")
        .or_else(|| host_port.strip_prefix("localhost:"))
        .unwrap_or(host_port);
    match normalized {
        "5432" => Some(("ferrum-ci-postgres", IsolatedSqlKind::Postgres)),
        "3306" => Some(("ferrum-ci-mysql", IsolatedSqlKind::Mysql)),
        "15432" => Some(("ferrum-test-pg-tls", IsolatedSqlKind::Postgres)),
        "13306" => Some(("ferrum-test-mysql-tls", IsolatedSqlKind::Mysql)),
        _ => None,
    }
}

fn sql_url_credentials(url: &str) -> Option<(String, String)> {
    let stripped = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .or_else(|| url.strip_prefix("mysql://"))?;
    let authority = stripped.split(['/', '?']).next()?;
    let userinfo = authority.split('@').next()?;
    if !userinfo.contains(':') || !authority.contains('@') {
        return None;
    }
    let (user, password) = userinfo.split_once(':')?;
    // Connection URLs percent-encode reserved characters; docker CLI args need
    // the decoded secret.
    let user = percent_decode(user);
    let password = percent_decode(password);
    Some((user, password))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        if bytes[i] == b'+' {
            // application/x-www-form-urlencoded treats '+' as space; URL userinfo
            // does not, so keep literal '+'.
            out.push(b'+');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn rewrite_sql_url_database(url: &str, db_name: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, after_authority) = rest.split_once('/')?;
    let query = after_authority.find('?').map(|idx| &after_authority[idx..]);
    Some(match query {
        Some(query) => format!("{scheme}://{authority}/{db_name}{query}"),
        None => format!("{scheme}://{authority}/{db_name}"),
    })
}

fn redact_db_url(url: &str) -> String {
    ferrum_edge::config::db_backend::redact_url(url)
}

fn scrub_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "***")
}

/// Create a unique database on a known CI SQL container and return a URL that
/// points at it. Non-CI URLs keep the shared database (no-op isolation).
///
/// When backends/TLS fixtures are required and the URL maps to a CI container,
/// failure to create the database panics instead of silently sharing state.
pub fn provision_isolated_sql_database(base_url: &str) -> (String, Option<IsolatedSqlDatabase>) {
    let host_port = host_port_from_db_url(base_url);
    let Some((container, kind)) = ci_sql_container(&host_port) else {
        return (base_url.to_string(), None);
    };
    let Some((user, password)) = sql_url_credentials(base_url) else {
        if db_backends_required() || db_tls_required() {
            panic!(
                "cannot isolate SQL database for required CI backend: credentials missing in {}",
                redact_db_url(base_url)
            );
        }
        return (base_url.to_string(), None);
    };

    let db_name = format!("ferrum_cell_{}", uuid::Uuid::new_v4().simple());
    let create_output = match kind {
        IsolatedSqlKind::Postgres => std::process::Command::new("docker")
            .args([
                "exec",
                container,
                "psql",
                "-U",
                &user,
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                &format!("CREATE DATABASE \"{db_name}\";"),
            ])
            .output(),
        IsolatedSqlKind::Mysql => std::process::Command::new("docker")
            // Borrow so failure redaction (and IsolatedSqlDatabase ownership) retain the secret.
            .env("MYSQL_PWD", &password)
            .args([
                "exec",
                "-e",
                "MYSQL_PWD",
                container,
                "mysql",
                &format!("-u{user}"),
                "-e",
                &format!("CREATE DATABASE `{db_name}`;"),
            ])
            .output(),
    };

    let created = create_output
        .as_ref()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !created {
        let detail = create_output
            .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
            .unwrap_or_else(|error| error.to_string());
        // Scrub both the raw secret and any verbatim URL echo from docker/cli.
        let detail = ferrum_edge::config::db_backend::redact_error_text(
            scrub_secret(&detail, &password),
            &[base_url],
        );
        if db_backends_required() || db_tls_required() {
            panic!(
                "failed to create isolated SQL database {db_name} in {container} \
                 (required for CI cell isolation): {detail}"
            );
        }
        eprintln!(
            "WARN: could not isolate SQL database on {container}; reusing shared URL ({detail})"
        );
        return (base_url.to_string(), None);
    }

    let Some(url) = rewrite_sql_url_database(base_url, &db_name) else {
        panic!(
            "failed to rewrite isolated database URL for {}",
            redact_db_url(base_url)
        );
    };
    (
        url,
        Some(IsolatedSqlDatabase {
            container: container.to_string(),
            db_name,
            kind,
            user,
            password,
        }),
    )
}
