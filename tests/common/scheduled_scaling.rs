//! Shared policy for the scheduled 10k/30k scaling harnesses (issue #3892).
//!
//! Admin JWT lifetime is sized to the Scheduled Scaling Regression job timeout
//! (180 minutes) plus a one-hour margin, and the spawned gateway is configured
//! to accept that same maximum TTL. Consumer JWTs stay on their own 1-hour
//! minting path and must not reuse this constant.
//!
//! `POST /batch` is all-or-nothing. The only retried failures are the documented
//! HTTP 503 bodies: the namespace-fence object
//! `{"error":"Namespace mutation is temporarily unavailable; retry later"}` and
//! the persistence/lease object `{"error": <string>, "rollback": "not_needed"}`.

#![allow(dead_code)]

use std::time::Duration;

use serde_json::json;

/// Documented `rollback` value for all-or-nothing persistence/lease 503s.
pub const BATCH_ROLLBACK_NOT_NEEDED: &str = "not_needed";

/// Documented admin-facing namespace-fence retry message.
pub const NAMESPACE_FENCE_RETRY_MESSAGE: &str =
    "Namespace mutation is temporarily unavailable; retry later";

/// Admin JWT TTL for the scheduled scale/load harnesses, in seconds.
///
/// The workflow job timeout is 180 minutes (10800s). Tokens are minted after
/// setup, so 4 hours covers the remaining job budget with a bounded margin.
pub const SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS: i64 = 4 * 60 * 60;

/// Default sleep when `Retry-After` is absent or unusable (documented value).
pub const NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS: u64 = 1;

/// Cap on honored `Retry-After` delay-seconds so a huge header cannot stall
/// a 180-minute job.
pub const NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS: u64 = 5;

/// Bounded attempts for one atomic `POST /batch` body (1 try + retries).
///
/// The gateway answers the namespace fence with a constant `Retry-After: 1`
/// (`docs/admin_api.md`, `openapi.yaml`), so the header alone never widens the
/// wait. Paired with [`namespace_fence_backoff`] this budget is ~151 seconds
/// per body rather than the ~5 seconds a header-only schedule would give.
pub const NAMESPACE_FENCE_MAX_ATTEMPTS: u32 = 10;

/// Ceiling for one backed-off namespace-fence wait, in seconds.
pub const NAMESPACE_FENCE_MAX_BACKOFF_SECS: u64 = 30;

/// Per-request timeout for one atomic admin batch mutation.
///
/// The scale harness's general HTTP client uses a 60-second timeout for data
/// plane probes. Growing SQL-backed configuration sets can legitimately need
/// longer than that to commit one admin batch. Give the mutation a bounded
/// five-minute budget instead of retrying an ambiguous transport timeout: the
/// server may have committed even when the client did not receive a response.
pub const ADMIN_BATCH_REQUEST_TIMEOUT_SECS: u64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchProvisionDecision {
    Success,
    Retry { delay: Duration },
    Fatal { status: u16, body: String },
}

/// Env value paired with [`SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS`] so the
/// gateway's `FERRUM_ADMIN_JWT_MAX_TTL` accepts the harness-minted admin JWT.
pub fn scheduled_scaling_admin_jwt_max_ttl_value() -> String {
    SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS.to_string()
}

pub fn namespace_fence_retry_after_delay(header: Option<&str>) -> Duration {
    let secs = match header.map(str::trim) {
        Some(raw) if !raw.is_empty() => match raw.parse::<u64>() {
            Ok(0) => NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS,
            Ok(parsed) => parsed.min(NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS),
            Err(_) => NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS,
        },
        _ => NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS,
    };
    Duration::from_secs(secs)
}

/// Exponential floor for the wait before retry `attempt` (1-based).
///
/// `Retry-After` is documented as the *minimum* delay, and the gateway always
/// sends `1`, so honoring only the header spends the whole attempt budget in
/// about five seconds. The scheduled-scaling failures this harness exists for
/// (issue #3892) fenced the namespace while the admin plane was saturated and
/// were still fenced minutes later, so each retry also waits at least this
/// long. Doubling stops at [`NAMESPACE_FENCE_MAX_BACKOFF_SECS`], giving a
/// worst-case 1+2+4+8+16+30+30+30+30 = 151s for one atomic body. The first
/// exhausted body aborts provisioning, so that is the total added cost of a
/// fence that never clears — bounded well inside the 180-minute job budget.
pub fn namespace_fence_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    Duration::from_secs((1u64 << shift).min(NAMESPACE_FENCE_MAX_BACKOFF_SECS))
}

fn is_documented_retryable_batch_503_body(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Object(map) => {
            let error = map.get("error").and_then(serde_json::Value::as_str);
            if map.len() == 1 {
                return error == Some(NAMESPACE_FENCE_RETRY_MESSAGE);
            }
            map.len() == 2
                && error.is_some()
                && map.get("rollback").and_then(serde_json::Value::as_str)
                    == Some(BATCH_ROLLBACK_NOT_NEEDED)
        }
        _ => false,
    }
}

/// Classify a completed HTTP response to an atomic `POST /batch`.
///
/// Transport errors and unreadable bodies never reach this function and must
/// not be retried by the caller.
pub fn classify_admin_batch_response(
    status: u16,
    retry_after: Option<&str>,
    body: &str,
) -> BatchProvisionDecision {
    // POST /batch documents exactly one successful outcome. Treat every other
    // status, including generic 2xx and partial-success responses, as fatal so
    // a scaling gate cannot accept a partially or unexpectedly applied graph.
    if status == 201 {
        return BatchProvisionDecision::Success;
    }
    if status == 503 && is_documented_retryable_batch_503_body(body) {
        return BatchProvisionDecision::Retry {
            delay: namespace_fence_retry_after_delay(retry_after),
        };
    }
    BatchProvisionDecision::Fatal {
        status,
        body: body.to_string(),
    }
}

/// POST one atomic batch body, retrying only the documented all-or-nothing 503s.
pub async fn post_admin_batch(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    body: &serde_json::Value,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/batch", admin_url);
    let mut last_status = 0u16;
    let mut last_body = String::new();

    for attempt in 1..=NAMESPACE_FENCE_MAX_ATTEMPTS {
        let response = match client
            .post(&url)
            .header("Authorization", auth_header)
            .json(body)
            .timeout(Duration::from_secs(ADMIN_BATCH_REQUEST_TIMEOUT_SECS))
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) => {
                return Err(format!("{operation} transport error: {err}").into());
            }
        };

        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body_text = match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return Err(
                    format!("{operation} failed: {status} (unreadable body: {err})").into(),
                );
            }
        };

        match classify_admin_batch_response(status, retry_after.as_deref(), &body_text) {
            BatchProvisionDecision::Success => return Ok(()),
            BatchProvisionDecision::Fatal { status, body } => {
                return Err(format!("{operation} failed: {status} - {body}").into());
            }
            BatchProvisionDecision::Retry { delay } => {
                last_status = status;
                last_body = body_text;
                if attempt == NAMESPACE_FENCE_MAX_ATTEMPTS {
                    break;
                }
                // The classified `delay` is the server's documented minimum;
                // the exponential floor is what lets a bounded attempt count
                // outlast a fence that survives longer than one second.
                tokio::time::sleep(delay.max(namespace_fence_backoff(attempt))).await;
            }
        }
    }

    Err(format!(
        "{operation} failed after {NAMESPACE_FENCE_MAX_ATTEMPTS} attempts: {last_status} - {last_body}"
    )
    .into())
}

/// Canonical JSON body used by the documented namespace-fence contract.
pub fn documented_namespace_fence_body() -> serde_json::Value {
    json!({ "error": NAMESPACE_FENCE_RETRY_MESSAGE })
}

/// Canonical JSON body used by documented persistence/lease 503s.
pub fn documented_batch_rollback_not_needed_body(error: &str) -> serde_json::Value {
    json!({ "error": error, "rollback": BATCH_ROLLBACK_NOT_NEEDED })
}
