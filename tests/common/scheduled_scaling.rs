//! Shared policy for the scheduled 10k/30k scaling harnesses (issue #3892).
//!
//! Admin JWT lifetime is sized to the Scheduled Scaling Regression job timeout
//! (180 minutes) plus a one-hour margin, and the spawned gateway is configured
//! to accept that same maximum TTL. Consumer JWTs stay on their own 1-hour
//! minting path and must not reuse this constant.
//!
//! `POST /batch` is all-or-nothing. The only retried failure is the documented
//! namespace-fence response: HTTP 503 plus
//! `{"error":"Namespace mutation is temporarily unavailable; retry later"}`.

#![allow(dead_code)]

use std::time::Duration;

use serde_json::json;

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
pub const NAMESPACE_FENCE_MAX_ATTEMPTS: u32 = 6;

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

fn is_documented_namespace_fence_body(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Object(map) => {
            map.len() == 1
                && map.get("error").and_then(serde_json::Value::as_str)
                    == Some(NAMESPACE_FENCE_RETRY_MESSAGE)
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
    if (200..300).contains(&status) {
        return BatchProvisionDecision::Success;
    }
    if status == 503 && is_documented_namespace_fence_body(body) {
        return BatchProvisionDecision::Retry {
            delay: namespace_fence_retry_after_delay(retry_after),
        };
    }
    BatchProvisionDecision::Fatal {
        status,
        body: body.to_string(),
    }
}

/// POST one atomic batch body, retrying only the documented namespace-fence 503.
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
                return Err(format!(
                    "{operation} failed: {status} (unreadable body: {err})"
                )
                .into());
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
                tokio::time::sleep(delay).await;
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
