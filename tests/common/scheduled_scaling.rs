//! Shared policy for the scheduled 10k/30k scaling harnesses (issue #3892).
//!
//! Admin JWT lifetime is sized to the Scheduled Scaling Regression job timeout
//! (300 minutes) plus a one-hour margin, and the spawned gateway is configured
//! to accept that same maximum TTL. Consumer JWTs stay on their own 1-hour
//! minting path and must not reuse this constant.
//!
//! `POST /batch` is all-or-nothing. The only retried failures are the documented
//! HTTP 503 bodies: the namespace-fence object
//! `{"error":"Namespace mutation is temporarily unavailable; retry later"}` and
//! the persistence/lease object `{"error": <string>, "rollback": "not_needed"}`.

#![allow(dead_code)]

use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::json;

/// Documented `rollback` value for all-or-nothing persistence/lease 503s.
pub const BATCH_ROLLBACK_NOT_NEEDED: &str = "not_needed";

/// Documented admin-facing namespace-fence retry message.
pub const NAMESPACE_FENCE_RETRY_MESSAGE: &str =
    "Namespace mutation is temporarily unavailable; retry later";

/// Admin JWT TTL for the scheduled scale/load harnesses, in seconds.
///
/// The workflow job timeout is 300 minutes (issue #4136). Tokens are minted
/// after setup, so 6 hours covers the remaining budget with margin.
///
/// This MUST stay above the job budget: the harness mints ONE token for the
/// whole run and hands its TTL to the gateway as `FERRUM_ADMIN_JWT_MAX_TTL`,
/// so a token shorter than the job makes provisioning fail on auth partway
/// through — on whichever leg runs long enough to reach it.
pub const SCHEDULED_SCALING_ADMIN_JWT_TTL_SECS: i64 = 6 * 60 * 60;

/// Default sleep when `Retry-After` is absent or unusable (documented value).
pub const NAMESPACE_FENCE_DEFAULT_RETRY_AFTER_SECS: u64 = 1;

/// Cap on honored `Retry-After` delay-seconds so a huge header cannot stall
/// a 300-minute job.
pub const NAMESPACE_FENCE_MAX_RETRY_AFTER_SECS: u64 = 5;

/// Wall-clock budget for retrying ONE atomic `POST /batch` body.
///
/// An attempt-counted budget is the wrong shape for a documented-*transient*
/// contention 503. The namespace admission critical section is deliberately
/// serialized (`lock_mtls_dns_admission_tx` plus `lock_config_change_sequence_tx`
/// in `src/config/db_loader.rs`), so what decides whether this body is admitted
/// is how long the writer queue ahead of it takes to drain — not how many times
/// this client asks. Bound the wall clock and let [`namespace_fence_backoff`]
/// decide how many attempts fit inside it.
///
/// Ten minutes is five full server-side admission lease lifetimes
/// (`CONFIG_ADMISSION_LEASE_DURATION`, 120s). A queue that cannot admit one
/// body across five consecutive lease lifetimes is not transient contention;
/// it is an admission outage, and the harness must fail and say so.
pub const NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS: u64 = 10 * 60;

/// Secondary spin guard on attempts for one atomic `POST /batch` body.
///
/// [`NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS`] is the real bound; this only stops
/// a pathological zero-latency 503 loop from spinning. It is deliberately set
/// so the backoff schedule always exceeds the wall-clock budget before the
/// attempt ceiling can bind (see the unit contract in
/// `tests/unit/config/scheduled_scaling_tests.rs`).
pub const NAMESPACE_FENCE_MAX_ATTEMPTS: u32 = 40;

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
    /// The batch COMMITTED durably but the runtime had not published it yet.
    ///
    /// `POST /batch` answers 503 with `applied: false` and
    /// `reason: reload_timeout` / `sequence_unavailable` when the live-apply
    /// wait elapses (`LiveApplyFailure::error_message`, "Configuration was
    /// committed but is not live"). The resources EXIST, so re-posting the same
    /// all-or-nothing body would collide with itself; the caller must move on
    /// and gate on convergence instead.
    CommittedNotLive {
        reason: String,
    },
    Retry {
        delay: Duration,
    },
    Fatal {
        status: u16,
        body: String,
    },
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
/// sends `1`, so honoring only the header would retry roughly once a second.
/// The scheduled-scaling failures this harness exists for (issue #3892) fenced
/// the namespace while the admin plane was saturated and were still fenced
/// minutes later, so each retry also waits at least this long. Doubling stops
/// at [`NAMESPACE_FENCE_MAX_BACKOFF_SECS`], so the steady-state retry rate is
/// one every 30 seconds — slow enough that a client waiting on a serialized
/// admission lock is not itself adding load to the queue it is waiting for.
///
/// The first exhausted body aborts provisioning, so
/// [`NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS`] plus one in-flight
/// [`ADMIN_BATCH_REQUEST_TIMEOUT_SECS`] is the total added cost of a fence that
/// never clears — bounded well inside the 300-minute job budget.
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

/// Recognize the documented "committed but not live" `POST /batch` answer.
///
/// `reload_timeout` and `sequence_unavailable` both mean the write is DURABLE
/// and only its publication is unconfirmed, so provisioning must continue and
/// let the convergence gate decide when the data plane caught up. Retrying is
/// wrong (the resources already exist) and failing is wrong (nothing was lost).
///
/// `config_rejected` is deliberately NOT included: there the runtime refused
/// the candidate, so it will never go live and the harness must fail loudly.
fn committed_not_live_reason(status: u16, body: &str) -> Option<String> {
    if status != 503 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let map = value.as_object()?;
    if map.get("applied").and_then(serde_json::Value::as_bool) != Some(false) {
        return None;
    }
    let reason = map.get("reason").and_then(serde_json::Value::as_str)?;
    matches!(reason, "reload_timeout" | "sequence_unavailable").then(|| reason.to_string())
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
    if let Some(reason) = committed_not_live_reason(status, body) {
        return BatchProvisionDecision::CommittedNotLive { reason };
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
    let started = Instant::now();
    let retry_budget = Duration::from_secs(NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS);
    let mut attempts = 0u32;

    for attempt in 1..=NAMESPACE_FENCE_MAX_ATTEMPTS {
        attempts += 1;
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
            BatchProvisionDecision::CommittedNotLive { reason } => {
                // Durable, just not published yet. Carry on: the caller's
                // bounded convergence gate is what decides when the data plane
                // has caught up, and it reports far better than a retry here.
                eprintln!(
                    "{operation}: committed but not yet live ({reason}); \
                     continuing to the convergence gate"
                );
                return Ok(());
            }
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
                // the exponential floor is what keeps a waiting client from
                // adding load to the serialized admission queue it is waiting
                // for.
                let wait = delay.max(namespace_fence_backoff(attempt));
                // Stop when the next wait would leave the wall-clock budget,
                // so the reported bound is the one that was actually honored.
                if started.elapsed() + wait >= retry_budget {
                    break;
                }
                tokio::time::sleep(wait).await;
            }
        }
    }

    Err(format!(
        "{operation} was still refused as transient namespace-admission contention after \
         {attempts} attempts over {elapsed:.1}s (budget {NAMESPACE_FENCE_MAX_TOTAL_RETRY_SECS}s, \
         attempt ceiling {NAMESPACE_FENCE_MAX_ATTEMPTS}); treating it as a non-transient \
         admission outage: {last_status} - {last_body}",
        elapsed = started.elapsed().as_secs_f64()
    )
    .into())
}

/// Wall-clock bound on waiting for freshly provisioned config to become
/// routable before a measurement phase starts.
///
/// Provisioning a batch appends tens of thousands of `config_changes` rows.
/// When the poller's cursor falls more than `CHANGE_LOG_BATCH_LIMIT` (10,000)
/// rows behind, `load_config_changes_after` deliberately bails and forces a
/// FULL reload; on a SQL store with tens of thousands of proxies, consumers and
/// plugin configs that reload takes a substantial fraction of a 30-second
/// measurement window. Both safety valves are correct — but a throughput
/// measurement started inside that window measures convergence, not routing.
///
/// Five minutes is the bound on waiting it out. Both harnesses poll the
/// database every 2 seconds (`FERRUM_DB_POLL_INTERVAL=2`), and the forced full
/// reload observed at 9,000 proxies consumed roughly half of a 30-second
/// window, so 300s is an order of magnitude above a linear extrapolation to
/// 30,000 proxies. It also keeps the scale harness's ten-batch worst case
/// (50 minutes) plus provisioning inside the 300-minute job budget, so a
/// chronically non-converging gateway reports this explicit diagnostic rather
/// than a silent job timeout.
pub const CONFIG_CONVERGENCE_MAX_WAIT_SECS: u64 = 5 * 60;

/// Interval between convergence probes.
pub const CONFIG_CONVERGENCE_POLL_INTERVAL_SECS: u64 = 2;

/// How long a bounded convergence wait actually took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvergenceOutcome {
    pub waited: Duration,
    pub polls: u32,
}

/// Block until every sample probes routable, or fail with an explicit
/// convergence diagnostic.
///
/// `probe(index)` must issue one data-plane request for `samples[index]` and
/// return the HTTP status, or the transport error text. `samples` carries the
/// human-readable identity of each sample for the failure message only.
///
/// This exists so a measurement phase can never start against a configuration
/// the gateway has not published yet. The failure it returns is deliberately
/// distinct from a throughput assertion: "config never converged" and
/// "routing collapsed" are different defects and must not be reported as the
/// same one.
pub async fn wait_for_config_convergence<F, Fut>(
    label: &str,
    samples: &[String],
    mut probe: F,
) -> Result<ConvergenceOutcome, String>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<u16, String>>,
{
    if samples.is_empty() {
        return Err(format!(
            "config convergence for {label} was asked to wait on an empty sample set"
        ));
    }

    let budget = Duration::from_secs(CONFIG_CONVERGENCE_MAX_WAIT_SECS);
    let started = Instant::now();
    let mut polls = 0u32;
    let mut last: Vec<String> = vec!["not probed".to_string(); samples.len()];

    loop {
        polls += 1;
        let mut converged = true;
        for (index, outcome) in last.iter_mut().enumerate() {
            match probe(index).await {
                Ok(status) => {
                    *outcome = format!("HTTP {status}");
                    if !(200..300).contains(&status) {
                        converged = false;
                    }
                }
                Err(error) => {
                    *outcome = format!("transport error: {error}");
                    converged = false;
                }
            }
        }

        if converged {
            return Ok(ConvergenceOutcome {
                waited: started.elapsed(),
                polls,
            });
        }

        if started.elapsed() >= budget {
            let detail = samples
                .iter()
                .zip(last.iter())
                .map(|(sample, outcome)| format!("{sample} -> {outcome}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "config convergence never completed for {label}: waited {waited:.1}s across \
                 {polls} polls (bound {CONFIG_CONVERGENCE_MAX_WAIT_SECS}s); last sample outcomes: \
                 {detail}. This is a configuration-publication failure, not a throughput \
                 regression.",
                waited = started.elapsed().as_secs_f64()
            ));
        }

        tokio::time::sleep(Duration::from_secs(CONFIG_CONVERGENCE_POLL_INTERVAL_SECS)).await;
    }
}

/// Canonical JSON body used by the documented namespace-fence contract.
pub fn documented_namespace_fence_body() -> serde_json::Value {
    json!({ "error": NAMESPACE_FENCE_RETRY_MESSAGE })
}

/// Canonical JSON body used by documented persistence/lease 503s.
pub fn documented_batch_rollback_not_needed_body(error: &str) -> serde_json::Value {
    json!({ "error": error, "rollback": BATCH_ROLLBACK_NOT_NEEDED })
}
