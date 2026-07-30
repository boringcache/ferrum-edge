//! Classify notification delivery outcomes as success, transient failure, or
//! permanent failure.
//!
//! Transient outcomes are eligible for the bounded, jittered retry policy in
//! [`super::dispatch`]. Permanent outcomes fail immediately so a bad webhook
//! URL or auth rejection cannot burn the retry budget.
//!
//! HTTP status semantics mirror the shared batch-log helper:
//! - 2xx → success
//! - 408 / 429 / 5xx → transient
//! - other 4xx → permanent
//! - transport / connect / timeout errors → transient

use std::fmt;

use reqwest::StatusCode;

/// Fixed channel-type label set. Never derived from operator-chosen channel
/// *names* — only from the compiled-in transport discriminant — so Prometheus
/// cardinality stays bounded at five series per metric family.
pub const CHANNEL_TYPES: &[&str] = &["slack", "teams", "discord", "webhook", "email"];

/// Whether a failed delivery may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// Likely temporary (timeout, 429, 5xx, connect blip). Retry with backoff.
    Transient,
    /// Caller / config / auth fault. Do not retry.
    Permanent,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
        }
    }
}

/// Result of one channel send attempt (before retry policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryAttempt {
    Success,
    Failed {
        class: FailureClass,
        message: String,
    },
}

impl DeliveryAttempt {
    pub fn failed(class: FailureClass, message: impl Into<String>) -> Self {
        Self::Failed {
            class,
            message: message.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Failed {
                class: FailureClass::Transient,
                ..
            }
        )
    }
}

impl fmt::Display for DeliveryAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failed { class, message } => {
                write!(f, "{class} failure: {message}", class = class.as_str())
            }
        }
    }
}

/// Classify an HTTP response status for notification delivery.
pub fn classify_http_status(status: StatusCode) -> FailureClass {
    if status.is_success() {
        // Callers should not invoke this for success; treat as permanent so a
        // misuse cannot enter the retry loop.
        return FailureClass::Permanent;
    }
    if status == StatusCode::REQUEST_TIMEOUT || status == StatusCode::TOO_MANY_REQUESTS {
        return FailureClass::Transient;
    }
    if status.is_server_error() {
        return FailureClass::Transient;
    }
    if status.is_client_error() {
        return FailureClass::Permanent;
    }
    // 1xx / 3xx and other unexpected statuses: treat as transient so a flaky
    // intermediary cannot permanently suppress alerts.
    FailureClass::Transient
}

/// Classify a reqwest transport error (no HTTP status obtained).
pub fn classify_transport_error(error: &reqwest::Error) -> FailureClass {
    if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
        return FailureClass::Transient;
    }
    // Status-bearing reqwest errors are unusual on our path (we read status
    // ourselves); fall through to transient so we do not permanently drop.
    FailureClass::Transient
}

/// Classify an SMTP channel failure.
pub fn classify_smtp_failure(failure: &super::channels::email::SmtpFailure) -> FailureClass {
    use super::channels::email::SmtpFailure;
    match failure {
        SmtpFailure::Resolve
        | SmtpFailure::Connect
        | SmtpFailure::Timeout(_)
        | SmtpFailure::Io(_)
        | SmtpFailure::ClosedEarly(_)
        | SmtpFailure::TlsHandshake => FailureClass::Transient,
        SmtpFailure::UnexpectedCode { code, .. } if (400..500).contains(code) => {
            FailureClass::Transient
        }
        SmtpFailure::EgressDenied(_)
        | SmtpFailure::TlsSetup
        | SmtpFailure::StartTlsUnsupported
        | SmtpFailure::StartTlsResidualData
        | SmtpFailure::MalformedReply(_)
        | SmtpFailure::ReplyTooLarge(_)
        | SmtpFailure::UnexpectedCode { .. }
        | SmtpFailure::CredentialReflected(_)
        | SmtpFailure::NoSupportedAuthMechanism => FailureClass::Permanent,
    }
}

/// Build a [`DeliveryAttempt::Failed`] from a non-success HTTP status.
pub fn http_status_failure(
    channel: &str,
    status: StatusCode,
    redacted_url: &str,
) -> DeliveryAttempt {
    let class = classify_http_status(status);
    DeliveryAttempt::failed(
        class,
        format!("{channel} dispatch returned non-success status {status} from {redacted_url}"),
    )
}
