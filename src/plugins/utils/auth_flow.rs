use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::config::types::Consumer;
use crate::consumer_index::ConsumerIndex;
use crate::plugins::{PluginResult, RequestContext};

use super::auth_attempt::AuthenticationAttempt;

/// What an auth plugin extracted from the request.
#[derive(Debug, Clone)]
pub enum ExtractedCredential {
    BearerToken(String),
    ApiKey(String),
    BasicAuth {
        username: String,
        password: String,
    },
    /// Boxed because this variant is much larger than the others; an
    /// `ExtractedCredential` is also wrapped by other enums (e.g.
    /// `TokenLocationExtract`), so keeping it small avoids inflating them.
    HmacAuth(Box<HmacAuthCredential>),
    MtlsCert {
        der_bytes: Arc<Vec<u8>>,
        chain_der: Option<Arc<Vec<Vec<u8>>>>,
        connection_cache: Option<Arc<crate::plugins::mtls_auth::MtlsAuthConnectionCache>>,
    },
    /// Extract failed before verification could run (bad header scheme,
    /// malformed base64, missing required companion header, etc.).
    InvalidFormat(String),
    /// No credential present — multi-auth can continue with the next plugin.
    Missing,
}

/// HMAC credential fields extracted from a request, used to reconstruct the
/// signing string and verify the body digest. Boxed inside
/// [`ExtractedCredential::HmacAuth`].
#[derive(Debug, Clone)]
pub struct HmacAuthCredential {
    /// Namespace of the matched proxy. HMAC identity resolution is scoped to
    /// this namespace and the value is bound into the signing base.
    pub namespace: String,
    pub username: String,
    /// Canonical client-request authority bound into the versioned signature
    /// base so a captured request cannot cross virtual-host boundaries.
    pub authority: String,
    pub algorithm: String,
    pub signature: String,
    pub date: String,
    pub method: String,
    pub path: String,
    /// Raw request query string (verbatim, percent-encoded as received), bound
    /// into the signing string so query parameters cannot be altered without
    /// invalidating the HMAC. Empty when the request had no query.
    pub query: String,
    /// Value of legacy `Digest:` or RFC 9530 `Content-Digest:`
    /// header.
    pub digest_header: String,
    /// Hashes of the sole forwarding buffer used to verify `digest_header`
    /// without retaining another full request-body copy.
    pub request_body_sha256: [u8; 32],
    pub request_body_sha512: [u8; 64],
}

/// Shared auth verification result, mapped to PluginResult by the dispatcher.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    Success {
        consumer: Option<Arc<Consumer>>,
        external_identity: Option<String>,
        external_identity_header: Option<String>,
    },
    NotApplicable,
    /// Credential was malformed, but the issue was only discovered during
    /// provider-specific verification rather than initial extraction.
    InvalidFormat(String),
    /// Credential was well-formed enough to verify, but failed semantic or
    /// cryptographic validation.
    Invalid(String),
    ConsumerNotFound(String),
    VerificationFailed(String),
    Forbidden(String),
    Internal(String),
}

/// Canonical identifier for the principal one accepted authentication factor
/// proved.
///
/// Display names are deliberately never used for comparison: two unrelated
/// people can share a `username` or a `name` claim, so equating principals on a
/// display value would let one factor stand in for another. A gateway Consumer
/// is identified by its namespace-qualified stable Consumer ID, and an external
/// principal by the canonical identity string its mechanism verified (issuer +
/// subject, SPIFFE ID, or equivalent) — the same value that reaches
/// `authenticated_identity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalPrincipal {
    /// A gateway Consumer record, keyed on namespace + stable Consumer ID.
    Consumer { namespace: String, id: String },
    /// An external principal, keyed on the mechanism-canonical identity string.
    External(String),
}

/// The canonical principal set a request has committed, or that one attempt
/// asserts.
///
/// A single attempt may legitimately assert both sides at once when the
/// mechanism itself maps an external credential onto a Consumer record. That is
/// the only "already-supported mapping" that binds a Consumer to an external
/// identity, because one credential proved both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalBinding {
    pub consumer: Option<CanonicalPrincipal>,
    pub external: Option<CanonicalPrincipal>,
}

impl PrincipalBinding {
    fn is_empty(&self) -> bool {
        self.consumer.is_none() && self.external.is_none()
    }
}

/// Canonical principal set already committed for this request.
fn committed_principal_binding(ctx: &RequestContext) -> PrincipalBinding {
    PrincipalBinding {
        consumer: ctx
            .identified_consumer
            .as_ref()
            .filter(|consumer| !consumer.username.trim().is_empty())
            .map(|consumer| CanonicalPrincipal::Consumer {
                namespace: consumer.namespace.clone(),
                id: consumer.id.clone(),
            }),
        external: ctx
            .authenticated_identity
            .as_deref()
            .map(str::trim)
            .filter(|identity| !identity.is_empty())
            .map(|identity| CanonicalPrincipal::External(identity.to_string())),
    }
}

/// Deterministic same-principal rule for composed authentication factors.
///
/// A second accepted factor may only ride on an already-committed principal when
/// it asserts *exactly* the same canonical principal set. Concretely:
///
/// * Consumer/Consumer — same namespace + stable Consumer ID.
/// * external/external — byte-identical canonical identity string.
/// * mixed Consumer/external — only when the committed attempt already bound
///   both sides itself; a Consumer factor and a separate external factor are
///   never assumed to describe one person.
///
/// Anything else is unprovable, so it fails closed rather than letting one
/// factor's principal be retained while another factor's identity is dropped.
fn principal_binding_matches(committed: &PrincipalBinding, incoming: &PrincipalBinding) -> bool {
    committed == incoming
}

/// Same-principal guard for stream-lifecycle authentication.
///
/// `on_stream_connect` mechanisms authenticate against `StreamConnectionContext`
/// rather than `RequestContext`, but carry the same Consumer/external identity
/// pair, so they need the same binding rule as [`commit_authentication_attempt`].
/// Returns `true` when committing `incoming_consumer` would compose a principal
/// different from one already asserted for this connection.
///
/// Takes the already-committed identities as plain fields so this stays a pure
/// rule with no dependency on the stream context type.
pub fn stream_principal_binding_conflicts(
    committed_consumer: Option<&Consumer>,
    committed_external_identity: Option<&str>,
    incoming_consumer: &Consumer,
) -> bool {
    if let Some(committed) = committed_consumer.filter(|c| !c.username.trim().is_empty()) {
        // Compare stable Consumer identity, never the display username.
        return committed.namespace != incoming_consumer.namespace
            || committed.id != incoming_consumer.id;
    }
    // A separately asserted external principal cannot vouch for a Consumer
    // record, so pairing the two is unprovable and fails closed.
    committed_external_identity
        .map(str::trim)
        .is_some_and(|identity| !identity.is_empty())
}

impl VerifyOutcome {
    pub fn success(
        consumer: Option<Arc<Consumer>>,
        external_identity: Option<String>,
        external_identity_header: Option<String>,
    ) -> Self {
        let external_identity = external_identity.filter(|identity| !identity.trim().is_empty());
        let external_identity_header =
            external_identity_header.filter(|identity_header| !identity_header.trim().is_empty());
        Self::Success {
            consumer,
            external_identity,
            external_identity_header,
        }
    }

    pub fn consumer(consumer: Arc<Consumer>) -> Self {
        Self::success(Some(consumer), None, None)
    }
}

macro_rules! impl_auth_plugin {
    (
        $ty:ty,
        $name:literal,
        $priority:expr,
        $protocols:expr,
        $runner:path
        $(; $($extra:tt)*)?
    ) => {
        #[async_trait::async_trait]
        impl crate::plugins::Plugin for $ty {
            fn name(&self) -> &str {
                $name
            }

            fn is_auth_plugin(&self) -> bool {
                true
            }

            fn priority(&self) -> u16 {
                $priority
            }

            fn supported_protocols(&self) -> &'static [crate::plugins::ProxyProtocol] {
                $protocols
            }

            fn authentication_challenge(&self) -> Option<&'static str> {
                <$ty as crate::plugins::utils::auth_flow::AuthMechanism>::authentication_challenge(
                    self,
                )
            }

            async fn authenticate(
                &self,
                ctx: &mut crate::plugins::RequestContext,
                consumer_index: &crate::consumer_index::ConsumerIndex,
            ) -> crate::plugins::PluginResult {
                $runner(self, ctx, consumer_index).await
            }

            $($($extra)*)?
        }
    };
}

pub(crate) use impl_auth_plugin;

#[async_trait]
pub trait AuthMechanism: Send + Sync {
    fn mechanism_name(&self) -> &'static str;

    fn authentication_challenge(&self) -> Option<&'static str> {
        None
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential;

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome;
}

pub async fn run_auth<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> PluginResult {
    run_auth_impl(mechanism, ctx, consumer_index, false).await
}

pub async fn run_auth_external_identity<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
) -> PluginResult {
    run_auth_impl(mechanism, ctx, consumer_index, true).await
}

async fn run_auth_impl<M: AuthMechanism>(
    mechanism: &M,
    ctx: &mut RequestContext,
    consumer_index: &ConsumerIndex,
    allow_external_identity: bool,
) -> PluginResult {
    let credential = mechanism.extract(ctx);

    match credential {
        ExtractedCredential::Missing => {
            debug!("{}: no credential present", mechanism.mechanism_name());
            PluginResult::Continue
        }
        ExtractedCredential::InvalidFormat(body) => {
            reject(401, body, mechanism.authentication_challenge())
        }
        credential => match commit_authentication_attempt(
            ctx,
            AuthenticationAttempt::new(),
            mechanism.verify(credential, consumer_index).await,
            mechanism.mechanism_name(),
            allow_external_identity,
        ) {
            Ok(_) => PluginResult::Continue,
            Err(rejection) => {
                reject_for_verify_outcome(rejection, mechanism.authentication_challenge())
            }
        },
    }
}

/// Map a rejecting [`VerifyOutcome`] onto the shared HTTP-family status code and
/// challenge policy. Every authentication path must use this so a
/// principal-binding conflict, a bad credential, and a dependency failure keep
/// one consistent client-visible contract.
pub fn reject_for_verify_outcome(
    outcome: VerifyOutcome,
    challenge: Option<&'static str>,
) -> PluginResult {
    match outcome {
        VerifyOutcome::InvalidFormat(body)
        | VerifyOutcome::Invalid(body)
        | VerifyOutcome::ConsumerNotFound(body)
        | VerifyOutcome::VerificationFailed(body) => reject(401, body, challenge),
        VerifyOutcome::Forbidden(body) => reject(403, body, None),
        VerifyOutcome::Internal(body) => reject(500, body, None),
        VerifyOutcome::Success { .. } | VerifyOutcome::NotApplicable => PluginResult::Continue,
    }
}

/// Commit one authentication attempt transactionally.
///
/// `Ok(true)` means the attempt established a nonblank Consumer or a permitted
/// nonblank external principal. `Ok(false)` means it was not applicable or
/// produced no usable principal, so every staged mutation was discarded.
/// Verification errors are returned unchanged for the caller's protocol-
/// specific rejection mapping.
///
/// This is the single principal-binding boundary for every authentication path
/// that reaches a [`RequestContext`] (HTTP/1.1, HTTP/2, HTTP/3, native gRPC,
/// gRPC-Web, and the WebSocket upgrade all authenticate through
/// `run_authentication_phase`). When an earlier factor already committed a
/// principal, a later accepted factor asserting a *different* canonical
/// principal returns `Err(VerifyOutcome::Forbidden)` instead of being silently
/// discarded, so credentials belonging to different people can never be composed
/// into an apparent multi-factor chain. See `principal_binding_matches` for the
/// exact same-principal rule.
pub fn commit_authentication_attempt(
    ctx: &mut RequestContext,
    attempt: AuthenticationAttempt,
    outcome: VerifyOutcome,
    auth_method: &'static str,
    allow_external_identity: bool,
) -> Result<bool, VerifyOutcome> {
    let VerifyOutcome::Success {
        consumer,
        external_identity,
        external_identity_header,
    } = outcome
    else {
        return match outcome {
            VerifyOutcome::NotApplicable => Ok(false),
            rejection => Err(rejection),
        };
    };

    let consumer = consumer.filter(|consumer| !consumer.username.trim().is_empty());
    let external_identity = if allow_external_identity {
        nonblank_identity(external_identity)
    } else {
        None
    };
    // A display/header claim is meaningful only when the same attempt supplied
    // a usable external principal. A blank header simply falls back to the
    // external identity through RequestContext::backend_consumer_username().
    let external_identity_header = external_identity
        .as_ref()
        .and_then(|_| external_identity_header.filter(|header| !header.trim().is_empty()));

    if consumer.is_none() && external_identity.is_none() {
        return Ok(false);
    }

    let principal_already_committed = request_principal_is_committed(ctx);

    // Bind composed factors to one principal. When an earlier factor already
    // committed a principal, this factor may only proceed if it proves the very
    // same canonical principal set. Otherwise credentials belonging to different
    // people could be composed into an apparent AND/multi-factor chain and
    // authorized as whichever principal happened to populate the context first.
    //
    // This is checked before any staged mutation is committed so a rejected
    // composition leaves no credential cleanup or claim state behind.
    if principal_already_committed {
        let committed = committed_principal_binding(ctx);
        let incoming = PrincipalBinding {
            consumer: consumer
                .as_ref()
                .map(|consumer| CanonicalPrincipal::Consumer {
                    namespace: consumer.namespace.clone(),
                    id: consumer.id.clone(),
                }),
            external: external_identity
                .as_deref()
                .map(str::trim)
                .filter(|identity| !identity.is_empty())
                .map(|identity| CanonicalPrincipal::External(identity.to_string())),
        };
        if !incoming.is_empty() && !principal_binding_matches(&committed, &incoming) {
            // Mechanism names only. Canonical principals are identity material
            // (subject claims, SPIFFE IDs, Consumer IDs) and must not be logged.
            warn!(
                plugin = auth_method,
                reason = "principal_binding_conflict",
                "Rejected authentication chain composing credentials from different principals"
            );
            return Err(VerifyOutcome::Forbidden(
                r#"{"error":"Authentication factors do not belong to the same principal"}"#
                    .to_string(),
            ));
        }
    }

    // Cleanup is additive for every accepted credential that reaches this
    // boundary. The dispatcher normally stops after its first success; direct
    // or custom callers still cannot erase cleanup already requested. Failed
    // and principal-less attempts never reach this boundary.
    attempt.commit_credential_cleanup(ctx);

    if !principal_already_committed {
        if let Some(consumer) = consumer {
            debug!(
                "{}: identified consumer '{}'",
                auth_method, consumer.username
            );
            ctx.identified_consumer = Some(consumer);
        }
        ctx.authenticated_identity = external_identity;
        ctx.authenticated_identity_header = external_identity_header;
        if ctx.auth_method.is_none() {
            ctx.auth_method = Some(auth_method);
        }
        attempt.commit_principal_state(ctx);
    }

    Ok(true)
}

/// Whether this attempt could become the first accepted request principal.
/// Callers with irreversible side effects can use this as a non-mutating
/// preflight before performing them; the final commit still revalidates the
/// outcome at the transaction boundary.
pub fn authentication_attempt_can_commit(
    ctx: &RequestContext,
    outcome: &VerifyOutcome,
    allow_external_identity: bool,
) -> bool {
    if request_principal_is_committed(ctx) {
        return false;
    }
    let VerifyOutcome::Success {
        consumer,
        external_identity,
        ..
    } = outcome
    else {
        return false;
    };
    consumer
        .as_ref()
        .is_some_and(|consumer| !consumer.username.trim().is_empty())
        || (allow_external_identity
            && external_identity
                .as_deref()
                .is_some_and(|identity| !identity.trim().is_empty()))
}

fn request_principal_is_committed(ctx: &RequestContext) -> bool {
    ctx.identified_consumer
        .as_ref()
        .is_some_and(|consumer| !consumer.username.trim().is_empty())
        || ctx
            .authenticated_identity
            .as_deref()
            .is_some_and(|identity| !identity.trim().is_empty())
}

/// Retain an identity claim byte-for-byte when it contains a non-whitespace
/// principal, otherwise treat it as missing before Consumer lookup.
pub fn nonblank_identity(identity: Option<String>) -> Option<String> {
    identity.filter(|value| !value.trim().is_empty())
}

fn reject(status_code: u16, body: String, challenge: Option<&'static str>) -> PluginResult {
    let mut headers = HashMap::new();
    if status_code == 401
        && let Some(challenge) = challenge
    {
        headers.insert("WWW-Authenticate".to_string(), challenge.to_string());
    }
    PluginResult::Reject {
        status_code,
        body,
        headers,
    }
}

/// Constant-time byte comparison to prevent timing attacks on secret material.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq, run_auth,
        run_auth_external_identity,
    };
    use crate::config::types::{Consumer, default_namespace};
    use crate::consumer_index::ConsumerIndex;
    use crate::plugins::{PluginResult, RequestContext};
    use async_trait::async_trait;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Clone)]
    struct FakeMechanism {
        extracted: ExtractedCredential,
        outcome: VerifyOutcome,
    }

    #[async_trait]
    impl AuthMechanism for FakeMechanism {
        fn mechanism_name(&self) -> &'static str {
            "fake_auth"
        }

        fn extract(&self, _ctx: &RequestContext) -> ExtractedCredential {
            self.extracted.clone()
        }

        async fn verify(
            &self,
            _credential: ExtractedCredential,
            _consumer_index: &ConsumerIndex,
        ) -> VerifyOutcome {
            self.outcome.clone()
        }
    }

    #[tokio::test]
    async fn missing_credential_continues_without_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::Missing,
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.authenticated_identity_header.is_none());
    }

    #[tokio::test]
    async fn invalid_outcome_maps_to_401() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("bad-key".to_string()),
            outcome: VerifyOutcome::Invalid(r#"{"error":"Invalid API key"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 401);
    }

    #[tokio::test]
    async fn forbidden_outcome_maps_to_403() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Forbidden(r#"{"error":"Insufficient scope"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 403);
    }

    #[tokio::test]
    async fn success_sets_identified_consumer() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("test-key".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: None,
                external_identity_header: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.identified_consumer
                .as_ref()
                .map(|c| c.username.as_str()),
            Some("phase3-user")
        );
        assert!(ctx.authenticated_identity.is_none());
    }

    #[tokio::test]
    async fn external_identity_sets_authenticated_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("alice@example.com")
        );
        assert!(ctx.authenticated_identity_header.is_none());
    }

    #[tokio::test]
    async fn external_identity_flow_sets_both_consumer_and_identity() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BasicAuth {
                username: "phase3-user".to_string(),
                password: "secret".to_string(),
            },
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: Some("Alice Example".to_string()),
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            ctx.identified_consumer
                .as_ref()
                .map(|c| c.username.as_str()),
            Some("phase3-user")
        );
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("alice@example.com")
        );
        assert_eq!(
            ctx.authenticated_identity_header.as_deref(),
            Some("Alice Example")
        );
    }

    #[tokio::test]
    async fn auth_method_set_on_consumer_success() {
        let consumer = Arc::new(test_consumer());
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("key".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: Some(Arc::clone(&consumer)),
                external_identity: None,
                external_identity_header: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert_eq!(ctx.auth_method, Some("fake_auth"));
    }

    #[tokio::test]
    async fn auth_method_set_on_external_identity_success() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("alice@example.com".to_string()),
                external_identity_header: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert_eq!(ctx.auth_method, Some("fake_auth"));
    }

    #[tokio::test]
    async fn auth_method_none_on_missing_credential() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::Missing,
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn auth_method_none_on_rejection() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::ApiKey("bad".to_string()),
            outcome: VerifyOutcome::Invalid(r#"{"error":"bad"}"#.to_string()),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth(&mechanism, &mut ctx, &index).await;

        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn auth_method_none_when_success_establishes_no_identity() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: None,
                external_identity_header: None,
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(ctx.effective_identity().is_none());
        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn blank_external_identity_does_not_authenticate() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::Success {
                consumer: None,
                external_identity: Some("   \t".to_string()),
                external_identity_header: Some(" \n".to_string()),
            },
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth_external_identity(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.authenticated_identity.is_none());
        assert!(ctx.authenticated_identity_header.is_none());
        assert!(ctx.effective_identity().is_none());
        assert!(ctx.auth_method.is_none());
    }

    #[tokio::test]
    async fn not_applicable_continues() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::NotApplicable,
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(ctx.identified_consumer.is_none());
        assert!(ctx.authenticated_identity.is_none());
    }

    #[tokio::test]
    async fn consumer_not_found_maps_to_401() {
        let mechanism = FakeMechanism {
            extracted: ExtractedCredential::BearerToken("token".to_string()),
            outcome: VerifyOutcome::ConsumerNotFound(
                r#"{"error":"Consumer not found"}"#.to_string(),
            ),
        };
        let mut ctx = test_ctx();
        let index = ConsumerIndex::new(&[]);

        let result = run_auth(&mechanism, &mut ctx, &index).await;

        assert_reject(result, 401);
    }

    #[test]
    fn constant_time_eq_matches_equal_and_unequal_inputs() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    fn test_ctx() -> RequestContext {
        RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/phase3".to_string(),
        )
    }

    fn test_consumer() -> Consumer {
        Consumer {
            id: "phase3-consumer".to_string(),
            username: "phase3-user".to_string(),
            namespace: default_namespace(),
            custom_id: Some("phase3-custom".to_string()),
            credentials: HashMap::new(),
            acl_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn assert_reject(result: PluginResult, expected_status_code: u16) {
        match result {
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(status_code, expected_status_code);
            }
            other => panic!("expected reject result, got {other:?}"),
        }
    }
}
