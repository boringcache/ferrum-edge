//! Fail-closed transport admission for the stock (third-party) xDS profile
//! (issue #3853).
//!
//! `FERRUM_MESH_CONFIG_PROTOCOL=stock_xds` dials a control plane Ferrum does not
//! own. The only credential it ever presents is the externally issued bearer
//! token named by `FERRUM_MESH_STOCK_XDS_TOKEN_FILE`. Before this module the
//! client would happily open an `http://` ADS channel and attach that bearer to
//! the streaming RPC, so a production discovery session could run without
//! transport confidentiality or an authenticated server identity — and a secure
//! primary could silently fail over to a plaintext fallback.
//!
//! Ferrum's own CP/DP transport already has a production plaintext-admission
//! boundary (`EnvConfig::validate_cp_dp_grpc_transport_security`). This is the
//! independent stock path's equivalent, and it is deliberately **stricter**:
//!
//! * The complete primary/fallback set is admitted as ONE posture. A mixed
//!   `https://` + `http://` list is refused as a whole, so failover can never
//!   select an endpoint weaker than the primary.
//! * A configured token file requires `https://` for **every** endpoint,
//!   including loopback. There is no development carve-out for a bearer.
//! * Production mode (`FERRUM_MESH_PRODUCTION_MODE=true`) requires TLS for every
//!   endpoint whether or not a bearer is configured.
//! * The only plaintext path left is an explicit, loopback-only development
//!   switch (`FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT=true`) that is incompatible
//!   with bearer authentication and refused outright in production.
//!
//! Diagnostics are bounded and never echo the configured URL. An ADS endpoint
//! is operator-authored but may carry userinfo or a query, so refusals name the
//! endpoint by **index** plus a closed-set scheme and host class only.

use crate::modes::mesh::config_consumer::stock_xds_credential::StockXdsCredentialSource;

/// The admitted transport posture of one stock ADS endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockXdsTransport {
    /// `https://` — TLS with server-certificate verification against the
    /// configured CP/DP trust material (and client certificates when mTLS is
    /// configured). The only posture that may carry authorization metadata.
    AuthenticatedTls,
    /// `http://` on a loopback host, admitted **only** by the explicit
    /// development switch, only outside production mode, and only with no
    /// bearer credential configured.
    LoopbackPlaintextDev,
}

impl StockXdsTransport {
    /// True when this endpoint may carry `authorization` metadata.
    pub fn allows_authorization_metadata(self) -> bool {
        matches!(self, Self::AuthenticatedTls)
    }

    pub fn as_label(self) -> &'static str {
        match self {
            Self::AuthenticatedTls => "authenticated_tls",
            Self::LoopbackPlaintextDev => "loopback_plaintext_dev",
        }
    }
}

/// Closed-set reasons the stock endpoint set is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StockXdsTransportRefusal {
    /// The value did not parse as an absolute URI.
    MalformedUri,
    /// No scheme at all (`istiod:15012`). Ambiguous, so refused rather than
    /// guessed.
    MissingScheme,
    /// A scheme other than `http`/`https`.
    UnsupportedScheme,
    /// No authority/host component.
    MissingHost,
    /// Userinfo embedded in the authority (`https://user:pass@host`). A
    /// credential in a configured URL would be logged by any component that
    /// echoes the endpoint; the token file is the only supported credential.
    EmbeddedCredentials,
    /// Plaintext refused because `FERRUM_MESH_PRODUCTION_MODE=true`.
    PlaintextInProduction,
    /// Plaintext refused because the development switch is not enabled.
    PlaintextNotEnabled,
    /// Plaintext refused because the host is not loopback.
    PlaintextNotLoopback,
    /// Plaintext refused because a bearer token file is configured.
    PlaintextWithBearerToken,
    /// The configured set mixes authenticated TLS with plaintext.
    MixedTransportPosture,
}

impl StockXdsTransportRefusal {
    /// Fixed-cardinality label safe for logs and metrics.
    pub fn as_metric_label(self) -> &'static str {
        match self {
            Self::MalformedUri => "malformed_uri",
            Self::MissingScheme => "missing_scheme",
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::MissingHost => "missing_host",
            Self::EmbeddedCredentials => "embedded_credentials",
            Self::PlaintextInProduction => "plaintext_in_production",
            Self::PlaintextNotEnabled => "plaintext_not_enabled",
            Self::PlaintextNotLoopback => "plaintext_not_loopback",
            Self::PlaintextWithBearerToken => "plaintext_with_bearer_token",
            Self::MixedTransportPosture => "mixed_transport_posture",
        }
    }

    fn remedy(self) -> &'static str {
        match self {
            Self::MalformedUri | Self::MissingScheme => {
                "each FERRUM_MESH_STOCK_XDS_URLS entry must be an absolute 'https://host:port' URL"
            }
            Self::UnsupportedScheme => {
                "only 'https' (and, for loopback development, 'http') are supported"
            }
            Self::MissingHost => "the URL must name a host",
            Self::EmbeddedCredentials => {
                "remove the userinfo from the URL; use FERRUM_MESH_STOCK_XDS_TOKEN_FILE for the \
                 bearer credential"
            }
            Self::PlaintextInProduction => {
                "FERRUM_MESH_PRODUCTION_MODE=true requires 'https://' for every stock xDS endpoint"
            }
            Self::PlaintextNotEnabled => {
                "use 'https://', or set FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT=true for a \
                 loopback-only development control plane"
            }
            Self::PlaintextNotLoopback => {
                "FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT only admits loopback hosts (127.0.0.0/8, \
                 ::1, localhost)"
            }
            Self::PlaintextWithBearerToken => {
                "a bearer credential requires authenticated TLS on every endpoint; remove \
                 FERRUM_MESH_STOCK_XDS_TOKEN_FILE or use 'https://'"
            }
            Self::MixedTransportPosture => {
                "the whole primary/fallback set must share one transport posture so failover \
                 cannot downgrade"
            }
        }
    }
}

/// Bounded, redacted description of a refused endpoint.
///
/// Carries the endpoint's **index** in the configured list plus closed-set
/// scheme/host classifications. The URL itself is never retained or rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockXdsTransportError {
    pub index: usize,
    pub refusal: StockXdsTransportRefusal,
    scheme: &'static str,
    host_class: &'static str,
}

impl StockXdsTransportError {
    pub fn scheme(&self) -> &'static str {
        self.scheme
    }

    pub fn host_class(&self) -> &'static str {
        self.host_class
    }
}

impl std::fmt::Display for StockXdsTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stock xDS endpoint #{} (scheme='{}', host={}) refused: {} — {}",
            self.index,
            self.scheme,
            self.host_class,
            self.refusal.as_metric_label(),
            self.refusal.remedy()
        )
    }
}

impl std::error::Error for StockXdsTransportError {}

/// The security inputs the whole endpoint set is admitted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StockXdsTransportPolicy {
    /// A `FERRUM_MESH_STOCK_XDS_TOKEN_FILE` is configured.
    pub token_configured: bool,
    /// `FERRUM_MESH_PRODUCTION_MODE=true`.
    pub production_mode: bool,
    /// `FERRUM_MESH_STOCK_XDS_ALLOW_PLAINTEXT=true` — the loopback-only
    /// development switch.
    pub allow_loopback_plaintext: bool,
}

impl StockXdsTransportPolicy {
    /// Build the policy from the operator's credential source and the canonical
    /// production-mode read.
    pub fn from_runtime(
        credential_source: &StockXdsCredentialSource,
        allow_loopback_plaintext: bool,
    ) -> Self {
        Self {
            token_configured: credential_source.is_configured(),
            production_mode: crate::identity::production_mode(),
            allow_loopback_plaintext,
        }
    }
}

fn host_class(host: Option<&str>) -> &'static str {
    match host {
        None => "absent",
        Some(host) if is_loopback_host(host) => "loopback",
        Some(_) => "remote",
    }
}

/// Loopback classification for the development plaintext carve-out.
///
/// Deliberately narrow: the literal `localhost` name plus any address inside
/// `127.0.0.0/8` or `::1`. A hostname that merely *resolves* to loopback is not
/// accepted — resolution is not a configuration property and could change under
/// the data plane.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(addr)) => addr.is_loopback(),
        Ok(std::net::IpAddr::V6(addr)) => addr.is_loopback(),
        Err(_) => false,
    }
}

/// Classify ONE configured stock ADS endpoint.
///
/// This is also the connect-time defense in depth: `connect_stock_ads` re-runs
/// it for the endpoint it is about to dial, so a code path that somehow skipped
/// startup admission still fails closed before a socket is opened.
pub fn classify_stock_xds_endpoint(
    index: usize,
    url: &str,
    policy: StockXdsTransportPolicy,
) -> Result<StockXdsTransport, StockXdsTransportError> {
    let uri = match url.trim().parse::<http::Uri>() {
        Ok(uri) => uri,
        Err(_) => {
            return Err(StockXdsTransportError {
                index,
                refusal: StockXdsTransportRefusal::MalformedUri,
                scheme: "unparsed",
                host_class: "unparsed",
            });
        }
    };

    let scheme_owned = uri.scheme_str().map(str::to_ascii_lowercase);
    let scheme: &'static str = match scheme_owned.as_deref() {
        Some("https") => "https",
        Some("http") => "http",
        Some(_) => "other",
        None => "absent",
    };
    let host = uri.host();
    let host_class = host_class(host);
    let refuse = |refusal| StockXdsTransportError {
        index,
        refusal,
        scheme,
        host_class,
    };

    match scheme {
        "absent" => return Err(refuse(StockXdsTransportRefusal::MissingScheme)),
        "other" => return Err(refuse(StockXdsTransportRefusal::UnsupportedScheme)),
        _ => {}
    }
    let Some(host) = host else {
        return Err(refuse(StockXdsTransportRefusal::MissingHost));
    };
    // `http::Authority` accepts userinfo, and tonic would forward it. A
    // credential embedded in a configured endpoint is exactly the disclosure
    // this module exists to prevent, so it is refused rather than stripped.
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(refuse(StockXdsTransportRefusal::EmbeddedCredentials));
    }

    if scheme == "https" {
        return Ok(StockXdsTransport::AuthenticatedTls);
    }

    // Plaintext: every gate below is independent and fail-closed. Order is
    // chosen so the most security-relevant reason is the one reported.
    if policy.token_configured {
        return Err(refuse(StockXdsTransportRefusal::PlaintextWithBearerToken));
    }
    if policy.production_mode {
        return Err(refuse(StockXdsTransportRefusal::PlaintextInProduction));
    }
    if !policy.allow_loopback_plaintext {
        return Err(refuse(StockXdsTransportRefusal::PlaintextNotEnabled));
    }
    if !is_loopback_host(host) {
        return Err(refuse(StockXdsTransportRefusal::PlaintextNotLoopback));
    }
    Ok(StockXdsTransport::LoopbackPlaintextDev)
}

/// Admit the COMPLETE configured primary/fallback set as one security posture.
///
/// Returns the per-endpoint posture in configured order. A single refused
/// endpoint refuses the whole set: the point is that failover must not be able
/// to reach a weaker transport than the primary, which per-endpoint admission
/// alone cannot guarantee.
pub fn admit_stock_xds_endpoints(
    urls: &[String],
    policy: StockXdsTransportPolicy,
) -> Result<Vec<StockXdsTransport>, StockXdsTransportError> {
    let mut admitted = Vec::with_capacity(urls.len());
    for (index, url) in urls.iter().enumerate() {
        admitted.push(classify_stock_xds_endpoint(index, url, policy)?);
    }

    let has_tls = admitted.contains(&StockXdsTransport::AuthenticatedTls);
    let first_plaintext = admitted
        .iter()
        .position(|transport| *transport != StockXdsTransport::AuthenticatedTls);
    if let (true, Some(index)) = (has_tls, first_plaintext) {
        return Err(StockXdsTransportError {
            index,
            refusal: StockXdsTransportRefusal::MixedTransportPosture,
            scheme: "http",
            host_class: "loopback",
        });
    }

    Ok(admitted)
}
