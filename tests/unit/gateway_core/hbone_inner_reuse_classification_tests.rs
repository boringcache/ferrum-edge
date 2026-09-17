//! Which plugins let one admitted HBONE CONNECT carry LATER application
//! operations (issue #5583).
//!
//! Source-side reuse keeps the inner application connection inside an admitted
//! tunnel, so the destination's per-CONNECT plugin chain runs ONCE where it
//! would otherwise have run once per operation. The relay is a transparent byte
//! tunnel — the destination never parses the inner requests either way — so
//! every one of those elided runs would have carried IDENTICAL request
//! attributes. The only thing that differs across them is TIME, and only two
//! time-varying decisions are re-issued for a live tunnel: the local authorize
//! verdict (the fence's sweep) and the peer's mTLS credential (the fence's
//! credential gate). Everything else — a rate-limit token, a concurrency
//! permit, a mirror dispatch, an external CUSTOM verdict, a bearer credential's
//! own expiry — would be spent once and then honoured indefinitely.
//!
//! `Plugin::allows_hbone_inner_reuse` is therefore fail-closed by default and
//! this table forces every classification to be deliberate. The companion
//! re-evaluation contract lives in `authorize_reevaluation_contract_tests.rs`;
//! the two are coupled, because a `true` justified by "the sweep re-issues it"
//! is only true while that plugin also opts into `reevaluates_live_admission`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The override, exactly as an implementation must spell its signature.
const DECLARATION: &str = "    fn allows_hbone_inner_reuse(&self) -> bool {\n";

/// Every built-in that classifies itself, keyed by its path under
/// `src/plugins/`, with the exact body it must declare.
///
/// Reusable (`true`) requires case (a) — no per-operation decision and no
/// per-operation side effect — or case (b) — every decision it takes for the
/// tunnel is re-issued by the fence for the tunnel's whole life:
///
/// * `access_control` — (b). Its verdict is a pure function of the request's
///   identity inputs and immutable allow/deny sets, and every published
///   generation requests a sweep that re-runs exactly this hook.
/// * `mesh/authz` — (b) while no external executor is bound. The local tier is
///   re-issued by the sweep; CUSTOM delegation is deliberately not re-consulted,
///   so a bound executor refuses.
/// * `mesh/spiffe_identity` — (b), and the ONLY credential-bearing plugin that
///   qualifies: the credential it reads is the mTLS leaf, which is exactly what
///   the fence's credential gate re-verifies and expires.
/// * `mesh/workload_metrics`, `otel_tracing`, `prometheus_metrics`,
///   `proxy_alerts`, `stdout_logging` — (a). Pure observability: no admission
///   decision, no per-request budget, no rejection. Reuse costs record
///   fidelity, not enforcement.
///
/// Non-reusable (`false`) is REQUIRED wherever an operation is CHARGED:
///
/// * `adaptive_concurrency` — takes an in-flight permit per operation.
/// * `rate_limiting` — consumes a token per operation, in every `limit_by`
///   mode.
/// * `request_mirror` — dispatches a shadow request per operation, and in its
///   body-admission form also takes a permit and a byte-budget lease.
///
/// Every other built-in, and every custom plugin, inherits the fail-closed
/// default and is absent from this table.
const EXPECTED_CLASSIFICATION: &[(&str, &str)] = &[
    ("access_control.rs", "        true\n"),
    ("adaptive_concurrency.rs", "        false\n"),
    ("mesh/authz.rs", "        self.ext_authz.is_none()\n"),
    ("mesh/spiffe_identity.rs", "        true\n"),
    ("mesh/workload_metrics.rs", "        true\n"),
    ("otel_tracing.rs", "        true\n"),
    ("prometheus_metrics.rs", "        true\n"),
    ("proxy_alerts/mod.rs", "        true\n"),
    ("rate_limiting.rs", "        false\n"),
    ("request_mirror.rs", "        false\n"),
    ("stdout_logging.rs", "        true\n"),
];

fn read_source(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Built-in plugin sources that OVERRIDE the classification, as paths relative
/// to `src/plugins/`, paired with the body they declare. `mod.rs` is excluded:
/// it carries the trait's own default, pinned separately below.
fn classifying_plugin_sources() -> Vec<(String, String)> {
    let plugins_dir = repo_root().join("src/plugins");
    let mut files = Vec::new();
    collect_rust_sources(&plugins_dir, &mut files);
    files.sort();
    let mut sources = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&plugins_dir)
            .expect("path under src/plugins")
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "mod.rs" {
            continue;
        }
        let source = read_source(&path);
        let Some(start) = source.find(DECLARATION) else {
            continue;
        };
        let rest = &source[start + DECLARATION.len()..];
        let end = rest
            .find("    }\n")
            .unwrap_or_else(|| panic!("src/plugins/{relative}: classification body must close"));
        assert!(
            !rest[end + "    }\n".len()..].contains(DECLARATION),
            "src/plugins/{relative}: one classification per plugin source"
        );
        sources.push((relative, rest[..end].to_string()));
    }
    sources
}

#[test]
fn every_builtin_that_classifies_itself_is_in_the_reuse_table() {
    let sources = classifying_plugin_sources();
    let found: Vec<&str> = sources.iter().map(|(path, _)| path.as_str()).collect();
    let expected: Vec<&str> = EXPECTED_CLASSIFICATION.iter().map(|(p, _)| *p).collect();
    if found != expected {
        panic!(
            "built-in HBONE inner-reuse classifications changed: found {found:?}, expected \
             {expected:?}. A plugin may declare `allows_hbone_inner_reuse` as `true` only when it \
             takes no per-operation decision and has no per-operation side effect, or when every \
             decision it takes is re-issued by the HBONE admission fence for the tunnel's whole \
             life. Record the reason in EXPECTED_CLASSIFICATION"
        );
    }

    for ((path, body), (_, expected_body)) in sources.iter().zip(EXPECTED_CLASSIFICATION) {
        assert_eq!(
            body, expected_body,
            "src/plugins/{path}: `allows_hbone_inner_reuse` body changed; a reclassification must \
             move the table entry and its recorded reason together"
        );
    }
}

/// The default is what decides every UNCLASSIFIED plugin, including every
/// custom one. `is_authorize_plugin()` itself defaults to `true`, so
/// `!is_authorize_plugin()` refuses reuse for anything nobody has looked at —
/// which is the fail-closed direction. A default of a bare `true`, or one keyed
/// off a hook that most plugins do not implement, would silently opt the whole
/// plugin surface in.
#[test]
fn the_reuse_default_is_the_fail_closed_negation_of_the_authorize_marker() {
    let src = read_source(&repo_root().join("src/plugins/mod.rs"));
    let start = src
        .find(DECLARATION)
        .expect("the trait must declare the classification");
    let body = &src[start + DECLARATION.len()..];
    let end = body.find("    }\n").expect("the default body must close");
    assert_eq!(
        &body[..end],
        "        !self.is_authorize_plugin()\n",
        "the default classification must be the negation of the authorize marker, whose own \
         default is `true` — anything else opts unclassified and custom plugins into reuse"
    );

    let marker = "    fn is_authorize_plugin(&self) -> bool {\n        true\n    }\n";
    assert!(
        src.contains(marker),
        "the fail-closed reading of the reuse default depends on `is_authorize_plugin` itself \
         defaulting to `true`"
    );
}

/// The gate must fold the chain that ADMITTED this CONNECT — the
/// protocol-scoped slice the dispatcher resolved and passed in — and not
/// re-derive one. `HboneAdmissionView` is a `Copy` record of the protocol
/// selectors and the sweep epoch; it holds no plugins.
#[test]
fn the_connect_path_folds_the_admitting_plugin_chain() {
    let src = read_source(&repo_root().join("src/proxy/hbone_proxy.rs"));
    assert!(
        src.contains("tunnel.fence_in_force() && admitting_chain_allows_inner_reuse(plugins)"),
        "the advertisement must require BOTH the fence holding the tunnel and the admitting \
         chain classifying it reusable"
    );
    assert!(
        !src.contains("admission_view.plugins()"),
        "the admitting chain is the dispatcher's `plugins` slice; the admission view carries \
         only the protocol selectors and the sweep epoch"
    );
}

/// A datagram tunnel unframes into a local `UdpSocket` and carries no inner
/// request/response exchange a source could pool, so the capability simply does
/// not exist on that surface and the handler must never stamp it — whatever its
/// admitting chain would have classified.
#[test]
fn the_datagram_connect_path_never_stamps_the_reuse_header() {
    let src = read_source(&repo_root().join("src/proxy/hbone_proxy.rs"));
    let start = src
        .find("pub(super) async fn handle_hbone_udp_request(")
        .expect("the datagram CONNECT handler must exist");
    let rest = &src[start..];
    let end = rest
        .find("\n/// Resolve the CONNECT authority `host` to concrete IPs")
        .expect("the datagram CONNECT handler must terminate");
    assert!(
        !rest[..end].contains("TUNNEL_REUSE_HEADER"),
        "the datagram CONNECT path must never advertise inner reuse"
    );
}
