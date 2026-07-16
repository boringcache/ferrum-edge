//! Static registry of native field names for [`TransactionSummary`],
//! [`StreamTransactionSummary`], and WebSocket disconnect log entries.
//!
//! The schema customization layer validates operator-supplied field names
//! (in `omit`, `rename`, `order`, derived `from`) against these tables.
//! Drift between this registry and the structs is caught by the integration
//! test in `tests/integration/log_schema_registry_tests.rs`.

use super::SummaryType;

/// Optional field families a specific caller opts into.
///
/// [`super::SummarySchema::compile`] is shared by every logging plugin, but
/// only `ws_logging` serializes `WsDisconnectLogEntry`. The
/// WebSocket-disconnect field family is therefore gated behind an explicit
/// capability so every other caller (`http_logging`, `kafka_logging`,
/// `loki_logging`, `stdout_logging`, …) sees exactly the base HTTP / stream
/// registry: ws-only names stay rejected in `omit` / `rename` / `order` and
/// never reserve output keys that would collide with `static_fields` or
/// flattened metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SchemaCapabilities {
    /// Expose the `ws_logging` WebSocket-disconnect field family to `http`
    /// and `both` summary types.
    pub websocket_disconnect: bool,
}

impl SchemaCapabilities {
    /// Base registry shared by every non-WebSocket logging plugin — exactly
    /// the HTTP and stream field families, matching pre-WS behavior.
    pub const BASE: Self = Self {
        websocket_disconnect: false,
    };

    /// `ws_logging` capability: additionally expose the WebSocket-disconnect
    /// field family to `http` / `both` schemas.
    pub const WS_LOGGING: Self = Self {
        websocket_disconnect: true,
    };
}

/// Metadata for a single native field on a summary struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMeta {
    pub name: &'static str,
    /// `true` when the field is an RFC3339 timestamp string subject to
    /// [`super::TimestampFormat`] conversion at serialize time.
    pub is_timestamp: bool,
}

/// Fields on [`crate::plugins::TransactionSummary`] in declaration order.
pub const HTTP_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_received",
        is_timestamp: true,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "http_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_path",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_status_code",
        is_timestamp: false,
    },
    FieldMeta {
        name: "grpc_status",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_processing_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_ttfb_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_backend_total_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_execution_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_plugin_external_io_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "latency_gateway_overhead_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "request_user_agent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "response_streamed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_disconnected",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "body_completed",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "mirror",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Fields on [`crate::plugins::StreamTransactionSummary`] in declaration order.
pub const STREAM_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_resolved_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_sent",
        is_timestamp: false,
    },
    FieldMeta {
        name: "bytes_received",
        is_timestamp: false,
    },
    FieldMeta {
        name: "connection_error",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "disconnect_cause",
        is_timestamp: false,
    },
    FieldMeta {
        name: "timestamp_connected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "timestamp_disconnected",
        is_timestamp: true,
    },
    FieldMeta {
        name: "sni_hostname",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// Fields on the `ws_logging` WebSocket disconnect entry in declaration order.
///
/// WebSocket disconnect entries belong to the HTTP / WebSocket summary
/// family, but the shared log-schema compiler only exposes them to `http` /
/// `both` schemas when the caller opts in via
/// [`SchemaCapabilities::websocket_disconnect`] (i.e. the `ws_logging`
/// plugin). Every other logging plugin sees the base registry, so ws-only
/// names stay rejected and never reserve output keys.
pub const WS_DISCONNECT_FIELDS: &[FieldMeta] = &[
    FieldMeta {
        name: "event",
        is_timestamp: false,
    },
    FieldMeta {
        name: "namespace",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_id",
        is_timestamp: false,
    },
    FieldMeta {
        name: "proxy_name",
        is_timestamp: false,
    },
    FieldMeta {
        name: "client_ip",
        is_timestamp: false,
    },
    FieldMeta {
        name: "consumer_username",
        is_timestamp: false,
    },
    FieldMeta {
        name: "auth_method",
        is_timestamp: false,
    },
    FieldMeta {
        name: "backend_target",
        is_timestamp: false,
    },
    FieldMeta {
        name: "protocol",
        is_timestamp: false,
    },
    FieldMeta {
        name: "listen_port",
        is_timestamp: false,
    },
    FieldMeta {
        name: "duration_ms",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_client_to_backend",
        is_timestamp: false,
    },
    FieldMeta {
        name: "frames_backend_to_client",
        is_timestamp: false,
    },
    FieldMeta {
        name: "direction",
        is_timestamp: false,
    },
    FieldMeta {
        name: "io_side",
        is_timestamp: false,
    },
    FieldMeta {
        name: "error_class",
        is_timestamp: false,
    },
    FieldMeta {
        name: "metadata",
        is_timestamp: false,
    },
];

/// The field families visible for `summary_type` under `caps`.
///
/// The WebSocket-disconnect family is appended to the `http` / `both`
/// families only when the caller opts in via
/// [`SchemaCapabilities::websocket_disconnect`].
fn field_sets(summary_type: SummaryType, caps: SchemaCapabilities) -> Vec<&'static [FieldMeta]> {
    let mut sets: Vec<&'static [FieldMeta]> = match summary_type {
        SummaryType::Http => vec![HTTP_FIELDS],
        SummaryType::Stream => vec![STREAM_FIELDS],
        SummaryType::Both => vec![HTTP_FIELDS, STREAM_FIELDS],
    };
    if caps.websocket_disconnect && matches!(summary_type, SummaryType::Http | SummaryType::Both) {
        sets.push(WS_DISCONNECT_FIELDS);
    }
    sets
}

/// Look up a field by name for the given summary type and capabilities.
///
/// For [`SummaryType::Both`] the field may exist on any visible entry type.
pub fn lookup(
    summary_type: SummaryType,
    caps: SchemaCapabilities,
    name: &str,
) -> Option<FieldMeta> {
    field_sets(summary_type, caps)
        .iter()
        .flat_map(|set| set.iter())
        .find(|f| f.name == name)
        .copied()
}

/// All field names visible for the given summary type and capabilities, in
/// declaration order, deduplicated across entry types.
pub fn fields_for(summary_type: SummaryType, caps: SchemaCapabilities) -> Vec<FieldMeta> {
    union_fields(&field_sets(summary_type, caps))
}

fn union_fields(field_sets: &[&[FieldMeta]]) -> Vec<FieldMeta> {
    let mut out = Vec::new();
    for fields in field_sets {
        for field in *fields {
            if !out
                .iter()
                .any(|existing: &FieldMeta| existing.name == field.name)
            {
                out.push(*field);
            }
        }
    }
    out
}

/// Suggest the closest known field name to a misspelling, when the
/// Levenshtein distance is small enough to be useful (≤ 2 for short names,
/// ≤ 3 for long names).
pub fn levenshtein_suggest(
    summary_type: SummaryType,
    caps: SchemaCapabilities,
    name: &str,
) -> Option<&'static str> {
    let candidates = field_sets(summary_type, caps);
    let mut best: Option<(usize, &'static str)> = None;
    for set in &candidates {
        for field in *set {
            let d = levenshtein(name, field.name);
            if best.map(|(b, _)| d < b).unwrap_or(true) {
                best = Some((d, field.name));
            }
        }
    }
    let threshold = if name.len() > 8 { 3 } else { 2 };
    best.filter(|(d, _)| *d <= threshold).map(|(_, n)| n)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: SchemaCapabilities = SchemaCapabilities::BASE;
    const WS: SchemaCapabilities = SchemaCapabilities::WS_LOGGING;

    #[test]
    fn lookup_known_http_field() {
        assert_eq!(
            lookup(SummaryType::Http, BASE, "proxy_id"),
            Some(FieldMeta {
                name: "proxy_id",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_known_stream_field() {
        assert_eq!(
            lookup(SummaryType::Stream, BASE, "bytes_sent"),
            Some(FieldMeta {
                name: "bytes_sent",
                is_timestamp: false
            })
        );
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup(SummaryType::Http, BASE, "not_a_field").is_none());
    }

    #[test]
    fn lookup_http_field_not_on_stream() {
        // request_path is only on TransactionSummary.
        assert!(lookup(SummaryType::Stream, BASE, "request_path").is_none());
        assert!(lookup(SummaryType::Http, BASE, "request_path").is_some());
        assert!(lookup(SummaryType::Both, BASE, "request_path").is_some());
    }

    #[test]
    fn lookup_stream_only_field_not_on_http() {
        assert!(lookup(SummaryType::Http, BASE, "timestamp_connected").is_none());
        assert!(lookup(SummaryType::Stream, BASE, "timestamp_connected").is_some());
        assert!(lookup(SummaryType::Both, BASE, "timestamp_connected").is_some());
    }

    #[test]
    fn websocket_disconnect_field_gated_by_capability() {
        // WS-only field: invisible without the capability (every non-ws
        // plugin), visible with it (ws_logging).
        assert!(lookup(SummaryType::Http, BASE, "frames_client_to_backend").is_none());
        assert!(lookup(SummaryType::Both, BASE, "frames_client_to_backend").is_none());
        assert!(lookup(SummaryType::Http, WS, "frames_client_to_backend").is_some());
        assert!(lookup(SummaryType::Both, WS, "frames_client_to_backend").is_some());
        // The capability never leaks WS fields into stream schemas.
        assert!(lookup(SummaryType::Stream, WS, "frames_client_to_backend").is_none());
    }

    #[test]
    fn ws_only_protocol_field_gated_on_http() {
        // `protocol` exists on the WS-disconnect family but not on the base
        // HTTP registry. It must stay unknown for http/both without the
        // capability so non-ws plugins reject it exactly as before.
        assert!(lookup(SummaryType::Http, BASE, "protocol").is_none());
        assert!(lookup(SummaryType::Http, WS, "protocol").is_some());
        // Stream summaries carry their own `protocol` field regardless.
        assert!(lookup(SummaryType::Stream, BASE, "protocol").is_some());
    }

    #[test]
    fn timestamp_flag_set_correctly() {
        let f = lookup(SummaryType::Http, BASE, "timestamp_received").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, BASE, "timestamp_connected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Stream, BASE, "timestamp_disconnected").unwrap();
        assert!(f.is_timestamp);
        let f = lookup(SummaryType::Http, BASE, "client_ip").unwrap();
        assert!(!f.is_timestamp);
    }

    #[test]
    fn fields_for_both_unions_and_dedupes() {
        let all = fields_for(SummaryType::Both, BASE);
        // namespace, proxy_id, client_ip etc. exist on both — should appear once.
        let namespaces = all.iter().filter(|f| f.name == "namespace").count();
        assert_eq!(namespaces, 1);
        let proxy_ids = all.iter().filter(|f| f.name == "proxy_id").count();
        assert_eq!(proxy_ids, 1);
        // Base capability: no WS-disconnect family in the union.
        let expected = union_fields(&[HTTP_FIELDS, STREAM_FIELDS]);
        assert_eq!(all, expected);
    }

    #[test]
    fn fields_for_both_includes_ws_family_with_capability() {
        let base = fields_for(SummaryType::Both, BASE);
        let ws = fields_for(SummaryType::Both, WS);
        // The WS capability adds the WS-only fields (deduped against the
        // overlap with HTTP / stream fields).
        assert!(base.iter().all(|f| f.name != "frames_client_to_backend"));
        assert!(ws.iter().any(|f| f.name == "frames_client_to_backend"));
        assert_eq!(
            ws,
            union_fields(&[HTTP_FIELDS, STREAM_FIELDS, WS_DISCONNECT_FIELDS])
        );
    }

    #[test]
    fn levenshtein_suggests_close_match() {
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, BASE, "proxy_idd"),
            Some("proxy_id")
        );
        assert_eq!(
            levenshtein_suggest(SummaryType::Http, BASE, "lateny_total_ms"),
            Some("latency_total_ms")
        );
    }

    #[test]
    fn levenshtein_skips_far_matches() {
        assert!(levenshtein_suggest(SummaryType::Http, BASE, "completely_unrelated").is_none());
    }

    #[test]
    fn http_fields_match_expected_count() {
        // Drift sentinel — the integration test in
        // tests/integration/log_schema_registry_tests.rs verifies the
        // actual serde output keys match these. This is the cheap
        // unit-test guard against accidental deletions.
        assert_eq!(HTTP_FIELDS.len(), 30);
    }

    #[test]
    fn stream_fields_match_expected_count() {
        assert_eq!(STREAM_FIELDS.len(), 21);
    }

    #[test]
    fn websocket_disconnect_fields_match_expected_count() {
        assert_eq!(WS_DISCONNECT_FIELDS.len(), 17);
    }
}
