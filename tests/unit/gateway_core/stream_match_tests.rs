//! External tests for VirtualService L4 `Proxy.stream_match` predicates.

use ferrum_edge::proxy::stream_match::{
    CompiledStreamMatch, StreamMatchArm, StreamMatchCriteria, StreamMatchEvidence,
    canonicalize_gateway_name, source_namespace_from_spiffe, trusted_stream_gateway_ref,
};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[test]
fn stream_match_criteria_round_trips_through_json() {
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app".into(), "billing".into())]),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.1.0/24".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let json = serde_json::to_value(&criteria).expect("serialize");
    let back: StreamMatchCriteria = serde_json::from_value(json).expect("deserialize");
    assert_eq!(back, criteria);
    let compiled: CompiledStreamMatch = back.compile().expect("compile");
    assert!(!compiled.is_empty());
}

#[test]
fn missing_evidence_denies_each_predicate() {
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: BTreeMap::from([("app".into(), "billing".into())]),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.0.0/16".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let compiled = criteria.compile().unwrap();
    assert!(!compiled.matches(&StreamMatchEvidence::default()));
}

#[test]
fn combined_predicates_require_all_evidence() {
    let mut labels = BTreeMap::new();
    labels.insert("app".into(), "billing".into());
    let criteria = StreamMatchCriteria {
        arms: vec![StreamMatchArm {
            source_labels: labels.clone(),
            source_namespace: Some("prod".into()),
            source_subnets: vec!["10.0.0.0/8".into()],
            destination_subnets: vec!["192.168.0.0/16".into()],
            gateways: vec!["mesh".into()],
        }],
    };
    let compiled = criteria.compile().unwrap();
    let evidence = StreamMatchEvidence {
        source_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
        destination_ip: Some("192.168.1.9".parse::<IpAddr>().unwrap()),
        source_namespace: Some("prod"),
        source_labels: Some(&labels),
        trusted_gateway_ref: Some("mesh"),
    };
    assert!(compiled.matches(&evidence));
}

#[test]
fn gateway_canonicalize_and_default_binding() {
    assert_eq!(
        canonicalize_gateway_name("ingress", "bookinfo").unwrap(),
        "bookinfo/ingress"
    );
    assert_eq!(
        trusted_stream_gateway_ref().as_deref(),
        Some("mesh"),
        "unset FERRUM_STREAM_GATEWAY_REF defaults to mesh"
    );
    assert_eq!(
        source_namespace_from_spiffe("spiffe://cluster.local/ns/prod/sa/web").as_deref(),
        Some("prod")
    );
}
