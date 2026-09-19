//! Capture the actual DP refusal emitter without starting a reconnect loop.

use super::*;
use crate::grpc::admission::CpGrpcAdmissionRejection;

#[path = "../../common/diagnostic_logs.rs"]
mod diagnostic_logs;

#[test]
fn dp_admission_emission_retains_all_five_known_budgets() {
    for rejection in [
        CpGrpcAdmissionRejection::TotalStreams,
        CpGrpcAdmissionRejection::NamespaceStreams,
        CpGrpcAdmissionRejection::PrincipalStreams,
        CpGrpcAdmissionRejection::NodeStreams,
        CpGrpcAdmissionRejection::NodeCardinality,
    ] {
        let known = rejection.into_native_status();
        let expected = known.message().to_string();
        let error = anyhow::Error::new(known);
        let status = subscribe_admission_refusal(&error).expect("known admission refusal");
        let ((), logs) = diagnostic_logs::capture_logs(|| {
            log_subscribe_admission_refusal(status, "http://UNREGISTERED_cp", 1, 2);
        });
        assert!(logs.contains(&expected), "{logs}");
        assert!(logs.contains("REFUSED the ConfigSync subscription"), "{logs}");
        assert!(logs.contains("Last-known-good configuration keeps serving"), "{logs}");
        assert!(!logs.contains("UNREGISTERED_cp"), "{logs}");
        assert_eq!(status.message(), expected);
    }
}

#[test]
fn dp_admission_emission_withholds_forged_classifier_matching_status() {
    let message = "CP gRPC UNREGISTERED_PEER_5591 (FERRUM_XDS_MAX_STREAMS)";
    let error = anyhow::Error::new(tonic::Status::resource_exhausted(message));
    // Diagnostic policy must not change reconnect or stale-fence classification.
    let status = subscribe_admission_refusal(&error).expect("existing classifier accepts this");
    let ((), logs) = diagnostic_logs::capture_logs(|| {
        log_subscribe_admission_refusal(status, "http://UNREGISTERED_cp", 1, 1);
    });
    assert!(logs.contains("CP gRPC stream admission refused"), "{logs}");
    assert!(logs.contains("unrecognized details withheld"), "{logs}");
    assert!(logs.contains("this DP keeps retrying"), "{logs}");
    assert!(!logs.contains("UNREGISTERED"), "{logs}");
    assert!(!logs.contains("FERRUM_XDS_MAX_STREAMS"), "{logs}");
    assert_eq!(status.message(), message);
    assert_eq!(status.code(), tonic::Code::ResourceExhausted);
}
