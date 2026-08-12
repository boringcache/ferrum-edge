//! Static Helm/chart contract coverage for Ambient UDP established-placement
//! attestation (issue #3703 / PR #3795).
//!
//! These tests pin the settled-vs-migrating attestation gates without mutating
//! `.github/workflows/ci.yml` (Trusted Cross Build Policy forbids Cross-surface
//! workflow edits outside the protected ARM64 job). Hosted CI still exercises
//! `helm template` for the broader UDP placement upgrade matrix.

use std::path::PathBuf;

fn chart_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("charts/ferrum-mesh")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(chart_root().join(rel)).unwrap_or_else(|e| {
        panic!("failed to read charts/ferrum-mesh/{rel}: {e}");
    })
}

#[test]
fn values_document_installed_contract_attestation() {
    let values = read("values.yaml");
    assert!(
        values.contains("FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            && values.contains("ferrum-mesh-udp-placement-<release>")
            && values.contains("never rendered by the release that changes the placement"),
        "ambient values must document release-level established attestation from the installed ConfigMap"
    );
}

#[test]
fn ambient_attests_only_settled_upgrade_matching_installed_contract() {
    let ambient = read("templates/ambient-daemonset.yaml");

    // Settled host (or pod) placement: derive attestation only for Ambient +
    // stable phase + upgrade, and only when the installed ConfigMap already
    // recorded this exact target in a settled (stable/finalize) phase.
    assert!(
        ambient.contains(
            "eq $ambientTopology \"ambient\") (eq $ambientUdpMigrationPhase \"stable\") .Release.IsUpgrade"
        ),
        "established attestation must require Ambient topology, current stable phase, and an upgrade"
    );
    assert!(
        ambient.contains("ferrum-mesh-udp-placement-%s")
            && ambient
                .contains("lookup \"v1\" \"ConfigMap\" .Release.Namespace $ambientUdpContractName"),
        "attestation must read the installed placement ConfigMap, never invent cluster state"
    );
    assert!(
        ambient.contains(
            "eq (toString (index $ambientUdpInstalledData \"target\")) $ambientUdpTarget"
        ) && ambient.contains(
            "has (toString (index $ambientUdpInstalledData \"phase\")) (list \"stable\" \"finalize\")"
        ),
        "installed contract must already record the same target in a settled phase"
    );
    assert!(
        ambient.contains("$ambientUdpEstablished = $ambientUdpTarget")
            && ambient.contains("ternary \"host-netns\" \"pod-netns\" $ambientUdpHostNetns"),
        "a settled host placement must be able to attest host-netns (and pod-netns when that is the target)"
    );
}

#[test]
fn ambient_never_attests_while_current_release_is_migrating() {
    let ambient = read("templates/ambient-daemonset.yaml");

    // Attestation derivation is gated on the CURRENT release phase being
    // stable. A cleanup/finalize rollout that is CHANGING placement therefore
    // cannot emit FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED for itself.
    let established_gate = "eq $ambientTopology \"ambient\") (eq $ambientUdpMigrationPhase \"stable\") .Release.IsUpgrade";
    assert!(
        ambient.contains(established_gate),
        "migrating releases (cleanup/finalize) must be excluded from established attestation"
    );
    assert!(
        !ambient.contains("eq $ambientUdpMigrationPhase \"cleanup\") .Release.IsUpgrade")
            && !ambient.contains("eq $ambientUdpMigrationPhase \"finalize\") .Release.IsUpgrade"),
        "established attestation must not be derivable during cleanup or finalize of the current release"
    );

    // Rendering of the env entry is gated on the derived value, not on migration
    // phase alone, so an empty $ambientUdpEstablished yields no env row.
    assert!(
        ambient.contains(
            "if and $ambientUdpEstablished (not (hasKey $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED\"))"
        ),
        "chart must render FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED only when established is derived"
    );
    assert!(
        ambient.contains("- name: FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED")
            && ambient.contains("value: {{ $ambientUdpEstablished | quote }}"),
        "settled attestation env row must quote the derived established placement"
    );
}

#[test]
fn ambient_env_override_still_wins_over_chart_managed_attestation() {
    let ambient = read("templates/ambient-daemonset.yaml");
    assert!(
        ambient
            .contains("not (hasKey $ambientEnv \"FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED\")"),
        "explicit ambient.env attestation must win so GitOps/client-render pipelines can supply their own gate"
    );
}

// ── Node-specific proof boundary (issue #3809) ──────────────────────────────

#[test]
fn a_settled_host_placement_renders_the_privileged_node_preflight() {
    let ambient = read("templates/ambient-daemonset.yaml");

    // The preflight is scoped to exactly the ambiguous case: the SETTLED
    // (stable-phase) host placement, which is the one that drops setns and
    // therefore cannot inspect a pod netns for itself.
    assert!(
        ambient.contains(
            "$ambientUdpRunNodePreflight := and $ambientUdpLifecycle $ambientUdpHostNetns (eq $ambientUdpMigrationPhase \"stable\") $ambientUdpNodePreflightEnabled"
        ),
        "the preflight must render only for a settled host-netns Ambient placement"
    );
    assert!(
        ambient.contains("initContainers:")
            && ambient.contains("name: ferrum-udp-node-preflight")
            && ambient.contains("args: [\"ambient-udp-preflight\", \"-v\"]"),
        "the preflight must be a one-shot init container running the dedicated subcommand"
    );

    // Privilege containment: the setns set lives in the INIT stage, and the
    // steady-state container's own gate is unchanged.
    let (before_init, after_init) = ambient
        .split_once("initContainers:")
        .expect("init container block");
    let (init_block, steady_state) = after_init
        .split_once("      containers:")
        .expect("steady-state container block");
    for privilege in ["SYS_ADMIN", "SYS_PTRACE"] {
        assert!(
            init_block.contains(privilege),
            "the preflight init stage needs {privilege} to enter pod netns"
        );
    }
    // The one-shot stage's privilege surface is exactly the four declared
    // capabilities: it drops the runtime's ambient/default set FIRST and cannot
    // gain more, so the elevated init stage is narrower than the pod default
    // rather than merely additive.
    assert!(
        init_block.contains("allowPrivilegeEscalation: false"),
        "the preflight init stage must forbid privilege escalation"
    );
    let (init_drop, init_add) = init_block
        .split_once("              add:")
        .expect("the preflight capability add list");
    assert!(
        init_drop.contains("              drop:\n                - ALL\n"),
        "the preflight init stage must drop ALL capabilities before adding its own"
    );
    for privilege in ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"] {
        assert!(
            init_add.contains(privilege),
            "the preflight init stage must re-add {privilege} explicitly after the drop"
        );
    }

    assert!(
        steady_state.contains("{{- if $ambientSetnsCapture }}"),
        "the steady-state container must keep its own narrow setns gate"
    );
    assert!(
        !steady_state.contains("allowPrivilegeEscalation") && !steady_state.contains("drop:"),
        "narrowing the one-shot stage must not silently rewrite the steady-state \
         container's capability contract"
    );
    assert!(
        !steady_state.contains("$ambientUdpRunNodePreflight"),
        "the preflight must not widen the steady-state container's privileges"
    );
    assert!(
        before_init.contains("if or $ambientSetnsCapture $ambientUdpRunNodePreflight")
            && before_init.contains("hostPID: true"),
        "hostPID is required by the init stage's setns work and must be gated on it"
    );

    // The preflight needs the registry (its proof artifact and pod inventory)
    // and the host cgroup mount (pod netns resolution).
    assert!(
        init_block.contains("name: node-waypoint-pod-registry")
            && init_block.contains("name: cgroup"),
        "the preflight must mount the pod registry and host cgroup"
    );
}

#[test]
fn the_node_proof_generation_is_derived_from_the_installed_contract_for_both_daemonsets() {
    let helpers = read("templates/_helpers.tpl");
    let ambient = read("templates/ambient-daemonset.yaml");
    let node_agent = read("templates/node-agent-daemonset.yaml");

    assert!(
        helpers.contains("define \"ferrum-mesh.ambientUdpNodeProofGeneration\"")
            && helpers.contains("lookup \"v1\" \"ConfigMap\" .Release.Namespace $contractName"),
        "the node-proof generation must be derived from the INSTALLED placement contract"
    );
    // The helper reads the PERSISTED era-qualified token and nothing else. A
    // token derived from the release's observable shape repeats the moment a
    // target and phase recur, which is exactly the replay issue #3809 refuses.
    assert!(
        helpers.contains("index $data \"nodeProofGeneration\""),
        "the node-proof generation must come from the contract's persisted \
         era-qualified field"
    );
    assert!(
        !helpers.contains("printf \"%s-%s\" $target $phase"),
        "a `<target>-<phase>` fallback recurs across placement eras and must not exist"
    );

    // One shared helper, so the ambient pod, its preflight, and the node-agent's
    // registry-synchronization publication can never disagree.
    for (name, template) in [("ambient", &ambient), ("node-agent", &node_agent)] {
        assert!(
            template.contains("include \"ferrum-mesh.ambientUdpNodeProofGeneration\""),
            "{name} must derive the node-proof generation from the shared helper"
        );
        assert!(
            template.contains("- name: FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"),
            "{name} must carry FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"
        );
    }
    assert!(
        node_agent.contains(
            "\"FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION\"\n  \"FERRUM_MESH_TOPOLOGY\""
        ),
        "the node-agent must treat the node-proof generation as chart-managed"
    );

    // Fail closed rather than rendering a preflight that can prove nothing.
    assert!(
        ambient.contains(
            "requires an installed placement contract to derive FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION"
        ),
        "a settled host placement with no derivable proof generation must fail rendering"
    );
}

#[test]
fn client_render_parity_keeps_an_explicit_env_value_under_the_same_boundary() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let values = read("values.yaml");

    // An explicit ambient.env value still wins for BOTH variables, so a
    // GitOps/client-render pipeline supplies its own — and is held to the same
    // node-specific proof contract, because the boundary lives in the runtime.
    for name in [
        "FERRUM_MESH_CAPTURE_UDP_PLACEMENT_ESTABLISHED",
        "FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION",
    ] {
        assert!(
            ambient.contains(&format!("not (hasKey $ambientEnv \"{name}\")")),
            "an explicit ambient.env {name} must win over the chart-derived value"
        );
    }
    assert!(
        ambient.contains("authorizes nothing on its own")
            || ambient.contains("DESIRED STATE, not authorization"),
        "the template must record that the release attestation is not authorization"
    );

    // The escape hatch is documented as non-relaxing.
    assert!(
        values.contains("udpNodePreflight")
            && values.contains("does NOT relax the runtime boundary"),
        "values must document that disabling the preflight keeps the runtime fail-closed"
    );
}

#[test]
fn the_node_agent_can_read_its_own_node_object_for_the_uid_binding() {
    let rbac = read("templates/node-agent-rbac.yaml");
    assert!(
        rbac.contains("resources: [\"nodes\"]") && rbac.contains("verbs: [\"get\"]"),
        "the node-agent needs a read-only nodes grant to resolve Node.metadata.uid"
    );
    assert!(
        !rbac.contains("verbs: [\"*\"]")
            && !rbac.contains("\"create\"")
            && !rbac.contains("\"patch\""),
        "the nodes grant must stay read-only"
    );
}

/// The placement contract carries the migration-era provenance the whole proof
/// boundary rests on, and the era is what makes the token non-recurring.
#[test]
fn the_placement_contract_persists_a_non_recurring_node_proof_era() {
    let contract = read("templates/udp-placement-contract.yaml");

    assert!(
        contract.contains("nodeProofEra: {{ $nodeProofEra | toString | quote }}")
            && contract.contains("nodeProofGeneration: {{ $nodeProofGeneration | quote }}"),
        "the installed contract must record the era and its era-qualified token"
    );
    // Starting a migration opens a NEW era; resuming the same cleanup release
    // keeps the one already open, so retries are idempotent while transitions
    // strictly advance.
    assert!(
        contract.contains("{{- $nodeProofEra = add1 $previousEra -}}")
            && contract
                .contains("{{- $nodeProofGeneration = printf \"e%d.%s\" $nodeProofEra $generation")
            && contract.contains("{{- if not (and $resumeCleanup $nodeProofGeneration) -}}"),
        "a cleanup START must open the next era and an era-qualified token"
    );
    // Finalize and every settled release after it carry the era forward
    // unchanged: only the cleanup branch reassigns it.
    assert!(
        contract.matches("$nodeProofEra = ").count() == 1
            && contract.matches("$nodeProofGeneration = ").count() == 1,
        "only the cleanup branch may stamp a new era; every other phase carries \
         the installed contract's value forward"
    );
    assert!(
        contract.contains(
            "$previousNodeProofGeneration = trim (toString (default \"\" (index $previous \"nodeProofGeneration\")))"
        ),
        "the carried-forward token must come from the installed contract"
    );
}

/// The preflight resolves this node's UID itself, so it can never pair a stale
/// identity publication with the stale cleanup proof written under it.
#[test]
fn the_preflight_binds_its_node_lookup_to_this_pods_node_name() {
    let ambient = read("templates/ambient-daemonset.yaml");
    let rbac = read("templates/ambient-rbac.yaml");

    let (_, after_init) = ambient
        .split_once("initContainers:")
        .expect("init container block");
    let (init_block, _) = after_init
        .split_once("      containers:")
        .expect("steady-state container block");
    assert!(
        init_block.contains("- name: FERRUM_K8S_NODE_NAME")
            && init_block.contains("fieldPath: spec.nodeName"),
        "the preflight must receive this pod's node name from the downward API"
    );

    assert!(
        rbac.contains("resources: [\"nodes\"]") && rbac.contains("verbs: [\"get\"]"),
        "the ambient service account needs a read-only nodes grant for the preflight lookup"
    );
    // Least privilege: a named `get` and nothing that could enumerate or mutate
    // the cluster's nodes.
    for forbidden in [
        "\"list\"", "\"watch\"", "\"create\"", "\"update\"", "\"patch\"", "\"delete\"", "\"*\"",
    ] {
        assert!(
            !rbac.contains(forbidden),
            "the ambient nodes grant must not carry {forbidden}"
        );
    }
    assert!(
        rbac.contains("name: ferrum-mesh\n    namespace: {{ .Release.Namespace }}"),
        "the grant must bind the ambient DaemonSet's own service account"
    );
}
