"""Strict small result validator; positive evidence survives incomplete capture."""

KINDS = {
    1: "tx_gso", 2: "tx_ordinary", 3: "tx_error", 4: "tx_uncovered",
    5: "rx_gro", 6: "rx_ordinary", 7: "rx_error", 8: "rx_truncated", 9: "rx_peek",
    10: "classic_selected", 11: "classic_null", 12: "selector_selected",
    13: "selector_fallback", 14: "attach_ok", 15: "attach_error",
}
LOSSES = ["map_full", "read_failed", "unknown_cookie", "nested", "unmatched",
          "attempts", "recorded", "excluded_api"]


def assess(ready, final, fixture, family, forced_overflow=False):
    result = {"status": ready["status"], "positive": [], "exact_totals": False,
              "absence_claim_allowed": False, "gateway_behavior_proven": False,
              "scope": "native_amd64_ipv4_fixture_netns", "routing_distribution_complete": False}
    if ready["status"] != "supported":
        result["reason"] = ready.get("reason", "observer_not_ready")
        return result
    assert final and final["phase"] == "final", "missing final snapshot"
    assert len(final["rows"]) <= (1 if forced_overflow else 512)
    assert len(final["losses"]) == len(LOSSES)
    assert final["start_ns"] <= fixture["start_ns"] <= fixture["end_ns"] <= final["end_ns"]
    cookies = {entry["cookie"] for entry in fixture["sockets"]}
    rows = final["rows"]
    for row in rows:
        assert row["cookie"] in cookies, "event attributed to a foreign socket"
        assert row["peer_cookie"] == 0 or row["peer_cookie"] in cookies
        assert row["kind"] in KINDS and row["count"] > 0
        assert final["start_ns"] <= row["first_ns"] <= row["last_ns"] <= final["end_ns"]
        if row["kind"] in (1, 5):
            assert row["segment"] > 0 and row["length"] > row["segment"]
            assert row["result"] == row["length"]
            result["positive"].append(KINDS[row["kind"]])
        if row["kind"] == 10:
            assert row["peer_cookie"] > 0
            result["positive"].append("classic_execution_selected_socket")
    result["positive"] = sorted(set(result["positive"]))
    loss = dict(zip(LOSSES, final["losses"]))
    result["loss"] = loss
    incomplete = (any(loss[key] for key in LOSSES if key not in ("attempts", "recorded"))
                  or final["map_read_failures"] or final["pending_tx"] or final["pending_rx"] or final["pending_selector"]
                  or any(row["kind"] == 4 for row in rows))
    result["status"] = "partial_coverage" if incomplete else "supported"
    # Global totals/distribution stay unclaimed even with a complete fixture interval.
    result["fixture_interval_complete"] = not bool(incomplete)
    if fixture["status"] != "supported":
        result.update(status=fixture["status"], reason=fixture.get("reason", "fixture_failed"))
        return result
    by_kind = {row["kind"] for row in rows}
    if forced_overflow:
        assert loss["map_full"] > 0, "forced real map saturation was not detected"
        assert result["positive"], "overflow discarded previously retained positive evidence"
        assert result["status"] == "partial_coverage"
    elif fixture["mode"] == "offload":
        expected = {1, 2, 3} if family == "tx" else {5, 6, 7, 8, 9}
        assert expected <= by_kind, f"missing observed paths: {expected - by_kind}"
        sender = next(s["cookie"] for s in fixture["sockets"] if s["role"] == "sender")
        receiver = next(s["cookie"] for s in fixture["sockets"] if s["role"] == "receiver")
        target, kind = (sender, 1) if family == "tx" else (receiver, 5)
        assert any(r["cookie"] == target and r["kind"] == kind and r["length"] == 4096
                   and r["segment"] == 1024 for r in rows), "missing socket/default-segment attribution"
        assert any(r["cookie"] == target and r["kind"] == kind and r["length"] == 2048
                   and r["segment"] == 512 for r in rows), "missing cmsg-override attribution"
        if family == "tx":
            replacement = next(s["cookie"] for s in fixture["sockets"] if s["role"] == "sender_reused_fd")
            assert any(r["cookie"] == replacement and r["kind"] == 2 for r in rows)
    elif fixture["mode"] == "batches":
        if family == "tx":
            assert {1, 3} <= by_kind, "partial sendmmsg lost its successful message or error"
        else:
            assert loss["excluded_api"] > 0 and 5 not in by_kind
    elif fixture["mode"] == "read-failure":
        assert loss["read_failed"] > 0 and 7 in by_kind and 5 not in by_kind
    else:
        assert 14 in by_kind, "successful kernel attachment not observed"
        selection = next(op["selected_cookie"] for op in fixture["operations"] if op["op"] == "selection")
        if fixture["mode"] == "classic-select":
            assert {10, 12} <= by_kind
            assert any(r["kind"] == 10 and r["peer_cookie"] == selection for r in rows)
        else:
            assert {11, 13} <= by_kind and 10 not in by_kind
            assert any(r["kind"] == 13 and r["peer_cookie"] == selection for r in rows)
            result["status"] = "partial_coverage"
            result["fallback_limit"] = "classic_helper_null_is_not_itself_instruction_execution_proof"
    return result
