//! Access-log filter expression canonicalization bounds.
//!
//! Covers three-or-more same-operator chains (no recursion bomb) and the
//! post-canonical AST node ceiling after `response.code == N` expands.

use ferrum_edge::modes::mesh::access_log_filter::{
    AccessLogFilterContext, AccessLogFilterExpr, MAX_ACCESS_LOG_FILTER_AST_NODES,
    evaluate_access_log_filter_expr, parse_access_log_filter_expression,
    validate_access_log_filter_expr,
};

#[test]
fn three_term_and_flattens_without_recursion_bomb() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 400 && response.code <= 499 && response.duration >= 1000",
    )
    .expect("parses")
    .expect("filter");
    assert!(filter.expression.is_none());
    assert_eq!(filter.status_code_min, Some(400));
    assert_eq!(filter.status_code_max, Some(499));
    assert_eq!(filter.min_latency_ms, Some(1000));
}

#[test]
fn three_term_or_canonicalizes_without_recursion_bomb() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 500 || response.duration >= 1000 || response.code <= 399",
    )
    .expect("parses")
    .expect("filter");
    let expr = filter.expression.expect("uses expression tree");
    // Left-associative parser shape; boolean OR is associative so semantics
    // match any balanced tree with the same leaves.
    assert_eq!(
        expr,
        AccessLogFilterExpr::Or {
            left: Box::new(AccessLogFilterExpr::Or {
                left: Box::new(AccessLogFilterExpr::StatusCodeMin { value: 500 }),
                right: Box::new(AccessLogFilterExpr::MinLatencyMs { value: 1000 }),
            }),
            right: Box::new(AccessLogFilterExpr::StatusCodeMax { value: 399 }),
        }
    );

    let match_first = AccessLogFilterContext {
        response_status_code: 503,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    let match_middle = AccessLogFilterContext {
        response_status_code: 200,
        latency_total_ms: 1500.0,
        is_terminal_failure: false,
    };
    let match_last = AccessLogFilterContext {
        response_status_code: 200,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    let match_none = AccessLogFilterContext {
        response_status_code: 404,
        latency_total_ms: 1.0,
        is_terminal_failure: false,
    };
    assert!(evaluate_access_log_filter_expr(&expr, match_first));
    assert!(evaluate_access_log_filter_expr(&expr, match_middle));
    assert!(evaluate_access_log_filter_expr(&expr, match_last));
    assert!(!evaluate_access_log_filter_expr(&expr, match_none));
}

#[test]
fn and_still_binds_tighter_than_or_with_three_terms() {
    let filter = parse_access_log_filter_expression(
        "response.code >= 500 || response.code >= 400 && response.code <= 499 || response.duration >= 1000",
    )
    .expect("parses")
    .expect("filter");
    let expr = filter.expression.expect("uses expression tree");
    // A || (B && C) || D  — root remains Or with an And child.
    assert!(matches!(expr, AccessLogFilterExpr::Or { .. }));
    fn contains_and(expr: &AccessLogFilterExpr) -> bool {
        match expr {
            AccessLogFilterExpr::And { .. } => true,
            AccessLogFilterExpr::Or { left, right } => contains_and(left) || contains_and(right),
            _ => false,
        }
    }
    assert!(contains_and(&expr), "&& must bind inside the || chain");
}

#[test]
fn equality_expansion_cannot_exceed_final_ast_cap() {
    // Nine `response.code == N` atoms parse as 17 nodes (9 atoms + 8 `||`),
    // under the parse-time cap, but expand to 35 final nodes
    // (9×And(min,max) + 8 Or) and must fail closed on the final bound.
    let terms: Vec<String> = (500..509)
        .map(|code| format!("response.code == {code}"))
        .collect();
    let expr = terms.join(" || ");
    let err = parse_access_log_filter_expression(&expr).expect_err("final AST cap");
    assert!(
        err.contains("maximum AST node count"),
        "expected final AST cap diagnostic, got: {err}"
    );
    assert_eq!(MAX_ACCESS_LOG_FILTER_AST_NODES, 32);
}

#[test]
fn equality_expansion_at_final_ast_cap_is_accepted() {
    // Eight equality atoms + 7 Or => 8*3 + 7 = 31 final nodes (<= 32).
    let terms: Vec<String> = (500..508)
        .map(|code| format!("response.code == {code}"))
        .collect();
    let expr = terms.join(" || ");
    let filter = parse_access_log_filter_expression(&expr)
        .expect("parses at final cap")
        .expect("filter");
    let tree = filter.expression.expect("uses expression tree");
    validate_access_log_filter_expr(&tree).expect("final tree within cap");
}
