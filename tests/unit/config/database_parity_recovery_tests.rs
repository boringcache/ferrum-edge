//! Source contract for PostgreSQL/MySQL connectivity-recovery retries.
//!
//! Hosted data-plane CI failed when MySQL returned `409 Conflict` for the
//! entire 30s recovery window. `POST /proxies` maps an existing id or
//! overlapping `(listen_path, hosts)` to 409; retrying one hoisted identity
//! after a committed-but-unsettled write therefore cannot recover. The live
//! cells must mint a fresh id and listen_path inside the retry loop.

#[test]
fn connectivity_recovery_retries_mint_a_fresh_proxy_identity() {
    let src = include_str!("../../functional/functional_database_parity_test.rs");
    let start = src
        .find("async fn run_connectivity_recovery")
        .expect("run_connectivity_recovery helper");
    let fn_src = src[start..]
        .split("\n#[tokio::test]")
        .next()
        .expect("recovery helper body");
    let (before_loop, loop_src) = fn_src
        .split_once("loop {")
        .expect("recovery wait loop after unpause");

    assert!(
        !before_loop.contains("let recovery_id"),
        "do not hoist one recovery proxy id across retries; a committed MySQL \
         create that later returns 5xx then 409s for the rest of the deadline"
    );
    assert!(
        !before_loop.contains("let recovery_path"),
        "do not hoist one recovery listen_path across retries"
    );
    assert!(
        loop_src.contains("Uuid::new_v4()"),
        "each recovery POST must mint a fresh identity inside the retry loop"
    );
    assert!(
        loop_src.contains("let recovery_id") && loop_src.contains("let recovery_path"),
        "the retry loop must bind a per-attempt id and listen_path"
    );
}
