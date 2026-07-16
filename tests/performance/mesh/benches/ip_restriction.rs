//! Worst-case lookup timing for a large compiled `ip_restriction` policy.
//!
//! The miss is above every sparse deny interval; the high-address allow match
//! lands in the final interval. One- and four-instance cases cover the supported
//! composition where multiple scoped policies evaluate the same cached client IP.

use std::future::Future;
use std::hint::black_box;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use criterion::{Criterion, criterion_group, criterion_main};
use ferrum_edge::plugins::ip_restriction::IpRestriction;
use ferrum_edge::plugins::{Plugin, RequestContext};
use serde_json::json;

const RULE_COUNT: u32 = 10_000;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn poll_ready<F: Future>(future: F, waker: &Waker) -> F::Output {
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("ip_restriction hook unexpectedly yielded in a synchronous bench"),
    }
}

fn sparse_ipv4_rules() -> Vec<String> {
    (0..RULE_COUNT)
        .map(|index| std::net::Ipv4Addr::from(0x0a00_0001_u32 + index * 2).to_string())
        .collect()
}

fn build_instances(config: &serde_json::Value, count: usize) -> Vec<IpRestriction> {
    (0..count)
        .map(|_| IpRestriction::new(config).expect("benchmark policy must compile"))
        .collect()
}

fn run_instances(
    instances: &[IpRestriction],
    context: &mut RequestContext,
    waker: &Waker,
) {
    for plugin in instances {
        black_box(poll_ready(plugin.on_request_received(context), waker));
    }
}

fn bench_ip_restriction(c: &mut Criterion) {
    let rules = sparse_ipv4_rules();
    let high_match = rules
        .last()
        .expect("benchmark fixture must have a final rule")
        .clone();
    let deny_config = json!({"deny": rules, "mode": "deny_first"});
    let allow_config = json!({"allow": deny_config["deny"].clone()});
    let waker = Waker::from(Arc::new(NoopWake));

    let mut group = c.benchmark_group("ip_restriction_lookup");
    for instance_count in [1usize, 4] {
        let deny_instances = build_instances(&deny_config, instance_count);
        let mut miss_context = RequestContext::new(
            "203.0.113.250".to_string(),
            "GET".to_string(),
            "/benchmark".to_string(),
        );
        black_box(miss_context.canonical_client_ip());
        group.bench_function(
            format!("deny_miss/{RULE_COUNT}_rules/{instance_count}_instances"),
            |b| {
                b.iter(|| {
                    run_instances(
                        black_box(&deny_instances),
                        black_box(&mut miss_context),
                        black_box(&waker),
                    );
                });
            },
        );

        let allow_instances = build_instances(&allow_config, instance_count);
        let mut high_match_context = RequestContext::new(
            high_match.clone(),
            "GET".to_string(),
            "/benchmark".to_string(),
        );
        black_box(high_match_context.canonical_client_ip());
        group.bench_function(
            format!("high_match/{RULE_COUNT}_rules/{instance_count}_instances"),
            |b| {
                b.iter(|| {
                    run_instances(
                        black_box(&allow_instances),
                        black_box(&mut high_match_context),
                        black_box(&waker),
                    );
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_ip_restriction);
criterion_main!(benches);
