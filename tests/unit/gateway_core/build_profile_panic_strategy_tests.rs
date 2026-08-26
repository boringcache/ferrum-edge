//! Shipping-profile panic strategy (issue #4166).
//!
//! `[profile.release]` and `[profile.max-perf]` set `panic = "abort"`.
//! `ci-release` inherits `release`. Dev/test/`pr-build` keep the default
//! `unwind` so the test suite can observe `JoinError::is_panic()`.
//! This file pins both the Cargo.toml source of truth and the compiled cfg
//! split so the documented fail-fast policy cannot drift.

const ROOT_CARGO_TOML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));

fn profile_body<'a>(toml: &'a str, header: &str) -> &'a str {
    let start = toml
        .find(header)
        .unwrap_or_else(|| panic!("Cargo.toml must contain {header}"));
    let after_header = &toml[start + header.len()..];
    let end = after_header.find("\n[").unwrap_or(after_header.len());
    &after_header[..end]
}

fn profile_declares_panic_abort(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed.contains("panic") && trimmed.contains("\"abort\"")
    })
}

fn profile_declares_panic_unwind(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#') && trimmed.contains("panic") && trimmed.contains("\"unwind\"")
    })
}

#[test]
fn release_and_max_perf_set_panic_abort() {
    assert!(
        profile_declares_panic_abort(profile_body(ROOT_CARGO_TOML, "[profile.release]")),
        "[profile.release] must set panic = \"abort\""
    );
    assert!(
        profile_declares_panic_abort(profile_body(ROOT_CARGO_TOML, "[profile.max-perf]")),
        "[profile.max-perf] must set panic = \"abort\""
    );
}

#[test]
fn ci_release_inherits_release_without_overriding_panic() {
    let body = profile_body(ROOT_CARGO_TOML, "[profile.ci-release]");
    assert!(
        body.contains("inherits = \"release\""),
        "[profile.ci-release] must inherit release (and therefore panic = abort)"
    );
    assert!(
        !profile_declares_panic_abort(body) && !profile_declares_panic_unwind(body),
        "[profile.ci-release] must not override panic; inherit release's abort"
    );
}

#[test]
fn dev_and_pr_build_do_not_set_panic_abort() {
    let dev = profile_body(ROOT_CARGO_TOML, "[profile.dev]");
    assert!(
        !profile_declares_panic_abort(dev),
        "[profile.dev] must keep the default unwind strategy"
    );
    let pr_build = profile_body(ROOT_CARGO_TOML, "[profile.pr-build]");
    assert!(
        pr_build.contains("inherits = \"dev\""),
        "[profile.pr-build] must inherit dev (unwind)"
    );
    assert!(
        !profile_declares_panic_abort(pr_build),
        "[profile.pr-build] must not set panic = \"abort\""
    );
}

#[test]
fn compiled_panic_cfg_matches_documented_split() {
    // `cfg!` folds to a literal, so these are compile-time invariants rather
    // than runtime checks — clippy::assertions_on_constants says so. Asserting
    // them in a `const` block keeps the guarantee and states it honestly: the
    // build either has the right panic strategy or it does not compile.
    // The `if` must live INSIDE the const block. A `const { .. }` nested in a
    // runtime branch is still const-evaluated whether or not that branch is
    // taken, so putting one in each arm makes BOTH assertions fire and the
    // build dies on whichever profile it is not. With the branch inside, const
    // evaluation follows it and only the applicable assertion is checked.
    const {
        if cfg!(debug_assertions) {
            assert!(
                cfg!(panic = "unwind"),
                "dev/test/pr-build must unwind so JoinError::is_panic() is observable"
            )
        } else {
            assert!(
                cfg!(panic = "abort"),
                "shipping profiles must abort on panic; see Cargo.toml [profile.release]"
            )
        }
    };
}
