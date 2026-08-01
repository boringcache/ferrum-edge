# FIPS 140-2 / 140-3 Deployment Mode

## Status of this document

**Ferrum Edge is not a validated cryptographic module and is not independently
FIPS-certified. No configuration of this binary makes it so.**

This document describes:

1. the FIPS deployment mode that ships today — its request surface, its
   fail-closed behaviour, and the single cryptographic-provider seam it is built
   on;
2. the validated-module integration Ferrum has **selected** (`aws-lc-fips`), the
   exact build contract it requires, and what remains before that integration
   can ship;
3. the module boundary — what a validated module would and would not cover — and
   the operator obligations that no amount of gateway code can discharge.

Read §"Current capability" before planning a deployment. The mode is
**fail-closed**: on a build that cannot provide a validated module,
`FERRUM_FIPS_MODE=enforce` refuses to start rather than serving with
non-validated cryptography.

## Current capability

| | Status |
|---|---|
| Request surface (`--fips-mode`, `FERRUM_FIPS_MODE`, `FERRUM_FIPS_REQUIRED_PROVIDER`) | **Shipped** |
| Fail-closed bootstrap when the module is absent | **Shipped** |
| Single crypto-provider seam (`crate::fips`) across all rustls construction | **Shipped** |
| Admission policy (TLS versions/suites/groups, JWT algorithms, key sizes, non-approved plugins, MongoDB TLS) | **Shipped** |
| Authenticated status/health metadata | **Shipped** |
| Source-level crypto inventory | **Shipped** (`src/fips/inventory.rs`) |
| **AWS-LC-FIPS module linked into the binary** | **Not yet** — see §"Residual work" |

Because the module is not linked, `crate::fips::BUILD_CAPABLE` is `false` and
`FERRUM_FIPS_MODE=enforce` always fails startup with an explicit diagnostic.
That is deliberate. A mode that "enforces" without a validated module underneath
would be a compliance claim the binary cannot back, which is worse than no mode
at all.

## Configuration

Precedence follows Ferrum's standard order: **CLI > environment > `ferrum.conf`
> default**, with one deliberate exception documented below.

| Setting | Values | Default |
|---|---|---|
| `--fips-mode` / `FERRUM_FIPS_MODE` | `off`, `enforce` (also `true`/`false`/`on`/`disabled`) | `off` |
| `FERRUM_FIPS_REQUIRED_PROVIDER` | `aws-lc-fips` | `aws-lc-fips` |

An unrecognized `FERRUM_FIPS_MODE` value is a configuration error, not a silent
downgrade — a typo'd `enfroce` must not quietly run non-FIPS.

`FERRUM_FIPS_REQUIRED_PROVIDER` pins the integration the operator audited. Only
one integration is supported, so today its only effect is to reject a value that
names something else; its purpose is forward-looking, so a future build that
changed integrations cannot silently satisfy an existing deployment contract.

### The `ferrum.conf` exception

The rustls process-default cryptographic provider must be installed **before any
TLS material is parsed**, which is before `ferrum.conf` can be read (reading the
settings file that early would pin `CONF_FILE_CACHE` to the wrong path — see
`.claude/rules/tls-security.md`). A FIPS request therefore has to arrive through
the CLI flag or the process environment.

A request that appears **only** in `ferrum.conf` is not ignored: after `EnvConfig`
resolution, `fips::verify_resolved_mode` detects the mismatch and fails the
command with an explicit message telling the operator to move the setting. It
never serves under a provider chosen from a stale view of the request.

## What FIPS mode enforces

All of the following run identically during `ferrum-edge validate`, at startup,
and at every rustls policy construction — including after a frontend TLS live
reload, which rebuilds through the same constructor.

**Transport**

- TLS versions restricted to 1.2 / 1.3 (SP 800-52r2).
- Cipher suites and key-exchange groups screened by rustls's own
  `SupportedCipherSuite::fips()` / `SupportedKxGroup::fips()`. Ferrum delegates
  the classification rather than re-deriving an allow-list, so its notion of
  "approved" cannot drift from the module's.
- FIPS defaults drop **ChaCha20-Poly1305** (not an approved AEAD) and **X25519**
  (ECDH over Curve25519 is not an approved SP 800-56A scheme). An explicitly
  configured non-approved suite or group is rejected with a bounded diagnostic
  naming it — never silently dropped from the list.
- `FERRUM_TLS_NO_VERIFY=true` is refused: an unauthenticated peer defeats the
  point of an approved key exchange.

**Keys and algorithms**

- JWT/JWS algorithms restricted to HS256/384/512, RS256/384/512, PS256/384/512,
  ES256/384/512. `none` is always rejected. `EdDSA` is rejected — Ed25519 is
  approved by FIPS 186-5 but is not part of the algorithm set Ferrum routes
  through the selected module, so admitting it would be an unbacked claim.
- `FERRUM_ADMIN_JWT_SECRET` and `FERRUM_CP_DP_GRPC_JWT_SECRET` must be at least
  32 bytes (SP 800-107 HMAC key strength).

**Rejected configurations**

- `kafka_logging`: librdkafka performs its TLS through OpenSSL, outside the
  selected module. Use `tcp_logging`, `ws_logging`, or `http_logging`, which are
  rustls-based.
- `FERRUM_DB_TYPE=mongodb` with `FERRUM_DB_TLS_MODE` other than `disable`: the
  MongoDB driver pins its own non-validated rustls provider in its manifest and
  builds its client config from it, so Ferrum cannot route that transport. Use a
  SQL config store, file mode, or CP/DP distribution.

Every diagnostic is bounded — at most 8 offending entries are named, followed by
a count — and carries no secret, key material, path, or free-form
operator-supplied value.

## The module boundary

A FIPS 140-2/140-3 certificate covers a **cryptographic module**, not an
application. When the AWS-LC-FIPS integration ships, the boundary is:

**Inside the module** — block ciphers and AEADs, hashes and HMAC, the DRBG,
signature generation/verification, key agreement, and the TLS/QUIC key schedules
that consume them.

**Outside the module, Ferrum's responsibility** — protocol state machines,
certificate path building and policy, configuration admission, key *storage* and
file permissions, algorithm *selection* (what this mode enforces), and the
correctness with which Ferrum calls the module.

**Outside the module, the operator's responsibility** — and no gateway code can
discharge these:

- **The exact validated module.** A certificate names a module version built for
  a specific operating environment. Rebuilding AWS-LC-FIPS from source with a
  different toolchain produces a module that is *not* the validated one. The
  operator must record the certificate number, module version, and operating
  environment for their deployment.
- **Build reproducibility.** The binary an auditor examines must be the binary in
  production.
- **Operating environment.** The certificate's tested platform list is part of
  the validation. A container base image, kernel, and CPU feature set outside
  that list is outside the validation.
- **Key management.** Generation, storage, rotation, escrow, and destruction of
  private keys, JWT secrets, and PKCS#11 token credentials.
- **PKCS#11 tokens.** Signing happens inside the operator's HSM, which must carry
  its own validation. Ferrum's mode says nothing about it.
- **External secret providers** (Vault, AWS, Azure, GCP). Their SDK TLS stacks are
  not routed through Ferrum's provider. Secrets resolve once at startup, before
  the gateway serves; the remote KMS/HSM carries its own validation.

## Source-level crypto inventory

`src/fips/inventory.rs` is the machine-readable inventory: every
security-relevant cryptographic operation, the source location that performs it,
the implementing library, and its disposition. It is asserted by
`tests/unit/tls/fips_inventory_tests.rs`, which fails if an entry is
unclassified or if the rejected-plugin set drifts from the policy.

Dispositions are `module-backed`, `rejected` (refused by the admission policy),
and `outside-boundary` (not a claim Ferrum makes — see above).

## Residual work before the module can ship

These are the concrete, known blockers. None is a design question; all are
mechanical but individually verifiable work.

1. **Dependency-feature contract.** The crypto backend must become a pair of
   mutually exclusive cargo features (`crypto-ring`, default, and `fips`) rather
   than a set of unconditional dependency features. Cargo features are additive,
   and `sqlx-core`, `quinn-proto`, and `tonic` each gate their aws-lc arm on
   `not(ring)` — so additively "also enabling aws-lc" leaves the non-validated
   implementation in charge while *looking* switched. The verified mapping is:

   | Dependency | `crypto-ring` | `fips` |
   |---|---|---|
   | `rustls` | `ring` | `fips` |
   | `tonic` | `tls-ring` | `tls-aws-lc` |
   | `quinn` | `rustls-ring` | `rustls-aws-lc-rs-fips` |
   | `sqlx` | `tls-rustls-ring` | `tls-rustls-aws-lc-rs` |
   | `ldap3` | `tls-rustls-ring` | `tls-rustls-aws-lc-rs` |
   | `jsonwebtoken` | `rust_crypto` | `aws_lc_rs` |
   | `rcgen` | `ring` | `fips` |
   | `x509-parser` | `verify` | `verify-aws` |
   | `hyper-rustls` (acme) | `ring` | `fips` |
   | `instant-acme` (acme) | `ring` | `fips` |
   | `ring` / `aws-lc-rs` | `dep:ring` | `dep:aws-lc-rs` + `aws-lc-rs/fips` |

   `reqwest` 0.13's `rustls` feature is already aws-lc-rs backed, and `dimpl`
   (DTLS) already selects `aws-lc-rs`, so both follow feature unification.

2. **RustCrypto hash/MAC surface.** 47 source files import `sha2`/`hmac`
   directly. Most are non-security uses (cache keys, dedup keys, fingerprints),
   but `hmac_auth`, `basic_auth`, `dpop`, `mtls_auth`, `oidc_relying_party`, and
   `ai_transcript_audit` are security-relevant and must move onto the module or
   be classified and rejected. This is the largest remaining item and it is not
   mechanical: RustCrypto's streaming `Digest` API and the module's one-shot API
   differ.

3. **Inline `#[cfg(test)]` provider construction.** Several source modules build
   `rustls::crypto::ring` providers inside inline test modules. They must move
   onto `crate::fips::base_crypto_provider()` before `cargo test --features fips`
   can compile.

4. **Config-admission wiring.** `fips::policy::check_gateway_config` is
   implemented and tested but is not yet called from the file-mode SIGHUP reload,
   database poll apply, CP publication, or DP snapshot/delta apply paths. Until
   it is, gateway-document policy is enforced at `validate` and startup only.

5. **Hosted CI.** A `--no-default-features --features fips` build job (AWS-LC-FIPS
   needs cmake and Go, and is slow) plus the FIPS-profile test subset.

6. **`deny.toml` / dependency policy.** `[graph] all-features = true` means
   cargo-deny will resolve `aws-lc-fips-sys`; that must be reviewed and the
   dependency-policy inventory updated.

## Verifying a deployment

Once the module ships, an operator confirms the runtime posture through the
**authenticated** detail tier of `/health` or `/status`:

```json
{
  "fips": {
    "mode": "enforce",
    "enforcing": true,
    "build_capable": true,
    "provider": "aws-lc-fips",
    "module_self_test_passed": true,
    "provider_algorithms_approved": true,
    "certified": false,
    "boundary_documentation": "docs/fips.md"
  }
}
```

`certified` is always `false` and is present precisely so that a status scraper
cannot read `enforcing: true` as "certified". This object is never exposed on the
unauthenticated coarse tier (`/live`, or `/health` without credentials), which
continues to return only `status` and `ready`.

The gateway's report is necessary but not sufficient evidence. Deployment
compliance requires the exact validated module, build, operating environment, and
operational controls enumerated in §"The module boundary", established and
recorded by the operator.
