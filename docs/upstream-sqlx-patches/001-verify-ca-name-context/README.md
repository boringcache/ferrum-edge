# SQLx verify-ca hostname-error compatibility

## Status

Deliberate fork, unfiled upstream. Owner: Ferrum Edge maintainers. This patch
resolves Ferrum issue #5534 and follows the weekly review and stable-release
checkpoint in [dependency policy](../../dependency-policy.md).

## Patch

The base is the crates.io `sqlx-core` 0.8.6 source (package checksum
`ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`).
Only `src/net/tls/tls_rustls.rs` and the rustls dependency floor in the two
Cargo manifests differ from that source. The floor is 0.23.45, the version
already in Ferrum's locked graph, which provides the context-bearing variant.

SQLx correctly maps PostgreSQL `VerifyCa` and MySQL `VerifyCa` to
`NoHostnameTlsVerifier`. That wrapper waived only
`CertificateError::NotValidForName`; rustls now returns
`CertificateError::NotValidForNameContext` for the same name mismatch.
Handle both variants after WebPKI has verified the chain and certificate
validity. All other errors propagate. The verify-ca WebPKI verifier is also
built with the crypto provider the handshake already selected
(`builder_with_provider`) instead of the provider-less builder, which resolves
the process default from crate features and panics when both `ring` and
`aws-lc-rs` are compiled in and nothing installed a default. TLS 1.2 and 1.3 handshake signature
verification still delegates to the original WebPKI verifier. `verify-full`
does not use this wrapper and keeps hostname verification.

A gateway-side TLS option cannot replace SQLx Any's internal verifier. A
SQLx 0.9 migration would change the database dependency graph beyond this
compatibility fix; the small 0.8.6 patch keeps that graph unchanged.

## Regression coverage

`tests/service_integration/db_tls.rs` runs in hosted **Service Integration**:
both SQL dialects accept matching names and verify-ca name mismatches, reject
verify-full name mismatches, reject unrelated CAs, and reject expired leaves.
The same fixtures cover retained trust through rejected reloads and fresh
connections (#5535). Unit coverage pins EnvConfig-to-driver mode mapping for
database, CP, and migrate consumers and primary/failover/replica URLs.

## Retirement

Retire when a compatible upstream SQLx release supports both name-error
variants (or verifies chains separately from names) and passes the same
handshake controls. Remove both `[patch.crates-io]` entries, the vendor copy,
and lifecycle inventory row; update both lockfiles and the drift manifest.
Keep all Ferrum unit and service-integration regressions. No upstream review
or issue was requested as part of this dispatch.

Validation is GitHub-hosted CI on the pushed head. No project code, build,
test, formatter, or script was executed locally. The new vendor manifest
entries were prepared from static file hashes; the hosted drift guard must
verify them.
