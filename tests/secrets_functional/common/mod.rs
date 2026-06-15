//! Shared scaffolding for the secret-backend functional tests.

pub mod env;

// Docker-backed fixtures (Vault dev server, LocalStack) — only compiled when a
// provider that needs them is enabled.
#[cfg(any(feature = "secrets-vault", feature = "secrets-aws"))]
pub mod containers;

// In-process wiremock fakes (GCP, Azure) — only compiled when a provider that
// needs them is enabled.
#[cfg(any(feature = "secrets-gcp", feature = "secrets-azure"))]
pub mod fakes;
