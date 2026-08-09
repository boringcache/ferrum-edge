#![allow(dead_code)]

//! Mesh configuration consumers.

pub mod common;
pub mod file_source;
pub mod native_client;
/// Issue #3317: stock Envoy / third-party Istio ADS consumer. Separate from
/// [`xds_client`], which is the Ferrum-private xDS profile.
pub mod stock_xds_client;
pub mod update_validation;
pub mod xds_client;
