//! Canonical Subject Alternative Name strings for admin TLS summaries.
//!
//! Managed certificates/CA bundles, ACME certificate records, and the TLS
//! inventory all render `sans` through [`certificate_san_strings`]. The
//! values are plain canonical strings with **no** `DNS:` / `IP:` type prefix:
//! Foundry TLS pages and the existing managed/ACME summaries already treat
//! `sans` as the name itself (`localhost`, `api.example.com`), so prefixes
//! would be a display-layer concern rather than part of the API contract.
//!
//! Representation (issue #5543):
//!
//! - DNS names: the encoded name as-is (`localhost`)
//! - IPv4: dotted decimal via [`std::net::IpAddr`] (`127.0.0.1`)
//! - IPv6: RFC 5952 via [`std::net::IpAddr`] (`2001:db8::1`)
//! - URI: the URI string
//! - email (`rfc822Name`): the email string
//! - other / unknown `GeneralName` types: an explicit typed form that cannot be
//!   mistaken for a DNS, IP, URI, or email value:
//!   `othername:<oid>`, `directory:<dn>`, `rid:<oid>`, `x400`, `ediparty`,
//!   `invalid-ip:<hex>` (IP SAN that is not 4 or 16 bytes), or `invalid:<tag>`
//!
//! Returned values are unique and sorted.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;

/// Format one SAN [`GeneralName`] as a canonical admin-API string.
pub fn format_general_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(value) => value.to_string(),
        GeneralName::RFC822Name(value) => value.to_string(),
        GeneralName::URI(value) => value.to_string(),
        GeneralName::IPAddress(bytes) => match ip_addr_from_san_bytes(bytes) {
            Some(addr) => addr.to_string(),
            None => format!("invalid-ip:{}", hex::encode(bytes)),
        },
        GeneralName::OtherName(oid, _) => format!("othername:{oid}"),
        GeneralName::DirectoryName(dn) => format!("directory:{dn}"),
        GeneralName::RegisteredID(oid) => format!("rid:{oid}"),
        GeneralName::X400Address(_) => "x400".to_string(),
        GeneralName::EDIPartyName(_) => "ediparty".to_string(),
        GeneralName::Invalid(tag, _) => format!("invalid:{tag}"),
    }
}

/// Unique, sorted SAN strings from a parsed certificate's SAN extension(s).
pub fn certificate_san_strings(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut sans = BTreeSet::new();
    for extension in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            sans.insert(format_general_name(name));
        }
    }
    sans.into_iter().collect()
}

/// Parse an IP Address SAN as IPv4 (4 bytes) or IPv6 (16 bytes).
pub(crate) fn ip_addr_from_san_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => bytes
            .try_into()
            .ok()
            .map(|octets: [u8; 4]| IpAddr::V4(Ipv4Addr::from(octets))),
        16 => bytes
            .try_into()
            .ok()
            .map(|octets: [u8; 16]| IpAddr::V6(Ipv6Addr::from(octets))),
        _ => None,
    }
}
