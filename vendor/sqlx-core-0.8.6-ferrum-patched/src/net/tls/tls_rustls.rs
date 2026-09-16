use futures_util::future;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::{
    client::{
        danger::{ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{
        pem::{self, PemObject},
        CertificateDer, PrivateKeyDer, ServerName, UnixTime,
    },
    CertificateError, ClientConfig, ClientConnection, Error as TlsError, RootCertStore,
};

use crate::error::Error;
use crate::io::ReadBuf;
use crate::net::tls::util::StdSocket;
use crate::net::tls::TlsConfig;
use crate::net::Socket;

pub struct RustlsSocket<S: Socket> {
    inner: StdSocket<S>,
    state: ClientConnection,
    close_notify_sent: bool,
}

impl<S: Socket> RustlsSocket<S> {
    fn poll_complete_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.state.complete_io(&mut self.inner) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    futures_util::ready!(self.inner.poll_ready(cx))?;
                }
                ready => return Poll::Ready(ready.map(|_| ())),
            }
        }
    }

    async fn complete_io(&mut self) -> io::Result<()> {
        future::poll_fn(|cx| self.poll_complete_io(cx)).await
    }
}

impl<S: Socket> Socket for RustlsSocket<S> {
    fn try_read(&mut self, buf: &mut dyn ReadBuf) -> io::Result<usize> {
        self.state.reader().read(buf.init_mut())
    }

    fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.state.writer().write(buf) {
            // Returns a zero-length write when the buffer is full.
            Ok(0) => Err(io::ErrorKind::WouldBlock.into()),
            other => other,
        }
    }

    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_complete_io(cx)
    }

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_complete_io(cx)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_complete_io(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.close_notify_sent {
            self.state.send_close_notify();
            self.close_notify_sent = true;
        }

        futures_util::ready!(self.poll_complete_io(cx))?;

        // Server can close socket as soon as it receives the connection shutdown request.
        // We shouldn't expect it to stick around for the TLS session to close cleanly.
        // https://security.stackexchange.com/a/82034
        let _ = futures_util::ready!(self.inner.socket.poll_shutdown(cx));

        Poll::Ready(Ok(()))
    }
}

pub async fn handshake<S>(socket: S, tls_config: TlsConfig<'_>) -> Result<RustlsSocket<S>, Error>
where
    S: Socket,
{
    #[cfg(all(
        feature = "_tls-rustls-aws-lc-rs",
        not(feature = "_tls-rustls-ring-webpki"),
        not(feature = "_tls-rustls-ring-native-roots")
    ))]
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(any(
        feature = "_tls-rustls-ring-webpki",
        feature = "_tls-rustls-ring-native-roots"
    ))]
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    // Unwrapping is safe here because we use a default provider.
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();

    // authentication using user's key and its associated certificate
    let user_auth = match (tls_config.client_cert_path, tls_config.client_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_chain = certs_from_pem(cert_path.data().await?)?;
            let key_der = private_key_from_pem(key_path.data().await?)?;
            Some((cert_chain, key_der))
        }
        (None, None) => None,
        (_, _) => {
            return Err(Error::Configuration(
                "user auth key and certs must be given together".into(),
            ))
        }
    };

    let config = if tls_config.accept_invalid_certs {
        if let Some(user_auth) = user_auth {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier { provider }))
                .with_client_auth_cert(user_auth.0, user_auth.1)
                .map_err(Error::tls)?
        } else {
            config
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DummyTlsVerifier { provider }))
                .with_no_client_auth()
        }
    } else {
        // A configured root CA is EXCLUSIVE: it replaces the bundled/native
        // trust anchors instead of joining them. `verify-ca` waives only the
        // hostname check, so a store that still carried the public roots would
        // accept any publicly-trusted certificate for any name.
        let root_cert_pem = match tls_config.root_cert_path {
            Some(ca) => Some(ca.data().await?),
            None => None,
        };
        let cert_store = root_store_for(root_cert_pem.as_deref()).map_err(|err| match err {
            RootStoreError::InvalidPem => match tls_config.root_cert_path {
                Some(ca) => Error::Tls(format!("Invalid certificate {ca}").into()),
                None => Error::Tls("Invalid certificate".into()),
            },
            RootStoreError::Rejected(err) => Error::Tls(err.into()),
        })?;

        if tls_config.accept_invalid_hostnames {
            // Pin the verifier to the provider selected above. The provider-less
            // builder resolves the process default from crate features and
            // panics when both `ring` and `aws-lc-rs` are compiled in and no
            // default was installed, which is the state of a test binary that
            // never started the gateway.
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(cert_store), provider)
                    .build()
                    .map_err(|err| Error::Tls(err.into()))?;

            if let Some(user_auth) = user_auth {
                config
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                    .with_client_auth_cert(user_auth.0, user_auth.1)
                    .map_err(Error::tls)?
            } else {
                config
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoHostnameTlsVerifier { verifier }))
                    .with_no_client_auth()
            }
        } else if let Some(user_auth) = user_auth {
            config
                .with_root_certificates(cert_store)
                .with_client_auth_cert(user_auth.0, user_auth.1)
                .map_err(Error::tls)?
        } else {
            config
                .with_root_certificates(cert_store)
                .with_no_client_auth()
        }
    };

    let host = ServerName::try_from(tls_config.hostname.to_owned()).map_err(Error::tls)?;

    let mut socket = RustlsSocket {
        inner: StdSocket::new(socket),
        state: ClientConnection::new(Arc::new(config), host).map_err(Error::tls)?,
        close_notify_sent: false,
    };

    // Performs the TLS handshake or bails
    socket.complete_io().await?;

    Ok(socket)
}

/// Failure building the handshake trust store.
#[derive(Debug)]
enum RootStoreError {
    /// The configured root CA source did not parse as PEM certificate(s).
    InvalidPem,
    /// rustls refused a parsed certificate as a trust anchor.
    Rejected(TlsError),
}

/// Build the trust store for one handshake.
///
/// A configured root CA **replaces** the bundled WebPKI (or native) trust
/// anchors; it is never added to them. That matches libpq's `sslrootcert`
/// semantics and Ferrum's own rule that a custom CA is exclusive. It is also
/// load-bearing for `verify-ca`: [`NoHostnameTlsVerifier`] waives the hostname
/// check, so the issuer is the only remaining constraint, and a store that
/// still held the ~150 public roots would accept any publicly-trusted
/// certificate for any name. With no configured CA the bundled/native anchors
/// are used unchanged.
fn root_store_for(root_cert_pem: Option<&[u8]>) -> Result<RootCertStore, RootStoreError> {
    if let Some(pem) = root_cert_pem {
        let mut cert_store = RootCertStore::empty();

        for result in CertificateDer::pem_slice_iter(pem) {
            let Ok(cert) = result else {
                return Err(RootStoreError::InvalidPem);
            };

            cert_store.add(cert).map_err(RootStoreError::Rejected)?;
        }

        return Ok(cert_store);
    }

    #[cfg(any(feature = "_tls-rustls-aws-lc-rs", feature = "_tls-rustls-ring-webpki"))]
    let cert_store = certs_from_webpki();
    #[cfg(feature = "_tls-rustls-ring-native-roots")]
    let cert_store = certs_from_native_store();

    Ok(cert_store)
}

fn certs_from_pem(pem: Vec<u8>) -> Result<Vec<CertificateDer<'static>>, Error> {
    CertificateDer::pem_slice_iter(&pem)
        .map(|result| result.map_err(|err| Error::Tls(err.into())))
        .collect()
}

fn private_key_from_pem(pem: Vec<u8>) -> Result<PrivateKeyDer<'static>, Error> {
    match PrivateKeyDer::from_pem_slice(&pem) {
        Ok(key) => Ok(key),
        Err(pem::Error::NoItemsFound) => Err(Error::Configuration("no keys found pem file".into())),
        Err(e) => Err(Error::Configuration(e.to_string().into())),
    }
}

#[cfg(any(feature = "_tls-rustls-aws-lc-rs", feature = "_tls-rustls-ring-webpki"))]
fn certs_from_webpki() -> RootCertStore {
    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(feature = "_tls-rustls-ring-native-roots")]
fn certs_from_native_store() -> RootCertStore {
    let mut root_cert_store = RootCertStore::empty();

    let load_results = rustls_native_certs::load_native_certs();
    for e in load_results.errors {
        log::warn!("Error loading native certificates: {e:?}");
    }
    for cert in load_results.certs {
        if let Err(e) = root_cert_store.add(cert.into()) {
            log::warn!("rustls failed to parse native certificate: {e:?}");
        }
    }

    root_cert_store
}

#[derive(Debug)]
struct DummyTlsVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub struct NoHostnameTlsVerifier {
    verifier: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for NoHostnameTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            // rustls 0.23 also reports hostname mismatches with diagnostic context.
            // WebPKI checks the chain and validity before checking the name; only
            // the name failure is waived. Handshake signatures are still verified.
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            res => res,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two unrelated self-signed P-256 test CAs. `RootCertStore::add` parses a
    /// trust anchor without reading its validity window, and the verifier test
    /// below pins `now` explicitly, so neither fixture can expire this module.
    const TEST_CA_A_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBrjCCAVOgAwIBAgIUJpJ3aq4QUQ8sM9bU5ZREzbb1SFkwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYRmVycnVtIFNRTCBUTFMgVGVzdCBDQSBBMCAXDTI2MDkxNjIw
NTgzMVoYDzIxMjYwODIzMjA1ODMxWjAjMSEwHwYDVQQDDBhGZXJydW0gU1FMIFRM
UyBUZXN0IENBIEEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARMRh8FF/PBEmWo
wZNxMvnxffwNJbEk1ym2fYDd+PgPz7rWQkq7WvTd2kNWODGkqWJ99ptjlcRZKzjH
LkCJSCjWo2MwYTAdBgNVHQ4EFgQUa8F3oEZN9Qo56uOOfVb68HHZx8AwHwYDVR0j
BBgwFoAUa8F3oEZN9Qo56uOOfVb68HHZx8AwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAKrN9+tfIDun+m0pbk1//yLl
Sa7JjLbIvhSkWMez8B2kAiEAkgaWsGP/ftvw+EAZvYK2IFTennm0no/oOoqPPhuG
lvk=
-----END CERTIFICATE-----
";

    const TEST_CA_B_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBrTCCAVOgAwIBAgIUJriMxJnKEORniQsX8mz69c2/TjEwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYRmVycnVtIFNRTCBUTFMgVGVzdCBDQSBCMCAXDTI2MDkxNjIw
NTgzMVoYDzIxMjYwODIzMjA1ODMxWjAjMSEwHwYDVQQDDBhGZXJydW0gU1FMIFRM
UyBUZXN0IENBIEIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3ySfYU3Me2T02
49vCetYm5iGYHc4qPBsM8u+ajpA2VjGxRS8ExRcSFuGs14utKOOtBrs8QLiJpE3s
KsiV15Y1o2MwYTAdBgNVHQ4EFgQUK9PBG2ViotXwoqTgYC3KjYzYRo0wHwYDVR0j
BBgwFoAUK9PBG2ViotXwoqTgYC3KjYzYRo0wDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIgIHugsS6a/OEQk6PDErB256Us
3pnbfm6OPJ0u/r+s8DICIQDQsrDy1x+V1PS4athkSI3WKE95m42yRq6uTqYUxo0R
EQ==
-----END CERTIFICATE-----
";

    /// Fixed verification instant inside both fixtures' validity windows, so
    /// the refusal below can never be an expiry artifact.
    const FIXED_NOW_SECS: u64 = 1_800_000_000;

    #[test]
    fn root_store_with_configured_ca_replaces_the_default_trust_store() {
        let defaults = root_store_for(None).expect("default trust anchors load");
        assert!(
            defaults.roots.len() > 1,
            "the default trust store must hold more than one anchor for this test to mean anything"
        );

        let configured =
            root_store_for(Some(TEST_CA_A_PEM.as_bytes())).expect("configured CA parses");
        // Counting is decisive here: the additive store this patch replaced
        // produced `defaults.roots.len() + 1` anchors for the same input, so a
        // store of exactly one anchor proves no public root survived.
        assert_eq!(
            configured.roots.len(),
            1,
            "a configured root CA must be the ONLY trust anchor under verify-ca and verify-full"
        );
    }

    #[test]
    fn verify_ca_refuses_a_certificate_from_an_unconfigured_ca() {
        #[cfg(all(
            feature = "_tls-rustls-aws-lc-rs",
            not(feature = "_tls-rustls-ring-webpki"),
            not(feature = "_tls-rustls-ring-native-roots")
        ))]
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        #[cfg(any(
            feature = "_tls-rustls-ring-webpki",
            feature = "_tls-rustls-ring-native-roots"
        ))]
        let provider = Arc::new(rustls::crypto::ring::default_provider());

        let cert_store =
            root_store_for(Some(TEST_CA_A_PEM.as_bytes())).expect("configured CA parses");
        let verifier = NoHostnameTlsVerifier {
            verifier: WebPkiServerVerifier::builder_with_provider(Arc::new(cert_store), provider)
                .build()
                .expect("verify-ca verifier builds"),
        };

        let foreign: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(TEST_CA_B_PEM.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .expect("unconfigured CA parses");
        // `ServerCertVerified` is deliberately opaque, so match rather than
        // `expect_err`.
        let Err(error) = verifier.verify_server_cert(
            &foreign[0],
            &[],
            &ServerName::try_from("db.example.com").expect("server name parses"),
            &[],
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(FIXED_NOW_SECS)),
        ) else {
            panic!("verify-ca must refuse a chain that does not end at the configured CA");
        };
        assert!(
            !matches!(
                error,
                TlsError::InvalidCertificate(
                    CertificateError::NotValidForName
                        | CertificateError::NotValidForNameContext { .. }
                )
            ),
            "the verify-ca name waiver must never waive the issuer check: {error:?}"
        );
    }
}
