// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Foreign-language equivalent of the Rust APIs that take a `reqwest::Client`.
//!
//! The Rust APIs let callers hand over a fully built `reqwest::Client`. uniffi
//! has no way to carry one across the boundary, so the bindings describe what
//! they want instead and the client is built here.

use crate::error::{Result, SdkFfiError};

/// Sent as the `User-Agent` unless the caller overrides it.
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// How the SDK should build the HTTP client backing a connection.
#[derive(Debug, Default, uniffi::Record)]
pub struct HttpClientOptions {
    /// Additional DER-encoded CA certificates to trust, on top of the platform
    /// trust store and the bundled roots.
    #[uniffi(default = [])]
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Ignore the platform trust store, trusting only the bundled roots and
    /// `extra_root_certificates`. Combined with `exclude_bundled_roots`,
    /// only `extra_root_certificates` is trusted, which must then be non-empty.
    #[uniffi(default = false)]
    pub exclude_platform_roots: bool,
    /// Ignore the bundled Mozilla roots, trusting only the platform trust store
    /// and `extra_root_certificates`. Combined with `exclude_platform_roots`,
    /// only `extra_root_certificates` is trusted, which must then be non-empty.
    #[uniffi(default = false)]
    pub exclude_bundled_roots: bool,
    /// Total request timeout in milliseconds. `None` leaves it unbounded.
    #[uniffi(default = None)]
    pub timeout_ms: Option<u64>,
    /// Replaces the `User-Agent` the bindings would otherwise send.
    #[uniffi(default = None)]
    pub user_agent: Option<String>,
}

impl HttpClientOptions {
    /// Build the described client.
    pub(crate) fn build(&self) -> Result<reqwest::Client> {
        let mut builder = base_builder();

        if let Some(user_agent) = &self.user_agent {
            builder = builder.user_agent(user_agent.clone());
        }

        self.apply_transport(builder)?
            .build()
            .map_err(SdkFfiError::new)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn apply_transport(
        &self,
        mut builder: reqwest::ClientBuilder,
    ) -> Result<reqwest::ClientBuilder> {
        if let Some(timeout_ms) = self.timeout_ms {
            builder = builder.timeout(std::time::Duration::from_millis(timeout_ms));
        }

        let bundled: &[_] = if self.exclude_bundled_roots {
            &[]
        } else {
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
        };
        let mut roots = bundled
            .iter()
            .filter_map(|der| reqwest::Certificate::from_der(der).ok())
            .collect::<Vec<_>>();
        for der in &self.extra_root_certificates {
            roots.push(parse_root_certificate(der)?);
        }

        // Merging keeps the platform store and adds these as a floor. reqwest
        // only supports that where `rustls-platform-verifier` accepts extra
        // roots; elsewhere — Android in particular — the roots have to stand
        // alone.
        #[cfg(any(all(unix, not(target_os = "android")), target_os = "windows"))]
        let merge_supported = true;
        #[cfg(not(any(all(unix, not(target_os = "android")), target_os = "windows")))]
        let merge_supported = false;

        Ok(if !self.exclude_platform_roots && merge_supported {
            if roots.is_empty() {
                builder
            } else {
                builder.tls_certs_merge(roots)
            }
        } else if roots.is_empty() {
            return Err(SdkFfiError::custom(
                "no trusted root certificates: excluding the bundled roots without the \
                 platform trust store requires at least one extra root certificate",
            ));
        } else {
            builder.tls_certs_only(roots)
        })
    }

    /// On wasm32 the browser owns both certificate verification and request
    /// deadlines, and reqwest's wasm builder exposes neither. Asking for them
    /// is refused rather than silently ignored, so that a caller never believes
    /// it has pinned a root or bounded a request when it has not.
    #[cfg(target_arch = "wasm32")]
    fn apply_transport(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        if self.exclude_platform_roots {
            return Err(SdkFfiError::custom(
                "excluding the platform trust store is not supported on wasm32: \
                 the browser always verifies against its own store",
            ));
        }
        if !self.extra_root_certificates.is_empty() {
            return Err(SdkFfiError::custom(
                "custom root certificates are not supported on wasm32: \
                 the browser controls certificate verification",
            ));
        }
        if self.timeout_ms.is_some() {
            return Err(SdkFfiError::custom(
                "request timeouts are not supported on wasm32: \
                 the browser controls request deadlines",
            ));
        }
        Ok(builder)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_root_certificate(der: &[u8]) -> Result<reqwest::Certificate> {
    let cert = rustls::pki_types::CertificateDer::from(der);
    webpki::anchor_from_trusted_cert(&cert).map_err(|e| {
        SdkFfiError::custom(format!(
            "invalid root certificate, expected DER-encoded X.509: {e}"
        ))
    })?;
    reqwest::Certificate::from_der(der).map_err(SdkFfiError::new)
}

/// `reqwest` is built with `rustls-no-provider` across this workspace, so a
/// provider has to be installed before any client is built. The first caller
/// wins, so an application that has already chosen one keeps it.
#[cfg(not(target_arch = "wasm32"))]
fn base_builder() -> reqwest::ClientBuilder {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder().user_agent(USER_AGENT)
}

/// On wasm32 the browser owns certificate verification, so there is no provider
/// and no trust anchors to configure.
#[cfg(target_arch = "wasm32")]
fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().user_agent(USER_AGENT)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn some_root() -> Vec<u8> {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS[0].to_vec()
    }

    #[test]
    fn excluding_every_source_requires_extra_roots() {
        let options = HttpClientOptions {
            exclude_platform_roots: true,
            exclude_bundled_roots: true,
            ..Default::default()
        };
        assert!(options.build().is_err());
    }

    #[test]
    fn extra_roots_alone_build() {
        let options = HttpClientOptions {
            extra_root_certificates: vec![some_root()],
            exclude_platform_roots: true,
            exclude_bundled_roots: true,
            ..Default::default()
        };
        options.build().unwrap();
    }

    #[test]
    fn platform_roots_alone_build() {
        let options = HttpClientOptions {
            exclude_bundled_roots: true,
            ..Default::default()
        };
        options.build().unwrap();
    }

    #[test]
    fn pem_root_is_rejected() {
        let options = HttpClientOptions {
            extra_root_certificates: vec![b"-----BEGIN CERTIFICATE-----\n".to_vec()],
            ..Default::default()
        };
        assert!(options.build().is_err());
    }
}
