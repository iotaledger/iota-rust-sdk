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
    /// `extra_root_certificates`.
    #[uniffi(default = false)]
    pub exclude_platform_roots: bool,
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

        let mut roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|der| reqwest::Certificate::from_der(der).ok())
            .collect::<Vec<_>>();
        for der in &self.extra_root_certificates {
            roots.push(reqwest::Certificate::from_der(der).map_err(SdkFfiError::new)?);
        }

        // Merging keeps the platform store and adds these as a floor. reqwest
        // only supports that where `rustls-platform-verifier` accepts extra
        // roots; elsewhere (Android in particular), the roots have to stand
        // alone.
        #[cfg(any(all(unix, not(target_os = "android")), target_os = "windows"))]
        let merge_supported = true;
        #[cfg(not(any(all(unix, not(target_os = "android")), target_os = "windows")))]
        let merge_supported = false;

        Ok(if self.exclude_platform_roots || !merge_supported {
            builder.tls_certs_only(roots)
        } else {
            builder.tls_certs_merge(roots)
        })
    }

    /// On wasm32 the browser owns both certificate verification and request
    /// deadlines, and reqwest's wasm builder exposes neither. Asking for them
    /// is refused rather than silently ignored, so that a caller never believes
    /// it has pinned a root or bounded a request when it has not.
    #[cfg(target_arch = "wasm32")]
    fn apply_transport(&self, builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder> {
        if self.exclude_platform_roots || !self.extra_root_certificates.is_empty() {
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
