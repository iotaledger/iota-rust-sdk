// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Foreign-language equivalent of the Rust APIs that take a `reqwest::Client`.
//!
//! The Rust APIs let callers hand over a fully built `reqwest::Client`.
//! uniffi has no way to carry one across the boundary, so the bindings
//! describe what they want instead and the client is built on this side.

use crate::error::{Result, SdkFfiError};

/// How the SDK should build the HTTP client backing a connection.
#[derive(Debug, Default, uniffi::Record)]
pub struct HttpClientOptions {
    /// Additional DER-encoded CA certificates to trust, on top of the platform
    /// trust store and the bundled roots.
    #[uniffi(default = [])]
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Ignore the platform trust store, trusting only the SDK's bundled roots
    /// and `extra_root_certificates`.
    #[uniffi(default = false)]
    pub exclude_platform_roots: bool,
    /// Total request timeout in milliseconds. `None` leaves it unbounded.
    #[uniffi(default = None)]
    pub timeout_ms: Option<u64>,
    /// Replaces the `User-Agent` the SDK would otherwise send.
    #[uniffi(default = None)]
    pub user_agent: Option<String>,
}

impl HttpClientOptions {
    /// Build the described client.
    pub(crate) fn build(&self) -> Result<reqwest::Client> {
        let mut builder = iota_sdk::graphql_client::default_http_client_builder();

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

        let certificates = self
            .extra_root_certificates
            .iter()
            .map(|der| reqwest::Certificate::from_der(der).map_err(SdkFfiError::new))
            .collect::<Result<Vec<_>>>()?;

        Ok(if self.exclude_platform_roots {
            // The SDK's builder has already added the bundled roots, so this
            // drops the platform store and keeps those plus any supplied here.
            builder.tls_certs_only(certificates)
        } else if certificates.is_empty() {
            builder
        } else {
            builder.tls_certs_merge(certificates)
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
