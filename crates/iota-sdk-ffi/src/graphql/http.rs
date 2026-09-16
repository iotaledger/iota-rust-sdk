// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Foreign-language equivalent of `Client::with_http_client`.
//!
//! The Rust API lets callers hand over a fully built `reqwest::Client`. uniffi
//! has no way to carry one across the boundary, so the bindings describe what
//! they want instead and the client is built on this side.

use crate::error::{Result, SdkFfiError};

/// How the SDK should build the HTTP client backing a connection.
#[derive(Debug, Default, uniffi::Record)]
pub struct HttpClientOptions {
    /// Additional DER-encoded CA certificates to trust, on top of the platform
    /// trust store and the bundled roots.
    #[uniffi(default = [])]
    pub extra_root_certificates: Vec<Vec<u8>>,
    /// Trust `extra_root_certificates` and nothing else, ignoring both the
    /// platform trust store and the bundled roots.
    #[uniffi(default = false)]
    pub only_provided_roots: bool,
    /// Total request timeout in milliseconds. `None` leaves it unbounded.
    #[uniffi(default = None)]
    pub timeout_ms: Option<u64>,
    /// Replaces the `User-Agent` the SDK would otherwise send.
    #[uniffi(default = None)]
    pub user_agent: Option<String>,
}

impl HttpClientOptions {
    /// Build the described client.
    pub(crate) fn build(self) -> Result<reqwest::Client> {
        // `default_http_client_builder` has already merged the bundled roots,
        // so replacing them means starting from a bare builder rather than
        // layering `tls_certs_only` on top.
        let mut builder = if self.only_provided_roots {
            // This branch bypasses `default_http_client_builder`, which is what
            // normally selects the rustls provider.
            #[cfg(not(target_arch = "wasm32"))]
            iota_sdk::graphql_client::install_default_crypto_provider();
            reqwest::Client::builder().user_agent(iota_sdk::graphql_client::USER_AGENT)
        } else {
            iota_sdk::graphql_client::default_http_client_builder()
        };

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

        Ok(if self.only_provided_roots {
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
        if self.only_provided_roots || !self.extra_root_certificates.is_empty() {
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
