// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{BoxFuture, HttpRequest, HttpResponse, Transport};
use crate::TransportError;

/// A [`Transport`] backed by a [`reqwest::Client`].
///
/// This is the client's default transport. Pass your own `reqwest::Client`
/// to change its proxies, connect timeout, trust anchors or TLS backend; the
/// client's headers, timeout and retries still apply.
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// A transport sending its requests through `client`.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// The [`reqwest::ClientBuilder`] the built-in transport is built from:
    /// this crate's trust anchors and crypto provider (see the crate README),
    /// and a connect timeout of 5 seconds.
    ///
    /// Build your own `reqwest::Client` from it to change other settings
    /// while keeping those. With `tls-ring` or `tls-aws-lc`, calling it
    /// installs that crypto provider for the process, unless one is installed
    /// already.
    ///
    /// ```rust,ignore
    /// let http = ReqwestTransport::default_client_builder()
    ///     .connect_timeout(Duration::from_secs(3))
    ///     .build()?;
    /// let client = GraphQLClient::builder(endpoint).reqwest_client(http).build()?;
    /// ```
    pub fn default_client_builder() -> reqwest::ClientBuilder {
        super::tls::default_http_client_builder()
    }
}

impl Transport for ReqwestTransport {
    fn post(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async move {
            let mut builder = self.client.post(&request.url).body(request.body);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            let response = builder.send().await.map_err(transport_error)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let body = response.bytes().await.map_err(transport_error)?;
            Ok(HttpResponse::new(status, headers, body.to_vec()))
        })
    }
}

fn transport_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        return TransportError::timeout();
    }
    #[cfg(not(target_arch = "wasm32"))]
    if error.is_connect() {
        return TransportError::connect(error);
    }
    TransportError::other(error)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn the_default_client_builder_builds_without_a_preinstalled_provider() {
        ReqwestTransport::default_client_builder().build().unwrap();
    }
}
