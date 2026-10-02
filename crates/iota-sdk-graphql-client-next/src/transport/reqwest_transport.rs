// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{BoxFuture, HttpRequest, HttpResponse, Transport};
use crate::TransportError;

/// A [`Transport`] backed by a [`reqwest::Client`].
///
/// This is the client's default transport. Pass your own `reqwest::Client`
/// to choose its trust anchors, TLS backend or proxies; the client's headers,
/// timeout and retries still apply.
#[derive(Clone, Debug)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// A transport sending its requests through `client`.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
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
