// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The HTTP layer the client sends its requests through.
//!
//! The client builds every request itself, including its headers, and hands
//! it to a [`Transport`], so a custom transport only has to POST bytes and
//! return the response. Timeouts and retries are applied by the client around
//! the transport.

#[cfg(feature = "reqwest")]
mod reqwest_transport;
#[cfg(feature = "reqwest")]
pub(crate) mod tls;

use std::{fmt, future::Future, pin::Pin};

#[cfg(feature = "reqwest")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "reqwest")))]
pub use self::reqwest_transport::ReqwestTransport;
use crate::TransportError;

/// A boxed future, `Send` on every target but wasm32, where the browser's
/// futures are not.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A boxed future, `Send` on every target but wasm32, where the browser's
/// futures are not.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// `Send` on every target but wasm32, where nothing has to be sent between
/// threads.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// `Send` on every target but wasm32, where nothing has to be sent between
/// threads.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}

#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// Sends the client's HTTP requests.
pub trait Transport: fmt::Debug + Send + Sync + 'static {
    /// POST `request` and return the response, whatever its status.
    fn post(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, TransportError>>;
}

/// A POST request with a JSON body.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct HttpRequest {
    /// The URL to send the request to.
    pub url: String,
    /// The headers to send. The client already includes its content type,
    /// accepted types, user agent and any headers set on its builder.
    pub headers: Vec<(String, String)>,
    /// The JSON body.
    pub body: Vec<u8>,
}

/// The response to an [`HttpRequest`].
#[derive(Clone, Debug)]
pub struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    /// A response with the given status, headers and body.
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The value of the first header named `name`, compared case
    /// insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
