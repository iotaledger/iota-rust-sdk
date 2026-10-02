// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use cynic::{Operation, QueryBuilder};
use serde::{Serialize, de::DeserializeOwned};
use tracing::Instrument;

use crate::{
    Error, Query, Result, RetryPolicy, ServerErrors, ServerVersion, TransportError,
    api::chain::ChainIdentifierQuery,
    error::ServerError,
    time,
    transport::{HttpRequest, HttpResponse, Transport},
    version::VERSION_HEADER,
};

/// Value this crate sends as the `User-Agent` header.
pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

const MAINNET_ENDPOINT: &str = "https://graphql.mainnet.iota.cafe";
const TESTNET_ENDPOINT: &str = "https://graphql.testnet.iota.cafe";
const DEVNET_ENDPOINT: &str = "https://graphql.devnet.iota.cafe";
const LOCALNET_ENDPOINT: &str = "http://localhost:9125/graphql";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "reqwest")]
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A client for the IOTA GraphQL RPC service.
///
/// Cloning is cheap, and every clone shares the transport and the server
/// version learned from responses.
#[derive(Clone)]
pub struct GraphQLClient {
    inner: Arc<Inner>,
}

struct Inner {
    endpoint: url::Url,
    transport: Box<dyn Transport>,
    headers: Vec<(String, String)>,
    timeout: Option<Duration>,
    retry: RetryPolicy,
    server_version: Mutex<VersionState>,
}

/// What the client knows about the server's version.
#[derive(Clone)]
enum VersionState {
    /// No response has been received yet.
    Unseen,
    /// Responses carry no version header.
    Unreported,
    Known(ServerVersion),
}

impl fmt::Debug for GraphQLClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GraphQLClient")
            .field("endpoint", &self.inner.endpoint.as_str())
            .field("transport", &self.inner.transport)
            .field("timeout", &self.inner.timeout)
            .field("retry", &self.inner.retry)
            .finish_non_exhaustive()
    }
}

impl GraphQLClient {
    /// Start configuring a client for the GraphQL service at `endpoint`.
    pub fn builder(endpoint: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(endpoint.into())
    }

    /// A client for the GraphQL service at `endpoint`, with the default
    /// configuration.
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        Self::builder(endpoint).build()
    }

    /// A client for the mainnet GraphQL service.
    pub fn mainnet() -> Result<Self> {
        Self::new(MAINNET_ENDPOINT)
    }

    /// A client for the testnet GraphQL service.
    pub fn testnet() -> Result<Self> {
        Self::new(TESTNET_ENDPOINT)
    }

    /// A client for the devnet GraphQL service.
    pub fn devnet() -> Result<Self> {
        Self::new(DEVNET_ENDPOINT)
    }

    /// A client for the GraphQL service of a local network, at
    /// `http://localhost:9125/graphql`.
    pub fn localnet() -> Result<Self> {
        Self::new(LOCALNET_ENDPOINT)
    }

    /// The URL of the GraphQL service.
    pub fn endpoint(&self) -> &str {
        self.inner.endpoint.as_str()
    }

    /// The server version reported by the latest response, if any response
    /// has carried one.
    pub fn server_version(&self) -> Option<ServerVersion> {
        match &*self.version_state() {
            VersionState::Known(version) => Some(version.clone()),
            VersionState::Unseen | VersionState::Unreported => None,
        }
    }

    /// Send `query` and decode its response.
    ///
    /// The client's queries are usually sent by awaiting the [`Request`]
    /// their method returns; this sends any [`Query`], including one written
    /// outside this crate.
    ///
    /// [`Request`]: crate::Request
    pub async fn send<Q: Query>(&self, query: Q) -> Result<Q::Output> {
        let version = if Q::NEEDS_SERVER_VERSION {
            self.probe_server_version().await?
        } else {
            self.server_version()
        };
        let operation = query.operation(version.as_ref())?;
        let data = self.run(&operation).await?;
        query.decode(data)
    }

    /// The server's version, sending a request to learn it if no response
    /// has been received yet.
    async fn probe_server_version(&self) -> Result<Option<ServerVersion>> {
        if matches!(*self.version_state(), VersionState::Unseen) {
            self.run(&ChainIdentifierQuery::build(())).await?;
        }
        Ok(self.server_version())
    }

    fn version_state(&self) -> std::sync::MutexGuard<'_, VersionState> {
        self.inner
            .server_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Send `operation`, retrying it as the retry policy allows, and decode
    /// its response data.
    async fn run<D, V>(&self, operation: &Operation<D, V>) -> Result<D>
    where
        D: DeserializeOwned,
        V: Serialize,
    {
        let body = serde_json::to_vec(operation)
            .map_err(|error| Error::invalid_input(format!("cannot encode the request: {error}")))?;
        let name = operation.operation_name.as_deref().unwrap_or("anonymous");
        let span = tracing::debug_span!("graphql", operation = name);
        async {
            let mut attempt = 1;
            loop {
                let error = match self
                    .post(&body)
                    .await
                    .and_then(|response| decode(&response))
                {
                    Ok(data) => return Ok(data),
                    Err(error) => error,
                };
                if !error.is_retryable() || attempt >= self.inner.retry.max_attempts() {
                    tracing::debug!(attempt, %error, "failed");
                    return Err(error);
                }
                let delay = self.inner.retry.backoff(attempt);
                tracing::debug!(attempt, ?delay, %error, "retrying");
                time::sleep(delay).await;
                attempt += 1;
            }
        }
        .instrument(span)
        .await
    }

    /// Send one attempt of a request.
    async fn post(&self, body: &[u8]) -> Result<HttpResponse> {
        let request = HttpRequest {
            url: self.inner.endpoint.to_string(),
            headers: self.inner.headers.clone(),
            body: body.to_vec(),
        };
        let response = self.inner.transport.post(request);
        let response = match self.inner.timeout {
            Some(limit) => time::timeout(limit, response)
                .await
                .map_err(|_| TransportError::timeout())??,
            None => response.await?,
        };
        tracing::trace!(status = response.status(), "response");
        self.record_server_version(&response);
        Ok(response)
    }

    fn record_server_version(&self, response: &HttpResponse) {
        let state = match response.header(VERSION_HEADER).map(ServerVersion::parse) {
            Some(Some(version)) => VersionState::Known(version),
            Some(None) | None => VersionState::Unreported,
        };
        *self.version_state() = state;
    }
}

/// Decode a GraphQL response. Errors the server reports take precedence over
/// any partial data, whatever the HTTP status.
fn decode<D: DeserializeOwned>(response: &HttpResponse) -> Result<D> {
    #[derive(serde::Deserialize)]
    struct Errors {
        errors: Option<Vec<ServerError>>,
    }

    #[derive(serde::Deserialize)]
    struct Data<D> {
        data: Option<D>,
    }

    let success = (200..300).contains(&response.status());
    let errors = match serde_json::from_slice::<Errors>(response.body()) {
        Ok(errors) => errors.errors.unwrap_or_default(),
        Err(_) if !success => {
            return Err(TransportError::status(response.status(), response.body()).into());
        }
        Err(error) => return Err(Error::malformed_with("the response is not JSON", error)),
    };
    if !errors.is_empty() {
        return Err(ServerErrors::new(errors).into());
    }
    if !success {
        return Err(TransportError::status(response.status(), response.body()).into());
    }
    serde_json::from_slice::<Data<D>>(response.body())
        .map_err(|error| Error::malformed_with("cannot decode the response data", error))?
        .data
        .ok_or_else(|| Error::malformed("the response has neither data nor errors"))
}

/// Configures a [`GraphQLClient`].
#[must_use]
pub struct ClientBuilder {
    endpoint: String,
    transport: Option<Box<dyn Transport>>,
    headers: Vec<(String, String)>,
    timeout: Option<Duration>,
    #[cfg(feature = "reqwest")]
    connect_timeout: Option<Duration>,
    retry: RetryPolicy,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            transport: None,
            headers: Vec::new(),
            timeout: Some(DEFAULT_TIMEOUT),
            #[cfg(feature = "reqwest")]
            connect_timeout: Some(DEFAULT_CONNECT_TIMEOUT),
            retry: RetryPolicy::default(),
        }
    }

    /// Send a header with every request, e.g. an API key for the service. A
    /// header set here replaces the client's own header of the same name.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// How long one attempt of a request may take, from sending it to reading
    /// the whole response. Defaults to 30 seconds; `None` waits indefinitely.
    pub fn timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.timeout = timeout.into();
        self
    }

    /// How long the built-in transport may take to connect. Defaults to 5
    /// seconds; `None` waits indefinitely. A transport set with
    /// [`transport`](Self::transport) or
    /// [`reqwest_client`](Self::reqwest_client) is not affected.
    #[cfg(feature = "reqwest")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "reqwest")))]
    pub fn connect_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.connect_timeout = timeout.into();
        self
    }

    /// How to retry failed requests. Defaults to [`RetryPolicy::default`].
    pub fn retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Send requests through `transport` instead of the built-in one.
    pub fn transport(mut self, transport: impl Transport) -> Self {
        self.transport = Some(Box::new(transport));
        self
    }

    /// Send requests through `client`, e.g. to choose its trust anchors, TLS
    /// backend or proxies.
    ///
    /// Note that on a build with `tls-ring` or `tls-aws-lc`, `reqwest` has no
    /// crypto provider to fall back on, so building the `reqwest::Client`
    /// panics unless one has been installed for the process. See the crate
    /// README.
    #[cfg(feature = "reqwest")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "reqwest")))]
    pub fn reqwest_client(self, client: reqwest::Client) -> Self {
        self.transport(crate::transport::ReqwestTransport::new(client))
    }

    /// Build the client.
    ///
    /// Fails if the endpoint is not an `http` or `https` URL, if a header is
    /// not valid, or if the built-in transport cannot reach the endpoint
    /// because this build has no TLS.
    pub fn build(self) -> Result<GraphQLClient> {
        let endpoint = url::Url::parse(&self.endpoint).map_err(|error| {
            Error::invalid_input(format!("invalid endpoint `{}`: {error}", self.endpoint))
        })?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(Error::invalid_input(format!(
                "invalid endpoint `{endpoint}`: expected an http or https URL"
            )));
        }
        for (name, value) in &self.headers {
            validate_header(name, value)?;
        }
        let transport = match self.transport {
            Some(transport) => transport,
            #[cfg(feature = "reqwest")]
            None => default_transport(&endpoint, self.connect_timeout)?,
            #[cfg(not(feature = "reqwest"))]
            None => {
                return Err(Error::invalid_input(
                    "no transport: enable the `reqwest` feature or set a transport on the builder",
                ));
            }
        };
        Ok(GraphQLClient {
            inner: Arc::new(Inner {
                headers: request_headers(self.headers),
                endpoint,
                transport,
                timeout: self.timeout,
                retry: self.retry,
                server_version: Mutex::new(VersionState::Unseen),
            }),
        })
    }
}

/// The headers of every request: the client's own, then the caller's, which
/// replace the client's of the same name.
fn request_headers(custom: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut headers = vec![
        ("content-type".to_owned(), "application/json".to_owned()),
        (
            "accept".to_owned(),
            "application/graphql-response+json, application/json".to_owned(),
        ),
    ];
    // Browsers do not let a page set the user agent.
    if cfg!(not(target_arch = "wasm32")) {
        headers.push(("user-agent".to_owned(), USER_AGENT.to_owned()));
    }
    headers.retain(|(name, _)| {
        !custom
            .iter()
            .any(|(custom, _)| custom.eq_ignore_ascii_case(name))
    });
    headers.extend(custom);
    headers
}

fn validate_header(name: &str, value: &str) -> Result<()> {
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty() || !name.chars().all(token) {
        return Err(Error::invalid_input(format!(
            "invalid header name `{name}`"
        )));
    }
    if value.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(Error::invalid_input(format!(
            "invalid value for header `{name}`"
        )));
    }
    Ok(())
}

#[cfg(feature = "reqwest")]
fn default_transport(
    endpoint: &url::Url,
    connect_timeout: Option<Duration>,
) -> Result<Box<dyn Transport>> {
    if let Some(scheme) = crate::transport::tls::unsupported_scheme(endpoint.as_str()) {
        return Err(Error::invalid_input(format!(
            "`{scheme}` needs TLS: enable the `tls-ring` or `tls-aws-lc` feature, or set a \
             transport on the builder"
        )));
    }
    let builder = crate::transport::tls::default_http_client_builder();
    #[cfg(not(target_arch = "wasm32"))]
    let builder = match connect_timeout {
        Some(timeout) => builder.connect_timeout(timeout),
        None => builder,
    };
    #[cfg(target_arch = "wasm32")]
    let _ = connect_timeout;
    let client = builder
        .build()
        .map_err(|error| Error::invalid_input(format!("cannot build the HTTP client: {error}")))?;
    Ok(Box::new(crate::transport::ReqwestTransport::new(client)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_headers_replace_the_clients_own() {
        let headers = request_headers(vec![("User-Agent".to_owned(), "my-app".to_owned())]);
        let user_agents = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .collect::<Vec<_>>();
        assert_eq!(
            user_agents,
            [&("User-Agent".to_owned(), "my-app".to_owned())]
        );
    }

    #[test]
    fn rejects_invalid_endpoints_and_headers() {
        assert!(matches!(
            GraphQLClient::new("localhost:9125"),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            GraphQLClient::new("ftp://example.com"),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            GraphQLClient::builder(LOCALNET_ENDPOINT)
                .header("x-api-key", "line\nbreak")
                .build(),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(
            GraphQLClient::builder(LOCALNET_ENDPOINT)
                .header("bad name", "value")
                .build(),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn decode_prefers_server_errors_over_data() {
        let response = HttpResponse::new(
            200,
            Vec::new(),
            br#"{"data":{"events":null},"errors":[{"message":"boom","extensions":{"code":"BAD_USER_INPUT"}}]}"#
                .to_vec(),
        );
        let Err(Error::Server(errors)) = decode::<serde_json::Value>(&response) else {
            panic!("expected a server error");
        };
        assert!(errors.has_code("BAD_USER_INPUT"));
    }

    #[test]
    fn decode_reports_non_json_error_pages_as_transport_errors() {
        let response = HttpResponse::new(502, Vec::new(), b"<html>Bad Gateway</html>".to_vec());
        let Err(Error::Transport(error)) = decode::<serde_json::Value>(&response) else {
            panic!("expected a transport error");
        };
        assert_eq!(error.status_code(), Some(502));
        assert!(error.is_retryable());
    }

    #[test]
    fn decode_reports_missing_data() {
        let response = HttpResponse::new(200, Vec::new(), b"{}".to_vec());
        assert!(matches!(
            decode::<serde_json::Value>(&response),
            Err(Error::MalformedResponse(_))
        ));
    }
}
