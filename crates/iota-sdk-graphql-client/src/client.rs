// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core client implementation for the GraphQL API.

use std::sync::{Arc, OnceLock};

use cynic::{GraphQlResponse, Operation, QueryBuilder, serde};
use reqwest::Url;

use crate::{
    error::{ErrorExtensions, GraphQLError, GraphQLResult},
    pagination::{Direction, PaginationFilter, PaginationFilterResponse},
    query_types::{ServiceConfig, ServiceConfigQueryFragment},
};

pub(crate) const DEFAULT_ITEMS_PER_PAGE: i32 = 10;
pub(crate) const MAINNET_HOST: &str = "https://graphql.mainnet.iota.cafe";
pub(crate) const TESTNET_HOST: &str = "https://graphql.testnet.iota.cafe";
pub(crate) const DEVNET_HOST: &str = "https://graphql.devnet.iota.cafe";
pub(crate) const LOCAL_HOST: &str = "http://localhost:9125/graphql";
/// Connect timeout of the HTTP clients this crate builds itself.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) const DEFAULT_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Value this crate sends as the `User-Agent` header.
pub static USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Helper function to convert a GraphQL response to a `Result`.
///
/// A GraphQL response may carry `errors` together with (possibly partial)
/// `data` — for example when a request exceeds the server's max page size, the
/// failing field is set to `null` in `data` and the reason is reported in
/// `errors`. In that case the errors take precedence, so any populated `errors`
/// list is surfaced as a query error rather than being treated as a
/// success. A response with neither `data` nor `errors` is reported as an empty
/// response error instead of panicking.
pub(crate) fn response_to_result<T>(
    response: GraphQlResponse<T, ErrorExtensions>,
) -> GraphQLResult<T> {
    match (response.data, response.errors) {
        (_, Some(errors)) if !errors.is_empty() => Err(GraphQLError::Query(errors)),
        (Some(data), _) => Ok(data),
        (None, _) => Err(GraphQLError::EmptyResponse),
    }
}

/// The GraphQL client for interacting with the IOTA blockchain.
/// By default, it uses the `reqwest` crate as the HTTP client.
#[derive(Clone, Debug)]
pub struct GraphQLClient {
    /// The URL of the GraphQL server.
    pub(crate) rpc: Url,
    /// The reqwest client.
    pub(crate) inner: reqwest::Client,
    pub(crate) service_config: Arc<OnceLock<ServiceConfig>>,
}

/// Builds a [`GraphQLClient`] on top of the default HTTP client, so that
/// timeouts and headers can be set without losing the crate's user agent and
/// trust anchors. Created by [`GraphQLClient::builder`].
#[derive(Debug)]
pub struct GraphQLClientBuilder {
    server: String,
    http: reqwest::ClientBuilder,
}

impl GraphQLClientBuilder {
    /// Total timeout of each request, from connecting until the response body
    /// has been read. No timeout is set by default.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.http = self.http.timeout(timeout);
        self
    }

    /// Timeout for establishing a connection. Defaults to 5 seconds.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.http = self.http.connect_timeout(timeout);
        self
    }

    /// Add headers sent with every request, for example an API key. A header
    /// already set under the same name is replaced.
    pub fn default_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.http = self.http.default_headers(headers);
        self
    }

    /// Adjust the underlying [`reqwest::ClientBuilder`] for anything not
    /// covered by the other setters.
    pub fn configure(
        mut self,
        f: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Self {
        self.http = f(self.http);
        self
    }

    /// Build the client.
    ///
    /// An `https` or `wss` address is rejected on a build without a crypto
    /// provider, as with [`GraphQLClient::new`].
    pub fn build(self) -> GraphQLResult<GraphQLClient> {
        if let Some(scheme) = crate::tls::unsupported_scheme(&self.server) {
            return Err(GraphQLError::TlsUnavailable(scheme));
        }
        GraphQLClient::new_with_reqwest_client(&self.server, self.http.build()?)
    }
}

impl GraphQLClient {
    /// Create a new GraphQL client with the provided server address.
    ///
    /// The HTTP client is built for you, trusting the platform store plus the
    /// bundled Mozilla roots. Use [`Self::new_with_reqwest_client`] to supply
    /// your own.
    ///
    /// An `https` or `wss` address is rejected on a build without a crypto
    /// provider, since no request to it could succeed. See the crate README.
    pub fn new(server: &str) -> GraphQLResult<Self> {
        if let Some(scheme) = crate::tls::unsupported_scheme(server) {
            return Err(GraphQLError::TlsUnavailable(scheme));
        }
        Self::new_with_reqwest_client(server, crate::tls::default_http_client_builder().build()?)
    }

    /// Start building a client for `server` from this crate's default HTTP
    /// client, keeping its user agent and trust anchors while letting you set
    /// timeouts and headers.
    pub fn builder(server: &str) -> GraphQLClientBuilder {
        GraphQLClientBuilder {
            server: server.to_owned(),
            http: crate::tls::default_http_client_builder(),
        }
    }

    /// Create a new GraphQL client that issues its requests through the
    /// supplied [`reqwest::Client`].
    ///
    /// This is the way to choose your own trust anchors, TLS backend, proxies
    /// or timeouts.
    ///
    /// Note that on a build with `tls-ring` or `tls-aws-lc`, `reqwest` has no
    /// crypto provider to fall back on, so building the client panics unless
    /// one has been installed for the process. See the crate README.
    ///
    /// The client is used as given: the SDK does not set its user agent, so
    /// callers who want to be identifiable should apply [`USER_AGENT`]
    /// themselves.
    pub fn new_with_reqwest_client(server: &str, client: reqwest::Client) -> GraphQLResult<Self> {
        Ok(Self {
            rpc: reqwest::Url::parse(server)?,
            inner: client,
            service_config: Default::default(),
        })
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    pub fn new_mainnet() -> GraphQLResult<Self> {
        Self::new(MAINNET_HOST)
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    pub fn new_testnet() -> GraphQLResult<Self> {
        Self::new(TESTNET_HOST)
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    pub fn new_devnet() -> GraphQLResult<Self> {
        Self::new(DEVNET_HOST)
    }

    /// Create a new GraphQL client connected to a `localnet` GraphQL server:
    /// {LOCAL_HOST}.
    pub fn new_localnet() -> GraphQLResult<Self> {
        Self::new(LOCAL_HOST)
    }

    /// Return the URL for the GraphQL server.
    pub(crate) fn rpc_server(&self) -> &Url {
        &self.rpc
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> GraphQLResult<&ServiceConfig> {
        // If the value is already initialized, return it
        if let Some(service_config) = self.service_config.get() {
            return Ok(service_config);
        }

        // Otherwise, fetch and initialize it
        let operation = ServiceConfigQueryFragment::build(());
        let response = self.run_query(&operation).await?;

        let service_config = self
            .service_config
            .get_or_init(move || response.service_config);

        Ok(service_config)
    }

    /// Run a query on the GraphQL server and return the response.
    /// This method returns [`cynic::GraphQlResponse`]  over the query type `T`,
    /// and it is intended to be used with custom queries.
    pub async fn run_query<T, V>(&self, operation: &Operation<T, V>) -> GraphQLResult<T>
    where
        T: serde::de::DeserializeOwned,
        V: serde::Serialize,
    {
        response_to_result(
            self.post_query::<GraphQlResponse<T, ErrorExtensions>>(operation)
                .await?,
        )
    }

    /// POST a JSON-serializable GraphQL request body and decode the JSON
    /// response, surfacing the HTTP status and a truncated body on any non-2xx
    /// response or on a decode failure.
    async fn post_query<R>(&self, body: &impl serde::Serialize) -> GraphQLResult<R>
    where
        R: serde::de::DeserializeOwned,
    {
        let resp = self
            .inner
            .post(self.rpc_server().clone())
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let url = resp.url().clone();
        let bytes = resp.bytes().await?;
        let target_type = std::any::type_name::<R>();
        if !status.is_success() {
            return Err(GraphQLError::http(url, status, &bytes, target_type));
        }
        serde_json::from_slice::<R>(&bytes)
            .map_err(|e| GraphQLError::json(url, status, &bytes, target_type, e))
    }

    /// Run a JSON query on the GraphQL server and return the response data.
    /// This method expects a JSON map holding the GraphQL query string and
    /// matching GraphQL variables. Any GraphQL error in the response is
    /// returned as an error, even if partial data is present. In general, it
    /// is recommended to use [`run_query`](`Self::run_query`) which guarantees
    /// valid GraphQL query syntax and returns a proper response type.
    pub async fn run_query_from_json(
        &self,
        json: serde_json::Map<String, serde_json::Value>,
    ) -> GraphQLResult<serde_json::Value> {
        response_to_result(
            self.post_query::<GraphQlResponse<serde_json::Value, ErrorExtensions>>(&json)
                .await?,
        )
    }

    /// Handle pagination filters and return the appropriate values. If limit is
    /// omitted, it will use the max page size from the service config.
    pub async fn pagination_filter(
        &self,
        pagination_filter: PaginationFilter,
    ) -> PaginationFilterResponse {
        let limit = pagination_filter
            .limit
            .unwrap_or(self.max_page_size().await.unwrap_or(DEFAULT_ITEMS_PER_PAGE));

        let (after, before, first, last) = match pagination_filter.direction {
            Direction::Forward => (pagination_filter.cursor, None, Some(limit), None),
            Direction::Backward => (None, pagination_filter.cursor, None, Some(limit)),
        };
        PaginationFilterResponse {
            after,
            before,
            first,
            last,
        }
    }

    /// Lazily fetch the max page size
    pub async fn max_page_size(&self) -> GraphQLResult<i32> {
        self.service_config().await.map(|cfg| cfg.max_page_size)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Duration;

    use reqwest::header::{HeaderMap, HeaderValue};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::test_utils::test_client;

    #[test]
    fn test_rpc_server() {
        let client = GraphQLClient::new_localnet().unwrap();
        assert_eq!(client.rpc_server(), &LOCAL_HOST.parse().unwrap());
        let client = GraphQLClient::new_mainnet().unwrap();
        assert_eq!(client.rpc_server(), &MAINNET_HOST.parse().unwrap());
    }

    // A response carrying both partial `data` and a populated `errors` list
    // (e.g. an oversized page request) must surface the errors instead of
    // panicking on the unreachable arm.
    #[test]
    fn test_response_to_result_data_and_errors() {
        let response: GraphQlResponse<serde_json::Value, ErrorExtensions> =
            serde_json::from_value(json!({
                "data": { "epoch": null },
                "errors": [{
                    "message": "Page size 75 exceeds the max page size of 50",
                    "path": ["events"],
                    "extensions": { "code": "BAD_USER_INPUT", "other": 1 },
                }],
            }))
            .unwrap();

        let GraphQLError::Query(errors) = response_to_result(response).unwrap_err() else {
            panic!("expected GraphQLError::Query");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].message,
            "Page size 75 exceeds the max page size of 50"
        );
        assert_eq!(
            errors[0].extensions.as_ref().unwrap().code.as_deref(),
            Some("BAD_USER_INPUT")
        );
    }

    #[test]
    fn test_response_to_result_data_only() {
        let response: GraphQlResponse<serde_json::Value, ErrorExtensions> =
            serde_json::from_value(json!({ "data": { "epoch": 1 } })).unwrap();

        let data = response_to_result(response).unwrap();
        assert_eq!(data, json!({ "epoch": 1 }));
    }

    #[test]
    fn test_response_to_result_errors_only() {
        let response: GraphQlResponse<serde_json::Value, ErrorExtensions> =
            serde_json::from_value(json!({
                "data": null,
                "errors": [{ "message": "boom" }],
            }))
            .unwrap();

        let GraphQLError::Query(errors) = response_to_result(response).unwrap_err() else {
            panic!("expected GraphQLError::Query");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "boom");
    }

    #[tokio::test]
    async fn test_service_config_query() {
        let client = test_client();
        client
            .service_config()
            .await
            .map_err(|e| {
                format!(
                    "Service config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    async fn bind() -> (TcpListener, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/graphql", listener.local_addr().unwrap());
        (listener, url)
    }

    #[tokio::test]
    async fn builder_sends_default_headers_and_keeps_user_agent() {
        let (listener, url) = bind().await;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 13\r\n\r\n{\"data\":null}",
                )
                .await
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).to_lowercase()
        });

        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("secret"));
        let client = GraphQLClient::builder(&url)
            .default_headers(headers)
            .build()
            .unwrap();
        let _ = client.run_query_from_json(Default::default()).await;

        let request = server.await.unwrap();
        assert!(request.contains("x-api-key: secret"), "{request}");
        assert!(
            request.contains(&format!("user-agent: {}", USER_AGENT.to_lowercase())),
            "{request}"
        );
    }

    #[tokio::test]
    async fn builder_timeout_applies() {
        let (listener, url) = bind().await;
        // Accept the connection but never answer.
        let _server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let client = GraphQLClient::builder(&url)
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let err = client
            .run_query_from_json(Default::default())
            .await
            .unwrap_err();
        let GraphQLError::Request(err) = err else {
            panic!("expected a request error, got {err:?}");
        };
        assert!(err.is_timeout(), "{err:?}");
    }

    #[test]
    fn builder_rejects_invalid_url() {
        assert!(GraphQLClient::builder("not a url").build().is_err());
    }
}
