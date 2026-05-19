// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core client implementation for the GraphQL API.

use std::sync::Arc;

use cynic::{GraphQlResponse, Operation, QueryBuilder, serde};
use reqwest::Url;

use crate::{
    error::{Error, Result},
    pagination::{Direction, PaginationFilter, PaginationFilterResponse},
    query_types::{ServiceConfig, ServiceConfigQuery},
};

/// Returns `Some(Instant::now())` on native, `None` on wasm32 where
/// `std::time::Instant` is unsupported.
#[cfg(not(target_arch = "wasm32"))]
fn now() -> Option<std::time::Instant> {
    Some(std::time::Instant::now())
}

#[cfg(target_arch = "wasm32")]
fn now() -> Option<std::time::Instant> {
    None
}

fn elapsed(start: Option<std::time::Instant>) -> Option<std::time::Duration> {
    start.map(|s| s.elapsed())
}

pub(crate) const DEFAULT_ITEMS_PER_PAGE: i32 = 10;
pub(crate) const MAINNET_HOST: &str = "https://graphql.mainnet.iota.cafe";
pub(crate) const TESTNET_HOST: &str = "https://graphql.testnet.iota.cafe";
pub(crate) const DEVNET_HOST: &str = "https://graphql.devnet.iota.cafe";
pub(crate) const LOCAL_HOST: &str = "http://localhost:9125/graphql";
pub(crate) static USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Helper function to convert a GraphQL response to a Result.
pub(crate) fn response_to_err<T>(response: GraphQlResponse<T>) -> Result<T, Error> {
    match (response.data, response.errors) {
        (Some(data), None) => Ok(data),
        (None, Some(errors)) => Err(Error::graphql_error(errors)),
        _ => unreachable!(
            "Either data or errors must be present in a GraphQL response, but not both"
        ),
    }
}

/// Information about a completed GraphQL request, passed to inspectors.
#[derive(Debug, Clone)]
pub struct GraphQlRequestResult {
    /// The URL of the GraphQL endpoint that was called.
    pub url: String,
    /// The GraphQL operation name, if available.
    pub operation_name: Option<String>,
    /// The GraphQL query string that was sent.
    pub query: Option<String>,
    /// The serialized query variables, as a JSON string.
    pub variables: Option<String>,
    /// The raw JSON response body. Only populated when an inspector is
    /// attached, to avoid unnecessary allocations.
    pub response_body: Option<String>,
    /// If the request failed, the error message. `None` on success.
    pub error: Option<String>,
    /// How long the request took. `None` on wasm32 where `Instant` is
    /// unavailable.
    pub duration: Option<std::time::Duration>,
}

/// A callback invoked after every GraphQL request completes.
///
/// Implementations should be lightweight and non-blocking — this is
/// intended for telemetry / error-reporting (e.g. Sentry).
pub trait RequestInspector: Send + Sync + 'static {
    fn inspect(&self, result: &GraphQlRequestResult);
}

impl<F: Fn(&GraphQlRequestResult) + Send + Sync + 'static> RequestInspector for F {
    fn inspect(&self, result: &GraphQlRequestResult) {
        self(result);
    }
}

/// The GraphQL client for interacting with the IOTA blockchain.
/// By default, it uses the `reqwest` crate as the HTTP client.
pub struct Client {
    /// The URL of the GraphQL server.
    pub(crate) rpc: Url,
    /// The reqwest client.
    pub(crate) inner: reqwest::Client,
    pub(crate) service_config: std::sync::OnceLock<ServiceConfig>,
    /// Optional inspector called after every request.
    pub(crate) inspector: Option<Arc<dyn RequestInspector>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc.clone(),
            inner: self.inner.clone(),
            service_config: self.service_config.clone(),
            inspector: self.inspector.clone(),
        }
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("rpc", &self.rpc)
            .field("inner", &self.inner)
            .field("service_config", &self.service_config)
            .field("has_inspector", &self.inspector.is_some())
            .finish()
    }
}

impl Client {
    /// Create a new GraphQL client with the provided server address.
    pub fn new(server: &str) -> Result<Self> {
        let rpc = reqwest::Url::parse(server)?;

        let client = Client {
            rpc,
            inner: reqwest::Client::builder().user_agent(USER_AGENT).build()?,
            service_config: Default::default(),
            inspector: None,
        };
        Ok(client)
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    pub fn new_mainnet() -> Self {
        Self::new(MAINNET_HOST).expect("Invalid mainnet URL")
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    pub fn new_testnet() -> Self {
        Self::new(TESTNET_HOST).expect("Invalid testnet URL")
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    pub fn new_devnet() -> Self {
        Self::new(DEVNET_HOST).expect("Invalid devnet URL")
    }

    /// Create a new GraphQL client connected to a `localnet` GraphQL server:
    /// {LOCAL_HOST}.
    pub fn new_localnet() -> Self {
        Self::new(LOCAL_HOST).expect("Invalid localhost URL")
    }

    /// Return the URL for the GraphQL server.
    pub(crate) fn rpc_server(&self) -> &Url {
        &self.rpc
    }

    /// Attach a request inspector that will be called after every
    /// GraphQL request completes (both successes and failures).
    ///
    /// ```rust,no_run
    /// use iota_graphql_client::Client;
    ///
    /// let client = Client::new_devnet().with_inspector(|result| {
    ///     if let Some(err) = &result.error {
    ///         let op = result.operation_name.as_deref().unwrap_or("<unnamed>");
    ///         eprintln!("GraphQL error for {op} at {}: {err}", result.url);
    ///     }
    /// });
    /// ```
    pub fn with_inspector(mut self, inspector: impl RequestInspector) -> Self {
        self.inspector = Some(Arc::new(inspector));
        self
    }

    /// Set the request inspector. Replaces any previously set inspector.
    pub fn set_inspector(&mut self, inspector: impl RequestInspector) {
        self.inspector = Some(Arc::new(inspector));
    }

    /// Remove the current request inspector, if any.
    pub fn clear_inspector(&mut self) {
        self.inspector = None;
    }

    fn notify_inspector(&self, result: &GraphQlRequestResult) {
        if let Some(inspector) = &self.inspector {
            inspector.inspect(result);
        }
    }

    /// Set the server address for the GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub fn set_rpc_server(&mut self, server: &str) -> Result<()> {
        let rpc = reqwest::Url::parse(server)?;
        self.rpc = rpc;
        Ok(())
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<&ServiceConfig> {
        // If the value is already initialized, return it
        if let Some(service_config) = self.service_config.get() {
            return Ok(service_config);
        }

        // Otherwise, fetch and initialize it
        let operation = ServiceConfigQuery::build(());
        let response = self.run_query(&operation).await?;

        let service_config = self
            .service_config
            .get_or_init(move || response.service_config);

        Ok(service_config)
    }

    /// Run a query on the GraphQL server and return the response.
    /// This method returns [`cynic::GraphQlResponse`]  over the query type `T`,
    /// and it is intended to be used with custom queries.
    pub async fn run_query<T, V>(&self, operation: &Operation<T, V>) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        V: serde::Serialize,
    {
        let url = self.rpc_server().to_string();
        let operation_name = operation.operation_name.as_deref().map(String::from);
        let (query, variables) = if self.inspector.is_some() {
            (
                Some(operation.query.clone()),
                serde_json::to_string(&operation.variables).ok(),
            )
        } else {
            (None, None)
        };
        let has_inspector = self.inspector.is_some();
        let start = now();

        let (result, response_body) = if has_inspector {
            let body = self
                .inner
                .post(self.rpc_server().clone())
                .json(&operation)
                .send()
                .await?
                .text()
                .await?;
            let response: GraphQlResponse<T> = serde_json::from_str(&body)?;
            (response_to_err(response), Some(body))
        } else {
            let response = self
                .inner
                .post(self.rpc_server().clone())
                .json(&operation)
                .send()
                .await?
                .json::<GraphQlResponse<T>>()
                .await?;
            (response_to_err(response), None)
        };

        self.notify_inspector(&GraphQlRequestResult {
            url,
            operation_name,
            query,
            variables,
            response_body,
            error: result.as_ref().err().map(|e| e.to_string()),
            duration: elapsed(start),
        });

        result
    }

    /// Run a JSON query on the GraphQL server and return the response.
    /// This method expects a JSON map holding the GraphQL query string and
    /// matching GraphQL variables. It returns a [`cynic::GraphQlResponse`]
    /// wrapping a [`serde_json::Value`]. In general, it is recommended to use
    /// [`run_query`](`Self::run_query`) which guarantees valid GraphQL
    /// query syntax and returns a proper response type.
    pub async fn run_query_from_json(
        &self,
        json: serde_json::Map<String, serde_json::Value>,
    ) -> Result<GraphQlResponse<serde_json::Value>> {
        let url = self.rpc_server().to_string();
        let operation_name = json
            .get("operationName")
            .and_then(|v| v.as_str())
            .map(String::from);
        let (query, variables) = if self.inspector.is_some() {
            (
                json.get("query").and_then(|v| v.as_str()).map(String::from),
                json.get("variables")
                    .and_then(|v| serde_json::to_string(v).ok()),
            )
        } else {
            (None, None)
        };
        let has_inspector = self.inspector.is_some();
        let start = now();

        let (result, response_body): (Result<GraphQlResponse<serde_json::Value>>, Option<String>) =
            if has_inspector {
                match async {
                    let body = self
                        .inner
                        .post(self.rpc_server().clone())
                        .json(&json)
                        .send()
                        .await?
                        .text()
                        .await?;
                    let response: GraphQlResponse<serde_json::Value> = serde_json::from_str(&body)?;
                    Ok((response, body))
                }
                .await
                {
                    Ok((response, body)) => (Ok(response), Some(body)),
                    Err(e) => (Err(e), None),
                }
            } else {
                let result = async {
                    let res = self
                        .inner
                        .post(self.rpc_server().clone())
                        .json(&json)
                        .send()
                        .await?
                        .json::<GraphQlResponse<serde_json::Value>>()
                        .await?;
                    Ok(res)
                }
                .await;
                (result, None)
            };

        let error = match &result {
            Err(e) => Some(e.to_string()),
            Ok(response) if response.errors.is_some() => {
                Some(Error::graphql_error(response.errors.clone().unwrap()).to_string())
            }
            Ok(_) => None,
        };

        self.notify_inspector(&GraphQlRequestResult {
            url,
            operation_name,
            query,
            variables,
            response_body,
            error,
            duration: elapsed(start),
        });

        result
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
    pub async fn max_page_size(&self) -> Result<i32> {
        self.service_config().await.map(|cfg| cfg.max_page_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::test_utils::test_client;

    #[test]
    fn test_inspector_builder() {
        let results: Arc<std::sync::Mutex<Vec<GraphQlRequestResult>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let captured = results.clone();
        let client = Client::new_testnet().with_inspector(move |r: &GraphQlRequestResult| {
            captured.lock().unwrap().push(r.clone());
        });

        assert!(client.inspector.is_some());

        // Verify notify_inspector calls through
        client.notify_inspector(&GraphQlRequestResult {
            url: "https://example.com".into(),
            operation_name: Some("TestOp".into()),
            query: Some("{ test }".into()),
            variables: Some(r#"{"id":"0x1"}"#.into()),
            response_body: Some(r#"{"data":{"test":true}}"#.into()),
            error: None,
            duration: Some(std::time::Duration::from_millis(42)),
        });

        let captured = results.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].url, "https://example.com");
        assert_eq!(captured[0].operation_name.as_deref(), Some("TestOp"));
        assert!(captured[0].error.is_none());
        assert_eq!(
            captured[0].duration,
            Some(std::time::Duration::from_millis(42))
        );
    }

    #[test]
    fn test_inspector_set_and_clear() {
        let mut client = Client::new_testnet();
        assert!(client.inspector.is_none());

        client.set_inspector(|_: &GraphQlRequestResult| {});
        assert!(client.inspector.is_some());

        client.clear_inspector();
        assert!(client.inspector.is_none());
    }

    #[tokio::test]
    async fn test_inspector_receives_results_on_request() {
        use std::{io::Write, net::TcpListener};

        let results: Arc<std::sync::Mutex<Vec<GraphQlRequestResult>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        // Spin up a minimal HTTP server that returns a valid GraphQL response.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::task::spawn_blocking(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read request (we don't need to parse it)
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);

            let body = r#"{"data":{"serviceConfig":{"maxPageSize":50}}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let captured = results.clone();
        let client = Client::new(&format!("http://{addr}"))
            .unwrap()
            .with_inspector(move |r: &GraphQlRequestResult| {
                captured.lock().unwrap().push(r.clone());
            });

        // Use run_query_from_json so we can control the operationName.
        let mut json = serde_json::Map::new();
        json.insert(
            "query".into(),
            serde_json::Value::String("{ serviceConfig { maxPageSize } }".into()),
        );
        json.insert(
            "operationName".into(),
            serde_json::Value::String("TestQuery".into()),
        );

        let _ = client.run_query_from_json(json).await;
        server.await.unwrap();

        let captured = results.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].operation_name.as_deref(), Some("TestQuery"));
        assert!(captured[0].error.is_none());
        assert!(captured[0].duration.is_some());
        assert!(captured[0].url.contains(&addr.to_string()));
    }

    #[tokio::test]
    async fn test_inspector_captures_graphql_errors_from_json() {
        use std::{io::Write, net::TcpListener};

        let results: Arc<std::sync::Mutex<Vec<GraphQlRequestResult>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Return a response with GraphQL-level errors (HTTP 200, but errors field set).
        let server = tokio::task::spawn_blocking(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);

            let body = r#"{"data":null,"errors":[{"message":"Field not found","locations":[],"path":[]}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let captured = results.clone();
        let client = Client::new(&format!("http://{addr}"))
            .unwrap()
            .with_inspector(move |r: &GraphQlRequestResult| {
                captured.lock().unwrap().push(r.clone());
            });

        let mut json = serde_json::Map::new();
        json.insert(
            "query".into(),
            serde_json::Value::String("{ badField }".into()),
        );

        let _ = client.run_query_from_json(json).await;
        server.await.unwrap();

        let captured = results.lock().unwrap();
        assert_eq!(captured.len(), 1);
        // The inspector should report the GraphQL error even though HTTP was 200.
        assert!(
            captured[0].error.is_some(),
            "Inspector should capture GraphQL-level errors"
        );
        assert!(
            captured[0]
                .error
                .as_ref()
                .unwrap()
                .contains("Field not found")
        );
    }

    #[test]
    fn test_rpc_server() {
        let mut client = Client::new_mainnet();
        assert_eq!(client.rpc_server(), &MAINNET_HOST.parse().unwrap());
        client.set_rpc_server(TESTNET_HOST).unwrap();
        assert_eq!(client.rpc_server(), &TESTNET_HOST.parse().unwrap());
        client.set_rpc_server(DEVNET_HOST).unwrap();
        assert_eq!(client.rpc_server(), &DEVNET_HOST.parse().unwrap());
        client.set_rpc_server(LOCAL_HOST).unwrap();
        assert_eq!(client.rpc_server(), &LOCAL_HOST.parse().unwrap());

        assert!(client.set_rpc_server("localhost:9125/graphql").is_ok());
        assert!(client.set_rpc_server("9125/graphql").is_err());
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
}
