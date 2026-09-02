// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core client implementation for the GraphQL API.

use cynic::{GraphQlResponse, Operation, QueryBuilder, serde};
use reqwest::Url;

use crate::{
    error::{GraphQLError, GraphQLResult},
    pagination::{Direction, PaginationFilter, PaginationFilterResponse},
    query_types::{ServiceConfig, ServiceConfigQuery},
};

pub(crate) const DEFAULT_ITEMS_PER_PAGE: i32 = 10;
pub(crate) const MAINNET_HOST: &str = "https://graphql.mainnet.iota.cafe";
pub(crate) const TESTNET_HOST: &str = "https://graphql.testnet.iota.cafe";
pub(crate) const DEVNET_HOST: &str = "https://graphql.devnet.iota.cafe";
pub(crate) const LOCAL_HOST: &str = "http://localhost:9125/graphql";
pub(crate) static USER_AGENT: &str =
    concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Helper function to convert a GraphQL response to a GraphQLResult.
///
/// A GraphQL response may carry `errors` together with (possibly partial)
/// `data` — for example when a request exceeds the server's max page size, the
/// failing field is set to `null` in `data` and the reason is reported in
/// `errors`. In that case the errors take precedence, so any populated `errors`
/// list is surfaced as a query error rather than being treated as a
/// success. A response with neither `data` nor `errors` is reported as an empty
/// response error instead of panicking.
pub(crate) fn response_to_err<T>(response: GraphQlResponse<T>) -> GraphQLResult<T> {
    match (response.data, response.errors) {
        (_, Some(errors)) if !errors.is_empty() => Err(GraphQLError::Query(errors)),
        (Some(data), _) => Ok(data),
        (None, _) => Err(GraphQLError::EmptyResponse),
    }
}

/// The GraphQL client for interacting with the IOTA blockchain.
/// By default, it uses the `reqwest` crate as the HTTP client.
#[derive(Clone, Debug)]
pub struct Client {
    /// The URL of the GraphQL server.
    pub(crate) rpc: Url,
    /// The reqwest client.
    pub(crate) inner: reqwest::Client,
    pub(crate) service_config: std::sync::OnceLock<ServiceConfig>,
}

impl Client {
    /// Create a new GraphQL client with the provided server address.
    pub fn new(server: &str) -> GraphQLResult<Self> {
        let rpc = reqwest::Url::parse(server)?;

        let client = Client {
            rpc,
            inner: reqwest::Client::builder().user_agent(USER_AGENT).build()?,
            service_config: Default::default(),
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

    /// Set the server address for the GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub fn set_rpc_server(&mut self, server: &str) -> GraphQLResult<()> {
        let rpc = reqwest::Url::parse(server)?;
        self.rpc = rpc;
        Ok(())
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> GraphQLResult<&ServiceConfig> {
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
    pub async fn run_query<T, V>(&self, operation: &Operation<T, V>) -> GraphQLResult<T>
    where
        T: serde::de::DeserializeOwned,
        V: serde::Serialize,
    {
        response_to_err(self.post_query(operation).await?)
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

    /// Run a JSON query on the GraphQL server and return the response.
    /// This method expects a JSON map holding the GraphQL query string and
    /// matching GraphQL variables. It returns a [`cynic::GraphQlResponse`]
    /// wrapping a [`serde_json::Value`]. In general, it is recommended to use
    /// [`run_query`](`Self::run_query`) which guarantees valid GraphQL
    /// query syntax and returns a proper response type.
    pub async fn run_query_from_json(
        &self,
        json: serde_json::Map<String, serde_json::Value>,
    ) -> GraphQLResult<GraphQlResponse<serde_json::Value>> {
        self.post_query(&json).await
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_utils::test_client;

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

    // A response carrying both partial `data` and a populated `errors` list
    // (e.g. an oversized page request) must surface the errors instead of
    // panicking on the unreachable arm.
    #[test]
    fn test_response_to_err_data_and_errors() {
        let response: GraphQlResponse<serde_json::Value> = serde_json::from_value(json!({
            "data": { "epoch": null },
            "errors": [{ "message": "Page size 75 exceeds the max page size of 50" }],
        }))
        .unwrap();

        let err = response_to_err(response).unwrap_err();
        assert!(matches!(err, GraphQLError::Query(errors) if !errors.is_empty()));
    }

    #[test]
    fn test_response_to_err_data_only() {
        let response: GraphQlResponse<serde_json::Value> =
            serde_json::from_value(json!({ "data": { "epoch": 1 } })).unwrap();

        let data = response_to_err(response).unwrap();
        assert_eq!(data, json!({ "epoch": 1 }));
    }

    #[test]
    fn test_response_to_err_errors_only() {
        let response: GraphQlResponse<serde_json::Value> = serde_json::from_value(json!({
            "data": null,
            "errors": [{ "message": "boom" }],
        }))
        .unwrap();

        let err = response_to_err(response).unwrap_err();
        assert!(matches!(err, GraphQLError::Query(errors) if !errors.is_empty()));
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
