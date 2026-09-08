// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use tokio::sync::RwLock;

use crate::{
    error::{Result, SdkFfiError},
    graphql::query_types::ServiceConfig,
};

/// The GraphQL client for interacting with the IOTA blockchain.
#[derive(uniffi::Object)]
pub struct GraphQLClient(pub(crate) RwLock<iota_sdk::graphql_client::Client>);

impl GraphQLClient {
    pub fn inner(&self) -> &RwLock<iota_sdk::graphql_client::Client> {
        &self.0
    }

    pub fn into_inner(self) -> RwLock<iota_sdk::graphql_client::Client> {
        self.0
    }
}

#[derive(Debug, serde::Serialize, uniffi::Record)]
pub struct Query {
    // `query_string` avoids C# CS0542 (member == type `Query`); serde keeps the `query` wire key.
    #[serde(rename = "query")]
    pub query_string: String,
    #[uniffi(default = None)]
    #[serde(default)]
    pub variables: Option<serde_json::Value>,
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Create a new GraphQL client with the provided server address.
    #[uniffi::constructor]
    pub fn new(server: String) -> Result<Self> {
        Ok(Self(RwLock::new(iota_sdk::graphql_client::Client::new(
            &server,
        )?)))
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    #[uniffi::constructor]
    pub fn new_mainnet() -> Self {
        Self(RwLock::new(iota_sdk::graphql_client::Client::new_mainnet()))
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    #[uniffi::constructor]
    pub fn new_testnet() -> Self {
        Self(RwLock::new(iota_sdk::graphql_client::Client::new_testnet()))
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    #[uniffi::constructor]
    pub fn new_devnet() -> Self {
        Self(RwLock::new(iota_sdk::graphql_client::Client::new_devnet()))
    }

    /// Create a new GraphQL client connected to the `localhost` GraphQL server:
    /// {DEFAULT_LOCAL_HOST}.
    #[uniffi::constructor]
    pub fn new_localnet() -> Self {
        Self(RwLock::new(iota_sdk::graphql_client::Client::new_localnet()))
    }

    /// Lazily fetch the max page size
    pub async fn max_page_size(&self) -> Result<i32> {
        Ok(self.0.read().await.max_page_size().await?)
    }

    /// Set the server address for the GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub async fn set_rpc_server(&self, server: String) -> Result<()> {
        Ok(self.0.write().await.set_rpc_server(&server)?)
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<ServiceConfig> {
        Ok(self.0.read().await.service_config().await?.clone().into())
    }

    /// Run a query.
    pub async fn run_query(&self, query: Query) -> Result<serde_json::Value> {
        self.0
            .read()
            .await
            .run_query_from_json(
                serde_json::to_value(query)?
                    .as_object()
                    .ok_or_else(|| SdkFfiError::custom("invalid json; must be a map"))?
                    .clone(),
            )
            .await?
            .data
            .ok_or_else(|| SdkFfiError::custom("query yielded no data"))
    }
}
