// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, PoisonError, RwLock};

use crate::{
    error::{Result, SdkFfiError},
    graphql::query_types::ServiceConfig,
    http::HttpClientOptions,
    transaction_builder::{builder::TransactionBuilder, client_builder::GraphQLTransactionBuilder},
    types::address::Address,
};

/// The GraphQL client for interacting with the IOTA blockchain.
#[derive(uniffi::Object)]
pub struct GraphQLClient(RwLock<Arc<iota_sdk::graphql_client::GraphQLClient>>);

impl GraphQLClient {
    /// A handle on the current client configuration.
    pub(crate) fn client(&self) -> Arc<iota_sdk::graphql_client::GraphQLClient> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl From<iota_sdk::graphql_client::GraphQLClient> for GraphQLClient {
    fn from(client: iota_sdk::graphql_client::GraphQLClient) -> Self {
        Self(RwLock::new(Arc::new(client)))
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
        Ok(iota_sdk::graphql_client::GraphQLClient::new(&server)?.into())
    }

    /// Create a new GraphQL client with the provided server address, using an
    /// HTTP client built to the given options.
    #[uniffi::constructor]
    pub fn new_with_http_options(server: String, options: HttpClientOptions) -> Result<Self> {
        Ok(
            iota_sdk::graphql_client::GraphQLClient::new_with_reqwest_client(
                &server,
                options.build()?,
            )?
            .into(),
        )
    }

    /// Create a new GraphQL client connected to the `mainnet` GraphQL server:
    /// {MAINNET_HOST}.
    #[uniffi::constructor]
    pub fn new_mainnet() -> Self {
        iota_sdk::graphql_client::GraphQLClient::new_mainnet().into()
    }

    /// Create a new GraphQL client connected to the `testnet` GraphQL server:
    /// {TESTNET_HOST}.
    #[uniffi::constructor]
    pub fn new_testnet() -> Self {
        iota_sdk::graphql_client::GraphQLClient::new_testnet().into()
    }

    /// Create a new GraphQL client connected to the `devnet` GraphQL server:
    /// {DEVNET_HOST}.
    #[uniffi::constructor]
    pub fn new_devnet() -> Self {
        iota_sdk::graphql_client::GraphQLClient::new_devnet().into()
    }

    /// Create a new GraphQL client connected to the `localhost` GraphQL server:
    /// {DEFAULT_LOCAL_HOST}.
    #[uniffi::constructor]
    pub fn new_localnet() -> Self {
        iota_sdk::graphql_client::GraphQLClient::new_localnet().into()
    }

    /// Lazily fetch the max page size
    pub async fn max_page_size(&self) -> Result<i32> {
        Ok(self.client().max_page_size().await?)
    }

    /// Set the server address for the GraphQL client. It should be a
    /// valid URL with a host and optionally a port number.
    pub fn set_rpc_server(&self, server: String) -> Result<()> {
        let mut current = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let mut client = (**current).clone();
        client.set_rpc_server(&server)?;
        *current = Arc::new(client);
        Ok(())
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<ServiceConfig> {
        Ok(self.client().service_config().await?.clone().into())
    }

    /// Run a query.
    pub async fn run_query(&self, query: Query) -> Result<serde_json::Value> {
        Ok(self
            .client()
            .run_query_from_json(
                serde_json::to_value(query)?
                    .as_object()
                    .ok_or_else(|| SdkFfiError::custom("invalid json; must be a map"))?
                    .clone(),
            )
            .await?)
    }

    /// Create a new transaction builder with the given sender address, backed
    /// by this client.
    pub fn transaction_builder(self: Arc<Self>, sender: &Address) -> GraphQLTransactionBuilder {
        TransactionBuilder::new(sender).with_graphql_client(self)
    }
}
