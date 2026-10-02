// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Network API implementation.

use cynic::QueryBuilder;

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    pagination::{Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        ActiveValidatorsArgs, ActiveValidatorsQueryFragment, ChainIdentifierQueryFragment,
        EpochArgs, EpochSummaryQueryFragment, ProtocolConfigQueryFragment, ProtocolConfigs,
        ProtocolVersionArgs, Validator,
    },
};

define_query! {
    /// Query for [`GraphQLClient::chain_id`]. Await it to send the request.
    pub struct GetChainIdQuery {
        client: GraphQLClient,
    }
    output: GraphQLResult<String>;
}

impl GetChainIdQuery {
    fn operation(&self) -> cynic::Operation<ChainIdentifierQueryFragment, ()> {
        ChainIdentifierQueryFragment::build(())
    }

    async fn send(self) -> GraphQLResult<String> {
        let response = self.client.run_query(&self.operation()).await?;

        Ok(response.chain_identifier)
    }
}

define_query! {
    /// Query for [`GraphQLClient::active_validators`]. Await it to send the
    /// request.
    pub struct ListActiveValidatorsQuery {
        client: GraphQLClient,
        epoch: Option<u64>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<Validator>>;
}

impl ListActiveValidatorsQuery {
    /// Set the epoch number. Defaults to the current epoch.
    pub fn epoch_number(mut self, epoch_number: impl Into<Option<u64>>) -> Self {
        self.epoch = epoch_number.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation<'a>(
        &self,
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<ActiveValidatorsQueryFragment, ActiveValidatorsArgs<'a>> {
        ActiveValidatorsQueryFragment::build(ActiveValidatorsArgs {
            id: self.epoch,
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<Validator>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        if let Some(validators) = response.epoch.and_then(|v| v.validator_set) {
            let page_info = validators.active_validators.page_info;
            let nodes = validators
                .active_validators
                .nodes
                .into_iter()
                .collect::<Vec<_>>();
            Ok(Page::new(page_info, nodes))
        } else {
            Ok(Page::new_empty())
        }
    }
}

define_query! {
    /// Query for [`GraphQLClient::reference_gas_price`]. Await it to send the
    /// request.
    pub struct GetReferenceGasPriceQuery {
        client: GraphQLClient,
        epoch: Option<u64>,
    }
    output: GraphQLResult<Option<u64>>;
}

impl GetReferenceGasPriceQuery {
    /// Set the epoch number. Defaults to the last known epoch.
    pub fn epoch_number(mut self, epoch_number: impl Into<Option<u64>>) -> Self {
        self.epoch = epoch_number.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<u64>> {
        let operation = EpochSummaryQueryFragment::build(EpochArgs { id: self.epoch });
        let response = self.client.run_query(&operation).await?;

        response
            .epoch
            .and_then(|e| e.reference_gas_price)
            .map(|x| x.try_into())
            .transpose()
    }
}

define_query! {
    /// Query for [`GraphQLClient::protocol_config`]. Await it to send the
    /// request.
    pub struct GetProtocolConfigQuery {
        client: GraphQLClient,
        version: Option<u64>,
    }
    output: GraphQLResult<ProtocolConfigs>;
}

impl GetProtocolConfigQuery {
    /// Set the protocol version. Defaults to the latest version.
    pub fn version(mut self, version: impl Into<Option<u64>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<ProtocolConfigs> {
        let operation =
            ProtocolConfigQueryFragment::build(ProtocolVersionArgs { id: self.version });
        let response = self.client.run_query(&operation).await?;
        Ok(response.protocol_config)
    }
}

impl GraphQLClient {
    /// Get the chain identifier.
    pub fn chain_id(&self) -> GetChainIdQuery {
        GetChainIdQuery {
            client: self.clone(),
        }
    }

    /// Get the reference gas price. Defaults to the last known epoch.
    ///
    /// This will resolve to `Ok(None)` if the epoch requested is not available
    /// in the GraphQL service (e.g., due to pruning).
    pub fn reference_gas_price(&self) -> GetReferenceGasPriceQuery {
        GetReferenceGasPriceQuery {
            client: self.clone(),
            epoch: None,
        }
    }

    /// Get the protocol configuration. Defaults to the latest version.
    pub fn protocol_config(&self) -> GetProtocolConfigQuery {
        GetProtocolConfigQuery {
            client: self.clone(),
            version: None,
        }
    }

    /// Get the list of active validators, including related metadata.
    pub fn active_validators(&self) -> ListActiveValidatorsQuery {
        ListActiveValidatorsQuery {
            client: self.clone(),
            epoch: None,
            pagination: PaginationFilter::default(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use crate::{
        GraphQLClient,
        test_utils::{assert_backward_page, backward_page, sent_variables, test_client},
    };

    #[tokio::test]
    async fn active_validators_sends_the_epoch_and_pagination() {
        let vars = sent_variables("ActiveValidatorsQueryFragment", |client| async move {
            let _ = client
                .active_validators()
                .epoch_number(3)
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["id"], 3);
        assert_backward_page(&vars);
    }

    #[test]
    fn chain_id_builds_the_chain_identifier_operation() {
        let operation = GraphQLClient::new_localnet().chain_id().operation();
        assert_eq!(
            operation.operation_name.as_deref(),
            Some("ChainIdentifierQueryFragment")
        );
        assert!(operation.query.contains("chainIdentifier"));
    }

    #[tokio::test]
    async fn test_chain_id() {
        let client = test_client();
        let chain_id = client.chain_id().await.unwrap();
        assert!(!chain_id.is_empty());
    }

    #[tokio::test]
    async fn reference_gas_price_and_protocol_config_send_their_input() {
        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client.reference_gas_price().epoch_number(3).await;
        })
        .await;
        assert_eq!(vars["id"], 3);

        let vars = sent_variables("ProtocolConfigQueryFragment", |client| async move {
            let _ = client.protocol_config().version(50).await;
        })
        .await;
        assert_eq!(vars["id"], 50);

        let vars = sent_variables("EpochSummaryQueryFragment", |client| async move {
            let _ = client.reference_gas_price().await;
        })
        .await;
        assert!(vars["id"].is_null());

        let vars = sent_variables("ProtocolConfigQueryFragment", |client| async move {
            let _ = client.protocol_config().await;
        })
        .await;
        assert!(vars["id"].is_null());
    }

    #[tokio::test]
    async fn test_reference_gas_price_query() {
        let client = test_client();
        client
            .reference_gas_price()
            .await
            .map_err(|e| {
                format!(
                    "Reference gas price query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_protocol_config_query() {
        let client = test_client();
        client
            .protocol_config()
            .await
            .map_err(|e| {
                format!(
                    "Protocol config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        // test specific version
        let pc = client
            .protocol_config()
            .version(50)
            .await
            .map_err(|e| {
                format!(
                    "Protocol config query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert_eq!(
            pc.protocol_version,
            50,
            "Protocol version query mismatch for {} network. Expected: 50, received: {}",
            client.rpc_server(),
            pc.protocol_version
        );
    }

    #[tokio::test]
    async fn test_active_validators() {
        let client = test_client();
        let av = client
            .active_validators()
            .await
            .map_err(|e| {
                format!(
                    "Active validators query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        assert!(
            !av.is_empty(),
            "Active validators query returned no data for {} network",
            client.rpc_server()
        );
    }
}
