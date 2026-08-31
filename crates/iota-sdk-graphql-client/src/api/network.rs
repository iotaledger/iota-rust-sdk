// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Network API implementation.

use cynic::QueryBuilder;

use crate::{
    Client,
    error::GraphQLResult,
    pagination::{Page, PaginationFilter},
    query_types::{
        ActiveValidatorsArgs, ActiveValidatorsQuery, ChainIdentifierQuery, EpochArgs,
        EpochSummaryQuery, ProtocolConfigQuery, ProtocolConfigs, ProtocolVersionArgs, Validator,
    },
};

impl Client {
    /// Get the chain identifier.
    pub async fn chain_id(&self) -> GraphQLResult<String> {
        let operation = ChainIdentifierQuery::build(());
        let response = self.run_query(&operation).await?;

        Ok(response.chain_identifier)
    }

    /// Get the reference gas price for the provided epoch or the last known one
    /// if no epoch is provided.
    ///
    /// This will return `Ok(None)` if the epoch requested is not available in
    /// the GraphQL service (e.g., due to pruning).
    pub async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> GraphQLResult<Option<u64>> {
        let operation = EpochSummaryQuery::build(EpochArgs { id: epoch.into() });
        let response = self.run_query(&operation).await?;

        response
            .epoch
            .and_then(|e| e.reference_gas_price)
            .map(|x| x.try_into())
            .transpose()
    }

    /// Get the protocol configuration.
    pub async fn protocol_config(
        &self,
        version: impl Into<Option<u64>>,
    ) -> GraphQLResult<ProtocolConfigs> {
        let operation = ProtocolConfigQuery::build(ProtocolVersionArgs { id: version.into() });
        let response = self.run_query(&operation).await?;
        Ok(response.protocol_config)
    }

    /// Get the list of active validators for the provided epoch, including
    /// related metadata. If no epoch is provided, it will return the active
    /// validators for the current epoch.
    pub async fn active_validators(
        &self,
        epoch: impl Into<Option<u64>>,
        pagination_filter: PaginationFilter,
    ) -> GraphQLResult<Page<Validator>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = ActiveValidatorsQuery::build(ActiveValidatorsArgs {
            id: epoch.into(),
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        });
        let response = self.run_query(&operation).await?;

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

#[cfg(test)]
mod tests {
    use crate::{PaginationFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_chain_id() {
        let client = test_client();
        let chain_id = client.chain_id().await;
        assert!(chain_id.is_ok());
    }

    #[tokio::test]
    async fn test_reference_gas_price_query() {
        let client = test_client();
        client
            .reference_gas_price(None)
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
            .protocol_config(None)
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
            .protocol_config(Some(50))
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
            .active_validators(None, PaginationFilter::default())
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
