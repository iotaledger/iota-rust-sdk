// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coin API implementation.

use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    Client,
    error::Result,
    pagination::{Direction, Page, PaginationFilter},
    query_types::{CoinMetadata, CoinMetadataArgs, CoinMetadataQuery, ObjectFilter},
    streams::stream_paginated_query,
};

impl Client {
    /// Get the list of coins for the specified address as a stream.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    pub fn coins_stream(
        &self,
        address: Address,
        coin_type: impl Into<Option<StructTag>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Coin>> + '_ {
        let coin_type = coin_type.into();
        stream_paginated_query(
            move |filter| self.coins(address, coin_type.clone(), filter),
            streaming_direction,
        )
    }

    /// Get the list of gas coins for the specified address as a stream.
    pub fn gas_coins_stream(
        &self,
        address: Address,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Coin>> + '_ {
        stream_paginated_query(
            move |filter| self.gas_coins(address, filter),
            streaming_direction,
        )
    }

    /// Get the list of coins for the specified address.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    pub async fn coins(
        &self,
        owner: Address,
        coin_type: impl Into<Option<StructTag>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Coin>> {
        let filter = ObjectFilter {
            type_: Some(
                coin_type
                    .into()
                    .map(StructTag::new_coin)
                    .unwrap_or_else(|| {
                        StructTag::new(
                            Address::FRAMEWORK,
                            Identifier::from_static("coin"),
                            Identifier::from_static("Coin"),
                            Default::default(),
                        )
                    })
                    .to_string(),
            ),
            owner: Some(owner),
            object_ids: None,
        };
        let response = self.objects(filter, pagination_filter).await?;

        Ok(Page::new(
            response.page_info,
            response
                .data
                .iter()
                .flat_map(Coin::try_from_object)
                .collect::<Vec<_>>(),
        ))
    }

    /// Get the list of gas coins for the specified address.
    pub async fn gas_coins(
        &self,
        owner: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Coin>> {
        self.coins(owner, StructTag::new_gas(), pagination_filter)
            .await
    }

    /// Get the coin metadata for the coin type.
    pub async fn coin_metadata(&self, coin_type: &str) -> Result<Option<CoinMetadata>> {
        let operation = CoinMetadataQuery::build(CoinMetadataArgs { coin_type });
        let response = self.run_query(&operation).await?;

        Ok(response.coin_metadata)
    }

    /// Get total supply for the coin type.
    pub async fn total_supply(&self, coin_type: &str) -> Result<Option<u64>> {
        let coin_metadata = self.coin_metadata(coin_type).await?;

        coin_metadata
            .and_then(|c| c.supply)
            .map(|c| c.try_into())
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use iota_types::{Address, Ed25519PublicKey};

    use crate::{
        Direction, PaginationFilter,
        client::{DEVNET_HOST, LOCAL_HOST},
        faucet::FaucetClient,
        test_utils::{NUM_COINS_FROM_FAUCET, test_client},
    };

    #[tokio::test]
    async fn test_coins_query() {
        let client = test_client();
        client
            .coins(Address::STD, None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Coins query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_coins_stream() {
        let client = test_client();
        let faucet = match client.rpc_server().as_str() {
            LOCAL_HOST => FaucetClient::new_localnet(),
            DEVNET_HOST => FaucetClient::new_devnet(),
            // The testnet faucet is web-only and exposes no programmatic gas
            // endpoint, so this test cannot fund an address on testnet.
            _ => return,
        };
        let key = Ed25519PublicKey::generate(rand::thread_rng());
        let address = key.derive_address();
        faucet
            .request_and_wait_for_finalized(address, &client)
            .await
            .unwrap();

        let num_coins = client
            .coins_stream(address, None, Direction::default())
            .filter_map(|r| async { r.ok() })
            .count()
            .await;

        assert!(num_coins >= NUM_COINS_FROM_FAUCET);
    }

    #[tokio::test]
    async fn test_coin_metadata_query() {
        let client = test_client();
        client
            .coin_metadata("0x2::iota::IOTA")
            .await
            .map_err(|e| {
                format!(
                    "Coin metadata query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_total_supply() {
        let client = test_client();
        client
            .total_supply("0x2::iota::IOTA")
            .await
            .map_err(|e| {
                format!(
                    "Total supply query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }
}
