// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coin API implementation.

use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    GraphQLClient, ListObjectsQuery,
    api::define_query,
    error::GraphQLResult,
    pagination::{Direction, Page, PaginationFilter},
    query_types::{CoinMetadata, CoinMetadataArgs, CoinMetadataQueryFragment, ObjectFilter},
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::coins`]. Await it to send the request.
    pub struct ListCoinsQuery {
        client: GraphQLClient,
        owner: Address,
        coin_type: Option<StructTag>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<Coin>>;
}

impl ListCoinsQuery {
    /// Only return coins of this type. Defaults to every type.
    pub fn coin_type(mut self, coin_type: impl Into<Option<StructTag>>) -> Self {
        self.coin_type = coin_type.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn objects_query(self) -> ListObjectsQuery {
        let type_tag = self.coin_type.map(StructTag::new_coin).unwrap_or_else(|| {
            StructTag::new(
                Address::FRAMEWORK,
                Identifier::from_static("coin"),
                Identifier::from_static("Coin"),
                Default::default(),
            )
        });
        ListObjectsQuery::new(self.client)
            .filter(ObjectFilter {
                type_tag: Some(type_tag.to_string()),
                owner: Some(self.owner),
                object_ids: None,
            })
            .pagination(self.pagination)
    }

    async fn send(self) -> GraphQLResult<Page<Coin>> {
        let response = self.objects_query().await?;

        Ok(Page::new(
            response.page_info,
            response
                .data
                .iter()
                .flat_map(Coin::try_from_object)
                .collect::<Vec<_>>(),
        ))
    }
}

define_query! {
    /// Query for [`GraphQLClient::gas_coins`]. Await it to send the request.
    pub struct ListGasCoinsQuery {
        coins: ListCoinsQuery,
    }
    output: GraphQLResult<Page<Coin>>;
}

impl ListGasCoinsQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.coins = self.coins.pagination(pagination);
        self
    }

    async fn send(self) -> GraphQLResult<Page<Coin>> {
        self.coins.send().await
    }
}

impl GraphQLClient {
    /// Get the list of coins for the specified address as a stream.
    ///
    /// If `coin_type` is not provided, all coins will be returned. For IOTA
    /// coins, pass in the coin type: `0x2::iota::IOTA`.
    pub fn coins_stream(
        &self,
        address: Address,
        coin_type: impl Into<Option<StructTag>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<Coin>> + '_ {
        let coin_type = coin_type.into();
        stream_paginated_query(
            move |filter| {
                self.coins(address)
                    .coin_type(coin_type.clone())
                    .pagination(filter)
                    .into_future()
            },
            streaming_direction,
        )
    }

    /// Get the list of gas coins for the specified address as a stream.
    pub fn gas_coins_stream(
        &self,
        address: Address,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<Coin>> + '_ {
        stream_paginated_query(
            move |filter| self.gas_coins(address).pagination(filter).into_future(),
            streaming_direction,
        )
    }

    /// Get the list of coins for the specified address. For IOTA coins, set
    /// the coin type to `0x2::iota::IOTA`.
    pub fn coins(&self, owner: Address) -> ListCoinsQuery {
        ListCoinsQuery {
            client: self.clone(),
            owner,
            coin_type: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Get the list of gas coins for the specified address.
    pub fn gas_coins(&self, owner: Address) -> ListGasCoinsQuery {
        ListGasCoinsQuery {
            coins: self.coins(owner).coin_type(StructTag::new_gas()),
        }
    }

    /// Get the coin metadata for the coin type.
    pub async fn coin_metadata(&self, coin_type: &str) -> GraphQLResult<Option<CoinMetadata>> {
        let operation = CoinMetadataQueryFragment::build(CoinMetadataArgs { coin_type });
        let response = self.run_query(&operation).await?;

        Ok(response.coin_metadata)
    }

    /// Get total supply for the coin type.
    pub async fn total_supply(&self, coin_type: &str) -> GraphQLResult<Option<u64>> {
        let coin_metadata = self.coin_metadata(coin_type).await?;

        coin_metadata
            .and_then(|c| c.supply)
            .map(|c| c.try_into())
            .transpose()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use futures::StreamExt;
    use iota_types::{Address, Ed25519PublicKey, StructTag};
    use tokio::time;

    use crate::{
        Direction,
        client::LOCAL_HOST,
        faucet::FaucetClient,
        test_utils::{
            NUM_COINS_FROM_FAUCET, assert_backward_page, assert_forward_page, backward_page,
            forward_page, sent_variables, test_client,
        },
    };

    #[tokio::test]
    async fn coins_sends_the_owner_coin_type_and_pagination() {
        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .coins(Address::STD)
                .coin_type(StructTag::new_gas())
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["filter"]["owner"], Address::STD.to_string());
        assert_eq!(
            vars["filter"]["type"],
            StructTag::new_coin(StructTag::new_gas()).to_string()
        );
        assert_backward_page(&vars);

        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .coins(Address::STD)
                .coin_type(StructTag::new_gas())
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
    }

    #[tokio::test]
    async fn gas_coins_sends_the_gas_coin_type() {
        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .gas_coins(Address::STD)
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(
            vars["filter"]["type"],
            StructTag::new_coin(StructTag::new_gas()).to_string()
        );
    }

    #[tokio::test]
    async fn coins_default_to_every_coin_type() {
        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client.coins(Address::STD).pagination(backward_page()).await;
        })
        .await;
        assert_eq!(vars["filter"]["type"], "0x2::coin::Coin");
    }

    #[tokio::test]
    async fn test_coins_query() {
        let client = test_client();
        client
            .coins(Address::STD)
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
            // The testnet and devnet faucets are web-only and expose no
            // programmatic gas endpoint, so this test can only fund an
            // address on localnet.
            _ => return,
        };
        let key = Ed25519PublicKey::random();
        let address = key.derive_address();
        faucet
            .request_and_wait_for_finalized(address, &client)
            .await
            .unwrap();

        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY: time::Duration = time::Duration::from_secs(1);

        // Retry until the expected number of coins is streamed. Indexer lag can
        // return a successful but incomplete page, so retry on a low count as
        // well as on a stream error, re-counting from scratch each attempt.
        let mut num_coins = 0;
        for attempt in 0..MAX_RETRIES {
            num_coins = 0;
            let mut stream = client.coins_stream(address, None, Direction::default());
            let mut errored = false;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(_) => num_coins += 1,
                    Err(_) => {
                        errored = true;
                        break;
                    }
                }
            }

            if !errored && num_coins >= NUM_COINS_FROM_FAUCET {
                break;
            }
            if attempt < MAX_RETRIES - 1 {
                time::sleep(RETRY_DELAY).await;
            }
        }

        assert!(
            num_coins >= NUM_COINS_FROM_FAUCET,
            "expected at least {NUM_COINS_FROM_FAUCET} coins for {address}, got {num_coins}"
        );
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
