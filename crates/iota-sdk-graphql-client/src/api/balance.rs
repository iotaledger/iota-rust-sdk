// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Balance API implementation.

use cynic::QueryBuilder;
use iota_types::Address;

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    query_types::{BalanceArgs, BalanceQueryFragment},
};

define_query! {
    /// Query for [`GraphQLClient::balance`]. Await it to send the request.
    pub struct GetBalanceQuery {
        client: GraphQLClient,
        address: Address,
        coin_type: Option<String>,
    }
    output: GraphQLResult<Option<u64>>;
}

impl GetBalanceQuery {
    /// Set the coin type. Defaults to `0x2::iota::IOTA`.
    pub fn coin_type(mut self, coin_type: impl Into<Option<String>>) -> Self {
        self.coin_type = coin_type.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<u64>> {
        let operation = BalanceQueryFragment::build(BalanceArgs {
            address: self.address,
            coin_type: self.coin_type,
        });
        let response = self.client.run_query(&operation).await?;

        let total_balance = response
            .owner
            .and_then(|o| o.balance.and_then(|b| b.total_balance))
            .map(|x| x.0.parse::<u64>())
            .transpose()?;
        Ok(total_balance)
    }
}

impl GraphQLClient {
    /// Get the balance of all the coins owned by address.
    pub fn balance(&self, address: Address) -> GetBalanceQuery {
        GetBalanceQuery {
            client: self.clone(),
            address,
            coin_type: None,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::Address;

    use crate::test_utils::{sent_variables, test_client};

    #[tokio::test]
    async fn balance_sends_the_address_and_coin_type() {
        let vars = sent_variables("BalanceQueryFragment", |client| async move {
            let _ = client
                .balance(Address::STD)
                .coin_type("0x2::iota::IOTA".to_owned())
                .await;
        })
        .await;
        assert_eq!(vars["address"], Address::STD.to_string());
        assert_eq!(vars["coinType"], "0x2::iota::IOTA");

        let vars = sent_variables("BalanceQueryFragment", |client| async move {
            let _ = client.balance(Address::STD).await;
        })
        .await;
        assert!(vars["coinType"].is_null());
    }

    #[tokio::test]
    async fn test_balance_query() {
        let client = test_client();
        client
            .balance(Address::STD)
            .await
            .map_err(|e| {
                format!(
                    "Balance query failed for {} network: Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }
}
