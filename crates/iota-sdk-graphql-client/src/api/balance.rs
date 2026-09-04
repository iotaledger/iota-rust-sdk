// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Balance API implementation.

use cynic::QueryBuilder;
use iota_types::Address;

use crate::{
    Client,
    error::GraphQLResult,
    query_types::{BalanceArgs, BalanceQuery},
};

impl Client {
    /// Get the balance of all the coins owned by address for the provided coin
    /// type. Coin type will default to `0x2::coin::Coin<0x2::iota::IOTA>`
    /// if not provided.
    pub async fn balance(
        &self,
        address: Address,
        coin_type: impl Into<Option<String>>,
    ) -> GraphQLResult<Option<u64>> {
        let operation = BalanceQuery::build(BalanceArgs {
            address,
            coin_type: coin_type.into(),
        });
        let response = self.run_query(&operation).await?;

        let total_balance = response
            .owner
            .and_then(|o| o.balance.and_then(|b| b.total_balance))
            .map(|x| x.0.parse::<u64>())
            .transpose()?;
        Ok(total_balance)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::Address;

    use crate::test_utils::test_client;

    #[tokio::test]
    async fn test_balance_query() {
        let client = test_client();
        client
            .balance(Address::STD, None)
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
