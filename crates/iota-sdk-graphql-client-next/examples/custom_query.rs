// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! A query of your own, sent with the client's transport, retries and error
//! handling.

use cynic::QueryBuilder;
use eyre::Result;
use iota_sdk_graphql_client_next::{GraphQLClient, Query, ServerVersion};

#[cynic::schema("rpc")]
mod schema {}

cynic::impl_scalar!(u64, schema::UInt53);

#[derive(cynic::Scalar, Debug)]
#[cynic(graphql_type = "BigInt")]
struct BigInt(String);

// The data returned by the custom query.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Epoch")]
struct EpochData {
    epoch_id: u64,
    reference_gas_price: Option<BigInt>,
    total_gas_fees: Option<BigInt>,
    total_checkpoints: Option<u64>,
    total_transactions: Option<u64>,
}

// The variables of the custom query. Without an epoch id, the query returns
// the data of the last known epoch.
#[derive(cynic::QueryVariables, Debug)]
struct EpochVariables {
    id: Option<u64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EpochVariables")]
struct EpochQuery {
    #[arguments(id: $id)]
    epoch: Option<EpochData>,
}

/// An epoch's gas and transaction totals.
struct EpochTotals {
    id: Option<u64>,
}

impl Query for EpochTotals {
    type Output = Option<EpochData>;
    type Data = EpochQuery;
    type Variables = EpochVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> iota_sdk_graphql_client_next::Result<cynic::Operation<EpochQuery, EpochVariables>> {
        Ok(EpochQuery::build(EpochVariables { id: self.id }))
    }

    fn decode(self, data: EpochQuery) -> iota_sdk_graphql_client_next::Result<Option<EpochData>> {
        Ok(data.epoch)
    }
}

fn print(epoch: Option<EpochData>) {
    let Some(epoch) = epoch else {
        println!("No data for this epoch");
        return;
    };
    let big_int = |value: Option<BigInt>| value.map(|BigInt(digits)| digits).unwrap_or_default();
    println!("Epoch {}", epoch.epoch_id);
    println!(
        "  Reference gas price: {}",
        big_int(epoch.reference_gas_price)
    );
    println!("  Total gas fees: {}", big_int(epoch.total_gas_fees));
    println!(
        "  Checkpoints: {}",
        epoch.total_checkpoints.unwrap_or_default()
    );
    println!(
        "  Transactions: {}",
        epoch.total_transactions.unwrap_or_default()
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    print(client.send(EpochTotals { id: None }).await?);
    print(client.send(EpochTotals { id: Some(1) }).await?);

    Ok(())
}
