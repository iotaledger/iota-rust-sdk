// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Fetch all transactions for an address (both outgoing and incoming).
//!
//! The GraphQL service does not have a single filter that returns
//! transactions in *both* directions for an address. To get the full
//! history, run two queries and merge the results.

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, pagination::PaginationFilter, query_types::TransactionsFilter},
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let address =
        Address::from_str("0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa")?;

    let outgoing = client
        .transactions(
            TransactionsFilter::default().with_sent_address(address),
            PaginationFilter::default(),
        )
        .await?;

    let incoming = client
        .transactions(
            TransactionsFilter::default().with_recv_address(address),
            PaginationFilter::default(),
        )
        .await?;

    println!("Transactions for {address}");

    println!("\nOutgoing (sent by address): {}", outgoing.data().len());
    for tx in outgoing.data() {
        println!("  - {}", tx.transaction.digest());
    }

    println!(
        "\nIncoming (received by address): {}",
        incoming.data().len()
    );
    for tx in incoming.data() {
        println!("  - {}", tx.transaction.digest());
    }

    Ok(())
}
