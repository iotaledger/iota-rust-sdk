// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Fetch the latest transactions of an address: those it sent, those that
//! sent it objects, and those that affected it in either direction.

use eyre::{OptionExt, Result, bail};
use iota_sdk_graphql_client_next::{GraphQLClient, TransactionKindFilter, iota_types::Transaction};

#[tokio::main]
async fn main() -> Result<()> {
    let client = GraphQLClient::testnet()?;

    // The sender of the latest user transaction.
    let latest = client
        .transactions()
        .kind(TransactionKindFilter::Programmable)
        .last(1)
        .await?;
    let address = match &latest
        .items()
        .first()
        .ok_or_eyre("no transactions found")?
        .transaction
    {
        Transaction::V1(transaction) => transaction.sender,
        _ => bail!("unknown transaction version"),
    };

    let outgoing = client.transactions().sender(address).last(10).await?;
    let incoming = client.transactions().recipient(address).last(10).await?;
    let affected = client
        .transactions()
        .affected_address(address)
        .last(10)
        .await?;

    println!("Transactions for {address}");

    println!("\nOutgoing (sent by address): {}", outgoing.len());
    for tx in outgoing {
        println!("  - {}", tx.transaction.digest());
    }

    println!("\nIncoming (received by address): {}", incoming.len());
    for tx in incoming {
        println!("  - {}", tx.transaction.digest());
    }

    println!(
        "\nAffected (sender, recipient or gas owner): {}",
        affected.len()
    );
    for tx in affected {
        println!("  - {}", tx.transaction.digest());
    }

    Ok(())
}
