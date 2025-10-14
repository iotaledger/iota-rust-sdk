// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_graphql_client::faucet::FaucetClient;
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    let address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let faucet_receipt = FaucetClient::new_localnet()
        .request_and_wait(address)
        .await?;
    if let Some(receipt) = faucet_receipt {
        println!("Faucet receipt:");
        for coin in &receipt.sent {
            println!(
                "  Coin ID: {}, Amount: {}, Digest: {}",
                coin.id, coin.amount, coin.transfer_tx_digest
            );
        }
    } else {
        println!("Faucet receipt: None");
    }

    Ok(())
}
