// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use core::str::FromStr;

use eyre::Result;
use iota_sdk::{
    graphql_client::{Client, faucet::FaucetClient},
    transaction_builder::TransactionBuilder,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let sender: Address =
        "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522".parse()?;

    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender, &client)
        .await?;

    let mut builder = TransactionBuilder::new(sender).with_client(client);

    let address1 =
        Address::from_str("0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e")?;
    let address2 =
        Address::from_str("0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3")?;

    builder
        .move_call(Address::FRAMEWORK, "vec_map", "from_keys_values")
        .generics::<(Address, u64)>()
        .arguments(([address1, address2], [10000000u64, 20000000u64]));

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to call generic Move function: {err}");
    }

    println!("Successfully called generic Move function!");

    Ok(())
}
