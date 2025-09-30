// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use base64ct::Encoding;
use eyre::{OptionExt, Result};
use iota_graphql_client::Client;
use iota_transaction_builder::{TransactionBuilder, unresolved::Input};
use iota_types::{Address, Argument, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let sender_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;

    let gas_coin = client
        .object(
            ObjectId::from_str(
                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab",
            )?,
            None,
        )
        .await?
        .ok_or_eyre("missing gas coin")?;

    // Recipients and amounts
    let recipients = [
        (
            Address::from_str(
                "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
            )?,
            1_000_000_000u64,
        ),
        (
            Address::from_str(
                "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
            )?,
            2_000_000_000u64,
        ),
    ];
    let mut builder = TransactionBuilder::new();

    // Prepare split amounts and recipient inputs in a single pass
    let (split_amounts, recipient_inputs): (Vec<_>, Vec<_>) = recipients
        .iter()
        .map(|(addr, amount)| {
            let split_arg = builder.input(Input::pure(amount)?);
            let recipient_arg = builder.input(Input::pure(addr)?);
            Ok((split_arg, recipient_arg))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .unzip();

    // Split the gas coin into multiple coins
    let split_coins_result = builder.split_coins(Argument::Gas, split_amounts);

    // Transfer each split coin to its corresponding recipient
    for (i, recipient_input) in recipient_inputs.into_iter().enumerate() {
        let coin_arg = Argument::get_nested_result(&split_coins_result, i as u16)
            .ok_or_else(|| eyre::eyre!("Failed to get split coin result at index {i}"))?;
        builder.transfer_objects(vec![coin_arg], recipient_input);
    }

    builder.set_sender(sender_address);
    builder.set_gas_budget(50_000_000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .ok_or_eyre("missing ref gas price")?,
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);
    let txn = builder.finish()?;

    println!("Signing Digest: {}", hex::encode(txn.signing_digest()));
    println!(
        "Txn Bytes: {}",
        base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?)
    );

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to send IOTA: {err}");
    }

    println!("Send IOTA dry run was successful!");

    Ok(())
}
