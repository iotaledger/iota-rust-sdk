// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_transaction_builder::TransactionBuilder;
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let from_address =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let objs_to_transfer = [
        ObjectId::from_str("0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699")?,
        ObjectId::from_str("0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab")?,
        ObjectId::from_str("0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9")?,
    ];

    let mut builder = TransactionBuilder::new(from_address).with_client(&client);

    builder.transfer_objects(to_address, objs_to_transfer);

    let txn = builder.finish().await?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_tx(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to transfer objects: {err}");
    }

    println!("Transfer objects dry run was successful!");

    Ok(())
}
