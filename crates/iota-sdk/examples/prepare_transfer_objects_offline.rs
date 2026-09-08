// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_sdk::{
    graphql_client::Client,
    transaction_builder::TransactionBuilder,
    types::{Address, ObjectId},
};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let from_address =
        Address::from_str("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let mut objs_to_transfer = Vec::new();
    for obj in [
        "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
        "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
        "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2",
    ] {
        objs_to_transfer.push(
            client
                .object(ObjectId::from_str(obj)?, None)
                .await?
                .ok_or_eyre(format!("missing object {obj}"))?
                .object_ref(),
        );
    }
    let gas_coin_id =
        ObjectId::from_str("0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db")?;
    let gas_coin = client
        .object(gas_coin_id, None)
        .await?
        .ok_or_eyre(format!("missing gas coin {gas_coin_id}"))?
        .object_ref();
    let gas_price = client.reference_gas_price(None).await?.unwrap_or(100);

    let mut builder = TransactionBuilder::new(from_address);

    builder
        .transfer_objects(to_address, objs_to_transfer)
        .gas([gas_coin])
        .gas_price(gas_price)
        .gas_budget(500000000);

    let txn = builder.finish()?;

    println!("Signing Digest: {}", txn.signing_digest_hex());
    println!("Txn Bytes: {}", txn.to_base64());

    let res = client.dry_run_transaction(&txn, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to transfer objects: {err}");
    }

    println!("Transfer objects dry run was successful!");

    Ok(())
}
