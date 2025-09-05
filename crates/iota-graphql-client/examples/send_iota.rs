// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use anyhow::Result;
use base64ct::Encoding;
use iota_graphql_client::Client;
use iota_transaction_builder::{
    TransactionBuilder,
    unresolved::{Input, InputKind, Value},
};
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let from_address =
        Address::from_str("0xda06e01d11c8d3ef8f8e238c2f144076fdc6832378fb48b153d57027ae868b39")?;
    let to_address =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let mut builder = TransactionBuilder::new();
    let address = builder.input(Input {
        kind: Some(InputKind::Pure),
        value: Some(Value::String(base64ct::Base64::encode_string(
            to_address.as_bytes(),
        ))),
        ..Default::default()
    });
    let coin = client
        .object(
            ObjectId::from_str(
                "0xf12721f76c61ddd1752757fb5dfd4a5403d5c16b5b82adda9252836297a3c3ad",
            )?,
            None,
        )
        .await?
        .expect("missing object");
    let gas_coin = client
        .object(
            ObjectId::from_str(
                "0x8e6a474ae81616e0ec4e2844d2cd3f21bc42cb0f87bf5c39745ed13a8dabe2d7",
            )?,
            None,
        )
        .await?
        .expect("missing gas coin");
    let coin = builder.input(Input::from(&coin).with_owned_kind());
    builder.transfer_objects(vec![coin], address);
    builder.set_sender(from_address);
    builder.set_gas_budget(50000000);
    builder.set_gas_price(
        client
            .reference_gas_price(None)
            .await?
            .expect("missing ref gas price"),
    );
    builder.add_gas_objects([Input::from(&gas_coin).with_owned_kind()]);
    let txn = builder.finish()?;
    let txn_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&txn)?);
    println!("Signing Digest: {}", hex::encode(&txn.signing_digest()));
    println!("Txn Bytes: {txn_bytes}");

    Ok(())
}
