// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::{OptionExt, Result};
use iota_graphql_client::{Client, query_types::ObjectFilter};
use iota_transaction_builder::{SharedMut, TransactionBuilder};
use iota_types::{Address, ObjectId};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let staked_iota = client
        .objects(
            ObjectFilter {
                type_: "0x3::staking_pool::StakedIota".to_owned().into(),
                ..Default::default()
            },
            Default::default(),
        )
        .await?
        .data
        .into_iter()
        .next()
        .ok_or_eyre("no staked iota found")?;

    let mut builder =
        TransactionBuilder::new(*staked_iota.owner().as_address()).with_client(client);

    builder
        .move_call(Address::THREE, "iota_system", "request_withdraw_stake")
        .arguments((
            SharedMut(ObjectId::from_str("0x5")?),
            staked_iota.object_id(),
        ));

    let res = builder.dry_run(false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Failed to unstake: {err}");
    }

    println!("Unstake dry run was successful!");

    Ok(())
}
