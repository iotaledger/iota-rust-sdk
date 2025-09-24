// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{Client, error::Result, query_types::ObjectFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let staked_iotas = client
        .objects(
            ObjectFilter {
                type_: "0x3::staking_pool::StakedIota".to_owned().into(),
                ..Default::default()
            },
            Default::default(),
        )
        .await?;

    if staked_iotas.data.is_empty() {
        println!("No StakedIota objects found");
    } else {
        println!("StakedIota object IDs:");
        for staked_iota in staked_iotas.data {
            println!("{}", staked_iota.object_id());
        }
    }

    Ok(())
}
