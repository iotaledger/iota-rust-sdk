// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_graphql_client::Client;
use iota_types::Address;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let package_address =
        Address::from_str("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")?;
    let Some(package) = client.package(package_address, None).await? else {
        eyre::bail!("no package found")
    };

    for (module_id, _) in package.modules {
        let Some(module) = client
            .normalized_move_module(
                package_address,
                module_id.as_str(),
                None,
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
            )
            .await?
        else {
            eyre::bail!("module `{module_id}` not found")
        };
        if let Some(funs) = module.functions {
            println!("Module: {module_id}");
            for fun in funs.nodes {
                println!("- {fun}");
            }
            println!();
        }
    }

    Ok(())
}
