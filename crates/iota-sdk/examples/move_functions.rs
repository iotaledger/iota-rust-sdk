// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::Result;
use iota_sdk::{graphql_client::Client, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet();

    let package_address =
        Address::from_str("0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d")?;
    let Some(package) = client.package(package_address, None).await? else {
        eyre::bail!("no package found")
    };

    for (module_id, _) in package.modules {
        let Some(module) = client
            .move_schema_module(
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
