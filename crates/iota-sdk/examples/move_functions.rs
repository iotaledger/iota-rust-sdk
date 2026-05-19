// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{graphql_client::Client, types::Address};

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    // Inspect the IOTA framework package (0x2). It is present on every network
    // including localnet.
    let package_address = Address::FRAMEWORK;
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
