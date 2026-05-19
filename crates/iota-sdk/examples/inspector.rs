// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use eyre::OptionExt;
use iota_sdk::graphql_client::{Client, GraphQlRequestResult};
use iota_types::ObjectId;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let client = Client::new_testnet().with_inspector(|r: &GraphQlRequestResult| {
        let op = r.operation_name.as_deref().unwrap_or("<unnamed>");
        let duration = r
            .duration
            .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "N/A".into());
        println!("[inspector] {op} @ {}", r.url);
        if let Some(query) = &r.query {
            println!("[inspector] query: {}", query.trim());
        }
        if let Some(vars) = &r.variables {
            println!("[inspector] variables: {vars}");
        }
        if let Some(body) = &r.response_body {
            println!("[inspector] response: {body}");
        }
        match &r.error {
            Some(err) => println!("[inspector] -> ERROR ({duration}): {err}"),
            None => println!("[inspector] -> OK ({duration})"),
        }
    });

    let chain_id = client.chain_id().await?;
    println!("Chain ID: {chain_id}");

    let object_id =
        ObjectId::from_str("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")?;

    let obj = client
        .object(object_id, None)
        .await?
        .ok_or_eyre("missing object")?;

    println!("Object ID: {}", obj.object_id());

    Ok(())
}
