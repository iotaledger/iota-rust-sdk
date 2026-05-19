// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::graphql_client::Client;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    // The IOTA system state object owns the validator set and other dynamic
    // fields. It is available on every network including localnet.
    let parent_object_id = "0x5".parse()?;
    let dynamic_fields_page = client
        .dynamic_fields(parent_object_id, Default::default())
        .await?;
    println!("{:#?}", dynamic_fields_page.page_info());
    println!("Page size: {}", dynamic_fields_page.data().len());

    if let Some(first) = dynamic_fields_page.data().first() {
        println!(
            "First field name:\n{}",
            serde_json::to_string_pretty(&first.name)?
        );

        // The field value can be large (e.g. the validator set on 0x5), so we
        // print only the first few lines as a preview.
        let value_pretty = serde_json::to_string_pretty(&first.value_as_json)?;
        const PREVIEW_LINES: usize = 15;
        let mut iter = value_pretty.lines();
        let preview: Vec<&str> = iter.by_ref().take(PREVIEW_LINES).collect();
        let truncated = iter.next().is_some();
        println!("First field value (first {PREVIEW_LINES} lines):");
        println!("{}", preview.join("\n"));
        if truncated {
            println!("... [truncated]");
        }
    }

    Ok(())
}
