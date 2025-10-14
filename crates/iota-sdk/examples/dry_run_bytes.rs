// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_graphql_client::Client;
use iota_types::Transaction;

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_devnet();

    let tx_bytes_base64 = "AAACACAAAKSYS9SV1DRvogjd/09dXlrUjCHexjHd68mYCfFpAAAIAPIFKgEAAAACAgABAQEAAQECAAABAABhGDDTZBpo+UppDcwl0fSw2slIMlrBj23TJWQ3FzXzLAILAnDunSfaDbCWUeX3M436MsfuZEHM76H24wVzW8/Hq3M6MhwAAAAAIKlI7704HwxEKcAJUDavYxFuJgvpsFwQktqa3/trEI4n0EB3/jtvrROz1O0NU1t8qSr8rI8PKg4JJfufTwswxplyOjIcAAAAACBwo4RInFHkslDFUznEltYw/OPcH4EFo0/At7kMLZpocGEYMNNkGmj5SmkNzCXR9LDayUgyWsGPbdMlZDcXNfMs6AMAAAAAAACgLS0AAAAAAAA=";
    let transaction = Transaction::from_base64(tx_bytes_base64)?;

    let res = client.dry_run_tx(&transaction, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Dry run failed: {err}");
    }

    println!("Dry run was successful!");
    println!("Dry run result: {res:#?}");

    Ok(())
}
