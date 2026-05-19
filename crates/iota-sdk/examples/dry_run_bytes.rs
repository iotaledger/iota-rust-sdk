// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use iota_sdk::{graphql_client::Client, types::Transaction};

// A pre-encoded programmable transaction calling `0x1::u64::max(1, 2)` with
// empty gas-payment objects. Because the bytes do not reference any on-chain
// object refs, they stay valid across networks — the dry-run endpoint fills in
// gas coins on demand.
const TX_BYTES_BASE64: &str = "AAACAAgBAAAAAAAAAAAIAgAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA3U2NANtYXgAAgEAAAEBACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUiACIitGaiQ5nrz17A8EgggSriD+oQN8c2z+xgh1OqOLUi6AMAAAAAAAAAAAAAAAAAAAA=";

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_localnet();

    let transaction = Transaction::from_base64(TX_BYTES_BASE64)?;

    let res = client.dry_run_tx(&transaction, false).await?;

    if let Some(err) = res.error {
        eyre::bail!("Dry run failed: {err}");
    }

    println!("Dry run was successful!");
    println!("Dry run result: {res:#?}");

    Ok(())
}
