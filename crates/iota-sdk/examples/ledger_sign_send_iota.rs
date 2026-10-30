// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Send IOTA from a Ledger device's address on a local network. Set
//! `LEDGER_SIMULATOR` to use the Speculos emulator instead of a device.

use eyre::Result;
use iota_sdk::{
    graphql_client::{GraphQLClient, faucet::FaucetClient},
    ledger::Ledger,
    transaction_builder::WaitForTransaction,
    types::Address,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Amount to send in nanos
    let amount = 1_000u64;
    let recipient_address =
        Address::from_hex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;

    let mut ledger = if std::env::var_os("LEDGER_SIMULATOR").is_some() {
        Ledger::new_speculos("127.0.0.1", 9999)
    } else {
        Ledger::new_native_hid()?
    };
    ledger.open_app().await?;
    let signer = ledger.into_signer("m/44'/4218'/0'/0'/0'".parse()?).await?;
    let sender_address = signer.address();
    println!("Sender address: {sender_address}");

    let client = GraphQLClient::new_localnet()?;

    // Request funds from faucet
    FaucetClient::new_localnet()
        .request_and_wait_for_finalized(sender_address, &client)
        .await?;

    let mut builder = client.transaction_builder(sender_address);
    builder.send_iota(recipient_address, amount);

    // The builder passes the signer the coins the transaction spends, so the
    // device shows the transfer instead of asking to blind-sign
    println!("Review and approve the transaction on the device");
    let effects = builder
        .execute(&signer, WaitForTransaction::Finalized)
        .await?;
    println!("Digest: {}", effects.digest());
    println!("Transaction status: {:?}", effects.as_v1().status);

    Ok(())
}
