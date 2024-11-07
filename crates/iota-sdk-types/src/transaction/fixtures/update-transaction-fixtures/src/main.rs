// Copyright (c) 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Update the fixtures for the transaction_fixtures() test.
//! For this to work, have the `iota` repo next to `iota-rust-sdk` and in
//! the iota repo checkout to the branch for which the fixtures should be
//! created.
//!
//! cargo run

use std::{fs::OpenOptions, io::Write};

use fastcrypto::encoding::{Base64, Encoding};
use futures::StreamExt;
use iota_json_rpc_types::{
    IotaEndOfEpochTransactionKind, IotaTransactionBlockDataAPI, IotaTransactionBlockKind,
    IotaTransactionBlockResponseOptions, IotaTransactionBlockResponseQuery,
};
use iota_types::transaction::SenderSignedData;
use test_cluster::TestClusterBuilder;

const BASE_PATH: &str = "../";

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let test_cluster = TestClusterBuilder::new().build().await;
    let client = test_cluster.wallet.get_client().await?;

    // Build a PTB
    let address = test_cluster.get_address_0();
    let object_refs = client
        .read_api()
        .get_owned_objects(address, None, None, None)
        .await?;
    let gas_coin = object_refs.data.first().unwrap().object()?.object_id;
    let ptb_tx_data = client
        .transaction_builder()
        .split_coin(address, gas_coin, vec![1_000_000], None, 1_000_000)
        .await?;
    write_bs64_tx_to_file(&bcs::to_bytes(&ptb_tx_data)?, "ptb")?;

    // Force new epoch so we get a change epoch tx
    test_cluster.force_new_epoch().await;

    let mut txs = client
        .read_api()
        .get_transactions_stream(
            IotaTransactionBlockResponseQuery::new(
                None,
                Some(
                    IotaTransactionBlockResponseOptions::new()
                        .with_raw_input()
                        .with_input(),
                ),
            ),
            None,
            // Starts with the genesis tx
            false,
        )
        .boxed();

    let mut got_consensus_commit_prologue_v1 = false;
    let mut got_epoch_change = false;
    let mut got_genesis = false;

    while let Some(tx) = txs.next().await {
        let transaction = tx.transaction.as_ref().expect(
            "Missing tx in response, add .with_input() to IotaTransactionBlockResponseOptions",
        );
        match transaction.data.transaction() {
            IotaTransactionBlockKind::Genesis(_genesis_transaction) => {
                if !got_genesis {
                    write_bs64_tx_to_file(
                        &raw_tx_bytes_to_transaction_data_bytes(&tx.raw_transaction)?,
                        "genesis",
                    )?;
                    got_genesis = true;
                }
            }
            IotaTransactionBlockKind::ConsensusCommitPrologueV1(_consensus_commit_prologue) => {
                if !got_consensus_commit_prologue_v1 {
                    write_bs64_tx_to_file(
                        &raw_tx_bytes_to_transaction_data_bytes(&tx.raw_transaction)?,
                        "consensus-commit-prologue-v1",
                    )?;
                    got_consensus_commit_prologue_v1 = true;
                }
            }
            IotaTransactionBlockKind::EndOfEpochTransaction(end_of_epoch_tx) => {
                for tx_kind in &end_of_epoch_tx.transactions {
                    if let IotaEndOfEpochTransactionKind::ChangeEpoch(_change_epoch) = tx_kind {
                        if !got_epoch_change {
                            write_bs64_tx_to_file(
                                &raw_tx_bytes_to_transaction_data_bytes(&tx.raw_transaction)?,
                                "change-epoch",
                            )?;
                            got_epoch_change = true;
                        }
                    }
                }
            }
            _ => {} // We don't care about other types for now
        }
        // Break if we got all types
        if got_consensus_commit_prologue_v1 && got_epoch_change && got_genesis {
            break;
        }
    }

    if !(got_consensus_commit_prologue_v1 && got_epoch_change && got_genesis) {
        panic!(
            "Didn't get all transaction types: consensus_commit_prologue_v1: {got_consensus_commit_prologue_v1}, epoch_change: {got_epoch_change}, genesis: {got_genesis}"
        );
    }

    Ok(())
}

// Write the tx data bytes base64 encoded to a file with the BASE_PATH before
// the provided name
fn write_bs64_tx_to_file(tx_data_bytes: &[u8], name: &str) -> Result<(), anyhow::Error> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(format!("{BASE_PATH}{name}"))?;
    f.write_all(Base64::encode(tx_data_bytes).as_bytes())?;
    f.flush()?;
    Ok(())
}

fn raw_tx_bytes_to_transaction_data_bytes(raw_tx_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let sender_signed_data: SenderSignedData = bcs::from_bytes(raw_tx_bytes)?;
    let tx_data = sender_signed_data.transaction_data();
    let tx_data_bytes = bcs::to_bytes(tx_data)?;
    Ok(tx_data_bytes)
}
