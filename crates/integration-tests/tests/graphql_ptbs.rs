// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use eyre::Context;
use iota_crypto::ed25519::Ed25519PrivateKey;
use iota_graphql_client::{
    Client, Direction,
    faucet::{CoinInfo, FaucetClient},
    pagination::PaginationFilter,
    query_types::SubscriptionEventFilter,
};
use iota_transaction_builder::{
    TransactionBuilder, WaitForTx, assigned, error::Error, unresolved::Argument,
};
use iota_types::{
    Address, ExecutionStatus, IdOperation, MovePackageData, ObjectId, ObjectType, Transaction,
    TransactionEffects, UpgradePolicy,
};

/// This is used to read the json file that contains the modules/deps/digest
/// generated with iota move build --dump-bytecode-as-base64 on the
/// `test_example_v1 and test_example_v2` projects in the tests
/// directory. The json files are generated automatically when running
/// `make test-with-localnet` in the root of the
/// iota-sdk-transaction-builder crate.
fn move_package_data(file: &str) -> MovePackageData {
    let data = std::fs::read_to_string(file)
        .with_context(|| {
            format!(
                "Failed to read {file}. \
                    Run `make test-with-localnet` from the root of the repository that will \
                    generate the right json files with the package data and then run the tests."
            )
        })
        .unwrap();
    serde_json::from_str(&data).unwrap()
}

/// Generate a random private key and its corresponding address
fn helper_address_pk() -> (Address, Ed25519PrivateKey) {
    let pk = Ed25519PrivateKey::random_with(rand::thread_rng());
    let address = pk.public_key().derive_address();
    (address, pk)
}

/// Helper to:
/// - generate a private key and its corresponding address
/// - set the sender for the tx to this newly created address
/// - set gas price
/// - set gas budget
/// - call faucet which returns 5 coin objects
/// - set the gas object (last coin from the list of the 5 objects returned by
///   faucet)
/// - return the address, private key, and coins.
///
/// NB! This assumes that these tests run on a network whose faucet returns
/// 5 coins per each faucet request.
async fn helper_setup() -> (
    TransactionBuilder<Client>,
    Address,
    Ed25519PrivateKey,
    Vec<CoinInfo>,
) {
    let (address, pk) = helper_address_pk();
    let client = Client::new_localnet();
    let mut tx = TransactionBuilder::new(address).with_client(client.clone());
    let coins = FaucetClient::new_localnet()
        .request_and_wait(address)
        .await
        .unwrap()
        .unwrap()
        .sent;
    let tx_digest = coins.first().unwrap().transfer_tx_digest;
    client
        .wait_for_tx(tx_digest, WaitForTx::Finalized, Duration::from_secs(60))
        .await
        .unwrap();

    let gas = coins.last().unwrap().id;
    tx.gas([gas]);

    (tx, address, pk, coins)
}

/// Check the effects to ensure the transaction was successfully executed.
fn check_effects_status_success(effects: Result<TransactionEffects, Error>) {
    assert!(effects.is_ok(), "Execution failed. Effects: {effects:?}");

    // check that it succeeded
    match effects.unwrap() {
        TransactionEffects::V1(v1) => {
            assert_eq!(ExecutionStatus::Success, v1.status);
        }
        _ => unimplemented!(
            "a new TransactionEffects enum variant was added and needs to be handled"
        ),
    };
}

#[tokio::test]
async fn test_transfer_obj_execution() {
    let (mut tx, _, pk, coins) = helper_setup().await;

    // get the object information from the client
    let client = Client::new_localnet();
    let coin = coins.first().unwrap().id;
    let recipient = Address::random_with(rand::thread_rng());
    tx.transfer_objects(recipient, [coin]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);

    // check that recipient has 1 coin
    let recipient_coins = client
        .coins(recipient, None, PaginationFilter::default())
        .await
        .unwrap();
    assert_eq!(recipient_coins.data().len(), 1);
}

#[tokio::test]
async fn test_move_call() {
    // Check that `0x1::option::is_none` move call works when passing `1`
    // set up the sender, gas object, gas budget, and gas price and return the pk to
    // sign
    let (mut tx, _, pk, _) = helper_setup().await;
    tx.move_call(Address::STD, "option", "is_none")
        .generics::<u64>()
        .arguments([Some(1u64)]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);
}

#[tokio::test]
async fn test_split_transfer() {
    let client = Client::new_localnet();
    let (mut tx, _, pk, _) = helper_setup().await;

    // transfer 1 IOTA from Gas coin
    let gas = tx.get_gas()[0];
    tx.split_coins(gas, [1_000_000_000u64]).assign("coin");
    let recipient = Address::random_with(rand::thread_rng());
    tx.transfer_objects(recipient, [assigned("coin")]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);

    // check that recipient has 1 coin
    let recipient_coins = client
        .coins(recipient, None, PaginationFilter::default())
        .await
        .unwrap();
    assert_eq!(recipient_coins.data().len(), 1);
}

#[tokio::test]
async fn test_split_without_transfer_should_fail() {
    let (mut tx, _, pk, coins) = helper_setup().await;

    let coin = coins.first().unwrap().id;

    // transfer 1 IOTA
    tx.split_coins(coin, [1_000_000_000u64]);

    match tx.execute(&pk, WaitForTx::Finalized).await.unwrap() {
        TransactionEffects::V1(v1) => {
            // The tx failed, so we expect Failure instead of Success
            assert_ne!(ExecutionStatus::Success, v1.status);
        }
        _ => unimplemented!(
            "a new TransactionEffects enum variant was added and needs to be handled"
        ),
    };
}

#[tokio::test]
async fn test_merge_coins() {
    let (mut tx, address, pk, coins) = helper_setup().await;

    let coin1 = coins.first().unwrap().id;

    let mut coins_to_merge = vec![];
    // last coin is used for gas, first coin is the one we merge into
    for c in coins[1..&coins.len() - 1].iter() {
        coins_to_merge.push(c.id);
    }

    tx.merge_coins(coin1, coins_to_merge);
    let client = tx.get_client().clone();

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);

    // check that there are two coins
    let coins_after = client
        .coins(address, None, PaginationFilter::default())
        .await
        .unwrap();
    assert_eq!(coins_after.data().len(), 2);
}

#[tokio::test]
async fn test_make_move_vec() {
    let (mut tx, _, pk, _) = helper_setup().await;

    tx.make_move_vec([1u64]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);
}

#[tokio::test]
async fn test_publish() {
    let (mut tx, address, pk, _) = helper_setup().await;

    let package = move_package_data("../package_test_example_v1.json");
    tx.publish_package(package)
        .upgrade_cap("cap")
        .transfer_objects(address, [assigned("cap")]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);
}

#[tokio::test]
async fn test_upgrade() {
    let (mut tx, address, pk, coins) = helper_setup().await;

    let package = move_package_data("../package_test_example_v2.json");
    tx.publish_package(package)
        .upgrade_cap("cap")
        .transfer_objects(address, [assigned("cap")]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    let mut package_id: Option<ObjectId> = None;
    let mut created_objs = vec![];
    if let Ok(ref effects) = effects {
        match effects {
            TransactionEffects::V1(e) => {
                for obj in e.changed_objects.clone() {
                    if obj.id_operation == IdOperation::Created {
                        let change = obj.output_state;
                        match change {
                            iota_types::ObjectOut::PackageWrite { .. } => {
                                package_id = Some(obj.object_id);
                            }
                            iota_types::ObjectOut::ObjectWrite { .. } => {
                                created_objs.push(obj.object_id);
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
    check_effects_status_success(effects);

    let client = Client::new_localnet();
    let mut tx = client.transaction_builder(address);
    let mut upgrade_cap = None;
    for o in created_objs {
        let obj = client.object(o, None).await.unwrap().unwrap();
        match obj.object_type() {
            ObjectType::Struct(x) if x.name() == "UpgradeCap" => {
                upgrade_cap = Some(obj.id());
                break;
            }
            _ => {}
        };
    }

    let updated_package = move_package_data("../package_test_example_v2.json");

    // we need this ticket to authorize the upgrade
    tx.move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
        .arguments((
            upgrade_cap.unwrap(),
            UpgradePolicy::Compatible as u8,
            updated_package.digest,
        ))
        .assign("ticket");
    // now we can upgrade the package
    let receipt = tx
        .upgrade(package_id.unwrap(), updated_package, assigned("ticket"))
        .result();

    // commit the upgrade
    tx.move_call(Address::FRAMEWORK, "package", "commit_upgrade")
        .arguments((upgrade_cap.unwrap(), receipt));

    tx.gas([coins.last().unwrap().id]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    check_effects_status_success(effects);
}

/// Fund the sender with ~2044 coins (via repeated `split_coins` — each
/// command tops out at 511 amounts, with one slot used by the source
/// coin), then run a plain `send_iota` and let auto gas selection deal
/// with the resulting fleet of gas coins.
#[tokio::test]
async fn test_auto_gas_selection_with_many_coins() {
    let (mut tx, sender, pk, coins) = helper_setup().await;
    let client = tx.get_client().clone();
    let source = coins.first().unwrap().id;

    const SPLITS_PER_CMD: usize = 511;
    const NUM_SPLIT_CMDS: usize = 4;

    for round in 0..NUM_SPLIT_CMDS {
        tx.split_coins(source, vec![1u64; SPLITS_PER_CMD]);
        let split_cmd = (round * 2) as u16;
        let outputs: Vec<Argument> = (0..SPLITS_PER_CMD as u16)
            .map(|i| Argument::NestedResult(split_cmd, i))
            .collect();
        tx.transfer_objects(sender, outputs);
    }
    check_effects_status_success(tx.execute(&pk, WaitForTx::Finalized).await);

    let mut tx2 = TransactionBuilder::new(sender).with_client(client);
    let recipient = Address::random_with(rand::thread_rng());
    tx2.send_iota(recipient, 1_000u64);
    check_effects_status_success(tx2.execute(&pk, WaitForTx::Finalized).await);
}

/// Pin all 255 gas coins (the protocol cap, `gas().len() <
/// max_gas_payment_objects = 256`) and assert the gas-smashing
/// prologue consolidates them into a single coin during execution.
#[tokio::test]
async fn test_manual_gas_pin_consolidates_255_coins() {
    let (mut tx, sender, pk, coins) = helper_setup().await;
    let client = tx.get_client().clone();

    // helper_setup pinned coins.last() as gas; split a different
    // faucet coin so the source isn't already reserved.
    let source = coins.first().unwrap().id;

    // 255 outputs fits in a single split_coins command (511-arg cap,
    // minus the source-coin slot). PER_COIN × 255 must fit in the
    // source coin and exceed the gas budget below.
    const NUM_GAS_COINS: usize = 255;
    const PER_COIN: u64 = 10_000_000;
    const GAS_BUDGET: u64 = 100_000_000;

    tx.split_coins(source, vec![PER_COIN; NUM_GAS_COINS]);
    tx.transfer_objects(
        sender,
        (0..NUM_GAS_COINS as u16)
            .map(|i| Argument::NestedResult(0, i))
            .collect::<Vec<_>>(),
    );
    check_effects_status_success(tx.execute(&pk, WaitForTx::Finalized).await);

    async fn list_coins(client: &Client, owner: Address) -> Vec<(ObjectId, u64)> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = client
                .coins(
                    owner,
                    None,
                    PaginationFilter {
                        direction: Direction::Forward,
                        cursor: cursor.clone(),
                        limit: None,
                    },
                )
                .await
                .unwrap();
            out.extend(page.data().iter().map(|c| (*c.id(), c.balance())));
            if !page.page_info().has_next_page {
                break;
            }
            cursor = page.page_info().end_cursor.clone();
        }
        out
    }

    let before = list_coins(&client, sender).await;
    let split_ids: Vec<ObjectId> = before
        .iter()
        .filter(|(_, b)| *b == PER_COIN)
        .take(NUM_GAS_COINS)
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        split_ids.len(),
        NUM_GAS_COINS,
        "expected {NUM_GAS_COINS} split coins; got {}",
        split_ids.len(),
    );

    let mut tx2 = TransactionBuilder::new(sender).with_client(client.clone());
    let recipient = Address::random_with(rand::thread_rng());
    tx2.gas(split_ids)
        .gas_budget(GAS_BUDGET)
        .send_iota(recipient, 1_000u64);
    check_effects_status_success(tx2.execute(&pk, WaitForTx::Finalized).await);

    // send_iota's output belongs to `recipient`, so the only delta on
    // sender's side is the 255 → 1 smashing.
    let before_count = before.len();
    let after_count = list_coins(&client, sender).await.len();
    let expected_drop = NUM_GAS_COINS - 1;
    assert_eq!(
        before_count - after_count,
        expected_drop,
        "expected sender's coin count to drop by {expected_drop} after smashing; \
             went from {before_count} to {after_count}",
    );
}

/// Mint 50 coins of 1 IOTA each — any single one trivially covers the
/// gas budget — and let auto gas selection resolve a fresh tx without
/// pinning gas. It should pin *every* coin from the first page (not just
/// the one minimally needed), so gas smashing can consolidate them into
/// a single coin during execution.
#[tokio::test]
async fn test_auto_gas_pins_full_first_page_for_consolidation() {
    let (mut tx, sender, pk, coins) = helper_setup().await;
    let client = tx.get_client().clone();
    let source = coins.first().unwrap().id;

    // 50 matches the default IOTA GraphQL `max_page_size`, so all newly
    // minted coins land on the first page even alongside the few
    // leftover faucet coins. 1 IOTA per coin is well above any
    // realistic gas budget for a `send_iota` of 1 nano.
    const NUM_COINS: usize = 50;
    const PER_COIN: u64 = 1_000_000_000;
    const GAS_BUDGET: u64 = 50_000_000;

    tx.split_coins(source, vec![PER_COIN; NUM_COINS]);
    tx.transfer_objects(
        sender,
        (0..NUM_COINS as u16)
            .map(|i| Argument::NestedResult(0, i))
            .collect::<Vec<_>>(),
    );
    check_effects_status_success(tx.execute(&pk, WaitForTx::Finalized).await);

    // Build (but don't execute) a fresh tx without pinning gas. The
    // resolved transaction reveals what auto-gas picked.
    let mut tx2 = TransactionBuilder::new(sender).with_client(client.clone());
    let recipient = Address::random_with(rand::thread_rng());
    tx2.gas_budget(GAS_BUDGET);
    tx2.send_iota(recipient, 1u64);
    let Transaction::V1(resolved) = tx2.finish().await.unwrap() else {
        panic!("expected TransactionV1");
    };
    // First page covers the budget many times over, so every gas coin
    // from that page (capped at the protocol max) is pinned, including
    // the 50 newly minted ones.
    assert!(
        resolved.gas_payment.objects.len() >= NUM_COINS,
        "auto-gas should pin every gas coin from the first page \
             so smashing consolidates them; pinned {}, expected at least {NUM_COINS}",
        resolved.gas_payment.objects.len(),
    );
}

/// Open a live transactions subscription and assert it delivers a transaction.
/// A transfer is executed on a background task once the subscription has had a
/// moment to connect, so the live stream observes it. This exercises the
/// WebSocket transport, payload decoding, and resume-cursor tracking shared by
/// `events_stream`.
#[tokio::test]
async fn test_transactions_subscription() {
    use futures::StreamExt;

    let client = Client::new_localnet();
    let mut stream = client.transactions_stream(None, None);

    tokio::spawn(async move {
        // Give the subscription time to connect before generating activity.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (mut tx, _, pk, _) = helper_setup().await;
        let gas = tx.get_gas()[0];
        tx.split_coins(gas, [1_000_000_000u64]).assign("coin");
        let recipient = Address::random_with(rand::thread_rng());
        tx.transfer_objects(recipient, [assigned("coin")]);
        let _ = tx.execute(&pk, WaitForTx::Finalized).await;
    });

    let item = tokio::time::timeout(Duration::from_secs(120), stream.next())
        .await
        .expect("timed out waiting for a transaction from the subscription");
    assert!(
        matches!(item, Some(Ok(_))),
        "expected a transaction from the subscription, got {item:?}"
    );
}

/// Open a live events subscription and assert it delivers the
/// `0x3::validator::StakingRequestEvent` emitted by a staking transaction that
/// runs on a background task once the subscription has had a moment to connect.
/// The filter is set at package level, so other `0x3` events (epoch changes)
/// are skipped until the staking event arrives.
#[tokio::test]
async fn test_events_subscription() {
    use futures::StreamExt;

    let client = Client::new_localnet();
    let filter = SubscriptionEventFilter::default().with_emitting_module("0x3".to_owned());
    let mut stream = client.events_stream(filter, None);

    tokio::spawn(async move {
        // Give the subscription time to connect before generating activity.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let validator = Client::new_localnet()
            .active_validators(None, PaginationFilter::default())
            .await
            .unwrap()
            .data()
            .first()
            .expect("localnet runs at least one validator")
            .address
            .address;
        let (mut tx, _, pk, _) = helper_setup().await;
        tx.stake(1_000_000_000u64, validator);
        let _ = tx.execute(&pk, WaitForTx::Finalized).await;
    });

    let event = tokio::time::timeout(Duration::from_secs(120), async {
        while let Some(item) = stream.next().await {
            let event = item.expect("the events subscription returned an error");
            if event
                .type_
                .repr
                .ends_with("::validator::StakingRequestEvent")
            {
                return event;
            }
        }
        panic!("the events subscription ended without a staking event");
    })
    .await
    .expect("timed out waiting for a staking event from the subscription");

    assert!(!event.bcs.0.is_empty(), "staking event carries no bcs");
}

#[tokio::test]
async fn test_move_view_call() {
    let (mut tx, address, pk, _) = helper_setup().await;

    let package = move_package_data("../package_test_example_v1.json");
    tx.publish_package(package)
        .upgrade_cap("cap")
        .transfer_objects(address, [assigned("cap")]);

    let effects = tx.execute(&pk, WaitForTx::Finalized).await;
    let mut package_id: Option<ObjectId> = None;
    if let Ok(ref effects) = effects {
        match effects {
            TransactionEffects::V1(e) => {
                for obj in e.changed_objects.clone() {
                    if obj.id_operation == IdOperation::Created
                        && matches!(obj.output_state, iota_types::ObjectOut::PackageWrite { .. })
                    {
                        package_id = Some(obj.object_id);
                    }
                }
            }
            _ => unimplemented!("a new enum variant was added and needs to be handled"),
        }
    }
    check_effects_status_success(effects);

    let client = Client::new_localnet();
    let function = format!("{}::test_example::double", package_id.unwrap());

    let assert_doubled = |result: iota_graphql_client::query_types::MoveViewResult| {
        assert_eq!(
            result.error, None,
            "Move view call should not return an error"
        );
        let results = result
            .results
            .expect("Move view call should return results");
        assert_eq!(
            results.len(),
            1,
            "Move view call should return exactly one result"
        );
        // u64 return values are JSON-encoded as strings to avoid precision loss
        let value = results[0]
            .as_u64()
            .or_else(|| results[0].as_str().and_then(|s| s.parse().ok()))
            .expect("Result should be a u64");
        assert_eq!(value, 42);
    };

    // Typed arguments
    let result = client
        .move_view_call(&function, None, (21u64,))
        .await
        .unwrap();
    assert_doubled(result);

    // Raw JSON arguments
    let result = client
        .move_view_call_json(&function, None, Some(vec![serde_json::json!("21")]))
        .await
        .unwrap();
    assert_doubled(result);
}
