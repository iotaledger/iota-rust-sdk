// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Provides tools to simplify usage of the IOTA SDK.

#![warn(missing_docs)]
#![deny(unreachable_pub)]

pub mod builder;
pub mod error;
pub mod types;
#[allow(missing_docs)]
pub mod unresolved;

pub use self::{
    builder::{
        TransactionBuilder,
        client_methods::ClientMethods,
        ptb_arguments::{PTBArgument, PTBArgumentList, Receiving, Shared, SharedMut, res},
    },
    types::PureBytes,
};

#[cfg(test)]
mod tests {
    use eyre::Context;
    use iota_crypto::ed25519::Ed25519PrivateKey;
    use iota_graphql_client::{
        Client,
        faucet::{CoinInfo, FaucetClient},
        pagination::PaginationFilter,
    };
    use iota_types::{
        Address, Digest, ExecutionStatus, IdOperation, MovePackageData, ObjectId, ObjectReference,
        ObjectType, TransactionEffects, UpgradePolicy,
    };

    use crate::{TransactionBuilder, error::Error, res};

    /// This is used to read the json file that contains the modules/deps/digest
    /// generated with iota move build --dump-bytecode-as-base64 on the
    /// `test_example_v1 and test_example_v2` projects in the tests
    /// directory. The json files are generated automatically when running
    /// `make test-with-localnet` in the root of the
    /// iota-transaction-builder crate.
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
        let pk = Ed25519PrivateKey::generate(rand::thread_rng());
        let address = pk.public_key().derive_address();
        (address, pk)
    }

    /// Helper to:
    /// - generate a private key and its corresponding address
    /// - set the sender for the tx to this newly created address
    /// - set gas price
    /// - set gas budget
    /// - call faucet which returns 5 coin objects
    /// - set the gas object (last coin from the list of the 5 objects returned
    ///   by faucet)
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
        wait_for_tx(&client, tx_digest).await;

        let gas = coins.last().unwrap().id;
        tx.gas(gas);

        (tx, address, pk, coins)
    }

    /// Wait for the transaction to be finalized and indexed. This queries the
    /// GraphQL server until it retrieves the requested transaction.
    async fn wait_for_tx(client: &Client, digest: Digest) {
        while client.transaction(digest).await.unwrap().is_none() {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// Wait for the transaction to be finalized and indexed, and check the
    /// effects' to ensure the transaction was successfully executed.
    async fn wait_for_tx_and_check_effects_status_success(
        effects: Result<Option<TransactionEffects>, Error>,
    ) {
        assert!(effects.is_ok(), "Execution failed. Effects: {effects:?}");
        // check that it succeeded
        let status = effects.unwrap();
        let expected_status = ExecutionStatus::Success;
        assert_eq!(&expected_status, status.as_ref().unwrap().status());
    }

    #[tokio::test]
    async fn test_finish() {
        let mut tx = TransactionBuilder::new(
            "0xc574ea804d9c1a27c886312e96c0e2c9cfd71923ebaeb3000d04b5e65fca2793"
                .parse()
                .unwrap(),
        );
        let coin_obj_id = "0x19406ea4d9609cd9422b85e6bf2486908f790b778c757aff805241f3f609f9b4";
        let coin_digest = "7opR9rFUYivSTqoJHvFb9p6p54THyHTatMG6id4JKZR9";
        let coin_version = 2;
        let coin = ObjectReference::new(
            coin_obj_id.parse().unwrap(),
            coin_version,
            coin_digest.parse().unwrap(),
        );

        let recipient = Address::generate(rand::thread_rng());

        let result = tx.clone().finish();
        assert!(result.is_err());

        tx.transfer_objects(recipient, vec![coin]);
        tx.gas(ObjectReference::new(
            "0xd8792bce2743e002673752902c0e7348dfffd78638cb5367b0b85857bceb9821"
                .parse()
                .unwrap(),
            2,
            "2ZigdvsZn5BMeszscPQZq9z8ebnS2FpmAuRbAi9ednCk"
                .parse()
                .unwrap(),
        ));
        tx.gas_price(1000);

        tx.finish().unwrap();
    }

    #[tokio::test]
    async fn test_transfer_obj_execution() {
        let (mut tx, _, pk, coins) = helper_setup().await;

        // get the object information from the client
        let client = Client::new_localnet();
        let coin = coins.first().unwrap().id;
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [coin]);

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;

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
        tx.move_call(Address::STD_LIB, "option", "is_none")
            .generics::<u64>()
            .arguments([Some(1u64)]);

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_split_transfer() {
        let client = Client::new_localnet();
        let (mut tx, _, pk, _) = helper_setup().await;

        // transfer 1 IOTA from Gas coin
        let gas = tx.get_gas()[0];
        tx.split_coins(gas, [1_000_000_000u64]).name("coin");
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [res("coin")]);

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;

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

        let effects = tx.execute(&pk.into(), true).await.unwrap();

        let expected_status = ExecutionStatus::Success;
        // The tx failed, so we expect Failure instead of Success
        assert_ne!(&expected_status, effects.as_ref().unwrap().status());
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

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;

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

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_publish() {
        let (mut tx, address, pk, _) = helper_setup().await;

        let package = move_package_data("package_test_example_v1.json");
        tx.publish(package)
            .upgrade_cap("cap")
            .transfer_objects(address, [res("cap")]);

        let effects = tx.execute(&pk.into(), true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_upgrade() {
        let (mut tx, address, pk, coins) = helper_setup().await;
        let key = pk.into();

        let package = move_package_data("package_test_example_v2.json");
        tx.publish(package)
            .upgrade_cap("cap")
            .transfer_objects(address, [res("cap")]);

        let effects = tx.execute(&key, true).await;
        let mut package_id: Option<ObjectId> = None;
        let mut created_objs = vec![];
        if let Ok(Some(ref effects)) = effects {
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
            }
        }
        wait_for_tx_and_check_effects_status_success(effects).await;

        let client = Client::new_localnet();
        let mut tx = TransactionBuilder::new(address).with_client(&client);
        let mut upgrade_cap = None;
        for o in created_objs {
            let obj = client.object(o, None).await.unwrap().unwrap();
            match obj.object_type() {
                ObjectType::Struct(x) if x.name.to_string() == "UpgradeCap" => {
                    upgrade_cap = Some(obj.object_id());
                    break;
                }
                _ => {}
            };
        }

        let updated_package = move_package_data("package_test_example_v2.json");

        // we need this ticket to authorize the upgrade
        tx.move_call(Address::FRAMEWORK, "package", "authorize_upgrade")
            .arguments((
                upgrade_cap.unwrap(),
                UpgradePolicy::Compatible as u8,
                updated_package.digest,
            ))
            .name("ticket");
        // now we can upgrade the package
        let receipt = tx
            .upgrade(package_id.unwrap(), res("ticket"), updated_package)
            .arg();

        // commit the upgrade
        tx.move_call(Address::FRAMEWORK, "package", "commit_upgrade")
            .arguments((upgrade_cap.unwrap(), receipt));

        tx.gas(coins.last().unwrap().id);

        let effects = tx.execute(&key, true).await;
        wait_for_tx_and_check_effects_status_success(effects).await;
    }
}
