// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of [`ClientMethods`] for the GraphQL [`Client`].

use iota_transaction_builder::{ClientMethods, WaitForTx};
use iota_types::{
    Address, Digest, Object, ObjectId, SignedTransaction, Transaction, TransactionEffects, TypeTag,
    UserSignature,
};

use crate::{
    Client, DryRunResult,
    pagination::{Direction, PaginationFilter},
    query_types::{ObjectFilter, TransactionMetadata},
};

impl ClientMethods for Client {
    type Error = crate::error::Error;
    type DryRunResult = DryRunResult;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<u64>>,
    ) -> Result<Option<Object>, Self::Error> {
        self.object(object_id, version).await
    }

    async fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> Result<Vec<Object>, Self::Error> {
        Ok(self
            .objects(
                ObjectFilter {
                    type_: type_tag.as_ref().map(ToString::to_string),
                    owner,
                    object_ids,
                },
                PaginationFilter {
                    direction: if ascending {
                        Direction::Forward
                    } else {
                        Direction::Backward
                    },
                    cursor,
                    limit: limit.map(|v| v as _),
                },
            )
            .await?
            .data)
    }

    async fn transaction(&self, digest: Digest) -> Result<Option<SignedTransaction>, Self::Error> {
        self.transaction(digest).await
    }

    async fn transaction_effects(
        &self,
        digest: Digest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        self.transaction_effects(digest).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        self.reference_gas_price(epoch).await
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        let res = self.dry_run_tx(tx, true).await?;
        Ok(res.effects.map(|e| e.gas_summary().gas_used()))
    }

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        let Transaction::V1(tx) = &tx else {
            unimplemented!("a new enum variant was added and needs to be handled")
        };
        let gas_objects = tx
            .gas_payment
            .objects
            .iter()
            .map(|r| crate::query_types::ObjectRef {
                address: r.object_id,
                digest: r.digest.to_base58(),
                version: r.version,
            })
            .collect::<Vec<_>>();
        self.dry_run_tx_kind(
            &tx.kind,
            skip_checks,
            TransactionMetadata {
                gas_budget: (tx.gas_payment.budget > 0).then_some(tx.gas_payment.budget),
                gas_objects: (!gas_objects.is_empty()).then_some(gas_objects),
                gas_price: Some(tx.gas_payment.price),
                gas_sponsor: Some(tx.gas_payment.owner),
                sender: Some(tx.sender),
            },
        )
        .await
    }

    async fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        self.execute_tx(signatures, tx, wait_for).await
    }

    async fn wait_for_tx(&self, digest: Digest, wait_for: WaitForTx) -> Result<(), Self::Error> {
        self.wait_for_tx(digest, wait_for, None).await
    }
}

#[cfg(test)]
mod tests {
    use eyre::Context;
    use iota_crypto::ed25519::Ed25519PrivateKey;
    use iota_transaction_builder::{TransactionBuilder, WaitForTx, assigned, error::Error};
    use iota_types::{
        Address, Digest, ExecutionStatus, IdOperation, MovePackageData, ObjectId, ObjectType,
        TransactionEffects, UpgradePolicy,
    };

    use crate::{
        Client,
        faucet::{CoinInfo, FaucetClient},
        pagination::PaginationFilter,
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
        tx.gas([gas]);

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
    async fn check_effects_status_success(effects: Result<TransactionEffects, Error>) {
        assert!(effects.is_ok(), "Execution failed. Effects: {effects:?}");
        // check that it succeeded
        let status = effects.unwrap();
        let expected_status = ExecutionStatus::Success;
        assert_eq!(&expected_status, status.status());
    }

    #[tokio::test]
    async fn test_transfer_obj_execution() {
        let (mut tx, _, pk, coins) = helper_setup().await;

        // get the object information from the client
        let client = Client::new_localnet();
        let coin = coins.first().unwrap().id;
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [coin]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

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

        let effects = tx.execute(&pk, WaitForTx::Indexed).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_split_transfer() {
        let client = Client::new_localnet();
        let (mut tx, _, pk, _) = helper_setup().await;

        // transfer 1 IOTA from Gas coin
        let gas = tx.get_gas()[0];
        tx.split_coins(gas, [1_000_000_000u64]).assign("coin");
        let recipient = Address::generate(rand::thread_rng());
        tx.transfer_objects(recipient, [assigned("coin")]);

        let effects = tx.execute(&pk, WaitForTx::Finalized).await;
        check_effects_status_success(effects).await;

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

        let effects = tx.execute(&pk, WaitForTx::Indexed).await.unwrap();

        let expected_status = ExecutionStatus::Success;
        // The tx failed, so we expect Failure instead of Success
        assert_ne!(&expected_status, effects.status());
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
        check_effects_status_success(effects).await;

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

        let effects = tx.execute(&pk, WaitForTx::Indexed).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_publish() {
        let (mut tx, address, pk, _) = helper_setup().await;

        let package = move_package_data("package_test_example_v1.json");
        tx.publish(package)
            .upgrade_cap("cap")
            .transfer_objects(address, [assigned("cap")]);

        let effects = tx.execute(&pk, WaitForTx::Indexed).await;
        check_effects_status_success(effects).await;
    }

    #[tokio::test]
    async fn test_upgrade() {
        let (mut tx, address, pk, coins) = helper_setup().await;

        let package = move_package_data("package_test_example_v2.json");
        tx.publish(package)
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
        check_effects_status_success(effects).await;

        let client = Client::new_localnet();
        let mut tx = TransactionBuilder::new(address).with_client(&client);
        let mut upgrade_cap = None;
        for o in created_objs {
            let obj = client.object(o, None).await.unwrap().unwrap();
            match obj.object_type() {
                ObjectType::Struct(x) if x.name() == "UpgradeCap" => {
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
            .assign("ticket");
        // now we can upgrade the package
        let receipt = tx
            .upgrade(package_id.unwrap(), updated_package, assigned("ticket"))
            .arg();

        // commit the upgrade
        tx.move_call(Address::FRAMEWORK, "package", "commit_upgrade")
            .arguments((upgrade_cap.unwrap(), receipt));

        tx.gas([coins.last().unwrap().id]);

        let effects = tx.execute(&pk, WaitForTx::Indexed).await;
        check_effects_status_success(effects).await;
    }
}
