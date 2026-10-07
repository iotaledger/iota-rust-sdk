// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dry Run API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use iota_types::{Address, ObjectReference, Transaction, TransactionEffects, TransactionKind};

use crate::{
    DryRunEffect, DryRunResult, GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    query_types::{DryRunArgs, DryRunQueryFragment, ObjectRef, TransactionMetadata},
};

define_query! {
    /// Query for [`GraphQLClient::dry_run_transaction`]. Await it to send the
    /// request.
    pub struct DryRunTransactionQuery {
        client: GraphQLClient,
        transaction: Transaction,
        skip_checks: bool,
    }
    output: GraphQLResult<DryRunResult>;
}

impl DryRunTransactionQuery {
    /// Disable the usual verification checks that prevent access to objects
    /// that are owned by addresses other than the sender, and calling
    /// non-public, non-entry functions, and some other checks. Defaults to
    /// `false`.
    pub fn skip_checks(mut self, skip_checks: bool) -> Self {
        self.skip_checks = skip_checks;
        self
    }

    async fn send(self) -> GraphQLResult<DryRunResult> {
        let Transaction::V1(v1) = &self.transaction else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let gas_objects = v1.gas_payment.objects.clone();
        self.client
            .dry_run_transaction_kind(&v1.kind)
            .sender(v1.sender)
            .gas_budget(v1.gas_payment.budget)
            .gas_price(v1.gas_payment.price)
            .gas_objects((!gas_objects.is_empty()).then_some(gas_objects))
            .gas_sponsor(v1.gas_payment.owner)
            .skip_checks(self.skip_checks)
            .await
    }
}

define_query! {
    /// Query for [`GraphQLClient::dry_run_transaction_kind`]. Await it to send
    /// the request.
    pub struct DryRunTransactionKindQuery {
        client: GraphQLClient,
        transaction_kind: TransactionKind,
        transaction_metadata: TransactionMetadata,
        skip_checks: bool,
    }
    output: GraphQLResult<DryRunResult>;
}

impl DryRunTransactionKindQuery {
    /// Set the sender of the transaction.
    pub fn sender(mut self, sender: impl Into<Option<Address>>) -> Self {
        self.transaction_metadata.sender = sender.into();
        self
    }

    /// Set the gas budget of the transaction.
    pub fn gas_budget(mut self, gas_budget: impl Into<Option<u64>>) -> Self {
        self.transaction_metadata.gas_budget = gas_budget.into();
        self
    }

    /// Set the gas price of the transaction.
    pub fn gas_price(mut self, gas_price: impl Into<Option<u64>>) -> Self {
        self.transaction_metadata.gas_price = gas_price.into();
        self
    }

    /// Set the objects that pay for the gas.
    pub fn gas_objects(mut self, gas_objects: impl Into<Option<Vec<ObjectReference>>>) -> Self {
        self.transaction_metadata.gas_objects = gas_objects
            .into()
            .map(|objects| objects.into_iter().map(ObjectRef::from).collect());
        self
    }

    /// Set the sponsor that pays for the gas.
    pub fn gas_sponsor(mut self, gas_sponsor: impl Into<Option<Address>>) -> Self {
        self.transaction_metadata.gas_sponsor = gas_sponsor.into();
        self
    }

    /// Disable the usual verification checks that prevent access to objects
    /// that are owned by addresses other than the sender, and calling
    /// non-public, non-entry functions, and some other checks. Defaults to
    /// `false`.
    pub fn skip_checks(mut self, skip_checks: bool) -> Self {
        self.skip_checks = skip_checks;
        self
    }

    async fn send(self) -> GraphQLResult<DryRunResult> {
        let tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&self.transaction_kind)?);
        self.client
            .dry_run(tx_bytes, self.skip_checks, self.transaction_metadata)
            .await
    }
}

impl GraphQLClient {
    /// Dry run a [`Transaction`] and return the transaction effects and dry
    /// run error (if any).
    pub fn dry_run_transaction(&self, transaction: &Transaction) -> DryRunTransactionQuery {
        DryRunTransactionQuery {
            client: self.clone(),
            transaction: transaction.clone(),
            skip_checks: false,
        }
    }

    /// Dry run a [`TransactionKind`] and return the transaction effects and
    /// dry run error (if any).
    pub fn dry_run_transaction_kind(
        &self,
        transaction_kind: &TransactionKind,
    ) -> DryRunTransactionKindQuery {
        DryRunTransactionKindQuery {
            client: self.clone(),
            transaction_kind: transaction_kind.clone(),
            transaction_metadata: TransactionMetadata::default(),
            skip_checks: false,
        }
    }

    /// Internal implementation of the dry run API.
    pub(crate) async fn dry_run(
        &self,
        tx_bytes: String,
        skip_checks: bool,
        tx_meta: impl Into<Option<TransactionMetadata>>,
    ) -> GraphQLResult<DryRunResult> {
        let operation = DryRunQueryFragment::build(DryRunArgs {
            tx_bytes,
            skip_checks,
            tx_meta: tx_meta.into(),
        });
        let response = self.run_query(&operation).await?;

        // Convert DryRunEffect to DryRunEffect
        let results = response
            .dry_run_transaction_block
            .results
            .iter()
            .flatten()
            .map(DryRunEffect::try_from)
            .collect::<GraphQLResult<Vec<_>>>()?;

        let txn_block = &response.dry_run_transaction_block.transaction;

        let effects = txn_block
            .as_ref()
            .and_then(|tx| tx.effects.as_ref())
            .and_then(|tx| tx.bcs.as_ref())
            .map(|bcs| crate::error::decode_base64(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<TransactionEffects>(&bcs))
            .transpose()?;

        // Extract transaction
        let transaction = txn_block
            .as_ref()
            .and_then(|tx| tx.bcs_unsigned.as_ref())
            .map(|bcs| crate::error::decode_base64(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<Transaction>(&bcs))
            .transpose()?;

        let suggested_gas_price = response
            .dry_run_transaction_block
            .suggested_gas_price
            .map(u64::try_from)
            .transpose()?;

        Ok(DryRunResult {
            error: response.dry_run_transaction_block.error,
            results,
            transaction,
            effects,
            suggested_gas_price,
        })
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use base64ct::Encoding;
    use iota_types::{Address, ObjectDigest, ObjectId, ObjectReference, Transaction, Version};

    use crate::{
        GraphQLClient,
        test_utils::{sent_variables, test_transaction},
    };

    #[tokio::test]
    async fn dry_run_transaction_sends_the_kind_metadata_and_skip_checks() {
        let transaction = test_transaction();
        let Transaction::V1(v1) = &transaction else {
            unreachable!()
        };
        let expected_tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&v1.kind).unwrap());
        let vars = sent_variables("DryRunQueryFragment", |client| async move {
            let _ = client
                .dry_run_transaction(&transaction)
                .skip_checks(true)
                .await;
        })
        .await;
        assert_eq!(vars["txBytes"], expected_tx_bytes);
        assert_eq!(vars["skipChecks"], true);
        assert_eq!(vars["txMeta"]["sender"], Address::STD.to_string());
        assert_eq!(vars["txMeta"]["gasBudget"], 5_000_000);
        assert_eq!(vars["txMeta"]["gasPrice"], 1000);
        assert_eq!(vars["txMeta"]["gasSponsor"], Address::FRAMEWORK.to_string());
        let gas_object = &vars["txMeta"]["gasObjects"][0];
        assert_eq!(gas_object["address"], ObjectId::SYSTEM_STATE.to_string());
        assert_eq!(gas_object["version"], 3);
        assert_eq!(gas_object["digest"], ObjectDigest::ZERO.to_base58());

        let transaction = test_transaction();
        let vars = sent_variables("DryRunQueryFragment", |client| async move {
            let _ = client.dry_run_transaction(&transaction).await;
        })
        .await;
        assert_eq!(vars["skipChecks"], false);
    }

    #[tokio::test]
    async fn dry_run_transaction_kind_sends_the_kind_metadata_and_skip_checks() {
        let Transaction::V1(v1) = test_transaction() else {
            unreachable!()
        };
        let expected_tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&v1.kind).unwrap());
        let gas_object = ObjectReference::new(
            ObjectId::SYSTEM_STATE,
            Version::from_u64(3),
            ObjectDigest::ZERO,
        );
        let kind = v1.kind.clone();
        let vars = sent_variables("DryRunQueryFragment", |client| async move {
            let _ = client
                .dry_run_transaction_kind(&kind)
                .sender(Address::STD)
                .gas_budget(5_000_000)
                .gas_price(1000)
                .gas_objects(vec![gas_object])
                .gas_sponsor(Address::FRAMEWORK)
                .skip_checks(true)
                .await;
        })
        .await;
        assert_eq!(vars["txBytes"], expected_tx_bytes);
        assert_eq!(vars["skipChecks"], true);
        assert_eq!(vars["txMeta"]["sender"], Address::STD.to_string());
        assert_eq!(vars["txMeta"]["gasBudget"], 5_000_000);
        assert_eq!(vars["txMeta"]["gasPrice"], 1000);
        assert_eq!(vars["txMeta"]["gasSponsor"], Address::FRAMEWORK.to_string());
        let gas_object = &vars["txMeta"]["gasObjects"][0];
        assert_eq!(gas_object["address"], ObjectId::SYSTEM_STATE.to_string());
        assert_eq!(gas_object["version"], 3);
        assert_eq!(gas_object["digest"], ObjectDigest::ZERO.to_base58());

        let vars = sent_variables("DryRunQueryFragment", |client| async move {
            let _ = client.dry_run_transaction_kind(&v1.kind).await;
        })
        .await;
        assert_eq!(vars["skipChecks"], false);
        for field in [
            "sender",
            "gasBudget",
            "gasPrice",
            "gasObjects",
            "gasSponsor",
        ] {
            assert!(vars["txMeta"][field].is_null(), "{field} is set by default");
        }
    }

    // This needs the transaction builder to be able to be tested properly
    #[tokio::test]
    async fn test_dry_run() {
        let client = GraphQLClient::new_testnet().unwrap();
        let tx_bytes = "AAACAAgAypo7AAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgABAQAAAQEDAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACg9WqbvnpQmublI1+/dnonzEvhVPHnGEX++ianEHLIZmoiqRAAAAAAAgmrviNLnSJMjhRUZ8il2SFFjZ60cdJWv9v3M7pTsTQaA0FjZwX1JlYTftfc/+nF7J1QTfVacG+5wc2teKJoJHBDf/BgAAAAAAIOFdV7nQyvw+7AJpDmJFifAa4SqrI5qqXqAq1IKZsSxKVTI1Cd7yJVFzIqi4nnPX1ShmHEJWweFl5BId7OSkHXViNQ0AAAAAACA4U7t1jiQwTs87xenAvOkQWAAMWbElg0Exz1annhowtXPQJaMX5mcenWnm/aFAXhUM2rGsvqqa2zM2OOQyEKqbNP8GAAAAAAAg7pHVs4Z58mP71Y53cDuY3X/TbTgfmBHkDWe16J+kBOqhnfl+yRNiYZ3fpWvyc4rB2u+a2qjUGqcw7yFnlhJAj1w00w8AAAAAIDEjW30S0iN4lnDXpigCjEmOA0tUYKf339ZayYUU9PG6s1wmB/dndlMUdTZGe5MOz1baxXMESHbVd5L7XTObgECAQpEAAAAAACBCkCOAwD6Dl2DkdXj/eFRBTsNPWg3XYATTPxeThLuhzrTmcYf4XqT8ceMAoKbQBjtzyaTv+xb0K0MzHfvJR1NFgUKRAAAAAAAgxUVPvQUU/R1jcC2+AxZ7uC3ls+09G7xAk0xusdBSUkXPNNWDsV8xzw6ipjnf5pk9W3R9P0RD6iORRe+0JKaLtmE1DQAAAAAAIPhsUoriBlzhLc4SHds72JTbjeI37VhyjlFVtQurLY+26e+jqKb2TsdARpYEvxPl31WAelj2RMuUyK8S5NeluEWjKpEAAAAAACCR/0nc3l5UIXpl6I6SEpWABP/vJewHhZ5iMDpIDXdMqf0VCu+y2k/TZIpRFMDRiBO0oUW+L8+06uAi3pZkwpbFNf8GAAAAAAAgyIfExjdHxdt7+eiOLRh4N4/iSMZCrHf2t5iYI+Kl8ysAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgDAAAAAAAA4G88AAAAAAAA";

        client
            .dry_run(tx_bytes.to_string(), false, None)
            .await
            .map_err(|e| {
                format!(
                    "Dry run failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }
}
