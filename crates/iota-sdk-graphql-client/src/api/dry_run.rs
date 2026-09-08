// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dry Run API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use iota_types::{SignedTransaction, Transaction, TransactionEffects, TransactionKind};

use crate::{
    Client, DryRunEffect, DryRunResult,
    error::GraphQLResult,
    query_types::{DryRunArgs, DryRunQuery, ObjectRef, TransactionMetadata},
};

impl Client {
    /// Dry run a [`Transaction`] and return the transaction effects and dry
    /// run error (if any).
    ///
    /// The `skip_checks` flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks.
    pub async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> GraphQLResult<DryRunResult> {
        let Transaction::V1(v1) = transaction else {
            unimplemented!("a new Transaction enum variant was added and needs to be handled")
        };
        let gas_objects = v1
            .gas_payment
            .objects
            .iter()
            .map(|r| ObjectRef {
                address: *r.object_id(),
                version: r.version().as_u64(),
                digest: r.digest().to_base58(),
            })
            .collect::<Vec<_>>();
        self.dry_run_transaction_kind(
            &v1.kind,
            skip_checks,
            TransactionMetadata {
                gas_budget: Some(v1.gas_payment.budget),
                gas_objects: (!gas_objects.is_empty()).then_some(gas_objects),
                gas_price: Some(v1.gas_payment.price),
                gas_sponsor: Some(v1.gas_payment.owner),
                sender: Some(v1.sender),
            },
        )
        .await
    }

    /// Dry run a [`TransactionKind`] and return the transaction effects and dry
    /// run error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    ///
    /// `transaction_metadata` is the transaction metadata.
    pub async fn dry_run_transaction_kind(
        &self,
        transaction_kind: &TransactionKind,
        skip_checks: bool,
        transaction_metadata: TransactionMetadata,
    ) -> GraphQLResult<DryRunResult> {
        let tx_bytes = base64ct::Base64::encode_string(&bcs::to_bytes(&transaction_kind)?);
        self.dry_run(tx_bytes, skip_checks, Some(transaction_metadata))
            .await
    }

    /// Internal implementation of the dry run API.
    pub(crate) async fn dry_run(
        &self,
        tx_bytes: String,
        skip_checks: bool,
        tx_meta: impl Into<Option<TransactionMetadata>>,
    ) -> GraphQLResult<DryRunResult> {
        let operation = DryRunQuery::build(DryRunArgs {
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
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<TransactionEffects>(&bcs))
            .transpose()?;

        // Extract transaction
        let transaction = txn_block
            .as_ref()
            .and_then(|tx| tx.bcs.as_ref())
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<SignedTransaction>(&bcs))
            .transpose()?;

        Ok(DryRunResult {
            error: response.dry_run_transaction_block.error,
            results,
            transaction,
            effects,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Client;

    // This needs the transaction builder to be able to be tested properly
    #[tokio::test]
    async fn test_dry_run() {
        let client = Client::new_testnet();
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
