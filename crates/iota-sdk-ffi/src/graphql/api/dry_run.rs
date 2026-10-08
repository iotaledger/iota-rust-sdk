// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dry run API implementation.

use iota_sdk::graphql_client::DryRunTransactionKindQuery;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient, output_types::GraphQLDryRunResult,
        query_types::GraphQLTransactionMetadata,
    },
    helpers::SetIfSome,
    types::transaction::{Transaction, TransactionKind},
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Dry run a `Transaction` and return the transaction effects and dry run
    /// error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    #[uniffi::method(default(skip_checks = false))]
    pub async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> Result<GraphQLDryRunResult> {
        Ok(self
            .client()
            .dry_run_transaction(&transaction.0)
            .skip_checks(skip_checks)
            .await?
            .into())
    }

    /// Dry run a `TransactionKind` and return the transaction effects and dry
    /// run error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    ///
    /// `transaction_metadata` is the transaction metadata.
    #[uniffi::method(default(skip_checks = false))]
    pub async fn dry_run_transaction_kind(
        &self,
        transaction_kind: TransactionKind,
        transaction_metadata: GraphQLTransactionMetadata,
        skip_checks: bool,
    ) -> Result<GraphQLDryRunResult> {
        let metadata: iota_sdk::graphql_client::query_types::TransactionMetadata =
            transaction_metadata.into();
        let gas_objects = metadata
            .gas_objects
            .map(|objects| {
                objects
                    .into_iter()
                    .map(|object| {
                        Ok(iota_sdk::types::ObjectReference::new(
                            object.address,
                            iota_sdk::types::Version::from_u64(object.version),
                            iota_sdk::types::ObjectDigest::from_base58(&object.digest)?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;
        Ok(self
            .client()
            .dry_run_transaction_kind(&transaction_kind.into())
            .set_if_some(metadata.sender, DryRunTransactionKindQuery::sender)
            .set_if_some(metadata.gas_budget, DryRunTransactionKindQuery::gas_budget)
            .set_if_some(metadata.gas_price, DryRunTransactionKindQuery::gas_price)
            .set_if_some(gas_objects, DryRunTransactionKindQuery::gas_objects)
            .set_if_some(
                metadata.gas_sponsor,
                DryRunTransactionKindQuery::gas_sponsor,
            )
            .skip_checks(skip_checks)
            .await?
            .into())
    }
}
