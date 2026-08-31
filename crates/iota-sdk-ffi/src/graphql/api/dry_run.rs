// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dry run API implementation.

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient, output_types::DryRunResult, query_types::TransactionMetadata,
    },
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
    ) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_transaction(&transaction.0, skip_checks)
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
        transaction_metadata: TransactionMetadata,
        skip_checks: bool,
    ) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_transaction_kind(
                &transaction_kind.into(),
                skip_checks,
                transaction_metadata.into(),
            )
            .await?
            .into())
    }
}
