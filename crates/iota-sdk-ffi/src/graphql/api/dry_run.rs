// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dry run API implementation.

use iota_sdk::graphql_client::query_types::ServiceConfig;

use crate::{
    error::{Result, SdkFfiError},
    graphql::{
        client::GraphQLClient, output_types::DryRunResult, query_types::TransactionMetadata,
    },
    types::transaction::{Transaction, TransactionKind},
};

#[derive(Debug, uniffi::Record, serde::Serialize)]
pub struct Query {
    pub query: String,
    #[uniffi(default = None)]
    #[serde(default)]
    pub variables: Option<serde_json::Value>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    // ===========================================================================
    // Dry Run API
    // ===========================================================================

    /// Dry run a `Transaction` and return the transaction effects and dry run
    /// error (if any).
    ///
    /// `skipChecks` optional flag disables the usual verification checks that
    /// prevent access to objects that are owned by addresses other than the
    /// sender, and calling non-public, non-entry functions, and some other
    /// checks. Defaults to false.
    #[uniffi::method(default(skip_checks = false))]
    pub async fn dry_run_tx(&self, tx: &Transaction, skip_checks: bool) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_tx(&tx.0, skip_checks)
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
    /// `tx_meta` is the transaction metadata.
    #[uniffi::method(default(skip_checks = false))]
    pub async fn dry_run_tx_kind(
        &self,
        tx_kind: &TransactionKind,
        tx_meta: TransactionMetadata,
        skip_checks: bool,
    ) -> Result<DryRunResult> {
        Ok(self
            .0
            .read()
            .await
            .dry_run_tx_kind(&tx_kind.0, skip_checks, tx_meta.into())
            .await?
            .into())
    }

    /// Run a query.
    pub async fn run_query(&self, query: Query) -> Result<serde_json::Value> {
        self.0
            .read()
            .await
            .run_query_from_json(
                serde_json::to_value(query)?
                    .as_object()
                    .ok_or_else(|| SdkFfiError::custom("invalid json; must be a map"))?
                    .clone(),
            )
            .await?
            .data
            .ok_or_else(|| SdkFfiError::custom("query yielded no data"))
    }

    /// Get the GraphQL service configuration, including complexity limits, read
    /// and mutation limits, supported versions, and others.
    pub async fn service_config(&self) -> Result<ServiceConfig> {
        Ok(self.0.read().await.service_config().await?.clone())
    }
}
