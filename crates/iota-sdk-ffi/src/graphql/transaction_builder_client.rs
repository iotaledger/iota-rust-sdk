// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::{
    graphql_client::{Client, DryRunResult, WaitForTransaction},
    transaction_builder::{ObjectsPage, ProtocolConfig, TransactionBuilderClient},
    types::{
        Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
        Version,
    },
};

use crate::{
    graphql::client::GraphQLClient,
    transaction_builder::{builder::TransactionBuilder, client_builder::ClientTransactionBuilder},
};

#[uniffi::export]
impl GraphQLClient {
    /// Create a new `TransactionBuilder` with the given sender address.
    pub fn transaction_builder(
        self: Arc<GraphQLClient>,
        sender: &crate::types::address::Address,
    ) -> ClientTransactionBuilder {
        TransactionBuilder::new(sender).with_client(self)
    }
}

impl TransactionBuilderClient for GraphQLClient {
    type Error = <Client as TransactionBuilderClient>::Error;
    type DryRunResult = DryRunResult;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        TransactionBuilderClient::object(&*self.0.read().await, object_id, version).await
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        TransactionBuilderClient::objects(&*self.0.read().await, struct_tag, owner, cursor, limit)
            .await
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        TransactionBuilderClient::protocol_config(&*self.0.read().await).await
    }

    async fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<iota_sdk::types::SignedTransaction>, Self::Error> {
        TransactionBuilderClient::transaction(&*self.0.read().await, digest).await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        TransactionBuilderClient::transaction_effects(&*self.0.read().await, digest).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderClient::reference_gas_price(&*self.0.read().await, epoch).await
    }

    async fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderClient::estimate_transaction_budget(&*self.0.read().await, transaction)
            .await
    }

    async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        TransactionBuilderClient::dry_run_transaction(
            &*self.0.read().await,
            transaction,
            skip_checks,
        )
        .await
    }

    async fn execute_transaction(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> Result<TransactionEffects, Self::Error> {
        TransactionBuilderClient::execute_transaction(
            &*self.0.read().await,
            signatures,
            transaction,
            wait_for,
        )
        .await
    }

    async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<(), Self::Error> {
        TransactionBuilderClient::wait_for_transaction(&*self.0.read().await, digest, wait_for)
            .await
    }
}
