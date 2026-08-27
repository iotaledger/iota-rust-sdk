// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::{
    graphql_client::{Client, DryRunResult, WaitForTx},
    transaction_builder::{
        ObjectsPage, ProtocolConfig, TransactionBuilderClientBase,
        TransactionBuilderExecutionClient, TransactionBuilderLedgerClient,
        TransactionBuilderSimulationClient,
    },
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

impl TransactionBuilderClientBase for GraphQLClient {
    type Error = <Client as TransactionBuilderClientBase>::Error;
}

impl TransactionBuilderLedgerClient for GraphQLClient {
    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        TransactionBuilderLedgerClient::object(&*self.0.read().await, object_id, version).await
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        TransactionBuilderLedgerClient::objects(
            &*self.0.read().await,
            struct_tag,
            owner,
            cursor,
            limit,
        )
        .await
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        TransactionBuilderLedgerClient::protocol_config(&*self.0.read().await).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderLedgerClient::reference_gas_price(&*self.0.read().await, epoch).await
    }
}

impl TransactionBuilderSimulationClient for GraphQLClient {
    type DryRunResult = DryRunResult;

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderSimulationClient::estimate_tx_budget(&*self.0.read().await, tx).await
    }

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        TransactionBuilderSimulationClient::dry_run_tx(&*self.0.read().await, tx, skip_checks).await
    }
}

impl TransactionBuilderExecutionClient for GraphQLClient {
    async fn execute_tx(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        TransactionBuilderExecutionClient::execute_tx(
            &*self.0.read().await,
            signatures,
            tx,
            wait_for,
        )
        .await
    }

    async fn wait_for_tx(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> Result<(), Self::Error> {
        TransactionBuilderExecutionClient::wait_for_tx(&*self.0.read().await, digest, wait_for)
            .await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        TransactionBuilderExecutionClient::transaction_effects(&*self.0.read().await, digest).await
    }
}
