// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    graphql_client::{Client, DryRunResult, WaitForTx},
    transaction_builder::{
        ObjectsPage, ProtocolConfig, TransactionBuilderRead, TransactionBuilderWrite,
    },
    types::{
        Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
        Version,
    },
};

use crate::graphql::client::GraphQLClient;

impl TransactionBuilderRead for GraphQLClient {
    type Error = <Client as TransactionBuilderRead>::Error;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        TransactionBuilderRead::object(&*self.0.read().await, object_id, version).await
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        TransactionBuilderRead::objects(&*self.0.read().await, struct_tag, owner, cursor, limit)
            .await
    }

    async fn transaction(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<iota_sdk::types::SignedTransaction>, Self::Error> {
        TransactionBuilderRead::transaction(&*self.0.read().await, digest).await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        TransactionBuilderRead::transaction_effects(&*self.0.read().await, digest).await
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        TransactionBuilderRead::protocol_config(&*self.0.read().await).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderRead::reference_gas_price(&*self.0.read().await, epoch).await
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderRead::estimate_tx_budget(&*self.0.read().await, tx).await
    }
}

impl TransactionBuilderWrite for GraphQLClient {
    type DryRunResult = DryRunResult;

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        TransactionBuilderWrite::dry_run_tx(&*self.0.read().await, tx, skip_checks).await
    }

    async fn execute_tx(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        TransactionBuilderWrite::execute_tx(&*self.0.read().await, signatures, tx, wait_for).await
    }

    async fn wait_for_tx(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTx,
    ) -> Result<(), Self::Error> {
        TransactionBuilderWrite::wait_for_tx(&*self.0.read().await, digest, wait_for).await
    }
}
