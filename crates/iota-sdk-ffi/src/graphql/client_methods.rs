// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_sdk::{
    graphql_client::{Client, DryRunResult, WaitForTx},
    transaction_builder::ClientMethods,
    types::{Address, Digest, Object, ObjectId, Transaction, TransactionEffects, TypeTag, Version},
};

use crate::graphql::client::GraphQLClient;

impl ClientMethods for GraphQLClient {
    type Error = <Client as ClientMethods>::Error;
    type DryRunResult = DryRunResult;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        ClientMethods::object(&*self.0.read().await, object_id, version).await
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
        ClientMethods::objects(
            &*self.0.read().await,
            type_tag,
            owner,
            object_ids,
            ascending,
            cursor,
            limit,
        )
        .await
    }

    async fn gas_coins_page(
        &self,
        owner: Address,
        cursor: Option<String>,
    ) -> Result<(Vec<Object>, Option<String>), Self::Error> {
        ClientMethods::gas_coins_page(&*self.0.read().await, owner, cursor).await
    }

    async fn transaction(
        &self,
        digest: Digest,
    ) -> Result<Option<iota_sdk::types::SignedTransaction>, Self::Error> {
        ClientMethods::transaction(&*self.0.read().await, digest).await
    }

    async fn transaction_effects(
        &self,
        digest: Digest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        ClientMethods::transaction_effects(&*self.0.read().await, digest).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        ClientMethods::reference_gas_price(&*self.0.read().await, epoch).await
    }

    async fn estimate_tx_budget(&self, tx: &Transaction) -> Result<Option<u64>, Self::Error> {
        ClientMethods::estimate_tx_budget(&*self.0.read().await, tx).await
    }

    async fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        ClientMethods::dry_run_tx(&*self.0.read().await, tx, skip_checks).await
    }

    async fn execute_tx(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> Result<TransactionEffects, Self::Error> {
        ClientMethods::execute_tx(&*self.0.read().await, signatures, tx, wait_for).await
    }

    async fn wait_for_tx(&self, digest: Digest, wait_for: WaitForTx) -> Result<(), Self::Error> {
        ClientMethods::wait_for_tx(&*self.0.read().await, digest, wait_for).await
    }
}
