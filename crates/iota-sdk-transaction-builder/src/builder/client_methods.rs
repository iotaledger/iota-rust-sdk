// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::{
    DryRunResult, WaitForTx,
    pagination::{Direction, PaginationFilter},
    query_types::ObjectFilter,
};
use iota_types::{
    Address, Digest, Object, ObjectId, SignedTransaction, StructTag, Transaction,
    TransactionEffects, TypeTag, UserSignature, Version,
};

/// A trait which defines methods needed from the client for the Transaction
/// Builder.
pub trait ClientMethods {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;
    /// The result of a dry run.
    type DryRunResult;

    /// Fetch an object
    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>>;

    /// Fetch objects
    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>>;

    /// Fetch one page of gas-coin objects owned by `owner`, returning the
    /// page contents and a cursor for the next page (when one exists).
    ///
    /// Used by the transaction builder's automatic gas-payment selection to
    /// page through gas coins, stopping once cumulative balance meets the
    /// target budget. The default implementation falls back to
    /// [`Self::objects`] and reports no next cursor; clients with native
    /// pagination support should override it.
    fn gas_coins_page(
        &self,
        owner: Address,
        cursor: Option<String>,
    ) -> impl std::future::Future<Output = Result<(Vec<Object>, Option<String>), Self::Error>> {
        async move {
            let objects = self
                .objects(
                    Some(StructTag::new_gas_coin().into()),
                    Some(owner),
                    None,
                    true,
                    cursor,
                    None,
                )
                .await?;
            Ok((objects, None))
        }
    }

    /// Fetch a transaction
    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>>;

    /// Fetch transaction effects
    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>>;

    /// Get the reference gas price
    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    /// Estimate the gas budget needed for a transaction
    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    /// Dry run a transaction
    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>>;

    /// Execute a transaction
    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>>;

    /// Wait for the indexing or finalization of a transaction by its digest.
    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>>;
}

impl<T: ClientMethods> ClientMethods for &T {
    type Error = T::Error;
    type DryRunResult = T::DryRunResult;

    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        (*self).object(object_id, version)
    }

    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>> {
        (*self).objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn gas_coins_page(
        &self,
        owner: Address,
        cursor: Option<String>,
    ) -> impl std::future::Future<Output = Result<(Vec<Object>, Option<String>), Self::Error>> {
        (*self).gas_coins_page(owner, cursor)
    }

    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        (*self).transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        (*self).transaction_effects(digest)
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).reference_gas_price(epoch)
    }

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        (*self).estimate_tx_budget(tx)
    }

    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        (*self).dry_run_tx(tx, skip_checks)
    }

    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        (*self).execute_tx(signatures, tx, wait_for)
    }

    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        (*self).wait_for_tx(digest, wait_for)
    }
}

impl ClientMethods for iota_graphql_client::Client {
    type Error = iota_graphql_client::error::Error;
    type DryRunResult = DryRunResult;

    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
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

    async fn gas_coins_page(
        &self,
        owner: Address,
        cursor: Option<String>,
    ) -> Result<(Vec<Object>, Option<String>), Self::Error> {
        let page = self
            .objects(
                ObjectFilter {
                    type_: Some(StructTag::new_gas_coin().to_string()),
                    owner: Some(owner),
                    object_ids: None,
                },
                PaginationFilter {
                    direction: Direction::Forward,
                    cursor,
                    limit: None,
                },
            )
            .await?;
        let (page_info, data) = page.into_parts();
        let next = page_info
            .has_next_page
            .then_some(page_info.end_cursor)
            .flatten();
        Ok((data, next))
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
        (*self).dry_run_tx(tx, skip_checks).await
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

impl<T: ClientMethods> ClientMethods for std::sync::Arc<T> {
    type Error = T::Error;
    type DryRunResult = T::DryRunResult;

    fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> impl std::future::Future<Output = Result<Option<Object>, Self::Error>> {
        self.as_ref().object(object_id, version)
    }

    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<String>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<Object>, Self::Error>> {
        self.as_ref()
            .objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn gas_coins_page(
        &self,
        owner: Address,
        cursor: Option<String>,
    ) -> impl std::future::Future<Output = Result<(Vec<Object>, Option<String>), Self::Error>> {
        self.as_ref().gas_coins_page(owner, cursor)
    }

    fn transaction(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<SignedTransaction>, Self::Error>> {
        self.as_ref().transaction(digest)
    }

    fn transaction_effects(
        &self,
        digest: Digest,
    ) -> impl std::future::Future<Output = Result<Option<TransactionEffects>, Self::Error>> {
        self.as_ref().transaction_effects(digest)
    }

    fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().reference_gas_price(epoch)
    }

    fn estimate_tx_budget(
        &self,
        tx: &Transaction,
    ) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>> {
        self.as_ref().estimate_tx_budget(tx)
    }

    fn dry_run_tx(
        &self,
        tx: &Transaction,
        skip_checks: bool,
    ) -> impl std::future::Future<Output = Result<Self::DryRunResult, Self::Error>> {
        self.as_ref().dry_run_tx(tx, skip_checks)
    }

    fn execute_tx(
        &self,
        signatures: &[UserSignature],
        tx: &Transaction,
        wait_for: impl Into<Option<WaitForTx>>,
    ) -> impl std::future::Future<Output = Result<TransactionEffects, Self::Error>> {
        self.as_ref().execute_tx(signatures, tx, wait_for)
    }

    fn wait_for_tx(
        &self,
        digest: Digest,
        wait_for: WaitForTx,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> {
        self.as_ref().wait_for_tx(digest, wait_for)
    }
}
