// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use iota_graphql_client::{
    DryRunResult, WaitForTx,
    pagination::{Direction, PaginationFilter},
    query_types::ObjectFilter,
};
use iota_types::{
    Address, Digest, Object, ObjectId, SignedTransaction, Transaction, TransactionEffects, TypeTag,
    UserSignature, Version,
};

/// One page of objects plus an optional cursor for the next page. See
/// [`ClientMethods::objects`].
pub type ObjectsPage = (Vec<Object>, Option<Vec<u8>>);

/// Transport-neutral view of the chain's protocol configuration: a flat
/// map of attribute name to value, parsed by callers as needed.
#[derive(Clone, Debug, Default)]
pub struct ProtocolConfig {
    /// All available configuration attributes, keyed by their canonical
    /// protocol name (e.g. `"max_gas_payment_objects"`).
    pub attributes: BTreeMap<String, String>,
}

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

    /// Fetch one page of objects matching the filter, returning the page
    /// contents and a continuation cursor (when more pages exist).
    ///
    /// The cursor is opaque to callers — both GraphQL (base64-encoded
    /// JSON/BCS) and gRPC (`prost::bytes::Bytes` page token) formats fit
    /// into `Option<Vec<u8>>`. Pass `None` to start from the beginning;
    /// pass the cursor returned by a previous call to advance.
    fn objects(
        &self,
        type_tag: Option<TypeTag>,
        owner: Option<Address>,
        object_ids: Option<Vec<ObjectId>>,
        ascending: bool,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>>;

    /// Fetch the chain's protocol configuration. Implementations should
    /// populate [`ProtocolConfig::attributes`] with the protocol config
    /// attributes; callers look up the keys they care about.
    ///
    /// The default impl returns an empty [`ProtocolConfig`] so existing
    /// implementors do not have to grow protocol-config plumbing.
    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        std::future::ready(Ok(ProtocolConfig::default()))
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
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>> {
        (*self).objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        (*self).protocol_config()
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
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        // GraphQL cursors are base64 ASCII, so round-tripping through
        // Vec<u8> is lossless. Caller-supplied cursors must come from a
        // prior call to this method; anything else is rejected here
        // rather than panicked on.
        let cursor = cursor.map(String::from_utf8).transpose().map_err(|e| {
            iota_graphql_client::error::Error::from_error(
                iota_graphql_client::error::Kind::Parse,
                e,
            )
        })?;
        let page = self
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
            .await?;
        let (page_info, data) = page.into_parts();
        let next = page_info
            .has_next_page
            .then_some(page_info.end_cursor)
            .flatten()
            .map(String::into_bytes);
        Ok((data, next))
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        let cfg = iota_graphql_client::Client::protocol_config(self, None).await?;
        let attributes = cfg
            .configs
            .into_iter()
            .filter_map(|attr| attr.value.map(|v| (attr.key, v)))
            .collect();
        Ok(ProtocolConfig { attributes })
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
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<ObjectsPage, Self::Error>> {
        self.as_ref()
            .objects(type_tag, owner, object_ids, ascending, cursor, limit)
    }

    fn protocol_config(
        &self,
    ) -> impl std::future::Future<Output = Result<ProtocolConfig, Self::Error>> {
        self.as_ref().protocol_config()
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
