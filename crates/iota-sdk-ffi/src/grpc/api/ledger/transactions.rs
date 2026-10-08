// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use iota_sdk::{
    grpc_client::{GrpcResult, read_mask_fields::TransactionReadMask},
    grpc_types::{proto::proto_to_timestamp_ms, v1 as proto},
    transaction_builder::TransactionBuilderExecutionClient,
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::{client::GrpcClient, read_mask_fields::GrpcTransactionField},
    transaction_builder::WaitForTransaction,
    types::{
        digest::{TransactionDigest, TransactionEffectsDigest, TransactionEventsDigest},
        events::TransactionEvents,
        object::Object,
        signature::UserSignature,
        transaction::{Transaction, TransactionEffects},
    },
};

/// A transaction that has been executed, along with its signatures, effects,
/// events and objects.
///
/// The `transaction`, `effects`, `events`, and input/output object fields are
/// deserialized from BCS, so the read mask must include the matching
/// `GrpcTransactionField` (`TransactionBcs`, `EffectsBcs`, `EventsEventsBcs`,
/// `InputObjectsBcs`, `OutputObjectsBcs`), or its `GrpcCheckpointResponseField`
/// / `GrpcSimulateField` counterpart, for them to be populated; digest-only
/// read masks populate only the digest fields.
#[derive(Clone, uniffi::Record)]
pub struct GrpcExecutedTransaction {
    /// The digest of the transaction.
    pub digest: Option<Arc<TransactionDigest>>,
    /// The transaction itself.
    pub transaction: Option<Arc<Transaction>>,
    /// The user signatures that authorized the execution of the transaction.
    pub signatures: Option<Vec<Arc<UserSignature>>>,
    /// The digest of the transaction effects.
    pub effects_digest: Option<Arc<TransactionEffectsDigest>>,
    /// The effects of the transaction.
    pub effects: Option<Arc<TransactionEffects>>,
    /// The digest of the transaction events.
    pub events_digest: Option<Arc<TransactionEventsDigest>>,
    /// The events emitted by the transaction, if any.
    pub events: Option<Arc<TransactionEvents>>,
    /// The sequence number of the checkpoint that includes the transaction.
    pub checkpoint: Option<u64>,
    /// Unix timestamp in milliseconds of the checkpoint that includes the
    /// transaction.
    pub timestamp_ms: Option<u64>,
    /// The input objects used by the transaction.
    pub input_objects: Option<Vec<Arc<Object>>>,
    /// The output objects produced by the transaction.
    pub output_objects: Option<Vec<Arc<Object>>>,
}

/// The results of a batch of transactions, in request order. Each item is
/// either the transaction or the error the server reported for it.
///
/// Read items by position with `get`, or in order with `has_next` and `next`.
/// An item's error does not end the iteration: `next` throws it and the
/// following call moves on to the next item. Items can be read any number of
/// times.
#[derive(uniffi::Object)]
pub struct GrpcExecutedTransactionResults {
    results: Vec<std::result::Result<GrpcExecutedTransaction, String>>,
    cursor: AtomicUsize,
}

impl GrpcExecutedTransactionResults {
    /// Convert the client's results, failing if a transaction the server
    /// returned cannot be decoded.
    pub(crate) fn new(
        results: Vec<GrpcResult<proto::transaction::ExecutedTransaction>>,
    ) -> Result<Self> {
        Ok(Self {
            results: results
                .into_iter()
                .map(|result| match result {
                    Ok(transaction) => (&transaction).try_into().map(Ok),
                    Err(error) => Ok(Err(error.to_string())),
                })
                .collect::<Result<_>>()?,
            cursor: AtomicUsize::new(0),
        })
    }
}

#[uniffi::export]
impl GrpcExecutedTransactionResults {
    /// The number of items.
    pub fn len(&self) -> u64 {
        self.results.len() as u64
    }

    /// Whether there are no items.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// The transaction at `index`, or an error carrying the message the
    /// server reported for it. Errors if `index` is out of range.
    pub fn get(&self, index: u64) -> Result<GrpcExecutedTransaction> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.results.get(index))
            .ok_or_else(|| {
                SdkFfiError::custom(format!(
                    "index {index} out of range for {} results",
                    self.results.len()
                ))
            })?
            .clone()
            .map_err(SdkFfiError::custom)
    }

    /// Whether `next` has an item left to return.
    pub fn has_next(&self) -> bool {
        self.cursor.load(Ordering::Relaxed) < self.results.len()
    }

    /// The next transaction, or an error carrying the message the server
    /// reported for it. Errors once every item has been returned.
    ///
    /// `has_next` followed by `next` is not atomic: when several threads
    /// share the results, `next` can error as exhausted after `has_next`
    /// returned `true`.
    pub fn next(&self) -> Result<GrpcExecutedTransaction> {
        let len = self.results.len();
        let index = self.cursor.fetch_add(1, Ordering::Relaxed);
        if index >= len {
            self.cursor.fetch_min(len, Ordering::Relaxed);
            return Err(SdkFfiError::custom("no results left"));
        }
        self.get(index as u64)
    }
}

impl TryFrom<&proto::transaction::ExecutedTransaction> for GrpcExecutedTransaction {
    type Error = SdkFfiError;

    fn try_from(value: &proto::transaction::ExecutedTransaction) -> Result<Self> {
        Ok(Self {
            digest: value
                .transaction
                .as_ref()
                .and_then(|transaction| transaction.digest.as_ref())
                .map(iota_sdk::types::TransactionDigest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            transaction: value
                .transaction
                .as_ref()
                .filter(|transaction| transaction.bcs.is_some())
                .map(|transaction| transaction.transaction().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            signatures: value
                .signatures
                .as_ref()
                .map(Vec::<iota_sdk::types::UserSignature>::try_from)
                .transpose()?
                .map(|signatures| {
                    signatures
                        .into_iter()
                        .map(Into::into)
                        .map(Arc::new)
                        .collect()
                }),
            effects_digest: value
                .effects
                .as_ref()
                .and_then(|effects| effects.digest.as_ref())
                .map(iota_sdk::types::TransactionEffectsDigest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            effects: value
                .effects
                .as_ref()
                .filter(|effects| effects.bcs.is_some())
                .map(|effects| effects.effects().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            events_digest: value
                .events
                .as_ref()
                .and_then(|events| events.digest.as_ref())
                .map(iota_sdk::types::TransactionEventsDigest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            events: value
                .events
                .as_ref()
                .filter(|events| {
                    events
                        .events
                        .as_ref()
                        .is_some_and(|events| events.events.iter().all(|event| event.bcs.is_some()))
                })
                .map(|events| events.events().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            checkpoint: value.checkpoint,
            timestamp_ms: value.timestamp.map(proto_to_timestamp_ms).transpose()?,
            input_objects: value
                .input_objects
                .as_ref()
                .filter(|objects| objects.objects.iter().all(|object| object.bcs.is_some()))
                .map(Vec::<iota_sdk::types::Object>::try_from)
                .transpose()?
                .map(|objects| objects.into_iter().map(Into::into).map(Arc::new).collect()),
            output_objects: value
                .output_objects
                .as_ref()
                .filter(|objects| objects.objects.iter().all(|object| object.bcs.is_some()))
                .map(Vec::<iota_sdk::types::Object>::try_from)
                .transpose()?
                .map(|objects| objects.into_iter().map(Into::into).map(Arc::new).collect()),
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get transactions by their digests.
    ///
    /// Results are returned in the same order as the input digests, one per
    /// digest. A transaction the serving node cannot return — because it is
    /// not found or has been pruned — fails only its own item, which reading
    /// throws with the server's error message. A transaction the server returns
    /// but that cannot be decoded fails the whole call.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction, signatures, checkpoint, and timestamp are
    /// returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn transactions(
        &self,
        digests: Vec<Arc<TransactionDigest>>,
        read_mask: Option<Vec<GrpcTransactionField>>,
    ) -> Result<GrpcExecutedTransactionResults> {
        let digests = digests.iter().map(|digest| ***digest).collect::<Vec<_>>();
        GrpcExecutedTransactionResults::new(
            self.client()
                .transactions(digests)
                .read_mask(crate::grpc::api::read_mask::<TransactionReadMask, _>(
                    read_mask,
                ))
                .await?
                .into_inner(),
        )
    }

    /// Wait for the indexing (on the node) or finalization of a transaction by
    /// its digest, polling the node until then. Returns an error after 60s.
    pub async fn wait_for_transaction(
        &self,
        digest: &TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<()> {
        Ok(TransactionBuilderExecutionClient::wait_for_transaction(
            &self.client(),
            **digest,
            wait_for.into(),
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use iota_sdk::{
        grpc_client::GrpcError,
        grpc_types::v1 as proto,
        types::{TransactionDigest, TransactionEffectsDigest, TransactionEventsDigest},
    };

    use super::{GrpcExecutedTransaction, GrpcExecutedTransactionResults};

    #[test]
    fn digest_only_mask_populates_the_typed_digests() {
        let transaction_digest = TransactionDigest::from([1; 32]);
        let effects_digest = TransactionEffectsDigest::from([2; 32]);
        let events_digest = TransactionEventsDigest::from([3; 32]);

        let mut transaction = proto::transaction::Transaction::default();
        transaction.digest = Some(transaction_digest.into());
        let mut effects = proto::transaction::TransactionEffects::default();
        effects.digest = Some(effects_digest.into());
        let mut events = proto::transaction::TransactionEvents::default();
        events.digest = Some(events_digest.into());

        let mut value = proto::transaction::ExecutedTransaction::default();
        value.transaction = Some(transaction);
        value.effects = Some(effects);
        value.events = Some(events);

        let converted = GrpcExecutedTransaction::try_from(&value).unwrap();

        assert_eq!(converted.digest.unwrap().0, transaction_digest);
        assert_eq!(converted.effects_digest.unwrap().0, effects_digest);
        assert_eq!(converted.events_digest.unwrap().0, events_digest);
        assert!(converted.transaction.is_none());
        assert!(converted.effects.is_none());
        assert!(converted.events.is_none());
    }

    #[test]
    fn item_error_fails_only_its_own_item() {
        let results = GrpcExecutedTransactionResults::new(vec![
            Err(GrpcError::EmptyRequest),
            Ok(proto::transaction::ExecutedTransaction::default()),
        ])
        .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.get(0).is_err());
        assert!(results.get(1).is_ok());
        assert!(results.get(2).is_err());
    }

    #[test]
    fn next_moves_past_errors_and_stops_at_the_end() {
        let results = GrpcExecutedTransactionResults::new(vec![
            Err(GrpcError::EmptyRequest),
            Ok(proto::transaction::ExecutedTransaction::default()),
        ])
        .unwrap();

        assert!(results.has_next());
        assert!(results.next().is_err());
        assert!(results.has_next());
        assert!(results.next().is_ok());
        assert!(!results.has_next());
        assert!(results.next().is_err());
        assert!(!results.has_next());
        assert!(results.get(1).is_ok());
    }
}
