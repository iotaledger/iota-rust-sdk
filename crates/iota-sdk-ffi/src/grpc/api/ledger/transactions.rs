// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::sync::Arc;

use iota_sdk::{
    grpc_client::read_mask_fields::TransactionReadMask,
    grpc_types::{proto::proto_to_timestamp_ms, v1 as proto},
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::{
        digest::{Digest, TransactionDigest},
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
/// deserialized from BCS, so the read mask must include the corresponding
/// `bcs` sub-fields for them to be populated; digest-only read masks populate
/// only the digest fields.
#[derive(uniffi::Record)]
pub struct ExecutedTransaction {
    /// The digest of the transaction.
    pub digest: Option<Arc<Digest>>,
    /// The transaction itself.
    pub transaction: Option<Arc<Transaction>>,
    /// The user signatures that authorized the execution of the transaction.
    pub signatures: Option<Vec<Arc<UserSignature>>>,
    /// The digest of the transaction effects.
    pub effects_digest: Option<Arc<Digest>>,
    /// The effects of the transaction.
    pub effects: Option<Arc<TransactionEffects>>,
    /// The digest of the transaction events.
    pub events_digest: Option<Arc<Digest>>,
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

impl TryFrom<&proto::transaction::ExecutedTransaction> for ExecutedTransaction {
    type Error = SdkFfiError;

    fn try_from(value: &proto::transaction::ExecutedTransaction) -> Result<Self> {
        Ok(Self {
            digest: value
                .transaction
                .as_ref()
                .and_then(|transaction| transaction.digest.as_ref())
                .map(iota_sdk::types::Digest::try_from)
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
                .map(iota_sdk::types::Digest::try_from)
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
                .map(iota_sdk::types::Digest::try_from)
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
    /// Results are returned in the same order as the input digests.
    /// If any transaction cannot be read — because it is not found or has been
    /// pruned by the serving node — the whole call fails.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction, signatures, checkpoint, and timestamp are
    /// returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn transactions(
        &self,
        digests: Vec<Arc<TransactionDigest>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<ExecutedTransaction>> {
        let digests = digests.iter().map(|digest| ***digest).collect::<Vec<_>>();
        self.0
            .read()
            .await
            .transactions(
                digests,
                crate::grpc::api::read_mask::<TransactionReadMask>(&read_mask),
            )
            .await?
            .into_inner()
            .into_iter()
            .map(|transaction| ExecutedTransaction::try_from(&transaction?))
            .collect()
    }
}
