// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Common utilities shared across API modules.

use std::borrow::Cow;

pub use iota_grpc_types::{
    field::{FieldMask, FieldMaskUtil},
    field_mask_normalize,
    google::rpc::Status as RpcStatus,
    proto::TryFromProtoError,
};
use iota_grpc_types::{
    proto::GrpcConversionError,
    v1::{
        bcs::BcsData,
        ledger_service::{ObjectResult, TransactionResult, object_result, transaction_result},
        transaction::{ExecutedTransaction, Transaction as ProtoTransaction},
        transaction_execution_service::{
            ExecuteTransactionResult, SimulateTransactionResult, SimulatedTransaction,
            execute_transaction_result, simulate_transaction_result,
        },
        types::ObjectId as ProtoObjectId,
    },
};
use iota_types::{ObjectId, TransactionDigest};
use serde::Serialize;

use super::MetadataEnvelope;

/// Errors that can occur during gRPC client API operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Error converting proto types to SDK types.
    #[error("proto conversion error: {0}")]
    ProtoConversion(#[from] Box<TryFromProtoError>),

    /// Per-item error returned by the server (preserves code, message,
    /// details).
    #[error("server error (code {code}): {msg}", code = .0.code, msg = .0.message)]
    Server(RpcStatus),

    /// Client-side protocol error (e.g. checkpoint stream reassembly).
    #[error("protocol error: {0}")]
    Protocol(ProtocolError),

    /// Error converting signatures to proto format.
    #[error("signature conversion error: {0}")]
    Signature(GrpcConversionError),

    /// The caller passed an empty request (e.g. no object IDs or digests).
    #[error("empty request: at least one item must be provided")]
    EmptyRequest,

    /// The server stream ended unexpectedly while `has_next` was still true.
    #[error("stream ended unexpectedly: server indicated more results with has_next=true")]
    UnexpectedEndOfStream,

    /// gRPC transport or protocol error.
    #[error("grpc error: {0}")]
    Grpc(Box<tonic::Status>),
}

impl Error {
    /// Returns `true` if the error carries a `NOT_FOUND` status, whether the
    /// server reported it for the call or for a single item of a batched
    /// request.
    ///
    /// **Warning:** do not test the outer error of a batched read to decide
    /// that an item is absent. Those calls report an absent item against the
    /// request that asked for it, so a `NOT_FOUND` for the call means the
    /// endpoint is wrong; treating it as a missing item turns a misconfigured
    /// endpoint into a normal "not there" answer. Test the per-item result
    /// instead. Calls returning a single response, such as fetching a
    /// checkpoint, do report absence at the call level.
    pub fn is_not_found(&self) -> bool {
        match self {
            Error::Server(status) => status.code == i32::from(tonic::Code::NotFound),
            Error::Grpc(status) => status.code() == tonic::Code::NotFound,
            _ => false,
        }
    }
}

impl From<TryFromProtoError> for Error {
    fn from(err: TryFromProtoError) -> Self {
        Error::ProtoConversion(Box::new(err))
    }
}

impl From<tonic::Status> for Error {
    fn from(status: tonic::Status) -> Self {
        Error::Grpc(Box::new(status))
    }
}

impl From<Error> for tonic::Status {
    fn from(err: Error) -> Self {
        match err {
            Error::ProtoConversion(e) => {
                tonic::Status::internal(format!("proto conversion error: {e}"))
            }
            Error::Server(status) => status.to_tonic_status(),
            Error::Protocol(err) => tonic::Status::internal(format!("protocol error: {err}")),
            Error::Signature(err) => {
                tonic::Status::internal(format!("signature conversion error: {err}"))
            }
            Error::EmptyRequest => {
                tonic::Status::invalid_argument("empty request: at least one item must be provided")
            }
            Error::UnexpectedEndOfStream => {
                tonic::Status::internal("stream ended unexpectedly: has_next was true")
            }
            Error::Grpc(status) => *status,
        }
    }
}

/// Protocol-level errors encountered while processing gRPC responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Server returned an unrecognized proto oneof variant.
    #[error("unknown {0} variant")]
    UnknownVariant(&'static str),

    /// A required response field was unexpectedly empty.
    #[error("empty response field: {0}")]
    EmptyResponseField(&'static str),

    /// Error during checkpoint data stream reassembly.
    #[error("checkpoint stream error: {0}")]
    CheckpointStream(#[from] CheckpointStreamError),
}

/// Errors during checkpoint data stream reassembly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointStreamError {
    /// Received a data chunk before the checkpoint header.
    #[error("received {data_kind} before checkpoint header")]
    DataBeforeHeader { data_kind: &'static str },

    /// New checkpoint header received while previous was incomplete.
    #[error("new checkpoint header before previous completed")]
    IncompleteCheckpoint,

    /// EndMarker sequence number doesn't match current checkpoint.
    #[error("end marker sequence number {actual} does not match checkpoint {expected}")]
    SequenceNumberMismatch { expected: u64, actual: u64 },

    /// Unknown checkpoint data payload type.
    #[error("unknown checkpoint data payload type")]
    UnknownPayload,

    /// Stream ended with incomplete checkpoint data.
    #[error("stream ended with incomplete data for checkpoint {sequence_number}")]
    IncompleteStream { sequence_number: u64 },
}

/// Result type alias for API operations.
pub type Result<T> = std::result::Result<T, Error>;

// =============================================================================
// Field Masks
// =============================================================================

/// A read mask that can be passed to client methods.
///
/// Construct from field path constants defined in
/// [`read_mask_fields`](crate::read_mask_fields):
///
/// ```
/// use iota_sdk_grpc_client::{ReadMask, read_mask_fields::TransactionField};
///
/// // Single field
/// let mask = ReadMask::from(TransactionField::EFFECTS);
/// assert_eq!(mask.as_str(), "effects");
///
/// // Multiple fields
/// let mask = ReadMask::from(&[TransactionField::EFFECTS, TransactionField::CHECKPOINT]);
/// assert_eq!(mask.as_str(), "effects,checkpoint");
/// ```
#[derive(Clone, Debug)]
pub struct ReadMask<'a>(Cow<'a, str>);

impl<'a> ReadMask<'a> {
    /// Returns the comma-separated field mask string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'a> From<&'a str> for ReadMask<'a> {
    fn from(s: &'a str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for ReadMask<'_> {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl From<&[&str]> for ReadMask<'_> {
    /// Paths are normalized: broader paths subsume their sub-paths.
    fn from(paths: &[&str]) -> Self {
        Self(Cow::Owned(field_mask_normalize(&paths.join(","))))
    }
}

impl<const N: usize> From<&[&str; N]> for ReadMask<'_> {
    /// Paths are normalized: broader paths subsume their sub-paths.
    fn from(paths: &[&str; N]) -> Self {
        Self::from(paths.as_slice())
    }
}

impl From<FieldMask> for ReadMask<'_> {
    /// Paths are normalized: broader paths subsume their sub-paths.
    fn from(mask: FieldMask) -> Self {
        Self(Cow::Owned(field_mask_normalize(&mask.paths.join(","))))
    }
}

/// Build a field mask with a custom value or default.
///
/// This is a convenience helper that handles the common pattern of using
/// a user-provided field mask or falling back to a default.
pub fn field_mask_with_default(custom: Option<ReadMask<'_>>, default: &str) -> FieldMask {
    match custom {
        Some(mask) => FieldMask::from_str(mask.as_str()),
        None => FieldMask::from_str(default),
    }
}

/// Safely convert a `usize` to `u32`, saturating at `u32::MAX` instead of
/// silently truncating on 64-bit platforms.
pub fn saturating_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// A trait for proto result types that follow the pattern of having
/// `Some(Result::Value)`, `Some(Result::Error)`, or `None`.
///
/// This allows generic handling of gRPC response results that can be either
/// a success value, a server error, or missing.
pub trait ProtoResult {
    /// The success value type.
    type Value;

    /// Extract the result, converting to our error types.
    fn into_result(self) -> Result<Self::Value>;
}

/// Convert a batch of proto results into one result per requested item,
/// preserving request order.
///
/// The batched RPCs report a failure for a single item as a `google.rpc.Status`
/// in that item's slot, so the outcome for one item is independent of the
/// others: a caller that needs every item can `collect::<Result<Vec<_>>>()`,
/// while one that tolerates gaps can inspect each slot.
pub fn into_item_results<T: ProtoResult>(batch: Vec<T>) -> Vec<Result<T::Value>> {
    batch.into_iter().map(ProtoResult::into_result).collect()
}

impl ProtoResult for ObjectResult {
    type Value = iota_grpc_types::v1::object::Object;

    fn into_result(self) -> Result<Self::Value> {
        match self.result {
            Some(object_result::Result::Object(obj)) => Ok(obj),
            Some(object_result::Result::Error(e)) => Err(Error::Server(e)),
            None => Err(TryFromProtoError::missing("result").into()),
            Some(_) => Err(Error::Protocol(ProtocolError::UnknownVariant(
                "object result",
            ))),
        }
    }
}

impl ProtoResult for TransactionResult {
    type Value = ExecutedTransaction;

    fn into_result(self) -> Result<Self::Value> {
        match self.result {
            Some(transaction_result::Result::ExecutedTransaction(tx)) => Ok(tx),
            Some(transaction_result::Result::Error(e)) => Err(Error::Server(e)),
            None => Err(TryFromProtoError::missing("result").into()),
            Some(_) => Err(Error::Protocol(ProtocolError::UnknownVariant(
                "transaction result",
            ))),
        }
    }
}

impl ProtoResult for ExecuteTransactionResult {
    type Value = ExecutedTransaction;

    fn into_result(self) -> Result<Self::Value> {
        match self.result {
            Some(execute_transaction_result::Result::ExecutedTransaction(tx)) => Ok(tx),
            Some(execute_transaction_result::Result::Error(e)) => Err(Error::Server(e)),
            None => Err(TryFromProtoError::missing("result").into()),
            Some(_) => Err(Error::Protocol(ProtocolError::UnknownVariant(
                "execute transaction result",
            ))),
        }
    }
}

impl ProtoResult for SimulateTransactionResult {
    type Value = SimulatedTransaction;

    fn into_result(self) -> Result<Self::Value> {
        match self.result {
            Some(simulate_transaction_result::Result::SimulatedTransaction(tx)) => Ok(tx),
            Some(simulate_transaction_result::Result::Error(e)) => Err(Error::Server(e)),
            None => Err(TryFromProtoError::missing("result").into()),
            Some(_) => Err(Error::Protocol(ProtocolError::UnknownVariant(
                "simulate transaction result",
            ))),
        }
    }
}

/// Collect all items from a paginated gRPC stream into a single `Vec`.
///
/// This handles the common pattern of iterating over a `tonic::Streaming<T>`,
/// extracting items from each message via the `extract` closure, and checking
/// that the stream was not truncated (i.e. `has_next` is `false` on the last
/// message).
///
/// The `extract` closure receives each stream message and must return
/// `(has_next, items)`.  Because some streams require fallible per-item
/// conversion (e.g. via [`ProtoResult`]), the closure itself returns
/// `Result<…>`.
pub async fn collect_stream<T, I, F>(
    mut stream: tonic::Streaming<T>,
    metadata: tonic::metadata::MetadataMap,
    extract: F,
) -> Result<MetadataEnvelope<Vec<I>>>
where
    F: Fn(T) -> Result<(bool, Vec<I>)>,
{
    let mut results = Vec::new();
    let mut has_next = false;

    while let Some(response) = stream.message().await? {
        let (next, items) = extract(response)?;
        has_next = next;
        results.extend(items);
    }

    if has_next {
        return Err(Error::UnexpectedEndOfStream);
    }

    Ok(MetadataEnvelope::new(results, metadata))
}

/// A single page of results from a paginated list endpoint.
///
/// Returned when awaiting a list query builder directly (single-page mode).
/// Contains the items from this page plus an optional continuation token.
#[derive(Clone, Debug)]
pub struct Page<T> {
    /// The items returned in this page.
    pub items: Vec<T>,
    /// Token to retrieve the next page. `None` when this is the last page.
    pub next_page_token: Option<::prost::bytes::Bytes>,
}

/// Generate a paginated query builder for a list endpoint.
///
/// The generated struct implements [`IntoFuture`](std::future::IntoFuture) for
/// single-page retrieval and provides a [`collect`] method for auto-pagination.
///
/// # Parameters
///
/// - `$query_name` — name of the generated builder struct
/// - `$service_client_type` — the tonic service client type
/// - `$item_type` — the item type in the response vec
/// - `$rpc_method` — the RPC method name on the service client
/// - `$items_field` — the field name on the response containing the items vec
///
/// # Example
///
/// ```ignore
/// define_list_query! {
///     pub struct ListOwnedObjectsQuery {
///         service_client: StateServiceClient<InterceptedChannel>,
///         request: ListOwnedObjectsRequest,
///         item: Object,
///         rpc_method: list_owned_objects,
///         items_field: objects,
///     }
/// }
/// ```
macro_rules! define_list_query {
    (
        $(#[$meta:meta])*
        pub struct $query_name:ident {
            service_client: $service_client_type:ty,
            request: $request_type:ty,
            item: $item_type:ty,
            rpc_method: $rpc_method:ident,
            items_field: $items_field:ident,
        }
    ) => {
        $(#[$meta])*
        pub struct $query_name {
            service_client: $service_client_type,
            base_request: $request_type,
            max_message_size: Option<usize>,
            page_size: Option<u32>,
            page_token: Option<::prost::bytes::Bytes>,
        }

        impl $query_name {
            pub(crate) fn new(
                service_client: $service_client_type,
                base_request: $request_type,
                max_message_size: Option<usize>,
                page_size: Option<u32>,
                page_token: Option<::prost::bytes::Bytes>,
            ) -> Self {
                Self {
                    service_client,
                    base_request,
                    max_message_size,
                    page_size,
                    page_token,
                }
            }

            /// Auto-paginate through all pages, collecting up to `limit` items.
            ///
            /// If `limit` is `None`, collects all items across all pages.
            pub async fn collect(
                self,
                limit: impl Into<Option<u32>>,
            ) -> $crate::api::Result<$crate::api::MetadataEnvelope<Vec<$item_type>>> {
                let limit = limit.into();
                let mut all_items = Vec::new();
                let mut next_page_token = self.page_token;
                let mut result_metadata = None;
                let mut service_client = self.service_client;

                loop {
                    let mut request = self.base_request.clone();

                    // Cap page_size to the remaining items needed when a
                    // limit is set, so we don't over-fetch from the server.
                    let effective_page_size = match (self.page_size, limit) {
                        (Some(ps), Some(l)) => {
                            let remaining = (l as usize).saturating_sub(all_items.len());
                            Some(ps.min(remaining as u32))
                        }
                        (Some(ps), None) => Some(ps),
                        (None, Some(l)) => {
                            let remaining = (l as usize).saturating_sub(all_items.len());
                            Some(remaining as u32)
                        }
                        (None, None) => None,
                    };
                    if let Some(ps) = effective_page_size {
                        request = request.with_page_size(ps);
                    }
                    if let Some(token) = next_page_token.take() {
                        request = request.with_page_token(token);
                    }
                    if let Some(max_size) = self.max_message_size {
                        request = request.with_max_message_size_bytes(
                            $crate::api::saturating_usize_to_u32(max_size),
                        );
                    }

                    let response = service_client.$rpc_method(request).await?;
                    let (body, metadata) =
                        $crate::api::MetadataEnvelope::from(response).into_parts();
                    if result_metadata.is_none() {
                        result_metadata = Some(metadata);
                    }

                    all_items.extend(body.$items_field);

                    match body.next_page_token {
                        Some(token) => next_page_token = Some(token),
                        None => break,
                    }

                    if limit.is_some_and(|l| all_items.len() >= l as usize) {
                        break;
                    }
                }

                Ok($crate::api::MetadataEnvelope::new(
                    all_items,
                    result_metadata.unwrap_or_default(),
                ))
            }
        }

        impl ::std::future::IntoFuture for $query_name {
            type Output = $crate::api::Result<
                $crate::api::MetadataEnvelope<$crate::api::Page<$item_type>>,
            >;
            type IntoFuture = ::std::pin::Pin<
                Box<dyn ::std::future::Future<Output = Self::Output> + Send>,
            >;

            fn into_future(self) -> Self::IntoFuture {
                Box::pin(async move {
                    let mut service_client = self.service_client;
                    let mut request = self.base_request;

                    if let Some(ps) = self.page_size {
                        request = request.with_page_size(ps);
                    }
                    if let Some(token) = self.page_token {
                        request = request.with_page_token(token);
                    }
                    if let Some(max_size) = self.max_message_size {
                        request = request.with_max_message_size_bytes(
                            $crate::api::saturating_usize_to_u32(max_size),
                        );
                    }

                    let response = service_client.$rpc_method(request).await?;
                    let (body, metadata) =
                        $crate::api::MetadataEnvelope::from(response).into_parts();

                    Ok($crate::api::MetadataEnvelope::new(
                        $crate::api::Page {
                            items: body.$items_field,
                            next_page_token: body.next_page_token,
                        },
                        metadata,
                    ))
                })
            }
        }
    };
}

pub(crate) use define_list_query;

/// Convert an `ObjectId` to the gRPC proto `ObjectId` type.
pub fn proto_object_id(id: ObjectId) -> ProtoObjectId {
    ProtoObjectId::default().with_object_id(Vec::from(id))
}

/// Build a proto Transaction from serializable transaction data and digest.
pub fn build_proto_transaction<T: Serialize>(
    data: &T,
    digest: TransactionDigest,
) -> Result<ProtoTransaction> {
    let bcs = BcsData::serialize(data)
        .map_err(|e| Error::from(TryFromProtoError::invalid("transaction", e)))?;

    let proto_transaction = ProtoTransaction::default()
        .with_digest(digest)
        .with_bcs(bcs);

    Ok(proto_transaction)
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::{google::rpc::Status, v1::object::Object};

    use super::{Error, ObjectResult, into_item_results};

    #[test]
    fn a_per_item_error_keeps_the_surrounding_items() {
        let batch = vec![
            ObjectResult::default().with_object(Object::default()),
            ObjectResult::default().with_error(Status {
                code: tonic::Code::NotFound.into(),
                message: "Object 0x2 not found".to_owned(),
                details: Vec::new(),
            }),
            ObjectResult::default().with_object(Object::default()),
        ];

        let items = into_item_results(batch);

        assert_eq!(items.len(), 3);
        assert!(items[0].is_ok());
        assert!(matches!(items[1], Err(Error::Server(_))));
        assert!(items[2].is_ok());
    }

    #[test]
    fn an_all_error_batch_still_yields_one_item_per_request() {
        let batch = vec![
            ObjectResult::default().with_error(Status::default()),
            ObjectResult::default().with_error(Status::default()),
        ];

        assert_eq!(into_item_results(batch).len(), 2);
    }

    #[test]
    fn not_found_is_recognised_at_the_call_and_item_level() {
        let item_level = Error::Server(Status {
            code: tonic::Code::NotFound.into(),
            message: String::new(),
            details: Vec::new(),
        });
        let call_level = Error::from(tonic::Status::not_found("gone"));
        let other = Error::Server(Status {
            code: tonic::Code::Internal.into(),
            message: String::new(),
            details: Vec::new(),
        });

        assert!(item_level.is_not_found());
        assert!(call_level.is_not_found());
        assert!(!other.is_not_found());
        assert!(!Error::EmptyRequest.is_not_found());
    }
}
