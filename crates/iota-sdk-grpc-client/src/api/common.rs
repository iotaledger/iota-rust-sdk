// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Common utilities shared across API modules.

use std::borrow::Cow;

pub use iota_grpc_types::{
    field::FieldMask, field_mask_normalize, google::rpc::Status as RpcStatus,
    proto::TryFromProtoError,
};
use iota_grpc_types::{
    proto::GrpcConversionError,
    v1::{
        bcs::BcsData,
        ledger_service::{ObjectResult, TransactionResult, object_result, transaction_result},
        object::Object as ProtoObject,
        transaction::{ExecutedTransaction, Transaction as ProtoTransaction},
        transaction_execution_service::{
            ExecuteTransactionResult, SimulateTransactionResult, SimulatedTransaction,
            ViewFunctionCallOutputs, ViewFunctionCallResult, execute_transaction_result,
            simulate_transaction_result, view_function_call_result,
        },
        types::ObjectId as ProtoObjectId,
    },
};
use iota_types::{ObjectId, TransactionDigest, Version};
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

    /// A batched read returned a number of results that does not match the
    /// number of requested items.
    #[error("expected {expected} results, got {actual}")]
    UnexpectedResultCount { expected: usize, actual: usize },

    /// `objects` answered a position with a different object than the one
    /// requested there.
    #[error("requested object {expected} at position {position}, but got {actual}")]
    UnexpectedObject {
        position: usize,
        expected: ObjectId,
        actual: ObjectId,
    },

    /// `transactions` answered a position with a different transaction than
    /// the one requested there.
    #[error("requested transaction {expected} at position {position}, but got {actual}")]
    UnexpectedTransaction {
        position: usize,
        expected: TransactionDigest,
        actual: TransactionDigest,
    },
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

/// A low-level read mask string.
///
/// Most callers should use the scoped per-endpoint mask types in
/// [`read_mask_fields`](crate::read_mask_fields)
/// (e.g. [`ObjectReadMask`](crate::read_mask_fields::ObjectReadMask)) which
/// are passed directly to the client methods. This type is the underlying
/// string holder, useful when composing masks by hand:
///
/// ```
/// use iota_sdk_grpc_client::ReadMask;
///
/// let mask = ReadMask::from("effects,checkpoint");
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

/// Check that a batched read answered every requested item.
///
/// Callers pair results with requests by position, so a count that does not
/// match the request leaves no way to tell which item each result belongs to.
pub fn check_result_count<T>(results: &[T], expected: usize) -> Result<()> {
    if results.len() == expected {
        Ok(())
    } else {
        Err(Error::Protocol(ProtocolError::UnexpectedResultCount {
            expected,
            actual: results.len(),
        }))
    }
}

/// Check that each answered object is the one requested in that position.
///
/// A matching count only says how many results came back, not that position `i`
/// holds object `i`, so the pairing callers rely on is checked rather than
/// trusted.
pub fn check_object_identity(
    results: &[Result<ProtoObject>],
    requested: &[(ObjectId, Option<Version>)],
) -> Result<()> {
    for (position, (result, (expected, _))) in results.iter().zip(requested).enumerate() {
        let Ok(object) = result else { continue };
        let Some(actual) = answered_object_id(object)? else {
            continue;
        };
        if actual != *expected {
            return Err(Error::Protocol(ProtocolError::UnexpectedObject {
                position,
                expected: *expected,
                actual,
            }));
        }
    }
    Ok(())
}

/// Check that each answered transaction is the one requested in that position.
///
/// See [`check_object_identity`] for why the pairing is checked rather than
/// trusted.
pub fn check_transaction_identity(
    results: &[Result<ExecutedTransaction>],
    requested: &[TransactionDigest],
) -> Result<()> {
    for (position, (result, expected)) in results.iter().zip(requested).enumerate() {
        let Ok(transaction) = result else { continue };
        let Some(actual) = answered_transaction_digest(transaction)? else {
            continue;
        };
        if actual != *expected {
            return Err(Error::Protocol(ProtocolError::UnexpectedTransaction {
                position,
                expected: *expected,
                actual,
            }));
        }
    }
    Ok(())
}

/// The id of an answered object, taken from its reference or, when the read
/// mask left that out, from its BCS. `None` when it carries neither, leaving
/// nothing to compare.
fn answered_object_id(object: &ProtoObject) -> Result<Option<ObjectId>> {
    if let Some(id) = object
        .reference
        .as_ref()
        .and_then(|reference| reference.object_id.as_ref())
    {
        return Ok(Some(id.try_into()?));
    }
    if object.bcs.is_some() {
        return Ok(Some(object.object()?.id()));
    }
    Ok(None)
}

/// The digest of an answered transaction, taken from the response or, when the
/// read mask left it out, computed from the transaction's BCS. `None` when it
/// carries neither, leaving nothing to compare.
fn answered_transaction_digest(
    transaction: &ExecutedTransaction,
) -> Result<Option<TransactionDigest>> {
    let Some(transaction) = transaction.transaction.as_ref() else {
        return Ok(None);
    };
    if let Some(digest) = transaction.digest.as_ref() {
        return Ok(Some(digest.try_into()?));
    }
    if transaction.bcs.is_some() {
        return Ok(Some(transaction.transaction()?.digest()));
    }
    Ok(None)
}

impl ProtoResult for ObjectResult {
    type Value = ProtoObject;

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

impl ProtoResult for ViewFunctionCallResult {
    type Value = ViewFunctionCallOutputs;

    fn into_result(self) -> Result<Self::Value> {
        match self.result {
            Some(view_function_call_result::Result::CallOutputs(r)) => Ok(r),
            Some(view_function_call_result::Result::Error(e)) => Err(Error::Server(e)),
            None => Err(TryFromProtoError::missing("result").into()),
            Some(_) => Err(Error::Protocol(ProtocolError::UnknownVariant(
                "view function call result",
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
/// - `$item_type` — the item type exposed by the builder
/// - `$rpc_method` — the RPC method name on the service client
/// - `$items_field` — the field name on the response containing the items vec
/// - `map_item` (optional) — a fallible `fn(&ProtoItem) -> Result<$item_type>`
///   applied to each response element. When omitted, items are passed through
///   unchanged (so `$item_type` must be the response field's element type).
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
///
/// With a per-item conversion:
///
/// ```ignore
/// define_list_query! {
///     pub struct GetCoinsQuery {
///         service_client: StateServiceClient<InterceptedChannel>,
///         request: ListOwnedObjectsRequest,
///         item: Coin,
///         rpc_method: list_owned_objects,
///         items_field: objects,
///         map_item: object_to_coin, // fn(&Object) -> Result<Coin>
///     }
/// }
/// ```
macro_rules! define_list_query {
    // Pass-through variant: `$item_type` is the response element type.
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
        $crate::api::define_list_query! {
            @impl
            $(#[$meta])*
            pub struct $query_name {
                service_client: $service_client_type,
                request: $request_type,
                item: $item_type,
                rpc_method: $rpc_method,
                items_field: $items_field,
                map_item: |item| $crate::api::Result::Ok(item),
            }
        }
    };

    // Conversion variant: each response element is mapped through `$map_item`,
    // a fallible `fn(&ProtoItem) -> Result<$item_type>`.
    (
        $(#[$meta:meta])*
        pub struct $query_name:ident {
            service_client: $service_client_type:ty,
            request: $request_type:ty,
            item: $item_type:ty,
            rpc_method: $rpc_method:ident,
            items_field: $items_field:ident,
            map_item: $map_item:expr,
        }
    ) => {
        $crate::api::define_list_query! {
            @impl
            $(#[$meta])*
            pub struct $query_name {
                service_client: $service_client_type,
                request: $request_type,
                item: $item_type,
                rpc_method: $rpc_method,
                items_field: $items_field,
                map_item: |item| $map_item(&item),
            }
        }
    };

    (
        @impl
        $(#[$meta:meta])*
        pub struct $query_name:ident {
            service_client: $service_client_type:ty,
            request: $request_type:ty,
            item: $item_type:ty,
            rpc_method: $rpc_method:ident,
            items_field: $items_field:ident,
            map_item: $map_item:expr,
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
                let mut all_items: Vec<$item_type> = Vec::new();
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

                    let map_item = $map_item;
                    for item in body.$items_field {
                        all_items.push(map_item(item)?);
                    }

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

                    let map_item = $map_item;
                    let items = body
                        .$items_field
                        .into_iter()
                        .map(map_item)
                        .collect::<$crate::api::Result<Vec<$item_type>>>()?;

                    Ok($crate::api::MetadataEnvelope::new(
                        $crate::api::Page {
                            items,
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
    use iota_grpc_types::{
        google::rpc::Status,
        v1::{
            command::CommandOutputs, object::Object, transaction_execution_service::ExecutionError,
            types::ObjectReference as ProtoObjectReference, versioned::VersionedObject,
        },
    };
    use iota_types::{
        Address, MoveStruct, ObjectData, ObjectId, Owner, StructTag, TransactionDigest, Version,
    };

    use super::{
        BcsData, Error, ExecutedTransaction, ObjectResult, ProtoTransaction, ProtocolError, Result,
        ViewFunctionCallOutputs, ViewFunctionCallResult, check_object_identity,
        check_transaction_identity, into_item_results, proto_object_id,
    };

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

    /// Each view function call runs in its own transaction, so a call the node
    /// refuses fails only its own slot.
    #[test]
    fn a_rejected_view_function_call_keeps_the_surrounding_calls() {
        let batch = vec![
            ViewFunctionCallResult::default().with_call_outputs(
                ViewFunctionCallOutputs::default().with_return_values(CommandOutputs::default()),
            ),
            ViewFunctionCallResult::default().with_error(Status {
                code: tonic::Code::InvalidArgument.into(),
                message: "no function 'nope' in module 0x2::hash".to_owned(),
                details: Vec::new(),
            }),
        ];

        let items = into_item_results(batch);

        assert_eq!(items.len(), 2);
        assert!(items[0].is_ok());
        assert!(matches!(items[1], Err(Error::Server(_))));
    }

    /// A call that ran and aborted is not a failed *request*: it occupies the
    /// `Ok` slot, and the abort is read off the outputs. Only a call the node
    /// refused to run yields `Err`.
    #[test]
    fn an_aborted_view_function_call_reports_through_its_outputs() {
        let batch = vec![
            ViewFunctionCallResult::default().with_call_outputs(
                ViewFunctionCallOutputs::default().with_return_values(CommandOutputs::default()),
            ),
            ViewFunctionCallResult::default().with_call_outputs(
                ViewFunctionCallOutputs::default()
                    .with_execution_error(ExecutionError::default().with_source("MoveAbort(1)")),
            ),
        ];

        let items = into_item_results(batch);

        let returned = items[0].as_ref().expect("the call returned");
        assert!(returned.return_values().is_some());
        assert!(returned.execution_error().is_none());

        let aborted = items[1].as_ref().expect("the call ran, then aborted");
        assert!(aborted.return_values().is_none());
        assert_eq!(
            aborted.execution_error().and_then(|e| e.source.as_deref()),
            Some("MoveAbort(1)")
        );
    }

    #[test]
    fn a_view_function_call_result_without_a_variant_is_a_protocol_error() {
        let items = into_item_results(vec![ViewFunctionCallResult::default()]);

        assert!(matches!(items[0], Err(Error::ProtoConversion(_))));
    }

    fn object_id(byte: u8) -> ObjectId {
        ObjectId::new([byte; ObjectId::LENGTH])
    }

    fn transaction_digest(byte: u8) -> TransactionDigest {
        TransactionDigest::new([byte; TransactionDigest::LENGTH])
    }

    /// A proto object carrying just its reference, as the default read mask
    /// requests.
    fn answered(id: ObjectId) -> Result<Object> {
        let mut object = Object::default();
        object.reference =
            Some(ProtoObjectReference::default().with_object_id(proto_object_id(id)));
        Ok(object)
    }

    /// A proto object carrying only BCS, as a `bcs`-only read mask requests.
    fn answered_with_bcs_only(id: ObjectId) -> Object {
        let mut contents = Vec::from(id);
        contents.extend_from_slice(&0u64.to_le_bytes());
        let move_struct = MoveStruct::new(
            StructTag::new_gas_coin().into(),
            Version::from_u64(1),
            contents,
        )
        .expect("contents contain a full object id");
        let object = iota_types::Object::new(
            ObjectData::Struct(move_struct),
            Owner::Address(Address::ZERO),
            TransactionDigest::ZERO,
            0,
        );

        let mut answered = Object::default();
        answered.bcs =
            Some(BcsData::serialize(&VersionedObject::V1(object)).expect("object serializes"));
        answered
    }

    /// A proto transaction carrying just its digest, as the default read mask
    /// requests.
    fn answered_transaction(digest: TransactionDigest) -> ExecutedTransaction {
        ExecutedTransaction::default()
            .with_transaction(ProtoTransaction::default().with_digest(digest))
    }

    #[test]
    fn objects_answered_in_request_order_are_accepted() {
        let requested = [(object_id(1), None), (object_id(2), None)];
        let results = vec![answered(object_id(1)), answered(object_id(2))];

        assert!(check_object_identity(&results, &requested).is_ok());
    }

    #[test]
    fn a_substituted_object_is_rejected_with_both_ids() {
        let requested = [(object_id(1), None), (object_id(2), None)];
        let results = vec![answered(object_id(1)), answered(object_id(9))];

        let err = check_object_identity(&results, &requested).unwrap_err();
        let Error::Protocol(ProtocolError::UnexpectedObject {
            position,
            expected,
            actual,
        }) = err
        else {
            panic!("expected an UnexpectedObject error, got {err}");
        };
        assert_eq!(position, 1);
        assert_eq!(expected, object_id(2));
        assert_eq!(actual, object_id(9));
    }

    #[test]
    fn a_position_the_server_errored_on_has_no_id_to_check() {
        let requested = [(object_id(1), None), (object_id(2), None)];
        let results = vec![
            answered(object_id(1)),
            Err(Error::Server(Status {
                code: tonic::Code::NotFound.into(),
                message: String::new(),
                details: Vec::new(),
            })),
        ];

        assert!(check_object_identity(&results, &requested).is_ok());
    }

    #[test]
    fn an_object_answered_with_bcs_only_is_checked_against_the_id_in_its_bcs() {
        let requested = [(object_id(1), None)];
        let results = vec![Ok(answered_with_bcs_only(object_id(9)))];

        let err = check_object_identity(&results, &requested).unwrap_err();
        let Error::Protocol(ProtocolError::UnexpectedObject {
            expected, actual, ..
        }) = err
        else {
            panic!("expected an UnexpectedObject error, got {err}");
        };
        assert_eq!(expected, object_id(1));
        assert_eq!(actual, object_id(9));
    }

    #[test]
    fn an_object_carrying_neither_a_reference_nor_bcs_has_nothing_to_check() {
        let requested = [(object_id(1), None)];
        let results = vec![Ok(Object::default())];

        assert!(check_object_identity(&results, &requested).is_ok());
    }

    #[test]
    fn a_substituted_transaction_is_rejected_with_both_digests() {
        let requested = [transaction_digest(1), transaction_digest(2)];
        let results = vec![
            Ok(answered_transaction(transaction_digest(1))),
            Ok(answered_transaction(transaction_digest(9))),
        ];

        let err = check_transaction_identity(&results, &requested).unwrap_err();
        let Error::Protocol(ProtocolError::UnexpectedTransaction {
            position,
            expected,
            actual,
        }) = err
        else {
            panic!("expected an UnexpectedTransaction error, got {err}");
        };
        assert_eq!(position, 1);
        assert_eq!(expected, transaction_digest(2));
        assert_eq!(actual, transaction_digest(9));
    }

    #[test]
    fn not_found_is_recognized_at_the_call_and_item_level() {
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
