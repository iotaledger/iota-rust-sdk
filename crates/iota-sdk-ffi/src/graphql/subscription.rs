// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Live `events` / `transactions` subscriptions.
//!
//! The Rust API exposes these as a `Stream`, which has no uniffi equivalent, so
//! each subscription is a handle object that is pulled one item at a time with
//! `next`. The handle owns a clone of the client, so later calls to
//! [`GraphQLClient::set_rpc_server`] do not affect a subscription already
//! opened.

use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use futures::stream::BoxStream;
#[cfg(target_arch = "wasm32")]
use futures::stream::LocalBoxStream;
use futures::{Stream, StreamExt};
use iota_sdk::graphql_client::error::GraphQLResult;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        query_types::{GraphQLEvent, TransactionBlockKindInput},
    },
    stream::StreamHandle,
    types::{address::Address, transaction::SignedTransaction},
};

/// Filter incoming events in a subscription. Exactly one field must be set.
#[derive(Default, uniffi::Record)]
pub struct SubscriptionEventFilter {
    /// Filter incoming events by emitting module, e.g. `"0x02"` (package) or
    /// `"0x02::coin"` (module).
    #[uniffi(default = None)]
    pub emitting_module: Option<String>,
}

impl From<SubscriptionEventFilter>
    for iota_sdk::graphql_client::query_types::SubscriptionEventFilter
{
    fn from(value: SubscriptionEventFilter) -> Self {
        Self::default().with_emitting_module(value.emitting_module)
    }
}

/// Filter incoming transactions in a subscription. Exactly one field must be
/// set.
#[derive(Default, uniffi::Record)]
pub struct SubscriptionTransactionFilter {
    /// Filter incoming transactions by kind.
    #[uniffi(default = None)]
    pub kind: Option<TransactionBlockKindInput>,
    /// Filter incoming transactions by sender address.
    ///
    /// Only the sender is compared, despite the name: a sponsored transaction
    /// is not matched by its sponsor's (gas owner's) address, even though the
    /// sponsor also signed it.
    #[uniffi(default = None)]
    pub signing_address: Option<Arc<Address>>,
    /// Filter incoming transactions by package, module, or function name, e.g.
    /// `"0x03"`, `"0x03::iota_system"`, or
    /// `"0x03::iota_system::request_add_stake"`.
    #[uniffi(default = None)]
    pub function: Option<String>,
}

impl From<SubscriptionTransactionFilter>
    for iota_sdk::graphql_client::query_types::SubscriptionTransactionFilter
{
    fn from(value: SubscriptionTransactionFilter) -> Self {
        Self::default()
            .with_kind(value.kind.map(Into::into))
            .with_signing_address(value.signing_address.map(|a| a.0))
            .with_function(value.function)
    }
}

/// The boxed stream a subscription handle reads from.
///
/// On wasm the reconnect backoff is driven by a `setTimeout` future that is not
/// `Send`, so the stream is boxed thread-locally there. uniffi's
/// `wasm-unstable-single-threaded` drops the `Send + Sync` bound it would
/// otherwise place on an exported object, which is what lets the handle hold
/// one.
#[cfg(not(target_arch = "wasm32"))]
type SubscriptionStream<T> = BoxStream<'static, GraphQLResult<T>>;
#[cfg(target_arch = "wasm32")]
type SubscriptionStream<T> = LocalBoxStream<'static, GraphQLResult<T>>;

#[cfg(not(target_arch = "wasm32"))]
fn box_stream<T: 'static>(
    stream: impl Stream<Item = GraphQLResult<T>> + Send + 'static,
) -> SubscriptionStream<T> {
    stream.boxed()
}

#[cfg(target_arch = "wasm32")]
fn box_stream<T: 'static>(
    stream: impl Stream<Item = GraphQLResult<T>> + 'static,
) -> SubscriptionStream<T> {
    stream.boxed_local()
}

macro_rules! define_subscription {
    ($name:ident, $update:ident, $variant:ident, $field:ident, $item:ty, $ffi_item:ty, $convert:expr) => {
        /// An item delivered by a subscription.
        ///
        /// A subscription recovers from a lost connection or from falling behind
        /// the server on its own, so those interruptions are delivered as
        /// updates rather than raised as errors: a caller that does not care
        /// about the gap can ignore them and keep reading.
        #[derive(uniffi::Enum)]
        pub enum $update {
            $variant {
                $field: $ffi_item,
            },
            /// Delivery was interrupted and has recovered: the connection
            /// dropped, or the server dropped payloads because this client
            /// could not keep up. Items in the gap may have been missed.
            Interrupted {
                message: String,
            },
        }

        /// A live subscription.
        ///
        /// Call `next` in a loop to receive updates; it only returns `None` once
        /// `cancel` has been called, since the subscription itself never ends.
        #[derive(uniffi::Object)]
        pub struct $name(StreamHandle<SubscriptionStream<$item>>);

        #[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
        #[cfg_attr(target_arch = "wasm32", uniffi::export)]
        impl $name {
            /// Wait for the next update.
            ///
            /// Returns `None` once the subscription has been canceled.
            /// Concurrent calls are serialized; there is no ordering guarantee
            /// between them.
            ///
            /// Raises for errors the subscription cannot recover from by
            /// itself, such as a rejected filter. The subscription stays
            /// usable afterwards, so a caller that considers the error
            /// transient can keep calling `next`.
            pub async fn next(&self) -> Result<Option<$update>> {
                match self.0.next().await {
                    Some(Ok(item)) => Ok(Some($update::$variant {
                        $field: ($convert)(item)?,
                    })),
                    Some(Err(error)) if is_recoverable(&error) => Ok(Some($update::Interrupted {
                        message: error.to_string(),
                    })),
                    Some(Err(error)) => Err(error.into()),
                    None => Ok(None),
                }
            }

            /// Cancel the subscription, dropping the connection and unblocking
            /// a pending `next`.
            ///
            /// Idempotent, and safe to call while `next` is pending. The
            /// pending call drops the connection on its way out.
            ///
            /// Named `cancel` rather than `close` because a `close` method
            /// collides with the disposal method uniffi generates for objects
            /// in some languages.
            pub fn cancel(&self) {
                self.0.cancel();
            }

            /// Whether the subscription has been canceled.
            pub fn is_canceled(&self) -> bool {
                self.0.is_canceled()
            }
        }

        impl $name {
            fn new(stream: SubscriptionStream<$item>) -> Self {
                Self(StreamHandle::new(stream))
            }
        }
    };
}

define_subscription!(
    EventSubscription,
    EventUpdate,
    Event,
    event,
    iota_sdk::graphql_client::query_types::Event,
    GraphQLEvent,
    GraphQLEvent::try_from
);
define_subscription!(
    TransactionSubscription,
    TransactionUpdate,
    Transaction,
    transaction,
    iota_sdk::types::SignedTransaction,
    SignedTransaction,
    |transaction| Result::<SignedTransaction>::Ok(SignedTransaction::from(transaction))
);

/// Whether the subscription recovers from `error` on its own, in which case it
/// is reported as an interruption instead of being raised.
///
/// These are exactly the transport-level failures the reconnect loop handles:
/// a dropped WebSocket, a failed handshake, or the server dropping payloads for
/// a client that fell behind.
fn is_recoverable(error: &iota_sdk::graphql_client::error::GraphQLError) -> bool {
    matches!(
        error,
        iota_sdk::graphql_client::error::GraphQLError::Subscription(_)
            | iota_sdk::graphql_client::error::GraphQLError::Lagged { .. }
    )
}

/// Open the event stream a subscription handle reads from.
fn open_events(
    client: iota_sdk::graphql_client::GraphQLClient,
    filter: Option<SubscriptionEventFilter>,
    start_after: Option<String>,
) -> SubscriptionStream<iota_sdk::graphql_client::query_types::Event> {
    let filter = filter.map(Into::into);
    box_stream(async_stream::stream! {
        let client = client;
        let mut stream = std::pin::pin!(client.events_stream(filter, start_after));
        while let Some(item) = stream.next().await {
            yield item;
        }
    })
}

/// Open the transaction stream a subscription handle reads from.
fn open_transactions(
    client: iota_sdk::graphql_client::GraphQLClient,
    filter: Option<SubscriptionTransactionFilter>,
    start_after: Option<String>,
) -> SubscriptionStream<iota_sdk::types::SignedTransaction> {
    let filter = filter.map(Into::into);
    box_stream(async_stream::stream! {
        let client = client;
        let mut stream = std::pin::pin!(client.transactions_stream(filter, start_after));
        while let Some(item) = stream.next().await {
            yield item;
        }
    })
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// `start_after` optionally resumes from the transaction immediately
    /// following the given transaction digest; thereafter the subscription
    /// tracks its own resume point across reconnects.
    ///
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled (`serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available).
    #[uniffi::method(default(filter = None, start_after = None))]
    pub async fn events_subscription(
        &self,
        filter: Option<SubscriptionEventFilter>,
        start_after: Option<String>,
    ) -> EventSubscription {
        let client = self.0.read().await.clone();
        EventSubscription::new(open_events(client, filter, start_after))
    }

    /// Subscribe to a live stream of transactions matching the (optional)
    /// filter.
    ///
    /// `start_after` optionally resumes from the transaction immediately
    /// following the given digest; thereafter the subscription tracks its own
    /// resume point across reconnects.
    ///
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled (`serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available).
    #[uniffi::method(default(filter = None, start_after = None))]
    pub async fn transactions_subscription(
        &self,
        filter: Option<SubscriptionTransactionFilter>,
        start_after: Option<String>,
    ) -> TransactionSubscription {
        let client = self.0.read().await.clone();
        TransactionSubscription::new(open_transactions(client, filter, start_after))
    }
}
