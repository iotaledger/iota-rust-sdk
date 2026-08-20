// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Live `events` / `transactions` subscriptions.
//!
//! The Rust API exposes these as a `Stream`, which has no uniffi equivalent, so
//! each subscription is a handle object that is pulled one item at a time with
//! `next`. The handle owns a clone of the client, so later calls to
//! [`GraphQLClient::set_rpc_server`] do not affect a subscription already
//! opened.
//!
//! The WebSocket transport is not built for wasm32, but the API is still
//! exported there: the wasm bindings are generated from the same interface as
//! the native ones, so leaving the methods out would leave the generated glue
//! referencing symbols the wasm library does not export. On wasm `next` raises
//! instead of delivering anything.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use futures::{StreamExt, stream::BoxStream};
use iota_sdk::graphql_client::{
    error::Result as GqlResult, query_types::TransactionBlockKindInput,
};
use tokio::sync::{Mutex, Notify};

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::GraphQlEvent},
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

#[cfg(not(target_arch = "wasm32"))]
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
    /// Only the sender is compared, despite the name — a sponsored transaction
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

#[cfg(not(target_arch = "wasm32"))]
impl From<SubscriptionTransactionFilter>
    for iota_sdk::graphql_client::query_types::SubscriptionTransactionFilter
{
    fn from(value: SubscriptionTransactionFilter) -> Self {
        Self::default()
            .with_kind(value.kind)
            .with_signing_address(value.signing_address.map(|a| a.0))
            .with_function(value.function)
    }
}

/// A cancelation flag that a pending `next` can wait on.
///
/// Foreign async support is uneven — Kotlin, Swift and Python can cancel a
/// pending call, Go and C# cannot — so cancelation has to be something the
/// subscription itself understands rather than something the caller's runtime
/// does to it.
#[derive(Default)]
struct Cancel {
    canceled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_canceled(&self) -> bool {
        self.canceled.load(Ordering::Acquire)
    }

    /// Resolve once [`Cancel::cancel`] has been called.
    #[cfg(not(target_arch = "wasm32"))]
    async fn wait(&self) {
        loop {
            // Register for a wake-up before reading the flag, so a `cancel`
            // racing with this call cannot be missed.
            let notified = self.notify.notified();
            if self.is_canceled() {
                return;
            }
            notified.await;
        }
    }
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
            /// Delivery was interrupted and has recovered — the connection
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
        pub struct $name {
            stream: Mutex<BoxStream<'static, GqlResult<$item>>>,
            cancel: Cancel,
        }

        #[uniffi::export(async_runtime = "tokio")]
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
                self.next_update().await
            }

            /// Cancel the subscription, dropping the connection and unblocking
            /// a pending `next`.
            ///
            /// Idempotent, and safe to call while `next` is pending — the
            /// pending call drops the connection on its way out.
            ///
            /// Named `cancel` rather than `close` because a `close` method
            /// collides with the disposal method uniffi generates for objects
            /// in some languages.
            pub fn cancel(&self) {
                self.cancel.cancel();
                if let Ok(mut stream) = self.stream.try_lock() {
                    *stream = Self::drained();
                }
            }

            /// Whether the subscription has been canceled.
            pub fn is_canceled(&self) -> bool {
                self.cancel.is_canceled()
            }
        }

        impl $name {
            fn new(stream: BoxStream<'static, GqlResult<$item>>) -> Self {
                Self {
                    stream: Mutex::new(stream),
                    cancel: Cancel::default(),
                }
            }

            /// The stream a canceled subscription is left with, so that
            /// canceling drops the WebSocket instead of holding it until the
            /// handle is freed.
            fn drained() -> BoxStream<'static, GqlResult<$item>> {
                futures::stream::empty().boxed()
            }

            #[cfg(not(target_arch = "wasm32"))]
            async fn next_update(&self) -> Result<Option<$update>> {
                if self.cancel.is_canceled() {
                    return Ok(None);
                }
                let mut stream = self.stream.lock().await;
                let canceled = std::pin::pin!(self.cancel.wait());
                let item = match futures::future::select(canceled, stream.next()).await {
                    futures::future::Either::Left(((), _)) => {
                        *stream = Self::drained();
                        None
                    }
                    futures::future::Either::Right((item, _)) => item,
                };
                match item {
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

            #[cfg(target_arch = "wasm32")]
            async fn next_update(&self) -> Result<Option<$update>> {
                Err(unsupported())
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
    GraphQlEvent,
    GraphQlEvent::try_from
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
/// [`Kind::Subscription`] covers exactly the transport-level failures the
/// reconnect loop handles — a dropped WebSocket, a failed handshake, or the
/// server dropping payloads for a client that fell behind.
#[cfg(not(target_arch = "wasm32"))]
fn is_recoverable(error: &iota_sdk::graphql_client::error::Error) -> bool {
    matches!(
        error.kind(),
        iota_sdk::graphql_client::error::Kind::Subscription
    )
}

#[cfg(target_arch = "wasm32")]
fn unsupported() -> crate::error::SdkFfiError {
    crate::error::SdkFfiError::custom(
        "GraphQL subscriptions are unavailable in this build: the WebSocket transport they rely on is not built for wasm32",
    )
}

/// Open the event stream a subscription handle reads from.
#[cfg(not(target_arch = "wasm32"))]
fn open_events(
    client: iota_sdk::graphql_client::Client,
    filter: Option<SubscriptionEventFilter>,
    start_after: Option<String>,
) -> BoxStream<'static, GqlResult<iota_sdk::graphql_client::query_types::Event>> {
    let filter = filter.map(Into::into);
    async_stream::stream! {
        let client = client;
        let mut stream = std::pin::pin!(client.events_stream(filter, start_after));
        while let Some(item) = stream.next().await {
            yield item;
        }
    }
    .boxed()
}

/// Stand-in for the wasm build, where `next` raises instead of reading a
/// stream.
#[cfg(target_arch = "wasm32")]
fn open_events(
    _client: iota_sdk::graphql_client::Client,
    _filter: Option<SubscriptionEventFilter>,
    _start_after: Option<String>,
) -> BoxStream<'static, GqlResult<iota_sdk::graphql_client::query_types::Event>> {
    futures::stream::empty().boxed()
}

/// Open the transaction stream a subscription handle reads from.
#[cfg(not(target_arch = "wasm32"))]
fn open_transactions(
    client: iota_sdk::graphql_client::Client,
    filter: Option<SubscriptionTransactionFilter>,
    start_after: Option<String>,
) -> BoxStream<'static, GqlResult<iota_sdk::types::SignedTransaction>> {
    let filter = filter.map(Into::into);
    async_stream::stream! {
        let client = client;
        let mut stream = std::pin::pin!(client.transactions_stream(filter, start_after));
        while let Some(item) = stream.next().await {
            yield item;
        }
    }
    .boxed()
}

/// Stand-in for the wasm build, where `next` raises instead of reading a
/// stream.
#[cfg(target_arch = "wasm32")]
fn open_transactions(
    _client: iota_sdk::graphql_client::Client,
    _filter: Option<SubscriptionTransactionFilter>,
    _start_after: Option<String>,
) -> BoxStream<'static, GqlResult<iota_sdk::types::SignedTransaction>> {
    futures::stream::empty().boxed()
}

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// `start_after` optionally resumes from the transaction immediately
    /// following the given transaction digest; thereafter the subscription
    /// tracks its own resume point across reconnects.
    ///
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only. They are unavailable altogether
    /// in the wasm build, where `next` raises.
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
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only. They are unavailable altogether
    /// in the wasm build, where `next` raises.
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
