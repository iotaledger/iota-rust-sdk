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
//! Not available on wasm32: the transport relies on `tokio-tungstenite`.

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

/// Filter incoming events in a subscription. Exactly one field may be set.
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
        Self {
            emitting_module: value.emitting_module,
        }
    }
}

/// Filter incoming transactions in a subscription. Exactly one field may be
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

impl From<SubscriptionTransactionFilter>
    for iota_sdk::graphql_client::query_types::SubscriptionTransactionFilter
{
    fn from(value: SubscriptionTransactionFilter) -> Self {
        Self {
            kind: value.kind,
            signing_address: value.signing_address.map(|address| address.0),
            function: value.function,
        }
    }
}

/// A cancellation flag that a pending `next` can wait on.
///
/// Foreign async support is uneven — Kotlin, Swift and Python can cancel a
/// pending call, Go and C# cannot — so cancellation has to be something the
/// subscription itself understands rather than something the caller's runtime
/// does to it.
#[derive(Default)]
struct Cancel {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Resolve once [`Cancel::cancel`] has been called.
    async fn wait(&self) {
        loop {
            // Register for a wake-up before reading the flag, so a `cancel`
            // racing with this call cannot be missed.
            let notified = self.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

macro_rules! define_subscription {
    ($name:ident, $item:ty, $ffi_item:ty, $convert:expr) => {
        /// A live subscription.
        ///
        /// Call `next` in a loop to receive items; it only returns `None` once
        /// `cancel` has been called, since the subscription itself never ends.
        ///
        /// Errors are not terminal. A dropped connection or a server-side lag
        /// is reported through `next` and the subscription reconnects, so a
        /// caller that wants to keep going can simply call `next` again.
        #[derive(uniffi::Object)]
        pub struct $name {
            stream: Mutex<BoxStream<'static, GqlResult<$item>>>,
            cancel: Cancel,
        }

        #[uniffi::export(async_runtime = "tokio")]
        impl $name {
            /// Wait for the next item.
            ///
            /// Returns `None` once the subscription has been cancelled.
            /// Concurrent calls are serialized; there is no ordering guarantee
            /// between them.
            pub async fn next(&self) -> Result<Option<$ffi_item>> {
                if self.cancel.is_cancelled() {
                    return Ok(None);
                }
                let mut stream = self.stream.lock().await;
                let cancelled = std::pin::pin!(self.cancel.wait());
                let item = match futures::future::select(cancelled, stream.next()).await {
                    futures::future::Either::Left(((), _)) => {
                        *stream = Self::drained();
                        None
                    }
                    futures::future::Either::Right((item, _)) => item,
                };
                match item {
                    Some(Ok(item)) => Ok(Some(($convert)(item)?)),
                    Some(Err(error)) => Err(error.into()),
                    None => Ok(None),
                }
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

            /// Whether the subscription has been cancelled.
            pub fn is_cancelled(&self) -> bool {
                self.cancel.is_cancelled()
            }
        }

        impl $name {
            fn new(stream: BoxStream<'static, GqlResult<$item>>) -> Self {
                Self {
                    stream: Mutex::new(stream),
                    cancel: Cancel::default(),
                }
            }

            /// The stream a cancelled subscription is left with, so that
            /// cancelling drops the WebSocket instead of holding it until the
            /// handle is freed.
            fn drained() -> BoxStream<'static, GqlResult<$item>> {
                futures::stream::empty().boxed()
            }
        }
    };
}

define_subscription!(
    EventSubscription,
    iota_sdk::graphql_client::query_types::Event,
    GraphQlEvent,
    GraphQlEvent::try_from
);
define_subscription!(
    TransactionSubscription,
    iota_sdk::types::SignedTransaction,
    SignedTransaction,
    |transaction| Result::<SignedTransaction>::Ok(SignedTransaction::from(transaction))
);

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// `start_after` optionally resumes from the transaction immediately
    /// following the given transaction digest; thereafter the subscription
    /// tracks its own resume point across reconnects.
    ///
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only.
    #[uniffi::method(default(filter = None, start_after = None))]
    pub async fn events_subscription(
        &self,
        filter: Option<SubscriptionEventFilter>,
        start_after: Option<String>,
    ) -> EventSubscription {
        let client = self.0.read().await.clone();
        let filter = filter.map(Into::into);
        EventSubscription::new(
            async_stream::stream! {
                let client = client;
                let mut stream = std::pin::pin!(client.events_stream(filter, start_after));
                while let Some(item) = stream.next().await {
                    yield item;
                }
            }
            .boxed(),
        )
    }

    /// Subscribe to a live stream of transactions matching the (optional)
    /// filter.
    ///
    /// `start_after` optionally resumes from the transaction immediately
    /// following the given digest; thereafter the subscription tracks its own
    /// resume point across reconnects.
    ///
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only.
    #[uniffi::method(default(filter = None, start_after = None))]
    pub async fn transactions_subscription(
        &self,
        filter: Option<SubscriptionTransactionFilter>,
        start_after: Option<String>,
    ) -> TransactionSubscription {
        let client = self.0.read().await.clone();
        let filter = filter.map(Into::into);
        TransactionSubscription::new(
            async_stream::stream! {
                let client = client;
                let mut stream = std::pin::pin!(client.transactions_stream(filter, start_after));
                while let Some(item) = stream.next().await {
                    yield item;
                }
            }
            .boxed(),
        )
    }
}
