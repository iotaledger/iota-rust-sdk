// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Live `events` / `transactions` streams backed by GraphQL subscriptions over
//! a WebSocket (`graphql-transport-ws`).
//!
//! Unlike the paginated `events` / `transactions` page methods, these stream
//! data as it arrives and never terminate on their own. The stream
//! transparently reconnects on disconnect, resuming from the last item it
//! delivered via the subscription's `startAfter` cursor.
//!
//! Only built for non-wasm targets; the transport relies on
//! `tokio-tungstenite`.

use std::{future::Future, time::Duration};

use cynic::SubscriptionBuilder;
use futures::{Stream, StreamExt};
use iota_types::SignedTransaction;
use reqwest::Url;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

use crate::{
    Client,
    error::{Error, Kind, Result},
    query_types::{
        Event, EventSubscriptionPayload, EventsSubscription, EventsSubscriptionArgs,
        SubscriptionEventFilter, SubscriptionTransactionFilter,
        TransactionBlockSubscriptionPayload, TransactionsSubscription,
        TransactionsSubscriptionArgs,
    },
};

/// Backoff applied before the first reconnect attempt, doubled on each
/// consecutive failure up to [`MAX_BACKOFF`] and reset once an item is
/// received.
const INITIAL_BACKOFF: Duration = Duration::from_millis(250);
/// Upper bound on the reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// The result of decoding a single subscription payload.
enum Outcome<T> {
    /// A delivered item, along with the resume cursor to use should the
    /// connection drop after this item (`None` leaves the cursor unchanged).
    Item { value: T, cursor: Option<String> },
    /// The server dropped `count` payloads before this one.
    Lagged(i32),
    /// A payload that carries nothing to yield (unknown union variant or an
    /// empty response).
    Skip,
}

impl Client {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// The stream yields events as they arrive and reconnects automatically on
    /// disconnect. `start_after` optionally resumes the stream from the
    /// transaction immediately following the given transaction digest;
    /// thereafter the stream tracks its own resume point.
    ///
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only.
    pub fn events_stream(
        &self,
        filter: impl Into<Option<SubscriptionEventFilter>>,
        start_after: impl Into<Option<String>>,
    ) -> impl Stream<Item = Result<Event>> + '_ {
        let filter = filter.into();
        reconnecting_subscription(
            move |cursor| {
                let filter = filter.clone();
                async move {
                    let operation = EventsSubscription::build(EventsSubscriptionArgs {
                        start_after: cursor,
                        filter,
                    });
                    let subscription = self.open_subscription(operation).await?;

                    // Events from a single transaction arrive contiguously, so a
                    // transaction is only fully received once an event from the
                    // next one shows up. Advance the resume cursor to the
                    // previous transaction's digest only when the digest changes.
                    let mut current_tx: Option<String> = None;
                    let mapped = subscription.map(move |item| -> Result<Outcome<Event>> {
                        let data = decode_data(item?)?;
                        Ok(match data.events {
                            EventSubscriptionPayload::Event(event) => {
                                let digest = event.transaction_digest();
                                let mut cursor = None;
                                if let Some(new) = &digest
                                    && current_tx.as_deref() != Some(new.as_str())
                                {
                                    cursor = current_tx.take();
                                    current_tx = Some(new.clone());
                                }
                                Outcome::Item {
                                    value: Event::from(*event),
                                    cursor,
                                }
                            }
                            EventSubscriptionPayload::Lagged(lagged) => {
                                Outcome::Lagged(lagged.count)
                            }
                            EventSubscriptionPayload::Unknown => Outcome::Skip,
                        })
                    });
                    Ok(mapped.boxed())
                }
            },
            start_after.into(),
        )
    }

    /// Subscribe to a live stream of transactions matching the (optional)
    /// filter.
    ///
    /// The stream yields transactions as they arrive and reconnects
    /// automatically on disconnect. `start_after` optionally resumes the stream
    /// from the transaction immediately following the given digest; thereafter
    /// the stream tracks its own resume point.
    ///
    /// Note: subscriptions are served over a WebSocket and are currently
    /// supported on devnet and localnet only.
    pub fn transactions_stream(
        &self,
        filter: impl Into<Option<SubscriptionTransactionFilter>>,
        start_after: impl Into<Option<String>>,
    ) -> impl Stream<Item = Result<SignedTransaction>> + '_ {
        let filter = filter.into();
        reconnecting_subscription(
            move |cursor| {
                let filter = filter.clone();
                async move {
                    let operation = TransactionsSubscription::build(TransactionsSubscriptionArgs {
                        start_after: cursor,
                        filter,
                    });
                    let subscription = self.open_subscription(operation).await?;

                    let mapped = subscription.map(|item| -> Result<Outcome<SignedTransaction>> {
                        let data = decode_data(item?)?;
                        Ok(match data.transactions {
                            TransactionBlockSubscriptionPayload::TransactionBlock(block) => {
                                let cursor = block.digest.clone();
                                Outcome::Item {
                                    value: SignedTransaction::try_from(block)?,
                                    cursor,
                                }
                            }
                            TransactionBlockSubscriptionPayload::Lagged(lagged) => {
                                Outcome::Lagged(lagged.count)
                            }
                            TransactionBlockSubscriptionPayload::Unknown => Outcome::Skip,
                        })
                    });
                    Ok(mapped.boxed())
                }
            },
            start_after.into(),
        )
    }

    /// Derive the WebSocket URL for subscriptions from the configured RPC URL,
    /// upgrading the scheme (`http` → `ws`, `https` → `wss`).
    fn ws_url(&self) -> Result<Url> {
        let mut url = self.rpc.clone();
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" => "ws",
            "ws" | "wss" => return Ok(url),
            other => {
                return Err(Error::from_message(
                    Kind::Subscription,
                    format!("unsupported RPC scheme for subscriptions: {other}"),
                ));
            }
        };
        url.set_scheme(scheme).map_err(|_| {
            Error::from_message(
                Kind::Subscription,
                "failed to derive the WebSocket URL".to_string(),
            )
        })?;
        Ok(url)
    }

    /// Open a WebSocket and start `operation`, returning the response stream.
    async fn open_subscription<Operation>(
        &self,
        operation: Operation,
    ) -> Result<graphql_ws_client::Subscription<Operation>>
    where
        Operation: graphql_ws_client::graphql::GraphqlOperation + Unpin + Send + 'static,
    {
        let url = self.ws_url()?;
        let mut request = url.as_str().into_client_request()?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("graphql-transport-ws"),
        );
        let (connection, _response) = tokio_tungstenite::connect_async(request).await?;
        Ok(graphql_ws_client::Client::build(connection)
            .subscribe(operation)
            .await?)
    }
}

/// Decode the data payload from a subscription response, surfacing GraphQL
/// errors and treating an empty response as a skippable payload.
fn decode_data<T>(response: cynic::GraphQlResponse<T>) -> Result<T> {
    match (response.data, response.errors) {
        (Some(data), _) => Ok(data),
        (None, Some(errors)) => Err(Error::graphql_error(errors)),
        (None, None) => Err(Error::empty_response_error()),
    }
}

/// Wrap a connect-and-subscribe closure in an auto-reconnecting stream.
///
/// `connect` is called with the current resume cursor on every (re)connection
/// and must yield a stream of decoded [`Outcome`]s. Connection and transport
/// errors are surfaced to the consumer and then trigger a backed-off reconnect;
/// the stream itself never terminates.
fn reconnecting_subscription<'a, T, C, Fut, S>(
    connect: C,
    initial_cursor: Option<String>,
) -> impl Stream<Item = Result<T>> + 'a
where
    T: 'a,
    C: Fn(Option<String>) -> Fut + 'a,
    Fut: Future<Output = Result<S>> + 'a,
    S: Stream<Item = Result<Outcome<T>>> + Unpin + 'a,
{
    async_stream::stream! {
        let mut cursor = initial_cursor;
        let mut backoff = INITIAL_BACKOFF;
        loop {
            match connect(cursor.clone()).await {
                Ok(mut subscription) => {
                    while let Some(item) = subscription.next().await {
                        match item {
                            Ok(Outcome::Item { value, cursor: next }) => {
                                if next.is_some() {
                                    cursor = next;
                                }
                                backoff = INITIAL_BACKOFF;
                                yield Ok(value);
                            }
                            Ok(Outcome::Lagged(count)) => yield Err(Error::lagged(count)),
                            Ok(Outcome::Skip) => {}
                            Err(error) => {
                                yield Err(error);
                                break;
                            }
                        }
                    }
                }
                Err(error) => yield Err(error),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }
}
