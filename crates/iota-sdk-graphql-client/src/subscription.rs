// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Live `events` / `transactions` streams backed by GraphQL subscriptions over
//! a WebSocket (`graphql-transport-ws`).
//!
//! Unlike the paginated `events` / `transactions` page methods, these stream
//! data as it arrives. The stream transparently reconnects on disconnect,
//! resuming from the last item it delivered via the subscription's
//! `startAfter` cursor, and ends only on an error reconnecting cannot fix.

use std::{future::Future, time::Duration};

use cynic::SubscriptionBuilder;
use futures::{Stream, StreamExt};
use iota_types::{SignedTransaction, TransactionDigest};
use reqwest::Url;

use crate::{
    GraphQLClient,
    client::response_to_err,
    error::{GraphQLError, GraphQLResult},
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
/// The WebSocket subprotocol subscriptions are served over.
const WS_PROTOCOL: &str = "graphql-transport-ws";

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

impl GraphQLClient {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// The stream yields events as they arrive and reconnects automatically on
    /// disconnect. `start_after` optionally resumes the stream from the
    /// transaction immediately following the given transaction digest, such as
    /// [`Event::transaction_digest`] of the last event processed;
    /// thereafter the stream tracks its own resume point.
    ///
    /// Transport failures and [`GraphQLError::Lagged`] are yielded and the
    /// stream continues; any other error is yielded and ends the stream.
    ///
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled — `serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available.
    pub fn events_stream(
        &self,
        filter: impl Into<Option<SubscriptionEventFilter>>,
        start_after: impl Into<Option<TransactionDigest>>,
    ) -> impl Stream<Item = GraphQLResult<Event>> + Unpin + '_ {
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

                    // Events from a single transaction arrive contiguously, so a transaction is
                    // only fully received once an event from the next one shows up. Advance the
                    // resume cursor to the previous transaction's digest only when the digest
                    // changes.
                    let mut current_tx: Option<String> = None;
                    let mapped = subscription.map(move |item| -> GraphQLResult<Outcome<Event>> {
                        let data = response_to_err(item.map_err(GraphQLError::subscription)?)?;
                        Ok(match data.events {
                            EventSubscriptionPayload::Event(event) => {
                                let digest = event
                                    .transaction_block
                                    .as_ref()
                                    .and_then(|tx| tx.digest.clone());
                                let mut cursor = None;
                                if let Some(new) = digest
                                    && current_tx.as_ref() != Some(&new)
                                {
                                    cursor = current_tx.replace(new);
                                }
                                Outcome::Item {
                                    value: *event,
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
            start_after.into().map(|digest| digest.to_string()),
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
    /// Transport failures and [`GraphQLError::Lagged`] are yielded and the
    /// stream continues; any other error is yielded and ends the stream.
    ///
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled — `serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available.
    pub fn transactions_stream(
        &self,
        filter: impl Into<Option<SubscriptionTransactionFilter>>,
        start_after: impl Into<Option<TransactionDigest>>,
    ) -> impl Stream<Item = GraphQLResult<SignedTransaction>> + Unpin + '_ {
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

                    let mapped =
                        subscription.map(|item| -> GraphQLResult<Outcome<SignedTransaction>> {
                            let data = response_to_err(item.map_err(GraphQLError::subscription)?)?;
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
            start_after.into().map(|digest| digest.to_string()),
        )
    }

    /// Derive the WebSocket URL for subscriptions from the configured RPC URL,
    /// upgrading the scheme (`http` → `ws`, `https` → `wss`).
    fn ws_url(&self) -> GraphQLResult<Url> {
        let mut url = self.rpc.clone();
        match url.scheme() {
            "https" => url.set_scheme("wss"),
            "http" => url.set_scheme("ws"),
            "ws" | "wss" => Ok(()),
            other => {
                return Err(GraphQLError::UnsupportedSubscriptionScheme(
                    other.to_owned(),
                ));
            }
        }
        .map_err(|_| GraphQLError::subscription("failed to derive the WebSocket URL"))?;
        url.set_path("/subscriptions");
        Ok(url)
    }

    /// Open a WebSocket and start `operation`, returning the response stream.
    async fn open_subscription<Operation>(
        &self,
        operation: Operation,
    ) -> GraphQLResult<graphql_ws_client::Subscription<Operation>>
    where
        Operation: graphql_ws_client::graphql::GraphqlOperation + Unpin + Send + 'static,
    {
        let connection = connect(&self.ws_url()?).await?;
        graphql_ws_client::Client::build(connection)
            .subscribe(operation)
            .await
            .map_err(GraphQLError::subscription)
    }
}

/// Open a WebSocket to `url`, negotiating the `graphql-transport-ws`
/// subprotocol.
///
/// The two transports negotiate it differently: tungstenite sets it as a header
/// on the upgrade request, while a browser `WebSocket` rejects arbitrary
/// headers and takes the subprotocol as a constructor argument instead.
#[cfg(not(target_arch = "wasm32"))]
async fn connect(url: &Url) -> GraphQLResult<impl graphql_ws_client::Connection + Send + 'static> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(GraphQLError::subscription)?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(WS_PROTOCOL),
    );
    let (connection, _response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(GraphQLError::subscription)?;
    Ok(connection)
}

#[cfg(target_arch = "wasm32")]
async fn connect(url: &Url) -> GraphQLResult<impl graphql_ws_client::Connection + Send + 'static> {
    let connection = ws_stream_wasm::WsMeta::connect(url.as_str(), Some(vec![WS_PROTOCOL]))
        .await
        .map_err(GraphQLError::subscription)?;
    Ok(graphql_ws_client::ws_stream_wasm::Connection::new(connection).await)
}

/// Wrap a connect-and-subscribe closure in an auto-reconnecting stream.
///
/// `connect` is called with the current resume cursor on every (re)connection
/// and must yield a stream of decoded [`Outcome`]s. Transport errors are
/// surfaced to the consumer and then trigger a backed-off reconnect; any other
/// error is surfaced and ends the stream.
fn reconnecting_subscription<'a, T, C, Fut, S>(
    connect: C,
    initial_cursor: Option<String>,
) -> impl Stream<Item = GraphQLResult<T>> + Unpin + 'a
where
    T: 'a,
    C: Fn(Option<String>) -> Fut + 'a,
    Fut: Future<Output = GraphQLResult<S>> + 'a,
    S: Stream<Item = GraphQLResult<Outcome<T>>> + Unpin + 'a,
{
    Box::pin(async_stream::stream! {
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
                            // A negative count cannot happen; report 0
                            // rather than its magnitude.
                            Ok(Outcome::Lagged(count)) => yield Err(GraphQLError::Lagged {
                                count: u32::try_from(count).unwrap_or(0),
                            }),
                            Ok(Outcome::Skip) => {}
                            Err(error) => {
                                let reconnect = is_transport_error(&error);
                                yield Err(error);
                                if !reconnect {
                                    return;
                                }
                                break;
                            }
                        }
                    }
                }
                Err(error) => {
                    let reconnect = is_transport_error(&error);
                    yield Err(error);
                    if !reconnect {
                        return;
                    }
                }
            }
            crate::wait::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    })
}

/// Whether `error` is a transport failure that reconnecting can fix.
fn is_transport_error(error: &GraphQLError) -> bool {
    matches!(error, GraphQLError::Subscription(_))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::cell::Cell;

    use futures::{StreamExt, stream};

    use super::*;

    #[tokio::test]
    async fn fatal_connect_error_ends_the_stream() {
        let attempts = Cell::new(0);
        let mut stream = reconnecting_subscription(
            |_| {
                attempts.set(attempts.get() + 1);
                async {
                    GraphQLResult::<stream::Empty<GraphQLResult<Outcome<()>>>>::Err(
                        GraphQLError::UnsupportedSubscriptionScheme("ftp".to_owned()),
                    )
                }
            },
            None,
        );

        assert!(matches!(
            stream.next().await,
            Some(Err(GraphQLError::UnsupportedSubscriptionScheme(_)))
        ));
        assert!(stream.next().await.is_none());
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn fatal_item_error_ends_the_stream() {
        let mut stream = reconnecting_subscription(
            |_| async {
                Ok(stream::iter([
                    Ok(Outcome::Item {
                        value: 1,
                        cursor: None,
                    }),
                    Err(GraphQLError::EmptyResponse),
                    Ok(Outcome::Item {
                        value: 2,
                        cursor: None,
                    }),
                ]))
            },
            None,
        );

        assert!(matches!(stream.next().await, Some(Ok(1))));
        assert!(matches!(
            stream.next().await,
            Some(Err(GraphQLError::EmptyResponse))
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn transport_error_reconnects_from_the_cursor() {
        let cursors = std::cell::RefCell::new(Vec::new());
        let mut stream = reconnecting_subscription(
            |cursor| {
                cursors.borrow_mut().push(cursor);
                async {
                    Ok(stream::iter([
                        Ok(Outcome::Item {
                            value: (),
                            cursor: Some("tx".to_owned()),
                        }),
                        Err(GraphQLError::subscription("connection reset")),
                    ]))
                }
            },
            Some("start".to_owned()),
        );

        assert!(matches!(stream.next().await, Some(Ok(()))));
        assert!(matches!(
            stream.next().await,
            Some(Err(GraphQLError::Subscription(_)))
        ));
        assert!(matches!(stream.next().await, Some(Ok(()))));
        drop(stream);
        assert_eq!(
            *cursors.borrow(),
            [Some("start".to_owned()), Some("tx".to_owned())]
        );
    }
}
