// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Live `events` / `transactions` streams backed by GraphQL subscriptions over
//! a WebSocket (`graphql-transport-ws`).
//!
//! Unlike the paginated `events` / `transactions` page methods, these stream
//! data as it arrives and never terminate on their own. The stream
//! transparently reconnects on disconnect, resuming from the last item it
//! delivered via the subscription's `startAfter` cursor.

use std::{future::Future, time::Duration};

use cynic::SubscriptionBuilder;
use futures::{Stream, StreamExt};
use iota_types::SignedTransaction;
use reqwest::Url;

use crate::{
    GraphQLClient,
    client::response_to_result,
    error::{GraphQLError, GraphQLResult, query_error},
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

/// Convert a subscription response to a `Result`, surfacing any `errors` as a
/// query error. The server sends no error extensions on subscriptions, so the
/// errors carry no `code`.
fn subscription_response_to_result<T>(response: cynic::GraphQlResponse<T>) -> GraphQLResult<T> {
    response_to_result(cynic::GraphQlResponse {
        data: response.data,
        errors: response
            .errors
            .map(|errors| errors.into_iter().map(query_error).collect()),
    })
}

impl GraphQLClient {
    /// Subscribe to a live stream of events matching the (optional) filter.
    ///
    /// The stream yields events as they arrive and reconnects automatically on
    /// disconnect. `start_after` optionally resumes the stream from the
    /// transaction immediately following the given transaction digest;
    /// thereafter the stream tracks its own resume point.
    ///
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled — `serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available.
    pub fn events_stream(
        &self,
        filter: impl Into<Option<SubscriptionEventFilter>>,
        start_after: impl Into<Option<String>>,
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
                        let data = subscription_response_to_result(
                            item.map_err(GraphQLError::subscription)?,
                        )?;
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
    /// Note: subscriptions are served over a WebSocket, which the node has to
    /// have enabled — `serviceConfig.enabledFeatures` includes `SUBSCRIPTIONS`
    /// when it is available.
    pub fn transactions_stream(
        &self,
        filter: impl Into<Option<SubscriptionTransactionFilter>>,
        start_after: impl Into<Option<String>>,
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
                            let data = subscription_response_to_result(
                                item.map_err(GraphQLError::subscription)?,
                            )?;
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
/// and must yield a stream of decoded [`Outcome`]s. Connection and transport
/// errors are surfaced to the consumer and then trigger a backed-off reconnect;
/// the stream itself never terminates.
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
                                yield Err(error);
                                break;
                            }
                        }
                    }
                }
                Err(error) => yield Err(error),
            }
            crate::wait::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use cynic::{GraphQlError as CynicError, GraphQlErrorPathSegment, GraphQlResponse};

    use super::*;

    #[test]
    fn errors_surface_as_query_errors_without_a_code() {
        let response = GraphQlResponse {
            data: None::<()>,
            errors: Some(vec![CynicError::new(
                "boom".to_owned(),
                None,
                Some(vec![GraphQlErrorPathSegment::Field("events".to_owned())]),
                Some(Default::default()),
            )]),
        };

        let GraphQLError::Query(errors) = subscription_response_to_result(response).unwrap_err()
        else {
            panic!("expected GraphQLError::Query");
        };
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "boom");
        assert_eq!(
            errors[0].path,
            Some(vec![GraphQlErrorPathSegment::Field("events".to_owned())])
        );
        assert_eq!(errors[0].extensions, None);
    }

    #[test]
    fn data_without_errors_is_returned() {
        let response = GraphQlResponse {
            data: Some(1),
            errors: None,
        };
        assert_eq!(subscription_response_to_result(response).unwrap(), 1);
    }
}
