// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;

use crate::{
    api::QueryFuture,
    error::GraphQLResult,
    pagination::{Direction, Page, PaginationFilter},
};

#[cfg(not(target_arch = "wasm32"))]
type PageFn<T> = Box<dyn Fn(PaginationFilter) -> QueryFuture<GraphQLResult<Page<T>>> + Send>;
#[cfg(target_arch = "wasm32")]
type PageFn<T> = Box<dyn Fn(PaginationFilter) -> QueryFuture<GraphQLResult<Page<T>>>>;

/// A stream of the items of a list query, fetched page by page in the
/// direction of its pagination.
///
/// The stream ends after yielding an error. [`PageStream::pagination`] then
/// returns the page that failed, so passing it to the query's `pagination`
/// and streaming again continues where this stream stopped.
pub struct PageStream<T> {
    query_fn: PageFn<T>,
    pagination: PaginationFilter,
    state: State<T>,
}

enum State<T> {
    /// The page of `pagination` is fetched on the next poll.
    Idle,
    Fetching(QueryFuture<GraphQLResult<Page<T>>>),
    /// Yielding the items of the page of `pagination`, then continuing at
    /// `next_cursor` if there is one.
    Yielding {
        items: std::vec::IntoIter<T>,
        next_cursor: Option<String>,
    },
    Done,
}

impl<T> PageStream<T> {
    pub(crate) fn new(pagination: PaginationFilter, query_fn: PageFn<T>) -> Self {
        Self {
            query_fn,
            pagination,
            state: State::Idle,
        }
    }

    /// The pagination of the page the stream is yielding from, or is about
    /// to fetch.
    ///
    /// Streaming again from it repeats the items already yielded from that
    /// page. After an error it is the page that failed to fetch, so no item
    /// is repeated.
    pub fn pagination(&self) -> &PaginationFilter {
        &self.pagination
    }
}

// No field is structurally pinned: the page future is boxed.
impl<T> Unpin for PageStream<T> {}

impl<T> Stream for PageStream<T> {
    type Item = GraphQLResult<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                State::Idle => {
                    this.state = State::Fetching((this.query_fn)(this.pagination.clone()));
                }
                State::Fetching(future) => match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        this.state = State::Done;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(Ok(page)) => {
                        let (page_info, mut items) = page.into_parts();
                        let next_cursor = match this.pagination.direction {
                            Direction::Forward => {
                                page_info.has_next_page.then_some(page_info.end_cursor)
                            }
                            Direction::Backward => {
                                // Yield the items newest first.
                                items.reverse();
                                page_info
                                    .has_previous_page
                                    .then_some(page_info.start_cursor)
                            }
                        };
                        this.state = if items.is_empty() {
                            State::Done
                        } else {
                            State::Yielding {
                                items: items.into_iter(),
                                next_cursor: next_cursor.flatten(),
                            }
                        };
                    }
                },
                State::Yielding { items, next_cursor } => {
                    if let Some(item) = items.next() {
                        return Poll::Ready(Some(Ok(item)));
                    }
                    this.state = match next_cursor.take() {
                        Some(cursor) => {
                            this.pagination.cursor = Some(cursor);
                            State::Idle
                        }
                        None => State::Done,
                    };
                }
                State::Done => return Poll::Ready(None),
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use futures::StreamExt;
    use iota_types::Address;

    use super::*;
    use crate::{
        query_types::PageInfo,
        test_utils::{
            assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
        },
    };

    macro_rules! first_request_of {
        ($operation:expr, $query:expr) => {
            first_request_of!($operation, $query, backward_page())
        };
        ($operation:expr, $query:expr, $page:expr) => {
            sent_variables($operation, |client| async move {
                let _ = $query(client).pagination($page).stream().next().await;
            })
            .await
        };
    }

    fn page(items: Vec<i32>, has_more: bool, cursor: Option<&str>) -> Page<i32> {
        Page::new(
            PageInfo {
                has_previous_page: has_more,
                has_next_page: has_more,
                start_cursor: cursor.map(|c| format!("{c}-backward")),
                end_cursor: cursor.map(|c| format!("{c}-forward")),
            },
            items,
        )
    }

    /// The outcome of streaming a list of pages to its end.
    struct Run {
        items: Vec<GraphQLResult<i32>>,
        requests: Vec<PaginationFilter>,
        /// The stream's pagination once it ended.
        pagination: PaginationFilter,
    }

    /// Stream `pages` in order.
    async fn run(pagination: PaginationFilter, pages: Vec<GraphQLResult<Page<i32>>>) -> Run {
        let pages = std::sync::Mutex::new(pages.into_iter());
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut stream = PageStream::new(
            pagination,
            Box::new({
                let requests = requests.clone();
                move |filter: PaginationFilter| {
                    requests.lock().unwrap().push(filter);
                    let page = pages.lock().unwrap().next().expect("no page left");
                    Box::pin(async move { page })
                }
            }),
        );
        let items = stream.by_ref().collect().await;
        let requests = requests.lock().unwrap().clone();
        Run {
            items,
            requests,
            pagination: stream.pagination().clone(),
        }
    }

    fn values(items: Vec<GraphQLResult<i32>>) -> Vec<i32> {
        items.into_iter().map(Result::unwrap).collect()
    }

    #[tokio::test]
    async fn forward_pages_continue_from_the_end_cursor_with_the_same_limit() {
        let pagination = PaginationFilter {
            direction: Direction::Forward,
            cursor: Some("start".to_owned()),
            limit: Some(3),
        };
        let Run {
            items, requests, ..
        } = run(
            pagination,
            vec![
                Ok(page(vec![1, 2], true, Some("second"))),
                Ok(page(vec![3], false, None)),
            ],
        )
        .await;

        assert_eq!(values(items), [1, 2, 3]);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].cursor.as_deref(), Some("start"));
        assert_eq!(requests[1].cursor.as_deref(), Some("second-forward"));
        assert!(requests.iter().all(|r| r.limit == Some(3)));
        assert!(
            requests
                .iter()
                .all(|r| matches!(r.direction, Direction::Forward))
        );
    }

    #[tokio::test]
    async fn backward_pages_continue_from_the_start_cursor_newest_first() {
        let pagination = PaginationFilter {
            direction: Direction::Backward,
            cursor: Some("start".to_owned()),
            limit: Some(3),
        };
        let Run {
            items, requests, ..
        } = run(
            pagination,
            vec![
                Ok(page(vec![3, 4], true, Some("second"))),
                Ok(page(vec![1, 2], false, None)),
            ],
        )
        .await;

        assert_eq!(values(items), [4, 3, 2, 1]);
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].cursor.as_deref(), Some("start"));
        assert_eq!(requests[1].cursor.as_deref(), Some("second-backward"));
        assert!(requests.iter().all(|r| r.limit == Some(3)));
        assert!(
            requests
                .iter()
                .all(|r| matches!(r.direction, Direction::Backward))
        );
    }

    #[tokio::test]
    async fn an_empty_page_ends_the_stream() {
        let Run {
            items, requests, ..
        } = run(
            PaginationFilter::default(),
            vec![Ok(page(Vec::new(), true, Some("next")))],
        )
        .await;

        assert!(items.is_empty());
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn an_error_is_yielded_once_and_ends_the_stream() {
        let Run {
            items, requests, ..
        } = run(
            PaginationFilter::default(),
            vec![Err(crate::GraphQLError::Timeout)],
        )
        .await;

        assert!(matches!(
            items.as_slice(),
            [Err(crate::GraphQLError::Timeout)]
        ));
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn after_an_error_the_pagination_is_the_page_that_failed() {
        let pagination = PaginationFilter {
            direction: Direction::Backward,
            cursor: Some("start".to_owned()),
            limit: Some(3),
        };
        let Run {
            items,
            pagination: resume,
            ..
        } = run(
            pagination,
            vec![
                Ok(page(vec![3, 4], true, Some("second"))),
                Err(crate::GraphQLError::Timeout),
            ],
        )
        .await;

        assert!(matches!(
            items.as_slice(),
            [Ok(4), Ok(3), Err(crate::GraphQLError::Timeout)]
        ));
        assert_eq!(resume.cursor.as_deref(), Some("second-backward"));
        assert_eq!(resume.limit, Some(3));
        assert!(matches!(resume.direction, Direction::Backward));
    }

    #[tokio::test]
    async fn every_list_query_streams_from_its_pagination() {
        assert_backward_page(&first_request_of!(
            "CheckpointsQueryFragment",
            |c: crate::GraphQLClient| c.checkpoints()
        ));
        assert_forward_page(&first_request_of!(
            "CheckpointsQueryFragment",
            |c: crate::GraphQLClient| c.checkpoints(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.coins(Address::STD)
        ));
        assert_forward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.coins(Address::STD),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.gas_coins(Address::STD)
        ));
        assert_forward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.gas_coins(Address::STD),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "DynamicFieldsOwnerQueryFragment",
            |c: crate::GraphQLClient| c.dynamic_fields(Address::STD)
        ));
        assert_forward_page(&first_request_of!(
            "DynamicFieldsOwnerQueryFragment",
            |c: crate::GraphQLClient| c.dynamic_fields(Address::STD),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "EventsQueryFragment",
            |c: crate::GraphQLClient| c.events()
        ));
        assert_forward_page(&first_request_of!(
            "EventsQueryFragment",
            |c: crate::GraphQLClient| c.events(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "IotaNamesAddressRegistrationsQueryFragment",
            |c: crate::GraphQLClient| c.iota_names_registrations(Address::STD)
        ));
        assert_forward_page(&first_request_of!(
            "IotaNamesAddressRegistrationsQueryFragment",
            |c: crate::GraphQLClient| c.iota_names_registrations(Address::STD),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "ActiveValidatorsQueryFragment",
            |c: crate::GraphQLClient| c.active_validators()
        ));
        assert_forward_page(&first_request_of!(
            "ActiveValidatorsQueryFragment",
            |c: crate::GraphQLClient| c.active_validators(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.objects()
        ));
        assert_forward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.objects(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "PackageVersionsQueryFragment",
            |c: crate::GraphQLClient| c.package_versions(Address::FRAMEWORK)
        ));
        assert_forward_page(&first_request_of!(
            "PackageVersionsQueryFragment",
            |c: crate::GraphQLClient| c.package_versions(Address::FRAMEWORK),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "PackagesQueryFragment",
            |c: crate::GraphQLClient| c.packages()
        ));
        assert_forward_page(&first_request_of!(
            "PackagesQueryFragment",
            |c: crate::GraphQLClient| c.packages(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "TransactionBlocksQueryFragment",
            |c: crate::GraphQLClient| c.transactions()
        ));
        assert_forward_page(&first_request_of!(
            "TransactionBlocksQueryFragment",
            |c: crate::GraphQLClient| c.transactions(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "AddressTransactionsQueryFragment",
            |c: crate::GraphQLClient| c.address_transactions(Address::STD)
        ));
        assert_forward_page(&first_request_of!(
            "AddressTransactionsQueryFragment",
            |c: crate::GraphQLClient| c.address_transactions(Address::STD),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "TransactionBlocksEffectsQueryFragment",
            |c: crate::GraphQLClient| c.transactions_effects()
        ));
        assert_forward_page(&first_request_of!(
            "TransactionBlocksEffectsQueryFragment",
            |c: crate::GraphQLClient| c.transactions_effects(),
            forward_page()
        ));
        assert_backward_page(&first_request_of!(
            "TransactionBlocksWithEffectsQueryFragment",
            |c: crate::GraphQLClient| c.transactions_data_effects()
        ));
        assert_forward_page(&first_request_of!(
            "TransactionBlocksWithEffectsQueryFragment",
            |c: crate::GraphQLClient| c.transactions_data_effects(),
            forward_page()
        ));
    }

    #[cfg(feature = "move-types")]
    #[tokio::test]
    async fn move_objects_streams_from_its_pagination() {
        use iota_move_types::iota_framework::{coin::Coin, iota::IOTA};

        assert_backward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.move_objects::<Coin<IOTA>>()
        ));
        assert_forward_page(&first_request_of!(
            "ObjectsQueryFragment",
            |c: crate::GraphQLClient| c.move_objects::<Coin<IOTA>>(),
            forward_page()
        ));
    }
}
