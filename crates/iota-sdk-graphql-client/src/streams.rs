// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;

use crate::{
    error,
    pagination::{Direction, Page, PaginationFilter},
    query_types::PageInfo,
};

/// A stream that yields items from a paginated query with support for
/// bidirectional pagination.
pub struct PageStream<T, F, Fut> {
    query_fn: F,
    direction: Direction,
    limit: Option<i32>,
    start_cursor: Option<String>,
    current_page: Option<(PageInfo, std::vec::IntoIter<T>)>,
    current_future: Option<Pin<Box<Fut>>>,
    finished: bool,
}

impl<T, F, Fut> PageStream<T, F, Fut> {
    pub fn new(query_fn: F, pagination: PaginationFilter) -> Self {
        Self {
            query_fn,
            direction: pagination.direction,
            limit: pagination.limit,
            start_cursor: pagination.cursor,
            current_page: None,
            current_future: None,
            finished: false,
        }
    }
}

impl<T, F, Fut> Stream for PageStream<T, F, Fut>
where
    T: Clone + Unpin,
    F: Fn(PaginationFilter) -> Fut,
    F: Unpin,
    Fut: Future<Output = Result<Page<T>, error::GraphQLError>>,
{
    type Item = Result<T, error::GraphQLError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }

        loop {
            let direction = self.direction.clone();
            // If we have a current page, return the next item
            if let Some((page_info, iter)) = &mut self.current_page {
                if let Some(item) = iter.next() {
                    return Poll::Ready(Some(Ok(item)));
                }

                let should_continue = match direction {
                    Direction::Forward => page_info.has_next_page,
                    Direction::Backward => page_info.has_previous_page,
                };
                if !should_continue {
                    self.finished = true;
                    return Poll::Ready(None);
                }
            }

            // Get cursor from current page
            let current_cursor = self
                .current_page
                .as_ref()
                .and_then(|(page_info, _iter)| match self.direction {
                    Direction::Forward => page_info
                        .has_next_page
                        .then(|| page_info.end_cursor.clone()),
                    Direction::Backward => page_info
                        .has_previous_page
                        .then(|| page_info.start_cursor.clone()),
                })
                .flatten();

            // If there's no future yet, create one
            if self.current_future.is_none() {
                let current_cursor = if self.current_page.is_none() {
                    self.start_cursor.take()
                } else {
                    current_cursor
                };
                let filter = PaginationFilter {
                    direction: self.direction.clone(),
                    cursor: current_cursor,
                    limit: self.limit,
                };
                let future = (self.query_fn)(filter);
                self.current_future = Some(Box::pin(future));
            }

            // Poll the future
            match self.current_future.as_mut().unwrap().as_mut().poll(cx) {
                Poll::Ready(Ok(page)) => {
                    self.current_future = None;

                    if page.is_empty() {
                        self.finished = true;
                        return Poll::Ready(None);
                    }

                    let (page_info, data) = page.into_parts();
                    // For backward pagination, we need to reverse the items
                    let iter = match self.direction {
                        Direction::Forward => data.into_iter(),
                        Direction::Backward => {
                            let mut vec = data;
                            vec.reverse();
                            vec.into_iter()
                        }
                    };
                    self.current_page = Some((page_info, iter));
                }
                Poll::Ready(Err(e)) => {
                    self.finished = true;
                    self.current_future = None;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Creates a new `PageStream` for a paginated query.
pub fn stream_paginated_query<T, F, Fut>(
    query_fn: F,
    pagination: PaginationFilter,
) -> PageStream<T, F, Fut>
where
    F: Fn(PaginationFilter) -> Fut,
    Fut: Future<Output = Result<Page<T>, error::GraphQLError>>,
{
    PageStream::new(query_fn, pagination)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use futures::StreamExt;
    use iota_types::Address;

    use super::*;
    use crate::{
        error::GraphQLResult,
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

    /// Stream `pages` in order and return the items and the requests made.
    async fn run(
        pagination: PaginationFilter,
        pages: Vec<GraphQLResult<Page<i32>>>,
    ) -> (Vec<GraphQLResult<i32>>, Vec<PaginationFilter>) {
        let pages = std::sync::Mutex::new(pages.into_iter());
        let requests = std::sync::Mutex::new(Vec::new());
        let items = stream_paginated_query(
            |filter: PaginationFilter| {
                requests.lock().unwrap().push(filter);
                let page = pages.lock().unwrap().next().expect("no page left");
                async move { page }
            },
            pagination,
        )
        .collect()
        .await;
        (items, requests.into_inner().unwrap())
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
        let (items, requests) = run(
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
        let (items, requests) = run(
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
        let (items, requests) = run(
            PaginationFilter::default(),
            vec![Ok(page(Vec::new(), true, Some("next")))],
        )
        .await;

        assert!(items.is_empty());
        assert_eq!(requests.len(), 1);
    }

    #[tokio::test]
    async fn an_error_is_yielded_once_and_ends_the_stream() {
        let (items, requests) = run(
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
