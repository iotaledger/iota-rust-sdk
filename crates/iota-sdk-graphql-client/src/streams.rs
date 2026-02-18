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
    current_page: Option<(PageInfo, std::vec::IntoIter<T>)>,
    current_future: Option<Pin<Box<Fut>>>,
    finished: bool,
    is_first_page: bool,
}

impl<T, F, Fut> PageStream<T, F, Fut> {
    pub fn new(query_fn: F, direction: Direction) -> Self {
        Self {
            query_fn,
            direction,
            current_page: None,
            current_future: None,
            finished: false,
            is_first_page: true,
        }
    }
}

impl<T, F, Fut> Stream for PageStream<T, F, Fut>
where
    T: Clone + Unpin,
    F: Fn(PaginationFilter) -> Fut,
    F: Unpin,
    Fut: Future<Output = Result<Page<T>, error::Error>>,
{
    type Item = Result<T, error::Error>;

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

                // For backward pagination, we check for previous page
                // For the first page in backward pagination, we don't need to check
                // has_previous_page
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
                .and_then(|(page_info, _iter)| {
                    match self.direction {
                        Direction::Forward => page_info
                            .has_next_page
                            .then(|| page_info.end_cursor.clone()),
                        Direction::Backward => {
                            // For the first page in backward pagination, we don't use a cursor
                            // This ensures we start from the last page
                            if self.is_first_page {
                                None
                            } else {
                                page_info
                                    .has_previous_page
                                    .then(|| page_info.start_cursor.clone())
                            }
                        }
                    }
                })
                .flatten();

            // If there's no future yet, create one
            if self.current_future.is_none() {
                if self.is_first_page && current_cursor.is_some() {
                    self.is_first_page = false;
                }
                let filter = PaginationFilter {
                    direction: self.direction.clone(),
                    cursor: current_cursor,
                    limit: None,
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

                    if self.is_first_page {
                        self.is_first_page = false;
                    }
                }
                Poll::Ready(Err(e)) => {
                    if self.is_first_page {
                        self.is_first_page = false;
                    }
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
///
/// ## Example
///
/// ```rust,ignore
/// use futures::StreamExt;
/// use iota_graphql_client::streams::stream_paginated_query;
/// use iota_graphql_client::Client;
/// use iota_graphql_client::PaginationFilter;
/// use iota_graphql_client::Direction;
///
/// let client = Client::new_testnet();
/// let stream = stream_paginated_query(|pagination_filter, Direction::Forward| {
///    client.coins(owner, coin_type, pagination_filter)
/// });
///
/// while let Some(result) = stream.next().await {
///    match result {
///        Ok(coin) => println!("Got coin: {:?}", coin),
///        Err(e) => eprintln!("Error: {}", e),
///    }
/// }
/// ```
pub fn stream_paginated_query<T, F, Fut>(query_fn: F, direction: Direction) -> PageStream<T, F, Fut>
where
    F: Fn(PaginationFilter) -> Fut,
    Fut: Future<Output = Result<Page<T>, error::Error>>,
{
    PageStream::new(query_fn, direction)
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;
    use crate::{pagination::Page, query_types::PageInfo};

    // Helper to create a PageInfo
    fn page_info(has_next: bool, has_prev: bool) -> PageInfo {
        PageInfo {
            has_next_page: has_next,
            has_previous_page: has_prev,
            start_cursor: Some("start".to_string()),
            end_cursor: Some("end".to_string()),
        }
    }

    // --- stream_paginated_query factory tests ---

    #[tokio::test]
    async fn stream_empty_returns_no_items() {
        let stream = stream_paginated_query(
            |_filter: PaginationFilter| async {
                Ok::<Page<i32>, error::Error>(Page::<i32>::new_empty())
            },
            Direction::Forward,
        );
        let results: Vec<Result<i32, _>> = stream.collect().await;
        assert!(results.is_empty());
    }

    // --- Forward pagination tests ---

    #[tokio::test]
    async fn stream_forward_single_page() {
        let stream = stream_paginated_query(
            |_filter: PaginationFilter| async {
                Ok(Page::new(
                    page_info(false, false), // no more pages
                    vec![1, 2, 3],
                ))
            },
            Direction::Forward,
        );

        let results: Vec<Result<i32, _>> = stream.collect().await;
        let values: Vec<i32> = results.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn stream_forward_multiple_pages() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();

        let stream = stream_paginated_query(
            move |_filter: PaginationFilter| {
                let count = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    match count {
                        0 => Ok(Page::new(page_info(true, false), vec![1, 2])),
                        1 => Ok(Page::new(page_info(false, false), vec![3, 4])),
                        _ => Ok(Page::<i32>::new_empty()),
                    }
                }
            },
            Direction::Forward,
        );

        let results: Vec<i32> = stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(results, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn stream_forward_empty_page_stops() {
        let stream = stream_paginated_query(
            |_filter: PaginationFilter| async { Ok(Page::<i32>::new_empty()) },
            Direction::Forward,
        );

        let results: Vec<Result<i32, _>> = stream.collect().await;
        assert!(results.is_empty());
    }

    // --- Backward pagination tests ---

    #[tokio::test]
    async fn stream_backward_reverses_items() {
        let stream = stream_paginated_query(
            |_filter: PaginationFilter| async {
                Ok(Page::new(
                    page_info(false, false),
                    vec![1, 2, 3], // Server returns in natural order
                ))
            },
            Direction::Backward,
        );

        let results: Vec<i32> = stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        // Backward pagination reverses items
        assert_eq!(results, vec![3, 2, 1]);
    }

    // --- Error propagation tests ---

    #[tokio::test]
    async fn stream_error_propagation() {
        let stream = stream_paginated_query(
            |_filter: PaginationFilter| async {
                Err(error::Error::from_message(
                    error::Kind::Query,
                    "query failed".to_string(),
                ))
            },
            Direction::Forward,
        );

        let results: Vec<Result<i32, _>> = stream.collect().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[tokio::test]
    async fn stream_error_stops_iteration() {
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = call_count.clone();

        let stream = stream_paginated_query(
            move |_filter: PaginationFilter| {
                let count = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    match count {
                        0 => Err(error::Error::from_message(
                            error::Kind::Query,
                            "fail".to_string(),
                        )),
                        _ => Ok(Page::new(page_info(false, false), vec![1])),
                    }
                }
            },
            Direction::Forward,
        );

        let results: Vec<Result<i32, _>> = stream.collect().await;
        // Should only have the error, no further items
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }
}
