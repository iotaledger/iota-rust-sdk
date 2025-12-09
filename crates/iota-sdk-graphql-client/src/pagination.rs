// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::PageInfo;

/// A page of items returned by the GraphQL server.
#[derive(Clone, Debug)]
pub struct Page<T> {
    /// Information about the page, such as the cursor and whether there are
    /// more pages.
    pub page_info: PageInfo,
    /// The data returned by the server.
    pub data: Vec<T>,
}

impl<T> Page<T> {
    /// Return the page information.
    pub fn page_info(&self) -> &PageInfo {
        &self.page_info
    }

    /// Return the data in the page.
    pub fn data(&self) -> &[T] {
        &self.data
    }

    /// Create a new page with the provided data and page information.
    pub fn new(page_info: PageInfo, data: Vec<T>) -> Self {
        Self { page_info, data }
    }

    /// Check if the page has no data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Create a page with no data.
    pub fn new_empty() -> Self {
        Self::new(PageInfo::default(), vec![])
    }

    /// Return a tuple of page info and the data.
    pub fn into_parts(self) -> (PageInfo, Vec<T>) {
        (self.page_info, self.data)
    }

    pub fn map<F: Fn(T) -> U, U>(self, map_fn: F) -> Page<U> {
        Page {
            page_info: self.page_info,
            data: self.data.into_iter().map(map_fn).collect(),
        }
    }
}

/// Pagination direction.
#[derive(Clone, Debug, Default)]
pub enum Direction {
    #[default]
    Forward,
    Backward,
}

/// Pagination options for querying the GraphQL server. It defaults to forward
/// pagination with the GraphQL server's max page size.
#[derive(Clone, Debug, Default)]
pub struct PaginationFilter {
    /// The direction of pagination.
    pub direction: Direction,
    /// An opaque cursor used for pagination.
    pub cursor: Option<String>,
    /// The maximum number of items to return. If this is omitted, it will
    /// lazily query the service configuration for the max page size.
    pub limit: Option<i32>,
}

#[derive(Clone, Debug, Default)]
pub struct PaginationFilterResponse {
    pub after: Option<String>,
    pub before: Option<String>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}
