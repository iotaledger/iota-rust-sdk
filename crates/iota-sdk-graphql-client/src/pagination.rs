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

    pub fn try_map<F: FnMut(T) -> Result<U, E>, U, E>(self, map_fn: F) -> Result<Page<U>, E> {
        Ok(Page {
            page_info: self.page_info,
            data: self
                .data
                .into_iter()
                .map(map_fn)
                .collect::<Result<_, _>>()?,
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Page<u32> {
        Page::new(
            PageInfo {
                has_previous_page: true,
                has_next_page: true,
                start_cursor: Some("s".to_owned()),
                end_cursor: Some("e".to_owned()),
            },
            vec![1, 2, 3],
        )
    }

    #[test]
    fn try_map_keeps_the_page_info_and_the_order() {
        let page = page().try_map(|n| Ok::<_, ()>(n * 10)).unwrap();
        assert_eq!(page.data, [10, 20, 30]);
        assert!(page.page_info.has_previous_page);
        assert!(page.page_info.has_next_page);
        assert_eq!(page.page_info.start_cursor.as_deref(), Some("s"));
        assert_eq!(page.page_info.end_cursor.as_deref(), Some("e"));
    }

    #[test]
    fn try_map_returns_the_first_error() {
        let result = page().try_map(|n| if n >= 2 { Err(n) } else { Ok(n) });
        assert_eq!(result.err(), Some(2));
    }
}
