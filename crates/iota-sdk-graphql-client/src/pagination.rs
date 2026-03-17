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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_page_info() -> PageInfo {
        PageInfo {
            has_previous_page: false,
            has_next_page: true,
            start_cursor: Some("start".to_string()),
            end_cursor: Some("end".to_string()),
        }
    }

    #[test]
    fn page_new_stores_data_and_info() {
        let page: Page<i32> = Page::new(sample_page_info(), vec![1, 2, 3]);
        assert_eq!(page.data().len(), 3);
        assert!(page.page_info().has_next_page);
    }

    #[test]
    fn page_is_empty_true_when_no_data() {
        let page: Page<i32> = Page::new_empty();
        assert!(page.is_empty());
    }

    #[test]
    fn page_is_empty_false_when_has_data() {
        let page = Page::new(PageInfo::default(), vec![42]);
        assert!(!page.is_empty());
    }

    #[test]
    fn page_new_empty_defaults() {
        let page: Page<String> = Page::new_empty();
        assert!(page.is_empty());
        assert!(!page.page_info().has_next_page);
        assert!(!page.page_info().has_previous_page);
        assert!(page.page_info().start_cursor.is_none());
        assert!(page.page_info().end_cursor.is_none());
    }

    #[test]
    fn page_into_parts_decomposes() {
        let page = Page::new(sample_page_info(), vec![10, 20]);
        let (info, data) = page.into_parts();
        assert_eq!(data, vec![10, 20]);
        assert!(info.has_next_page);
    }

    #[test]
    fn page_map_transforms_data() {
        let page = Page::new(sample_page_info(), vec![1, 2, 3]);
        let mapped = page.map(|x| x * 10);
        assert_eq!(mapped.data(), &[10, 20, 30]);
        // Page info is preserved
        assert!(mapped.page_info().has_next_page);
    }

    #[test]
    fn page_map_empty_page() {
        let page: Page<i32> = Page::new_empty();
        let mapped = page.map(|x| x.to_string());
        assert!(mapped.is_empty());
    }

    #[test]
    fn direction_default_is_forward() {
        let dir = Direction::default();
        assert!(matches!(dir, Direction::Forward));
    }

    #[test]
    fn pagination_filter_default() {
        let filter = PaginationFilter::default();
        assert!(matches!(filter.direction, Direction::Forward));
        assert!(filter.cursor.is_none());
        assert!(filter.limit.is_none());
    }
}
