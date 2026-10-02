// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use futures::{Stream, StreamExt, stream};

use crate::{
    Query, Request, Result,
    transport::MaybeSend,
    wire::{self},
};

/// A position in a paginated list, taken from a [`Page`] to fetch the pages
/// before or after it.
///
/// Cursors are opaque, and only valid for the list they came from. Store one
/// with [`as_str`](Self::as_str) to resume a walk later.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Cursor(String);

impl Cursor {
    /// A cursor from its string form, as returned by [`as_str`](Self::as_str).
    pub fn new(cursor: impl Into<String>) -> Self {
        Self(cursor.into())
    }

    /// The cursor's string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which page of a list to fetch: the connection arguments of the GraphQL
/// field.
///
/// Set through the [`Request`] methods [`first`](Request::first),
/// [`after`](Request::after), [`last`](Request::last) and
/// [`before`](Request::before). A [`Paginated`] query reads them when building
/// its operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PageArgs {
    backward: bool,
    limit: Option<u32>,
    cursor: Option<Cursor>,
}

impl PageArgs {
    /// The `first` argument: the page size when paging forward.
    pub fn first(&self) -> Option<i32> {
        self.limit
            .filter(|_| !self.backward)
            .map(|limit| limit.try_into().unwrap_or(i32::MAX))
    }

    /// The `after` argument: where paging forward starts.
    pub fn after(&self) -> Option<String> {
        self.cursor
            .as_ref()
            .filter(|_| !self.backward)
            .map(|cursor| cursor.0.clone())
    }

    /// The `last` argument: the page size when paging backward.
    pub fn last(&self) -> Option<i32> {
        self.limit
            .filter(|_| self.backward)
            .map(|limit| limit.try_into().unwrap_or(i32::MAX))
    }

    /// The `before` argument: where paging backward starts.
    pub fn before(&self) -> Option<String> {
        self.cursor
            .as_ref()
            .filter(|_| self.backward)
            .map(|cursor| cursor.0.clone())
    }

    /// Whether the pages are fetched from the end of the list.
    pub fn is_backward(&self) -> bool {
        self.backward
    }

    fn set_direction(&mut self, backward: bool) {
        if self.backward != backward {
            *self = Self {
                backward,
                ..Self::default()
            };
        }
    }
}

/// One page of a paginated list.
#[derive(Clone, Debug)]
pub struct Page<T> {
    items: Vec<T>,
    has_previous_page: bool,
    has_next_page: bool,
    start_cursor: Option<Cursor>,
    end_cursor: Option<Cursor>,
}

impl<T> Page<T> {
    /// A page of `items`, with the cursors of its first and last item and
    /// whether the list continues before and after it.
    pub fn new(
        items: Vec<T>,
        has_previous_page: bool,
        has_next_page: bool,
        start_cursor: Option<Cursor>,
        end_cursor: Option<Cursor>,
    ) -> Self {
        Self {
            items,
            has_previous_page,
            has_next_page,
            start_cursor,
            end_cursor,
        }
    }

    pub(crate) fn from_wire(items: Vec<T>, page_info: wire::PageInfo) -> Self {
        Self::new(
            items,
            page_info.has_previous_page,
            page_info.has_next_page,
            page_info.start_cursor.map(Cursor),
            page_info.end_cursor.map(Cursor),
        )
    }

    /// The items, in list order.
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// The items, in list order.
    pub fn into_items(self) -> Vec<T> {
        self.items
    }

    /// The number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the page has no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the list has items before this page.
    pub fn has_previous_page(&self) -> bool {
        self.has_previous_page
    }

    /// Whether the list has items after this page.
    pub fn has_next_page(&self) -> bool {
        self.has_next_page
    }

    /// The cursor of the first item: pass it to [`Request::before`] for the
    /// previous page.
    pub fn start_cursor(&self) -> Option<&Cursor> {
        self.start_cursor.as_ref()
    }

    /// The cursor of the last item: pass it to [`Request::after`] for the next
    /// page.
    pub fn end_cursor(&self) -> Option<&Cursor> {
        self.end_cursor.as_ref()
    }

    /// The same page with `f` applied to every item.
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.start_cursor,
            end_cursor: self.end_cursor,
        }
    }

    pub(crate) fn try_map<U>(self, f: impl FnMut(T) -> Result<U>) -> Result<Page<U>> {
        Ok(Page {
            items: self.items.into_iter().map(f).collect::<Result<_>>()?,
            has_previous_page: self.has_previous_page,
            has_next_page: self.has_next_page,
            start_cursor: self.start_cursor,
            end_cursor: self.end_cursor,
        })
    }

    /// The cursor to continue a walk from, in the given direction, if the
    /// list continues.
    fn continuation(&self, backward: bool) -> Option<Cursor> {
        if self.items.is_empty() {
            return None;
        }
        if backward {
            self.has_previous_page
                .then(|| self.start_cursor.clone())
                .flatten()
        } else {
            self.has_next_page
                .then(|| self.end_cursor.clone())
                .flatten()
        }
    }
}

impl<T> IntoIterator for Page<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// A [`Query`] for one page of a list.
///
/// Its [`Request`] gets the pagination methods and the `pages` and `items`
/// streams.
pub trait Paginated: Query<Output = Page<Self::Item>> + Clone {
    /// The list's items.
    type Item;

    /// The page to fetch.
    fn page_args(&self) -> &PageArgs;

    /// The page to fetch.
    fn page_args_mut(&mut self) -> &mut PageArgs;
}

impl<Q: Paginated> Request<Q> {
    /// Fetch the first `count` items, or the `count` items after the
    /// [`after`](Self::after) cursor. Without it, the server's default page
    /// size applies.
    pub fn first(self, count: u32) -> Self {
        self.map(|mut query| {
            let args = query.page_args_mut();
            args.set_direction(false);
            args.limit = Some(count);
            query
        })
    }

    /// Fetch the items after `cursor`, from a page's
    /// [`end_cursor`](Page::end_cursor).
    pub fn after(self, cursor: Cursor) -> Self {
        self.map(|mut query| {
            let args = query.page_args_mut();
            args.set_direction(false);
            args.cursor = Some(cursor);
            query
        })
    }

    /// Fetch the last `count` items, or the `count` items before the
    /// [`before`](Self::before) cursor. Discards [`first`](Self::first) and
    /// [`after`](Self::after), and vice versa.
    pub fn last(self, count: u32) -> Self {
        self.map(|mut query| {
            let args = query.page_args_mut();
            args.set_direction(true);
            args.limit = Some(count);
            query
        })
    }

    /// Fetch the items before `cursor`, from a page's
    /// [`start_cursor`](Page::start_cursor).
    pub fn before(self, cursor: Cursor) -> Self {
        self.map(|mut query| {
            let args = query.page_args_mut();
            args.set_direction(true);
            args.cursor = Some(cursor);
            query
        })
    }
}

impl<Q> Request<Q>
where
    Q: Paginated + MaybeSend + 'static,
    Q::Variables: MaybeSend + Sync,
{
    /// Fetch page after page, starting with the page this request selects
    /// and continuing in its direction, until the list ends or a request
    /// fails.
    ///
    /// The stream ends after yielding an error. To resume, continue from the
    /// last page received: [`after`](Self::after) its
    /// [`end_cursor`](Page::end_cursor), or [`before`](Self::before) its
    /// [`start_cursor`](Page::start_cursor) when paging backward.
    pub fn pages(self) -> impl Stream<Item = Result<Page<Q::Item>>> {
        stream::unfold(Some(self), |request| async move {
            let request = request?;
            let backward = request.query().page_args().is_backward();
            let next = request.clone();
            match request.await {
                Ok(page) => {
                    let next = page.continuation(backward).map(|cursor| {
                        if backward {
                            next.before(cursor)
                        } else {
                            next.after(cursor)
                        }
                    });
                    Some((Ok(page), next))
                }
                Err(error) => Some((Err(error), None)),
            }
        })
    }

    /// The items of [`pages`](Self::pages), one by one. Paging backward
    /// yields them from the end of the list to its start.
    pub fn items(self) -> impl Stream<Item = Result<Q::Item>> {
        let backward = self.query().page_args().is_backward();
        self.pages().flat_map(move |page| {
            let items = match page {
                Ok(page) => {
                    let mut items = page.into_items();
                    if backward {
                        items.reverse();
                    }
                    items.into_iter().map(Ok).collect()
                }
                Err(error) => vec![Err(error)],
            };
            stream::iter(items)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_direction_discards_the_other_directions_arguments() {
        let mut args = PageArgs::default();
        args.set_direction(false);
        args.limit = Some(5);
        args.cursor = Some(Cursor::new("a"));
        assert_eq!(
            (args.first(), args.after()),
            (Some(5), Some("a".to_owned()))
        );
        assert_eq!((args.last(), args.before()), (None, None));

        args.set_direction(true);
        assert_eq!(
            args,
            PageArgs {
                backward: true,
                ..PageArgs::default()
            }
        );
    }

    #[test]
    fn continuation_follows_the_direction() {
        let page = Page::new(
            vec![1, 2],
            true,
            true,
            Some(Cursor::new("start")),
            Some(Cursor::new("end")),
        );
        assert_eq!(page.continuation(false), Some(Cursor::new("end")));
        assert_eq!(page.continuation(true), Some(Cursor::new("start")));

        let last = Page::new(vec![3], true, false, None, Some(Cursor::new("end")));
        assert_eq!(last.continuation(false), None);

        let empty = Page::<i32>::new(Vec::new(), true, true, None, Some(Cursor::new("end")));
        assert_eq!(empty.continuation(false), None);
    }
}
