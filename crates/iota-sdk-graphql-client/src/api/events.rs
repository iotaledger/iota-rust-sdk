// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Events API implementation.

use cynic::QueryBuilder;
use futures::Stream;

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    pagination::{Page, PaginationFilter, PaginationFilterResponse},
    query_types::{Event, EventFilter, EventsQueryArgs, EventsQueryFragment},
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::events`]. Await it to send the request.
    #[derive(Clone)]
    pub struct ListEventsQuery {
        client: GraphQLClient,
        filter: Option<EventFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<Event>>;
}

impl ListEventsQuery {
    /// Only return the events that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<EventFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> impl Stream<Item = GraphQLResult<Event>> {
        let pagination = self.pagination.clone();
        stream_paginated_query(move |page| self.clone().pagination(page).send(), pagination)
    }

    fn operation<'a>(
        &self,
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<EventsQueryFragment, EventsQueryArgs<'a>> {
        EventsQueryFragment::build(EventsQueryArgs {
            filter: self.filter.clone(),
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<Event>> {
        let pagination = self.client.pagination_filter(self.pagination.clone()).await;
        let response = self.client.run_query(&self.operation(&pagination)).await?;

        let ec = response.events;
        let page_info = ec.page_info;

        let events = ec.nodes;

        Ok(Page::new(page_info, events))
    }
}

impl GraphQLClient {
    /// Return a page of events.
    pub fn events(&self) -> ListEventsQuery {
        ListEventsQuery {
            client: self.clone(),
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::Address;

    use crate::{
        query_types::EventFilter,
        test_utils::{assert_backward_page, backward_page, sent_variables, test_client},
    };

    #[tokio::test]
    async fn events_sends_the_filter_and_pagination() {
        let vars = sent_variables("EventsQueryFragment", |client| async move {
            let _ = client
                .events()
                .filter(EventFilter {
                    sender: Some(Address::FRAMEWORK),
                    ..Default::default()
                })
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["filter"]["sender"], Address::FRAMEWORK.to_string());
        assert_backward_page(&vars);
    }

    #[tokio::test]
    async fn test_events_query() {
        let client = test_client();
        let events = client
            .events()
            .await
            .map_err(|e| {
                format!(
                    "Events query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !events.is_empty(),
            "Events query returned no data for {} network",
            client.rpc_server()
        );
    }
}
