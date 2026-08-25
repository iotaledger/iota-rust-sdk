// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Events API implementation.

use cynic::QueryBuilder;

use crate::{
    Client,
    error::Result,
    pagination::{Page, PaginationFilter},
    query_types::{Event, EventFilter, EventsQuery, EventsQueryArgs},
};

impl Client {
    /// Return a page of events based on the (optional) event filter.
    pub async fn events(
        &self,
        filter: impl Into<Option<EventFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Event>> {
        let pagination = self.pagination_filter(pagination_filter).await;

        let operation = EventsQuery::build(EventsQueryArgs {
            filter: filter.into(),
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

        let ec = response.events;
        let page_info = ec.page_info;

        let events = ec.nodes;

        Ok(Page::new(page_info, events))
    }
}

#[cfg(test)]
mod tests {
    use crate::{PaginationFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_events_query() {
        let client = test_client();
        let events = client
            .events(None, PaginationFilter::default())
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
