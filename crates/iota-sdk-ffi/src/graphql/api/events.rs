// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Events API implementation.

use iota_sdk::graphql_client::pagination::Page;

use crate::{
    error::Result,
    graphql::{
        client::GraphQLClient,
        pagination::GraphQLEventPage,
        query_types::{GraphQLEvent, GraphQLEventFilter, GraphQLPaginationFilter},
    },
};

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Return a page of tuple (event, transaction digest) based on the
    /// (optional) event filter.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn events(
        &self,
        filter: Option<GraphQLEventFilter>,
        pagination_filter: Option<GraphQLPaginationFilter>,
    ) -> Result<GraphQLEventPage> {
        let (page_info, events) = self
            .client()
            .events(
                filter.map(|f| f.into()),
                pagination_filter.map(Into::into).unwrap_or_default(),
            )
            .await?
            .into_parts();
        let events = events
            .into_iter()
            .map(GraphQLEvent::from)
            .collect::<Vec<_>>();
        Ok(Page::new(page_info, events).into())
    }
}
