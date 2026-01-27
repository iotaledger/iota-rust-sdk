// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Events API implementation.

use iota_sdk::graphql_client::pagination::PaginationFilter;

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, pagination::EventPage},
    types::graphql::EventFilter,
};

#[uniffi::export(async_runtime = "tokio")]
impl GraphQLClient {
    // ===========================================================================
    // Events API
    // ===========================================================================

    /// Return a page of tuple (event, transaction digest) based on the
    /// (optional) event filter.
    #[uniffi::method(default(pagination_filter = None, filter = None))]
    pub async fn events(
        &self,
        filter: Option<EventFilter>,
        pagination_filter: Option<PaginationFilter>,
    ) -> Result<EventPage> {
        Ok(self
            .0
            .read()
            .await
            .events(
                filter.map(|f| f.into()),
                pagination_filter.unwrap_or_default(),
            )
            .await?
            .map(Into::into)
            .into())
    }
}
