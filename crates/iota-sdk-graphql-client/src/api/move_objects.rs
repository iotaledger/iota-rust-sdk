// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Typed object queries, decoding each object into a Move-type mirror.

use futures::Stream;
use iota_move_types::MoveObject;
use iota_types::{Address, ObjectId};

use crate::{
    Client,
    error::Result,
    pagination::{Direction, Page, PaginationFilter},
    query_types::ObjectFilter,
    streams::stream_paginated_query,
};

/// Filter for the typed object queries.
///
/// [`ObjectFilter`] without its type field: the Move type comes from the type
/// parameter, so there is no second place to set it and nothing to disagree
/// about.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MoveObjectFilter {
    /// Filter by the address owning the object.
    pub owner: Option<Address>,
    /// Filter by object ids.
    pub object_ids: Option<Vec<ObjectId>>,
}

impl MoveObjectFilter {
    /// Filter by the address owning the object.
    pub fn with_owner(mut self, owner: impl Into<Option<Address>>) -> Self {
        self.owner = owner.into();
        self
    }

    /// Filter by object ids.
    pub fn with_object_ids(mut self, object_ids: impl Into<Option<Vec<ObjectId>>>) -> Self {
        self.object_ids = object_ids.into();
        self
    }

    /// Widen into an [`ObjectFilter`] pinned to `T`'s Move type.
    fn into_object_filter<T: MoveObject>(self) -> ObjectFilter {
        ObjectFilter {
            type_tag: Some(T::struct_tag().to_string()),
            owner: self.owner,
            object_ids: self.object_ids,
        }
    }
}

impl Client {
    /// Return a page of objects of the Move type `T`, decoded into `T`.
    ///
    /// The type filter is derived from `T`, so unlike [`Client::objects`] this
    /// needs no type string and no separate decode step.
    ///
    /// # Errors
    ///
    /// Returns an error if any object in the page fails to decode. The query
    /// filters on `T`'s exact type, so a failure means the on-chain type has
    /// moved out from under the mirror rather than that one object is odd —
    /// yielding the rest of the page would hide that.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let staked: Page<StakedIota> = client
    ///     .move_objects(MoveObjectFilter::default().with_owner(address), Default::default())
    ///     .await?;
    /// ```
    pub async fn move_objects<T: MoveObject>(
        &self,
        filter: impl Into<Option<MoveObjectFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<T>> {
        let filter = filter.into().unwrap_or_default().into_object_filter::<T>();
        let page = self.objects(filter, pagination_filter).await?;
        let (page_info, objects) = page.into_parts();
        let decoded = objects
            .iter()
            .map(T::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Page::new(page_info, decoded))
    }

    /// Return a stream of objects of the Move type `T`, decoded into `T`.
    ///
    /// Page-by-page equivalent of [`Client::move_objects`]; the same decode
    /// failure ends the stream with an error.
    pub fn move_objects_stream<'a, T>(
        &'a self,
        filter: impl Into<Option<MoveObjectFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<T>> + 'a
    where
        T: MoveObject + Clone + Unpin + 'a,
    {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.move_objects(filter.clone(), pag_filter),
            streaming_direction,
        )
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use iota_move_types::iota_framework::{coin::Coin, iota::IOTA};

    use super::*;
    use crate::test_utils::test_client;

    #[tokio::test]
    async fn test_move_objects_query() {
        let client = test_client();
        let coins = client
            .move_objects::<Coin<IOTA>>(None, PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Move objects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !coins.is_empty(),
            "Move objects query returned no data for {} network",
            client.rpc_server()
        );
    }

    /// The type filter comes from `T`, so a page reached this way holds only
    /// objects of that type — every one of them decoded, or the call failed.
    #[tokio::test]
    async fn test_move_objects_stream() {
        let client = test_client();
        let mut stream =
            Box::pin(client.move_objects_stream::<Coin<IOTA>>(None, Direction::Forward));
        stream
            .next()
            .await
            .unwrap_or_else(|| {
                panic!(
                    "Move objects stream yielded nothing for {} network",
                    client.rpc_server()
                )
            })
            .map_err(|e| {
                format!(
                    "Move objects stream failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }
}
