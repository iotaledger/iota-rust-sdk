// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Typed object queries, decoding each object into a Move-type mirror paired
//! with its object reference.

use std::marker::PhantomData;

use iota_move_types::MoveObject;
use iota_types::{Address, ObjectId, ObjectReference};

use crate::{
    GraphQLClient, ListObjectsQuery,
    api::define_query,
    error::GraphQLResult,
    pagination::{Page, PaginationFilter},
    query_types::ObjectFilter,
    streams::PageStream,
};

/// An object of the Move type `T`, decoded into `T`.
#[derive(Clone, Debug)]
pub struct OwnedMoveObject<T> {
    object_ref: ObjectReference,
    object: T,
}

impl<T> OwnedMoveObject<T> {
    /// Get the object's reference.
    pub fn object_ref(&self) -> ObjectReference {
        self.object_ref
    }

    /// Get the object's contents.
    pub fn object(&self) -> &T {
        &self.object
    }

    /// Consume the object and return its contents.
    pub fn into_object(self) -> T {
        self.object
    }
}

/// Filter for the typed object queries.
///
/// [`ObjectFilter`] without its type field: the Move type comes from the type
/// parameter, so there is no second place to set it and nothing to disagree
/// about.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MoveObjectFilter {
    /// Filter by the address owning the object.
    owner: Option<Address>,
    /// Filter by object ids.
    object_ids: Option<Vec<ObjectId>>,
}

impl MoveObjectFilter {
    /// Filter by the address owning the object.
    pub fn with_owner(mut self, owner: Address) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Filter by object ids.
    pub fn with_object_ids(mut self, object_ids: Vec<ObjectId>) -> Self {
        self.object_ids = Some(object_ids);
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

define_query! {
    /// Query for [`GraphQLClient::move_objects`]. Await it to send the request.
    pub struct ListMoveObjectsQuery<T: MoveObject> {
        client: GraphQLClient,
        filter: Option<MoveObjectFilter>,
        pagination: PaginationFilter,
        _marker: PhantomData<fn() -> T>,
    }
    output: GraphQLResult<Page<OwnedMoveObject<T>>>;
}

impl<T: MoveObject> Clone for ListMoveObjectsQuery<T> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            filter: self.filter.clone(),
            pagination: self.pagination.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T: MoveObject> ListMoveObjectsQuery<T> {
    /// Only return the objects that match `filter`.
    pub fn filter(mut self, filter: MoveObjectFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> PageStream<OwnedMoveObject<T>>
    where
        T: 'static,
    {
        let pagination = self.pagination.clone();
        PageStream::new(
            pagination,
            Box::new(move |page| self.clone().pagination(page).into_future()),
        )
    }

    fn objects_query(self) -> ListObjectsQuery {
        ListObjectsQuery::new(self.client)
            .filter(self.filter.unwrap_or_default().into_object_filter::<T>())
            .pagination(self.pagination)
    }

    async fn send(self) -> GraphQLResult<Page<OwnedMoveObject<T>>> {
        let page = self.objects_query().await?;
        let (page_info, objects) = page.into_parts();
        let decoded = objects
            .iter()
            .map(|object| {
                Ok(OwnedMoveObject {
                    object_ref: object.object_ref(),
                    object: T::try_from(object)?,
                })
            })
            .collect::<GraphQLResult<Vec<_>>>()?;
        Ok(Page::new(page_info, decoded))
    }
}

impl GraphQLClient {
    /// Return a page of objects of the Move type `T`, decoded into `T` and
    /// paired with their object references.
    ///
    /// The type filter is derived from `T`, so unlike
    /// [`GraphQLClient::objects`] this needs no type string and no separate
    /// decode step.
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
    /// let staked: Page<OwnedMoveObject<StakedIota>> = client
    ///     .move_objects()
    ///     .filter(MoveObjectFilter::default().with_owner(address))
    ///     .await?;
    /// ```
    pub fn move_objects<T: MoveObject>(&self) -> ListMoveObjectsQuery<T> {
        ListMoveObjectsQuery {
            client: self.clone(),
            filter: None,
            pagination: PaginationFilter::default(),
            _marker: PhantomData,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use futures::StreamExt;
    use iota_move_types::iota_framework::{coin::Coin, iota::IOTA};

    use super::*;
    use crate::test_utils::{
        assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
        test_client,
    };

    #[tokio::test]
    async fn move_objects_sends_the_type_filter_and_pagination() {
        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .move_objects::<Coin<IOTA>>()
                .filter(MoveObjectFilter::default().with_owner(Address::STD))
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["filter"]["owner"], Address::STD.to_string());
        assert_eq!(
            vars["filter"]["type"],
            Coin::<IOTA>::struct_tag().to_string()
        );
        assert_backward_page(&vars);

        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .move_objects::<Coin<IOTA>>()
                .filter(MoveObjectFilter::default().with_owner(Address::STD))
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
    }

    #[tokio::test]
    async fn test_move_objects_query() {
        let client = test_client();
        let coins = client
            .move_objects::<Coin<IOTA>>()
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
        let mut stream = client.move_objects::<Coin<IOTA>>().stream();
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
