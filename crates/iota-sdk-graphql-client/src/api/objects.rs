// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{Object, ObjectId, Version};

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    pagination::{Direction, Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        ObjectFilter, ObjectQueryArgs, ObjectQueryFragment, ObjectsQueryArgs, ObjectsQueryFragment,
    },
    streams::stream_paginated_query,
};

define_query! {
    /// Query for [`GraphQLClient::objects`]. Await it to send the request.
    pub struct ListObjectsQuery {
        client: GraphQLClient,
        filter: Option<ObjectFilter>,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<Object>>;
}

impl ListObjectsQuery {
    pub(crate) fn new(client: GraphQLClient) -> Self {
        Self {
            client,
            filter: None,
            pagination: PaginationFilter::default(),
        }
    }

    /// Only return the objects that match `filter`.
    pub fn filter(mut self, filter: impl Into<Option<ObjectFilter>>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    fn operation(
        filter: Option<ObjectFilter>,
        pagination: PaginationFilterResponse,
    ) -> cynic::Operation<ObjectsQueryFragment, ObjectsQueryArgs> {
        ObjectsQueryFragment::build(ObjectsQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter,
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<Object>> {
        let Self {
            client,
            pagination,
            filter,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(filter, pagination))
            .await?;

        let oc = response.objects;
        let page_info = oc.page_info;
        let bcs = oc
            .nodes
            .iter()
            .map(|o| &o.bcs)
            .filter_map(|b64| {
                b64.as_ref()
                    .map(|b| base64ct::Base64::decode_vec(b.0.as_str()))
            })
            .collect::<Result<Vec<_>, base64ct::Error>>()?;
        let objects = bcs
            .iter()
            .map(|b| bcs::from_bytes::<iota_types::Object>(b))
            .collect::<Result<Vec<_>, bcs::Error>>()?;

        Ok(Page::new(page_info, objects))
    }
}

define_query! {
    /// Query for [`GraphQLClient::object`]. Await it to send the request.
    pub struct GetObjectQuery {
        client: GraphQLClient,
        object_id: ObjectId,
        version: Option<Version>,
    }
    output: GraphQLResult<Option<Object>>;
}

impl GetObjectQuery {
    /// Set the object version. Defaults to the latest version.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<Object>> {
        let operation = ObjectQueryFragment::build(ObjectQueryArgs {
            object_id: self.object_id,
            version: self.version.map(|v| v.as_u64()),
        });

        let response = self.client.run_query(&operation).await?;

        let obj = response.object;
        let bcs = obj
            .and_then(|o| o.bcs)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            .transpose()?;

        let object = bcs
            .map(|b| bcs::from_bytes::<iota_types::Object>(&b))
            .transpose()?;

        Ok(object)
    }
}

define_query! {
    /// Query for [`GraphQLClient::move_object_contents`]. Await it to send the
    /// request.
    pub struct GetMoveObjectContentsQuery {
        client: GraphQLClient,
        object_id: ObjectId,
        version: Option<Version>,
    }
    output: GraphQLResult<Option<serde_json::Value>>;
}

impl GetMoveObjectContentsQuery {
    /// Set the object version. Defaults to the latest version.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<serde_json::Value>> {
        let operation = ObjectQueryFragment::build(ObjectQueryArgs {
            object_id: self.object_id,
            version: self.version.map(|v| v.as_u64()),
        });

        let response = self.client.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .and_then(|mv| mv.json))
    }
}

define_query! {
    /// Query for [`GraphQLClient::move_object_contents_bcs`]. Await it to send
    /// the request.
    pub struct GetMoveObjectContentsBcsQuery {
        client: GraphQLClient,
        object_id: ObjectId,
        version: Option<Version>,
    }
    output: GraphQLResult<Option<Vec<u8>>>;
}

impl GetMoveObjectContentsBcsQuery {
    /// Set the object version. Defaults to the latest version.
    pub fn version(mut self, version: impl Into<Option<Version>>) -> Self {
        self.version = version.into();
        self
    }

    async fn send(self) -> GraphQLResult<Option<Vec<u8>>> {
        let operation = ObjectQueryFragment::build(ObjectQueryArgs {
            object_id: self.object_id,
            version: self.version.map(|v| v.as_u64()),
        });

        let response = self.client.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.bcs.0.as_str()))
            .transpose()?)
    }
}

impl GraphQLClient {
    /// Return a stream of objects based on the (optional) object filter.
    pub fn objects_stream(
        &self,
        filter: impl Into<Option<ObjectFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = GraphQLResult<Object>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| {
                self.objects()
                    .filter(filter.clone())
                    .pagination(pag_filter)
                    .into_future()
            },
            streaming_direction,
        )
    }

    /// Return an object based on the provided [`Address`](iota_types::Address).
    ///
    /// If the object does not exist (e.g., due to pruning), this will resolve
    /// to `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will resolve to `Ok(None)`.
    pub fn object(&self, object_id: ObjectId) -> GetObjectQuery {
        GetObjectQuery {
            client: self.clone(),
            object_id,
            version: None,
        }
    }

    /// Return a page of objects.
    ///
    /// Use [`ListObjectsQuery::filter`] together with
    /// [`ObjectFilter::with_owner`] to get the objects owned by an address.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let filter = ObjectFilter::default().with_owner(Address::from_str("test").unwrap());
    ///
    /// let owned_objects = client.objects().filter(filter).await;
    /// ```
    pub fn objects(&self) -> ListObjectsQuery {
        ListObjectsQuery::new(self.clone())
    }

    /// Return the object's bcs content [`Vec<u8>`] based on the provided
    /// [`Address`](iota_types::Address).
    pub async fn object_bcs(&self, object_id: ObjectId) -> GraphQLResult<Option<Vec<u8>>> {
        let operation = ObjectQueryFragment::build(ObjectQueryArgs {
            object_id,
            version: None,
        });

        let response = self.run_query(&operation).await.unwrap();

        Ok(response
            .object
            .and_then(|o| {
                o.bcs
                    .map(|bcs| base64ct::Base64::decode_vec(bcs.0.as_str()))
            })
            .transpose()?)
    }

    /// Return the contents JSON of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will resolve
    /// to `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will resolve to `Ok(None)`.
    pub fn move_object_contents(&self, object_id: ObjectId) -> GetMoveObjectContentsQuery {
        GetMoveObjectContentsQuery {
            client: self.clone(),
            object_id,
            version: None,
        }
    }

    /// Return the BCS of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will resolve
    /// to `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will resolve to `Ok(None)`.
    pub fn move_object_contents_bcs(&self, object_id: ObjectId) -> GetMoveObjectContentsBcsQuery {
        GetMoveObjectContentsBcsQuery {
            client: self.clone(),
            object_id,
            version: None,
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::{Address, ObjectId, Version};

    use crate::{
        query_types::ObjectFilter,
        test_utils::{
            assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
            test_client,
        },
    };

    #[tokio::test]
    async fn object_queries_send_the_object_id_and_version() {
        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client
                .object(ObjectId::SYSTEM_STATE)
                .version(Version::from_u64(3))
                .await;
        })
        .await;
        assert_eq!(vars["objectId"], ObjectId::SYSTEM_STATE.to_string());
        assert_eq!(vars["version"], 3);

        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client
                .move_object_contents(ObjectId::SYSTEM_STATE)
                .version(Version::from_u64(4))
                .await;
        })
        .await;
        assert_eq!(vars["objectId"], ObjectId::SYSTEM_STATE.to_string());
        assert_eq!(vars["version"], 4);

        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client
                .move_object_contents_bcs(ObjectId::SYSTEM_STATE)
                .version(Version::from_u64(5))
                .await;
        })
        .await;
        assert_eq!(vars["objectId"], ObjectId::SYSTEM_STATE.to_string());
        assert_eq!(vars["version"], 5);

        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client.object(ObjectId::SYSTEM_STATE).await;
        })
        .await;
        assert!(vars["version"].is_null());

        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client.move_object_contents(ObjectId::SYSTEM_STATE).await;
        })
        .await;
        assert!(vars["version"].is_null());

        let vars = sent_variables("ObjectQueryFragment", |client| async move {
            let _ = client
                .move_object_contents_bcs(ObjectId::SYSTEM_STATE)
                .await;
        })
        .await;
        assert!(vars["version"].is_null());
    }

    #[tokio::test]
    async fn objects_sends_the_filter_and_pagination() {
        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .objects()
                .filter(ObjectFilter::default().with_owner(Address::FRAMEWORK))
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["filter"]["owner"], Address::FRAMEWORK.to_string());
        assert_backward_page(&vars);

        let vars = sent_variables("ObjectsQueryFragment", |client| async move {
            let _ = client
                .objects()
                .filter(ObjectFilter::default().with_owner(Address::FRAMEWORK))
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
    }

    #[tokio::test]
    async fn test_objects_query() {
        let client = test_client();
        let objects = client
            .objects()
            .await
            .map_err(|e| {
                format!(
                    "Objects query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
        assert!(
            !objects.is_empty(),
            "Objects query returned no data for {} network",
            client.rpc_server()
        );
    }

    #[tokio::test]
    async fn test_object_query() {
        let client = test_client();
        client
            .object(ObjectId::SYSTEM_STATE)
            .await
            .map_err(|e| {
                format!(
                    "Object query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_object_bcs_query() {
        let client = test_client();
        client
            .object_bcs(ObjectId::SYSTEM_STATE)
            .await
            .map_err(|e| {
                format!(
                    "Object bcs query failed for {} network: Error {e}",
                    client.rpc_server()
                )
            })
            .unwrap()
            .unwrap();
    }
}
