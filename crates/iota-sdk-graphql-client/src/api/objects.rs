// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{Object, ObjectId, Version};

use crate::{
    Client,
    error::Result,
    pagination::{Direction, Page, PaginationFilter},
    query_types::{ObjectFilter, ObjectQuery, ObjectQueryArgs, ObjectsQuery, ObjectsQueryArgs},
    streams::stream_paginated_query,
};

impl Client {
    /// Return a stream of objects based on the (optional) object filter.
    pub fn objects_stream(
        &self,
        filter: impl Into<Option<ObjectFilter>>,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<Object>> + '_ {
        let filter = filter.into();
        stream_paginated_query(
            move |pag_filter| self.objects(filter.clone(), pag_filter),
            streaming_direction,
        )
    }

    /// Return an object based on the provided [`Address`](iota_types::Address).
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into().map(|v| v.as_u64()),
        });

        let response = self.run_query(&operation).await?;

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

    /// Return a page of objects based on the provided parameters.
    ///
    /// Use this function together with the
    /// [`ObjectFilter::with_owner`] to get the objects owned by an address.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let filter = ObjectFilter::default().with_owner(Address::from_str("test").unwrap());
    ///
    /// let owned_objects = client.objects(filter, PaginationFilter::default()).await;
    /// ```
    pub async fn objects(
        &self,
        filter: impl Into<Option<ObjectFilter>>,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<Object>> {
        let pagination = self.pagination_filter(pagination_filter).await;
        let operation = ObjectsQuery::build(ObjectsQueryArgs {
            after: pagination.after,
            before: pagination.before,
            filter: filter.into(),
            first: pagination.first,
            last: pagination.last,
        });

        let response = self.run_query(&operation).await?;

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

    /// Return the object's bcs content [`Vec<u8>`] based on the provided
    /// [`Address`](iota_types::Address).
    pub async fn object_bcs(&self, object_id: ObjectId) -> Result<Option<Vec<u8>>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
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
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn move_object_contents(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<serde_json::Value>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into().map(|v| v.as_u64()),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .and_then(|mv| mv.json))
    }

    /// Return the BCS of an object that is a Move object.
    ///
    /// If the object does not exist (e.g., due to pruning), this will return
    /// `Ok(None)`. Similarly, if this is not an object but an address, it
    /// will return `Ok(None)`.
    pub async fn move_object_contents_bcs(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Vec<u8>>> {
        let operation = ObjectQuery::build(ObjectQueryArgs {
            object_id,
            version: version.into().map(|v| v.as_u64()),
        });

        let response = self.run_query(&operation).await?;

        Ok(response
            .object
            .and_then(|o| o.as_move_object)
            .and_then(|o| o.contents)
            .map(|bcs| base64ct::Base64::decode_vec(bcs.bcs.0.as_str()))
            .transpose()?)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::ObjectId;

    use crate::{PaginationFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_objects_query() {
        let client = test_client();
        let objects = client
            .objects(None, PaginationFilter::default())
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
            .object(ObjectId::SYSTEM_STATE, None)
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
