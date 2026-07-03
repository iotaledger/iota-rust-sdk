// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dynamic Fields API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use futures::Stream;
use iota_types::{Address, TypeTag};

use crate::{
    Client, DynamicFieldOutput, NameValue,
    error::Result,
    pagination::{Direction, Page, PaginationFilter},
    query_types::{
        DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldQuery, DynamicFieldsOwnerQuery,
        DynamicObjectFieldQuery,
    },
    streams::stream_paginated_query,
};

impl Client {
    /// Get a stream of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    pub fn dynamic_fields_stream(
        &self,
        address: Address,
        streaming_direction: Direction,
    ) -> impl Stream<Item = Result<DynamicFieldOutput>> + '_ {
        stream_paginated_query(
            move |filter| self.dynamic_fields(address, filter),
            streaming_direction,
        )
    }

    /// Access a dynamic field on an object using its name. Names are arbitrary
    /// Move values whose type have copy, drop, and store, and are specified
    /// using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument can be either a [`BcsName`](crate::BcsName) for
    /// passing raw bcs bytes or a type that implements Serialize.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    ///
    /// # Example
    /// ```rust,ignore
    /// 
    /// let client = iota_graphql_client::Client::new_testnet();
    /// let address = ObjectId::system().into();
    /// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
    ///
    /// # alternatively, pass in the bcs bytes
    /// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
    /// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
    /// ```
    pub async fn dynamic_field(
        &self,
        address: Address,
        type_: TypeTag,
        name: impl Into<NameValue>,
    ) -> Result<Option<DynamicFieldOutput>> {
        let bcs = name.into().0;
        let operation = DynamicFieldQuery::build(DynamicFieldArgs {
            address,
            name: crate::query_types::DynamicFieldName {
                type_: type_.to_string(),
                bcs: crate::query_types::Base64(base64ct::Base64::encode_string(&bcs)),
            },
        });

        let response = self.run_query(&operation).await?;

        let result = response
            .owner
            .and_then(|o| o.dynamic_field)
            .map(|df| df.try_into())
            .transpose()?;

        Ok(result)
    }

    /// Access a dynamic object field on an object using its name. Names are
    /// arbitrary Move values whose type have copy, drop, and store, and are
    /// specified using their type, and their BCS contents, Base64 encoded.
    ///
    /// The `name` argument can be either a [`BcsName`](crate::BcsName) for
    /// passing raw bcs bytes or a type that implements Serialize.
    ///
    /// This returns [`DynamicFieldOutput`] which contains the name, the value
    /// as json, and object.
    pub async fn dynamic_object_field(
        &self,
        address: Address,
        type_: TypeTag,
        name: impl Into<NameValue>,
    ) -> Result<Option<DynamicFieldOutput>> {
        let bcs = name.into().0;
        let operation = DynamicObjectFieldQuery::build(DynamicFieldArgs {
            address,
            name: crate::query_types::DynamicFieldName {
                type_: type_.to_string(),
                bcs: crate::query_types::Base64(base64ct::Base64::encode_string(&bcs)),
            },
        });

        let response = self.run_query(&operation).await?;

        let result: Option<DynamicFieldOutput> = response
            .owner
            .and_then(|o| o.dynamic_object_field)
            .map(|df| df.try_into())
            .transpose()?;
        Ok(result)
    }

    /// Get a page of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    ///
    /// This returns [`Page`] of [`DynamicFieldOutput`]s.
    pub async fn dynamic_fields(
        &self,
        address: Address,
        pagination_filter: PaginationFilter,
    ) -> Result<Page<DynamicFieldOutput>> {
        let pagination = self.pagination_filter(pagination_filter).await;
        let operation = DynamicFieldsOwnerQuery::build(DynamicFieldConnectionArgs {
            address,
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        });
        let response = self.run_query(&operation).await?;

        let DynamicFieldsOwnerQuery { owner: Some(dfs) } = response else {
            return Ok(Page::new_empty());
        };

        Ok(Page::new(
            dfs.dynamic_fields.page_info,
            dfs.dynamic_fields
                .nodes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use base64ct::Encoding;
    use iota_types::{ObjectId, TypeTag};

    use crate::{BcsName, PaginationFilter, test_utils::test_client};

    #[tokio::test]
    async fn test_dynamic_field_query() {
        let client = test_client();
        let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
        client
            .dynamic_field(ObjectId::SYSTEM_STATE.into(), TypeTag::U64, BcsName(bcs))
            .await
            .map_err(|e| {
                format!(
                    "Dynamic field query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();

        client
            .dynamic_field(ObjectId::SYSTEM_STATE.into(), TypeTag::U64, 2u64)
            .await
            .map_err(|e| {
                format!(
                    "Dynamic field query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }

    #[tokio::test]
    async fn test_dynamic_fields_query() {
        let client = test_client();
        client
            .dynamic_fields(ObjectId::SYSTEM_STATE.into(), PaginationFilter::default())
            .await
            .map_err(|e| {
                format!(
                    "Dynamic fields query failed for {} network. Error: {e}",
                    client.rpc_server()
                )
            })
            .unwrap();
    }
}
