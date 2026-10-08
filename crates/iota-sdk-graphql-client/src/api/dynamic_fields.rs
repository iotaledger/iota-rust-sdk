// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Dynamic Fields API implementation.

use base64ct::Encoding;
use cynic::QueryBuilder;
use iota_types::{Address, TypeTag};

use crate::{
    DynamicFieldOutput, GraphQLClient, NameValue,
    api::define_query,
    error::GraphQLResult,
    pagination::{Page, PaginationFilter, PaginationFilterResponse},
    query_types::{
        Base64, DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldName,
        DynamicFieldQueryFragment, DynamicFieldsOwnerQueryFragment,
        DynamicObjectFieldQueryFragment,
    },
    streams::PageStream,
};

define_query! {
    /// Query for [`GraphQLClient::dynamic_fields`]. Await it to send the
    /// request.
    #[derive(Clone)]
    pub struct ListDynamicFieldsQuery {
        client: GraphQLClient,
        address: Address,
        pagination: PaginationFilter,
    }
    output: GraphQLResult<Page<DynamicFieldOutput>>;
}

impl ListDynamicFieldsQuery {
    /// Set the page to fetch.
    pub fn pagination(mut self, pagination: PaginationFilter) -> Self {
        self.pagination = pagination;
        self
    }

    /// Stream every item, page by page, starting at the pagination's cursor
    /// and in its direction, with its limit as the page size.
    pub fn stream(self) -> PageStream<DynamicFieldOutput> {
        let pagination = self.pagination.clone();
        PageStream::new(
            pagination,
            Box::new(move |page| self.clone().pagination(page).into_future()),
        )
    }

    fn operation<'a>(
        address: Address,
        pagination: &'a PaginationFilterResponse,
    ) -> cynic::Operation<DynamicFieldsOwnerQueryFragment, DynamicFieldConnectionArgs<'a>> {
        DynamicFieldsOwnerQueryFragment::build(DynamicFieldConnectionArgs {
            address,
            after: pagination.after.as_deref(),
            before: pagination.before.as_deref(),
            first: pagination.first,
            last: pagination.last,
        })
    }

    async fn send(self) -> GraphQLResult<Page<DynamicFieldOutput>> {
        let Self {
            client,
            pagination,
            address,
        } = self;
        let pagination = client.pagination_filter(pagination).await;
        let response = client
            .run_query(&Self::operation(address, &pagination))
            .await?;

        let DynamicFieldsOwnerQueryFragment { owner: Some(dfs) } = response else {
            return Ok(Page::new_empty());
        };

        Ok(Page::new(
            dfs.dynamic_fields.page_info,
            dfs.dynamic_fields
                .nodes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<GraphQLResult<Vec<_>>>()?,
        ))
    }
}

fn dynamic_field_name(type_tag: TypeTag, name: impl Into<NameValue>) -> DynamicFieldName {
    DynamicFieldName {
        type_tag: type_tag.to_string(),
        bcs: Base64(base64ct::Base64::encode_string(&name.into().0)),
    }
}

define_query! {
    /// Query for [`GraphQLClient::dynamic_field`]. Await it to send the
    /// request.
    pub struct GetDynamicFieldQuery {
        client: GraphQLClient,
        address: Address,
        name: DynamicFieldName,
    }
    output: GraphQLResult<Option<DynamicFieldOutput>>;
}

impl GetDynamicFieldQuery {
    async fn send(self) -> GraphQLResult<Option<DynamicFieldOutput>> {
        let operation = DynamicFieldQueryFragment::build(DynamicFieldArgs {
            address: self.address,
            name: self.name,
        });

        let response = self.client.run_query(&operation).await?;

        let result = response
            .owner
            .and_then(|o| o.dynamic_field)
            .map(|df| df.try_into())
            .transpose()?;

        Ok(result)
    }
}

define_query! {
    /// Query for [`GraphQLClient::dynamic_object_field`]. Await it to send the
    /// request.
    pub struct GetDynamicObjectFieldQuery {
        client: GraphQLClient,
        address: Address,
        name: DynamicFieldName,
    }
    output: GraphQLResult<Option<DynamicFieldOutput>>;
}

impl GetDynamicObjectFieldQuery {
    async fn send(self) -> GraphQLResult<Option<DynamicFieldOutput>> {
        let operation = DynamicObjectFieldQueryFragment::build(DynamicFieldArgs {
            address: self.address,
            name: self.name,
        });

        let response = self.client.run_query(&operation).await?;

        let result: Option<DynamicFieldOutput> = response
            .owner
            .and_then(|o| o.dynamic_object_field)
            .map(|df| df.try_into())
            .transpose()?;
        Ok(result)
    }
}

impl GraphQLClient {
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
    /// let client = iota_graphql_client::GraphQLClient::new_testnet().unwrap();
    /// let address = ObjectId::system().into();
    /// let df = client.dynamic_field_with_name(address, "u64", 2u64).await.unwrap();
    ///
    /// # alternatively, pass in the bcs bytes
    /// let bcs = base64ct::Base64::decode_vec("AgAAAAAAAAA=").unwrap();
    /// let df = client.dynamic_field(address, "u64", BcsName(bcs)).await.unwrap();
    /// ```
    pub fn dynamic_field(
        &self,
        address: Address,
        type_tag: TypeTag,
        name: impl Into<NameValue>,
    ) -> GetDynamicFieldQuery {
        GetDynamicFieldQuery {
            client: self.clone(),
            address,
            name: dynamic_field_name(type_tag, name),
        }
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
    pub fn dynamic_object_field(
        &self,
        address: Address,
        type_tag: TypeTag,
        name: impl Into<NameValue>,
    ) -> GetDynamicObjectFieldQuery {
        GetDynamicObjectFieldQuery {
            client: self.clone(),
            address,
            name: dynamic_field_name(type_tag, name),
        }
    }

    /// Get a page of dynamic fields for the provided address. Note that this
    /// will also fetch dynamic fields on wrapped objects.
    pub fn dynamic_fields(&self, address: Address) -> ListDynamicFieldsQuery {
        ListDynamicFieldsQuery {
            client: self.clone(),
            address,
            pagination: PaginationFilter::default(),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use base64ct::Encoding;
    use iota_types::{ObjectId, TypeTag};

    use crate::{
        BcsName,
        test_utils::{
            assert_backward_page, assert_forward_page, backward_page, forward_page, sent_variables,
            test_client,
        },
    };

    #[tokio::test]
    async fn dynamic_field_getters_send_the_address_and_name() {
        let address = ObjectId::SYSTEM_STATE.into();
        let vars = sent_variables("DynamicFieldQueryFragment", |client| async move {
            let _ = client.dynamic_field(address, TypeTag::U64, 2u64).await;
        })
        .await;
        assert_eq!(vars["address"], address.to_string());
        assert_eq!(vars["name"]["type"], "u64");
        assert_eq!(vars["name"]["bcs"], "AgAAAAAAAAA=");

        let vars = sent_variables("DynamicObjectFieldQueryFragment", |client| async move {
            let _ = client
                .dynamic_object_field(address, TypeTag::U64, 2u64)
                .await;
        })
        .await;
        assert_eq!(vars["address"], address.to_string());
        assert_eq!(vars["name"]["type"], "u64");
        assert_eq!(vars["name"]["bcs"], "AgAAAAAAAAA=");
    }

    #[tokio::test]
    async fn dynamic_fields_sends_the_address_and_pagination() {
        let address = ObjectId::SYSTEM_STATE.into();
        let vars = sent_variables("DynamicFieldsOwnerQueryFragment", |client| async move {
            let _ = client
                .dynamic_fields(address)
                .pagination(backward_page())
                .await;
        })
        .await;
        assert_eq!(vars["address"], address.to_string());
        assert_backward_page(&vars);

        let vars = sent_variables("DynamicFieldsOwnerQueryFragment", |client| async move {
            let _ = client
                .dynamic_fields(address)
                .pagination(forward_page())
                .await;
        })
        .await;
        assert_forward_page(&vars);
    }

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
            .dynamic_fields(ObjectId::SYSTEM_STATE.into())
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
