// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing dynamic fields.
//!
//! # Read Mask
//!
//! Without [`read_mask`](ListDynamicFieldsQuery::read_mask), the default mask
//! is used. Pass a [`DynamicFieldReadMask`] built from a
//! [`DynamicFieldField`](iota_grpc_types::read_mask_fields::DynamicFieldField)
//! (or any slice/array/vec of fields) to choose the returned fields.

use iota_grpc_types::{
    read_mask_fields::{DynamicFieldReadMask, IntoReadMask},
    v1::{
        dynamic_field::DynamicField,
        state_service::{ListDynamicFieldsRequest, state_service_client::StateServiceClient},
    },
};
use iota_types::ObjectId;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{define_list_query, proto_object_id},
};

define_list_query! {
    /// Builder for listing dynamic fields of a parent object.
    ///
    /// Created by [`GrpcClient::dynamic_fields`]. Await directly for a
    /// single page, or call [`.collect(limit)`](Self::collect) to
    /// auto-paginate.
    pub struct ListDynamicFieldsQuery {
        service_client: StateServiceClient<InterceptedChannel>,
        request: ListDynamicFieldsRequest,
        item: DynamicField,
        rpc_method: list_dynamic_fields,
        items_field: dynamic_fields,
    }
}

impl ListDynamicFieldsQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<DynamicFieldReadMask>) -> Self {
        self.base_request.read_mask = Some(read_mask.into_read_mask().into());
        self
    }
}

impl GrpcClient {
    /// List dynamic fields owned by a parent object.
    ///
    /// Returns a query builder. Await it directly for a single page
    /// (with access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results. Choose the returned fields with
    /// [`read_mask`](ListDynamicFieldsQuery::read_mask), and page with
    /// [`page_size`](ListDynamicFieldsQuery::page_size) and
    /// [`page_token`](ListDynamicFieldsQuery::page_token).
    ///
    /// # Parameters
    ///
    /// - `parent` - The object ID of the parent object.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let parent: ObjectId = "0x2".parse()?;
    ///
    /// let page = client.dynamic_fields(parent).await?;
    /// for field in &page.body().items {
    ///     println!("Dynamic field: {:?}", field);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let parent: ObjectId = "0x2".parse()?;
    ///
    /// let all = client
    ///     .dynamic_fields(parent)
    ///     .page_size(50)
    ///     .collect(None)
    ///     .await?;
    /// for field in all.body() {
    ///     println!("Dynamic field: {:?}", field);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn dynamic_fields(&self, parent: ObjectId) -> ListDynamicFieldsQuery {
        let base_request = ListDynamicFieldsRequest::default()
            .with_parent(proto_object_id(parent))
            .with_read_mask(DynamicFieldReadMask::default());

        ListDynamicFieldsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
        )
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{DynamicFieldField, DynamicFieldReadMask};
    use iota_types::ObjectId;

    use crate::GrpcClient;

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.dynamic_fields(ObjectId::ZERO);
        assert_eq!(
            query.base_request.read_mask,
            Some(DynamicFieldReadMask::default().into())
        );

        let query = query.read_mask(DynamicFieldField::ALL);
        assert_eq!(
            query.base_request.read_mask,
            Some(DynamicFieldReadMask::from(DynamicFieldField::ALL).into())
        );
    }
}
