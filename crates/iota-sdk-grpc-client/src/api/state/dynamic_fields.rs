// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing dynamic fields.
//!
//! # Read Mask
//!
//! Pass `None` for the default mask, or a [`DynamicFieldReadMask`] built from a
//! [`DynamicFieldField`](iota_grpc_types::read_mask_fields::DynamicFieldField)
//! (or any slice/array/vec of fields).

use iota_grpc_types::{
    read_mask_fields::DynamicFieldReadMask,
    v1::{
        dynamic_field::DynamicField,
        state_service::{ListDynamicFieldsRequest, state_service_client::StateServiceClient},
    },
};
use iota_types::ObjectId;

use crate::{
    Client, InterceptedChannel,
    api::{
        LIST_DYNAMIC_FIELDS_READ_MASK, define_list_query, field_mask_with_default, proto_object_id,
    },
};

define_list_query! {
    /// Builder for listing dynamic fields of a parent object.
    ///
    /// Created by [`Client::list_dynamic_fields`]. Await directly for a
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

impl Client {
    /// List dynamic fields owned by a parent object.
    ///
    /// Returns a query builder. Await it directly for a single page
    /// (with access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results.
    ///
    /// The `read_mask` controls which fields the server returns; pass `None`
    /// for the default field mask [`LIST_DYNAMIC_FIELDS_READ_MASK`], or a
    /// [`DynamicFieldReadMask`](iota_grpc_types::read_mask_fields::DynamicFieldReadMask)
    /// built from a
    /// [`DynamicFieldField`](iota_grpc_types::read_mask_fields::DynamicFieldField)
    /// or any slice/array/vec of fields.
    ///
    /// # Parameters
    ///
    /// - `parent` - The object ID of the parent object.
    /// - `page_size` - Optional maximum number of fields per page.
    /// - `page_token` - Optional continuation token from a previous page.
    /// - `read_mask` - Optional field mask; `None` uses the default.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let parent: ObjectId = "0x2".parse()?;
    ///
    /// let page = client.list_dynamic_fields(parent, None, None, None).await?;
    /// for field in &page.body().items {
    ///     println!("Dynamic field: {:?}", field);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let parent: ObjectId = "0x2".parse()?;
    ///
    /// let all = client
    ///     .list_dynamic_fields(parent, Some(50), None, None)
    ///     .collect(None)
    ///     .await?;
    /// for field in all.body() {
    ///     println!("Dynamic field: {:?}", field);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_dynamic_fields(
        &self,
        parent: ObjectId,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
        read_mask: impl Into<Option<DynamicFieldReadMask>>,
    ) -> ListDynamicFieldsQuery {
        self.list_dynamic_fields_internal(
            parent,
            page_size.into(),
            page_token.into(),
            read_mask.into(),
        )
    }

    fn list_dynamic_fields_internal(
        &self,
        parent: ObjectId,
        page_size: Option<u32>,
        page_token: Option<prost::bytes::Bytes>,
        read_mask: Option<DynamicFieldReadMask>,
    ) -> ListDynamicFieldsQuery {
        let base_request = ListDynamicFieldsRequest::default()
            .with_parent(proto_object_id(parent))
            .with_read_mask(field_mask_with_default(
                read_mask.as_ref().map(|m| m.as_str()),
                LIST_DYNAMIC_FIELDS_READ_MASK,
            ));

        ListDynamicFieldsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
            page_size,
            page_token,
        )
    }
}
