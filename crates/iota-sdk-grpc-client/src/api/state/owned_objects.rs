// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing owned objects.
//!
//! # Read Mask
//!
//! [`list_owned_objects`](Client::list_owned_objects) uses the default field
//! mask `OwnedObjectReadMask::default()`. Use
//! [`list_owned_objects_masked`](Client::list_owned_objects_masked) to pass an
//! [`OwnedObjectField`](iota_grpc_types::read_mask_fields::OwnedObjectField)
//! (or any slice/array/vec of fields).

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, OwnedObjectReadMask},
    v1::{
        object::Object,
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_types::{Address, StructTag};

use crate::{Client, InterceptedChannel, api::define_list_query};

define_list_query! {
    /// Builder for listing objects owned by an address.
    ///
    /// Created by [`Client::list_owned_objects`]. Await directly for a
    /// single page, or call [`.collect(limit)`](Self::collect) to
    /// auto-paginate.
    pub struct ListOwnedObjectsQuery {
        service_client: StateServiceClient<InterceptedChannel>,
        request: ListOwnedObjectsRequest,
        item: Object,
        rpc_method: list_owned_objects,
        items_field: objects,
    }
}

impl Client {
    /// List objects owned by an address.
    ///
    /// Returns a query builder. Await it directly for a single page
    /// (with access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results.
    ///
    /// Uses the default field mask `OwnedObjectReadMask::default()`. Use
    /// [`list_owned_objects_masked`](Self::list_owned_objects_masked) to
    /// specify a custom mask.
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the objects.
    /// - `object_type` - Optional type filter as a [`StructTag`].
    /// - `page_size` - Optional maximum number of objects per page.
    /// - `page_token` - Optional continuation token from a previous page.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client.list_owned_objects(owner, None, None, None).await?;
    /// for obj in &page.body().items {
    ///     println!("Owned object: {:?}", obj);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let all = client
    ///     .list_owned_objects(owner, None, Some(50), None)
    ///     .collect(Some(500))
    ///     .await?;
    /// for obj in all.body() {
    ///     println!("Owned object: {:?}", obj);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_owned_objects(
        &self,
        owner: Address,
        object_type: impl Into<Option<StructTag>>,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
    ) -> ListOwnedObjectsQuery {
        self.list_owned_objects_internal(
            owner,
            object_type.into(),
            page_size.into(),
            page_token.into(),
            Default::default(),
        )
    }

    /// List objects owned by an address, with a custom read mask.
    ///
    /// See [`list_owned_objects`](Self::list_owned_objects) for behavior. Pass
    /// an
    /// [`OwnedObjectField`](iota_grpc_types::read_mask_fields::OwnedObjectField)
    /// or any slice/array/vec of fields — conversion is automatic.
    pub fn list_owned_objects_masked(
        &self,
        owner: Address,
        object_type: impl Into<Option<StructTag>>,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
        read_mask: impl IntoReadMask<OwnedObjectReadMask>,
    ) -> ListOwnedObjectsQuery {
        self.list_owned_objects_internal(
            owner,
            object_type.into(),
            page_size.into(),
            page_token.into(),
            read_mask.into_read_mask(),
        )
    }

    fn list_owned_objects_internal(
        &self,
        owner: Address,
        object_type: Option<StructTag>,
        page_size: Option<u32>,
        page_token: Option<prost::bytes::Bytes>,
        read_mask: OwnedObjectReadMask,
    ) -> ListOwnedObjectsQuery {
        let mut base_request = ListOwnedObjectsRequest::default()
            .with_owner(ProtoAddress::default().with_address(Vec::from(owner)))
            .with_read_mask(read_mask);

        if let Some(t) = object_type {
            base_request = base_request.with_object_type(t.to_string());
        }

        ListOwnedObjectsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
            page_size,
            page_token,
        )
    }
}
