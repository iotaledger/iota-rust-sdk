// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing owned objects.
//!
//! # Read Mask
//!
//! Without [`read_mask`](ListOwnedObjectsQuery::read_mask), the default mask is
//! used. Pass an [`OwnedObjectReadMask`] built from
//! an [`OwnedObjectField`](iota_grpc_types::read_mask_fields::OwnedObjectField)
//! (or any slice/array/vec of fields) to choose the returned fields.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, OwnedObjectReadMask},
    v1::{
        object::Object,
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_types::{Address, StructTag};

use crate::{GrpcClient, InterceptedChannel, api::define_list_query};

define_list_query! {
    /// Builder for listing objects owned by an address.
    ///
    /// Created by [`GrpcClient::owned_objects`]. Await directly for a
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

impl ListOwnedObjectsQuery {
    /// Filter by object type. If `None`, lists objects of all types.
    pub fn object_type(mut self, object_type: impl Into<Option<StructTag>>) -> Self {
        self.base_request.object_type = object_type.into().map(|t| t.to_string());
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<OwnedObjectReadMask>) -> Self {
        self.base_request.read_mask = Some(read_mask.into_read_mask().into());
        self
    }
}

impl GrpcClient {
    /// List objects owned by an address.
    ///
    /// Returns a query builder. Await it directly for a single page
    /// (with access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results. Filter by type with
    /// [`object_type`](ListOwnedObjectsQuery::object_type), choose the
    /// returned fields with [`read_mask`](ListOwnedObjectsQuery::read_mask),
    /// and page with [`page_size`](ListOwnedObjectsQuery::page_size) and
    /// [`page_token`](ListOwnedObjectsQuery::page_token).
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the objects.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client.owned_objects(owner).await?;
    /// for obj in &page.body().items {
    ///     println!("Owned object: {:?}", obj);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let all = client
    ///     .owned_objects(owner)
    ///     .page_size(50)
    ///     .collect(500)
    ///     .await?;
    /// for obj in all.body() {
    ///     println!("Owned object: {:?}", obj);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn owned_objects(&self, owner: Address) -> ListOwnedObjectsQuery {
        let base_request = ListOwnedObjectsRequest::default()
            .with_owner(ProtoAddress::default().with_address(Vec::from(owner)))
            .with_read_mask(OwnedObjectReadMask::default());

        ListOwnedObjectsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
        )
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::{
        read_mask_fields::{OwnedObjectField, OwnedObjectReadMask},
        v1::types::Address as ProtoAddress,
    };
    use iota_types::{Address, StructTag};

    use crate::GrpcClient;

    #[tokio::test]
    async fn owned_objects_defaults_to_no_type_filter_and_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.owned_objects(Address::ZERO);
        assert_eq!(query.base_request.object_type, None);
        assert_eq!(
            query.base_request.read_mask,
            Some(OwnedObjectReadMask::default().into())
        );
        assert_eq!(query.page_size, None);
        assert_eq!(query.page_token, None);
    }

    #[tokio::test]
    async fn object_type_sets_the_type_filter_and_none_clears_it() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.owned_objects(Address::ZERO).object_type(
            "0x2::coin::Coin<0x2::iota::IOTA>"
                .parse::<StructTag>()
                .unwrap(),
        );
        assert_eq!(
            query.base_request.object_type.as_deref(),
            Some("0x2::coin::Coin<0x2::iota::IOTA>")
        );

        let query = query.object_type(None);
        assert_eq!(query.base_request.object_type, None);
    }

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client
            .owned_objects(Address::ZERO)
            .read_mask(OwnedObjectField::BCS);
        assert_eq!(
            query.base_request.read_mask,
            Some(OwnedObjectReadMask::from(OwnedObjectField::BCS).into())
        );
    }

    #[tokio::test]
    async fn page_setters_set_and_reset_the_page() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client
            .owned_objects(Address::ZERO)
            .page_size(10)
            .page_token(prost::bytes::Bytes::from_static(b"next"));
        assert_eq!(query.page_size, Some(10));
        assert_eq!(query.page_token.as_deref(), Some(&b"next"[..]));

        let query = query.page_size(None).page_token(None);
        assert_eq!(query.page_size, None);
        assert_eq!(query.page_token, None);
    }

    #[tokio::test]
    async fn the_request_carries_every_input() {
        let client = GrpcClient::new("http://localhost")
            .unwrap()
            .with_max_decoding_message_size(1024);
        let owner: Address = "0x5".parse().unwrap();
        let (_, request) = client
            .owned_objects(owner)
            .object_type(
                "0x2::coin::Coin<0x2::iota::IOTA>"
                    .parse::<StructTag>()
                    .unwrap(),
            )
            .read_mask(OwnedObjectField::BCS)
            .page_size(10)
            .page_token(prost::bytes::Bytes::from_static(b"next"))
            .into_request();
        assert_eq!(
            request.owner,
            Some(ProtoAddress::default().with_address(Vec::from(owner)))
        );
        assert_eq!(
            request.object_type.as_deref(),
            Some("0x2::coin::Coin<0x2::iota::IOTA>")
        );
        assert_eq!(
            request.read_mask,
            Some(OwnedObjectReadMask::from(OwnedObjectField::BCS).into())
        );
        assert_eq!(request.page_size, Some(10));
        assert_eq!(request.page_token.as_deref(), Some(&b"next"[..]));
        assert_eq!(request.max_message_size_bytes, Some(1024));
    }

    #[tokio::test]
    async fn the_request_leaves_unset_inputs_unset() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client.owned_objects(Address::ZERO).into_request();
        assert_eq!(request.object_type, None);
        assert_eq!(request.page_size, None);
        assert_eq!(request.page_token, None);
        assert_eq!(request.max_message_size_bytes, None);
    }
}
