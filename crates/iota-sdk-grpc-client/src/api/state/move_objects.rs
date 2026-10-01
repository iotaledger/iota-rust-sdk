// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing owned objects of a known Move type.
//!
//! Wraps [`Client::owned_objects`] with the type filter taken from the
//! type parameter, and decodes each returned proto `Object` into the mirror,
//! paired with its object reference.
//!
//! # Read Mask
//!
//! Not a parameter here. The mirror and the object reference both come out of
//! the BCS payload, so the query always asks for the default mask and there is
//! no way to request one that leaves the objects undecodable.

use iota_grpc_types::{
    read_mask_fields::OwnedObjectReadMask,
    v1::{
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_move_types::MoveObject;
use iota_types::{Address, ObjectReference};

use crate::{
    GrpcClient, GrpcError, InterceptedChannel,
    api::{GrpcResult, TryFromProtoError, define_list_query},
};

/// An owned object of the Move type `T`, decoded into `T`.
#[derive(Clone, Debug)]
pub struct OwnedMoveObject<T> {
    object_ref: ObjectReference,
    object: T,
}

#[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
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

define_list_query! {
    /// Builder for listing owned objects of the Move type `T`.
    ///
    /// Created by [`GrpcClient::owned_move_objects`]. Await directly for a
    /// single page, or call [`.collect(limit)`](Self::collect) to
    /// auto-paginate.
    ///
    /// Fails if any object fails to decode. The query filters on `T`'s exact
    /// type, so a failure means the on-chain type has moved out from under the
    /// mirror rather than that one object is odd — yielding the rest would hide
    /// that.
    pub struct ListOwnedMoveObjectsQuery<T: MoveObject> {
        service_client: StateServiceClient<InterceptedChannel>,
        request: ListOwnedObjectsRequest,
        item: OwnedMoveObject<T>,
        rpc_method: list_owned_objects,
        items_field: objects,
        map_item: decode::<T>,
    }
}

/// Decode a proto `Object` into an [`OwnedMoveObject`], by way of the SDK
/// `Object`.
fn decode<T: MoveObject>(
    object: &iota_grpc_types::v1::object::Object,
) -> GrpcResult<OwnedMoveObject<T>> {
    let object = object.object()?;
    let mirror = T::try_from(&object)
        .map_err(|e| GrpcError::from(TryFromProtoError::invalid("move object", e)))?;
    Ok(OwnedMoveObject {
        object_ref: object.object_ref(),
        object: mirror,
    })
}

#[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
impl GrpcClient {
    /// List objects of the Move type `T` owned by an address, decoded into `T`
    /// and paired with their object references.
    ///
    /// The type filter is derived from `T`, so unlike
    /// [`GrpcClient::owned_objects`] this needs neither a type argument nor a
    /// separate decode step.
    ///
    /// Returns a query builder. Await it directly for a single page (with
    /// access to `next_page_token`), or call `.collect(limit)` to auto-paginate
    /// through all results. Page with
    /// [`page_size`](ListOwnedMoveObjectsQuery::page_size) and
    /// [`page_token`](ListOwnedMoveObjectsQuery::page_token).
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the objects.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_move_types::iota_system::staking_pool::StakedIota;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client.owned_move_objects::<StakedIota>(owner).await?;
    /// for staked in &page.body().items {
    ///     println!(
    ///         "{}: staked {} nanos",
    ///         staked.object_ref().object_id,
    ///         staked.object().principal()
    ///     );
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn owned_move_objects<T: MoveObject>(
        &self,
        owner: Address,
    ) -> ListOwnedMoveObjectsQuery<T> {
        let base_request = ListOwnedObjectsRequest::default()
            .with_owner(ProtoAddress::default().with_address(Vec::from(owner)))
            .with_object_type(T::struct_tag().to_string())
            .with_read_mask(OwnedObjectReadMask::default());

        ListOwnedMoveObjectsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
        )
    }
}
