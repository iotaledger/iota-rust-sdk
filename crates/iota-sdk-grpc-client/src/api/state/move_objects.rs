// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing owned objects of a known Move type.
//!
//! Wraps [`Client::list_owned_objects`] with the type filter taken from the
//! type parameter, and decodes each returned proto `Object` into the mirror.
//!
//! # Read Mask
//!
//! Not a parameter here. Everything the mirror decodes comes out of the BCS
//! payload, so the query always asks for the default mask and there is no way
//! to request one that leaves the objects undecodable.

use std::{future::IntoFuture, marker::PhantomData, pin::Pin};

use iota_grpc_types::read_mask_fields::OwnedObjectReadMask;
use iota_move_types::MoveObject;
use iota_types::Address;

use crate::{
    Client,
    api::{
        Error, MetadataEnvelope, Page, Result, TryFromProtoError,
        state::owned_objects::ListOwnedObjectsQuery,
    },
};

/// Builder for listing owned objects of the Move type `T`.
///
/// Created by [`Client::list_owned_move_objects`]. Await directly for a single
/// page, or call [`.collect(limit)`](Self::collect) to auto-paginate.
pub struct ListOwnedMoveObjectsQuery<T> {
    inner: ListOwnedObjectsQuery,
    _marker: PhantomData<fn() -> T>,
}

impl<T: MoveObject> ListOwnedMoveObjectsQuery<T> {
    fn new(inner: ListOwnedObjectsQuery) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    /// Auto-paginate through all pages, collecting up to `limit` objects.
    ///
    /// If `limit` is `None`, collects all objects across all pages.
    ///
    /// # Errors
    ///
    /// Returns an error if any object fails to decode. The query filters on
    /// `T`'s exact type, so a failure means the on-chain type has moved out
    /// from under the mirror rather than that one object is odd — yielding the
    /// rest would hide that.
    pub async fn collect(self, limit: impl Into<Option<u32>>) -> Result<MetadataEnvelope<Vec<T>>> {
        let (objects, metadata) = self.inner.collect(limit).await?.into_parts();
        let decoded = objects
            .iter()
            .map(decode::<T>)
            .collect::<Result<Vec<_>>>()?;
        Ok(MetadataEnvelope::new(decoded, metadata))
    }
}

impl<T: MoveObject + Send + 'static> IntoFuture for ListOwnedMoveObjectsQuery<T> {
    type Output = Result<MetadataEnvelope<Page<T>>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let (page, metadata) = self.inner.await?.into_parts();
            let items = page
                .items
                .iter()
                .map(decode::<T>)
                .collect::<Result<Vec<_>>>()?;
            Ok(MetadataEnvelope::new(
                Page {
                    items,
                    next_page_token: page.next_page_token,
                },
                metadata,
            ))
        })
    }
}

/// Decode a proto `Object` into the mirror `T`, by way of the SDK `Object`.
fn decode<T: MoveObject>(object: &iota_grpc_types::v1::object::Object) -> Result<T> {
    let object = object.object()?;
    T::try_from(&object).map_err(|e| Error::from(TryFromProtoError::invalid("move object", e)))
}

impl Client {
    /// List objects of the Move type `T` owned by an address, decoded into `T`.
    ///
    /// The type filter is derived from `T`, so unlike
    /// [`Client::list_owned_objects`] this needs neither a type argument nor a
    /// separate decode step.
    ///
    /// Returns a query builder. Await it directly for a single page (with
    /// access to `next_page_token`), or call `.collect(limit)` to auto-paginate
    /// through all results.
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the objects.
    /// - `page_size` - Optional maximum number of objects per page.
    /// - `page_token` - Optional continuation token from a previous page.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_move_types::iota_system::staking_pool::StakedIota;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client
    ///     .list_owned_move_objects::<StakedIota>(owner, None, None)
    ///     .await?;
    /// for staked in &page.body().items {
    ///     println!("staked {} nanos", staked.principal());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_owned_move_objects<T: MoveObject>(
        &self,
        owner: Address,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
    ) -> ListOwnedMoveObjectsQuery<T> {
        ListOwnedMoveObjectsQuery::new(self.list_owned_objects(
            owner,
            T::struct_tag(),
            page_size,
            page_token,
            OwnedObjectReadMask::default(),
        ))
    }
}
