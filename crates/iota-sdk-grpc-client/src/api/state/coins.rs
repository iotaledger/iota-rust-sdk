// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing coins owned by an address.
//!
//! Wraps [`Client::list_owned_objects`](crate::Client::list_owned_objects)
//! with a coin type filter and converts each returned proto `Object` into an
//! [`iota_types::framework::Coin`].
//!
//! # Read Mask
//!
//! The default read mask is
//! [`LIST_OWNED_OBJECTS_READ_MASK`](iota_grpc_types::read_masks::LIST_OWNED_OBJECTS_READ_MASK).
//! Every `Coin` is decoded from the `bcs` field, so a mask that omits it is
//! amended to include it rather than failing every object in the response.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, OwnedObjectField, OwnedObjectReadMask},
    v1::{
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    Client, InterceptedChannel,
    api::{Error, Result, TryFromProtoError, define_list_query},
};

define_list_query! {
    /// Builder for listing coins owned by an address.
    ///
    /// Created by [`Client::get_coins`]. Await directly for a single page
    /// (with access to `next_page_token`), or call
    /// [`.collect(limit)`](Self::collect) to auto-paginate.
    pub struct GetCoinsQuery {
        service_client: StateServiceClient<InterceptedChannel>,
        request: ListOwnedObjectsRequest,
        item: Coin,
        rpc_method: list_owned_objects,
        items_field: objects,
        map_item: object_to_coin,
    }
}

/// Add `bcs` to `mask` unless it is already covered.
///
/// Without it every object in the response fails to convert, and the mask is
/// the only way a caller could ask for that, so there is nothing to preserve by
/// passing it through untouched.
fn with_bcs(mask: OwnedObjectReadMask) -> OwnedObjectReadMask {
    let paths = mask.as_str();
    let covered = paths
        .split(',')
        .any(|path| matches!(path.trim(), "*" | "bcs"));
    if covered {
        mask
    } else if paths.trim().is_empty() {
        OwnedObjectReadMask::from(OwnedObjectField::BCS)
    } else {
        OwnedObjectReadMask::from(format!("{paths},bcs"))
    }
}

fn object_to_coin(obj: &iota_grpc_types::v1::object::Object) -> Result<Coin> {
    let sdk_obj = obj.object()?;
    Coin::try_from_object(&sdk_obj).map_err(|e| Error::from(TryFromProtoError::invalid("coin", e)))
}

impl Client {
    /// List coins owned by an address.
    ///
    /// Returns a query builder. Await it directly for a single page (with
    /// access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results.
    ///
    /// Each returned [`Coin`] is converted from the underlying proto
    /// `Object`. The `read_mask` controls which fields the server returns; use
    /// `OwnedObjectReadMask::default()` for the default field mask, or pass an
    /// [`OwnedObjectReadMask`](iota_grpc_types::read_mask_fields::OwnedObjectReadMask)
    /// of your own. The conversion decodes the BCS payload, so
    /// [`OwnedObjectField::BCS`](iota_grpc_types::read_mask_fields::OwnedObjectField::BCS)
    /// is added to the mask when it is missing.
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the coins.
    /// - `coin_type` - Optional coin type filter as a [`StructTag`]. The value
    ///   must be the inner type `T` of `Coin<T>`. If `None`, lists all coin
    ///   types (with type `0x2::coin::Coin`).
    /// - `page_size` - Optional maximum number of coins per page.
    /// - `page_token` - Optional continuation token from a previous page.
    /// - `read_mask` - Field mask controlling the returned fields.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::OwnedObjectReadMask;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client
    ///     .get_coins(owner, None, None, None, OwnedObjectReadMask::default())
    ///     .await?;
    /// for coin in &page.body().items {
    ///     println!("Coin {}: {}", coin.id(), coin.balance());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Auto-paginate:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::OwnedObjectReadMask;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let all = client
    ///     .get_coins(owner, None, Some(50), None, OwnedObjectReadMask::default())
    ///     .collect(Some(500))
    ///     .await?;
    /// for coin in all.body() {
    ///     println!("Coin {}: {}", coin.id(), coin.balance());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_coins(
        &self,
        owner: Address,
        coin_type: impl Into<Option<StructTag>>,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
        read_mask: impl IntoReadMask<OwnedObjectReadMask>,
    ) -> GetCoinsQuery {
        self.get_coins_internal(
            owner,
            coin_type.into(),
            page_size.into(),
            page_token.into(),
            read_mask.into_read_mask(),
        )
    }

    fn get_coins_internal(
        &self,
        owner: Address,
        coin_type: Option<StructTag>,
        page_size: Option<u32>,
        page_token: Option<prost::bytes::Bytes>,
        read_mask: OwnedObjectReadMask,
    ) -> GetCoinsQuery {
        // When no specific coin type is provided, query for the generic
        // `0x2::coin::Coin` (no type params); the server returns all
        // `Coin<T>` objects regardless of `T`.
        let coin_type = coin_type.map(StructTag::new_coin).unwrap_or_else(|| {
            StructTag::new(
                Address::FRAMEWORK,
                Identifier::COIN_MODULE,
                Identifier::COIN,
                Vec::new(),
            )
        });

        let base_request = ListOwnedObjectsRequest::default()
            .with_owner(ProtoAddress::default().with_address(Vec::from(owner)))
            .with_object_type(coin_type.to_string())
            .with_read_mask(with_bcs(read_mask));

        GetCoinsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
            page_size,
            page_token,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mask_already_covers_bcs() {
        let mask = OwnedObjectReadMask::default();
        assert_eq!(with_bcs(mask.clone()).as_str(), mask.as_str());
    }

    #[test]
    fn wildcard_covers_bcs() {
        let mask = OwnedObjectReadMask::from(OwnedObjectField::ALL);
        assert_eq!(with_bcs(mask).as_str(), "*");
    }

    /// The case that used to fail every object in the response.
    #[test]
    fn mask_without_bcs_gains_it() {
        let mask = OwnedObjectReadMask::from(OwnedObjectField::REFERENCE);
        assert_eq!(with_bcs(mask).as_str(), "reference,bcs");
    }

    #[test]
    fn empty_mask_becomes_bcs_alone() {
        let mask = OwnedObjectReadMask::from(String::new());
        assert_eq!(with_bcs(mask).as_str(), "bcs");
    }

    /// `bcs` in any position counts, so the mask is not appended to twice.
    #[test]
    fn bcs_anywhere_in_the_mask_counts() {
        let mask = OwnedObjectReadMask::from("bcs,reference.version".to_string());
        assert_eq!(with_bcs(mask).as_str(), "bcs,reference.version");
    }
}
