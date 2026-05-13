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
//! The default read mask is [`LIST_OWNED_OBJECTS_READ_MASK`]; the `bcs` field
//! is required for the proto `Object` → SDK `Coin` conversion, so callers
//! supplying a custom mask must include it.

use std::{future::IntoFuture, pin::Pin};

use iota_grpc_types::{
    read_mask_fields::OwnedObjectReadMask,
    v1::{
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    Client, InterceptedChannel,
    api::{
        Error, LIST_OWNED_OBJECTS_READ_MASK, MetadataEnvelope, Page, Result, TryFromProtoError,
        field_mask_with_default, saturating_usize_to_u32,
    },
};

/// Builder for listing coins owned by an address.
///
/// Created by [`Client::get_coins`]. Await directly for a single page
/// (with access to `next_page_token`), or call
/// [`.collect(limit)`](Self::collect) to auto-paginate.
pub struct GetCoinsQuery {
    service_client: StateServiceClient<InterceptedChannel>,
    base_request: ListOwnedObjectsRequest,
    max_message_size: Option<usize>,
    page_size: Option<u32>,
    page_token: Option<prost::bytes::Bytes>,
}

impl GetCoinsQuery {
    pub(crate) fn new(
        service_client: StateServiceClient<InterceptedChannel>,
        base_request: ListOwnedObjectsRequest,
        max_message_size: Option<usize>,
        page_size: Option<u32>,
        page_token: Option<prost::bytes::Bytes>,
    ) -> Self {
        Self {
            service_client,
            base_request,
            max_message_size,
            page_size,
            page_token,
        }
    }

    /// Auto-paginate through all pages, collecting up to `limit` coins.
    ///
    /// If `limit` is `None`, collects all coins across all pages.
    pub async fn collect(
        self,
        limit: impl Into<Option<u32>>,
    ) -> Result<MetadataEnvelope<Vec<Coin>>> {
        let limit = limit.into();
        let mut all_items: Vec<Coin> = Vec::new();
        let mut next_page_token = self.page_token;
        let mut result_metadata = None;
        let mut service_client = self.service_client;

        loop {
            let mut request = self.base_request.clone();

            let effective_page_size = match (self.page_size, limit) {
                (Some(ps), Some(l)) => {
                    let remaining = (l as usize).saturating_sub(all_items.len());
                    Some(ps.min(remaining as u32))
                }
                (Some(ps), None) => Some(ps),
                (None, Some(l)) => {
                    let remaining = (l as usize).saturating_sub(all_items.len());
                    Some(remaining as u32)
                }
                (None, None) => None,
            };
            if let Some(ps) = effective_page_size {
                request = request.with_page_size(ps);
            }
            if let Some(token) = next_page_token.take() {
                request = request.with_page_token(token);
            }
            if let Some(max_size) = self.max_message_size {
                request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
            }

            let response = service_client.list_owned_objects(request).await?;
            let (body, metadata) = MetadataEnvelope::from(response).into_parts();
            if result_metadata.is_none() {
                result_metadata = Some(metadata);
            }

            for obj in body.objects {
                all_items.push(object_to_coin(&obj)?);
            }

            match body.next_page_token {
                Some(token) => next_page_token = Some(token),
                None => break,
            }

            if limit.is_some_and(|l| all_items.len() >= l as usize) {
                break;
            }
        }

        Ok(MetadataEnvelope::new(
            all_items,
            result_metadata.unwrap_or_default(),
        ))
    }
}

impl IntoFuture for GetCoinsQuery {
    type Output = Result<MetadataEnvelope<Page<Coin>>>;
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut service_client = self.service_client;
            let mut request = self.base_request;

            if let Some(ps) = self.page_size {
                request = request.with_page_size(ps);
            }
            if let Some(token) = self.page_token {
                request = request.with_page_token(token);
            }
            if let Some(max_size) = self.max_message_size {
                request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
            }

            let response = service_client.list_owned_objects(request).await?;
            let (body, metadata) = MetadataEnvelope::from(response).into_parts();

            let items = body
                .objects
                .iter()
                .map(object_to_coin)
                .collect::<Result<Vec<_>>>()?;

            Ok(MetadataEnvelope::new(
                Page {
                    items,
                    next_page_token: body.next_page_token,
                },
                metadata,
            ))
        })
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
    /// `Object`. Uses the default field mask [`LIST_OWNED_OBJECTS_READ_MASK`]
    /// which includes `bcs` (required for conversion). Use
    /// [`get_coins_masked`](Self::get_coins_masked) to specify a custom mask
    /// — it must include `bcs`.
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the coins.
    /// - `coin_type` - Optional coin type filter as a [`StructTag`]. If `None`,
    ///   lists all coin types (`0x2::coin::Coin`).
    /// - `page_size` - Optional maximum number of coins per page.
    /// - `page_token` - Optional continuation token from a previous page.
    ///
    /// # Examples
    ///
    /// Single page:
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000").await?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let page = client.get_coins(owner, None, None, None).await?;
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
    /// # use iota_types::Address;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000").await?;
    /// let owner: Address = "0x1".parse()?;
    ///
    /// let all = client
    ///     .get_coins(owner, None, Some(50), None)
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
    ) -> GetCoinsQuery {
        self.get_coins_internal(
            owner,
            coin_type.into(),
            page_size.into(),
            page_token.into(),
            None,
        )
    }

    /// List coins owned by an address, with a custom read mask.
    ///
    /// See [`get_coins`](Self::get_coins) for behavior. The mask **must**
    /// include [`OwnedObjectField::BCS`](iota_grpc_types::read_mask_fields::OwnedObjectField::BCS)
    /// because the proto `Object` → SDK `Coin` conversion deserializes the BCS
    /// payload.
    pub fn get_coins_masked(
        &self,
        owner: Address,
        coin_type: impl Into<Option<StructTag>>,
        page_size: impl Into<Option<u32>>,
        page_token: impl Into<Option<prost::bytes::Bytes>>,
        read_mask: impl Into<OwnedObjectReadMask>,
    ) -> GetCoinsQuery {
        self.get_coins_internal(
            owner,
            coin_type.into(),
            page_size.into(),
            page_token.into(),
            Some(read_mask.into()),
        )
    }

    fn get_coins_internal(
        &self,
        owner: Address,
        coin_type: Option<StructTag>,
        page_size: Option<u32>,
        page_token: Option<prost::bytes::Bytes>,
        read_mask: Option<OwnedObjectReadMask>,
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
            .with_read_mask(field_mask_with_default(
                read_mask.as_ref().map(|m| m.as_str()),
                LIST_OWNED_OBJECTS_READ_MASK,
            ));

        GetCoinsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
            page_size,
            page_token,
        )
    }
}
