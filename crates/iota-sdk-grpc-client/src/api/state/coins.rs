// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for listing coins owned by an address.
//!
//! Wraps [`GrpcClient::owned_objects`](crate::GrpcClient::owned_objects)
//! with a coin type filter and converts each returned proto `Object` into an
//! [`iota_types::framework::Coin`].

use iota_grpc_types::{
    read_mask_fields::OwnedObjectReadMask,
    v1::{
        state_service::{ListOwnedObjectsRequest, state_service_client::StateServiceClient},
        types::Address as ProtoAddress,
    },
};
use iota_types::{Address, Identifier, StructTag, framework::Coin};

use crate::{
    GrpcClient, InterceptedChannel,
    api::{GrpcError, GrpcResult, TryFromProtoError, define_list_query},
};

define_list_query! {
    /// Builder for listing coins owned by an address.
    ///
    /// Created by [`GrpcClient::coins`]. Await directly for a single page
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

fn object_to_coin(obj: &iota_grpc_types::v1::object::Object) -> GrpcResult<Coin> {
    let sdk_obj = obj.object()?;
    Coin::try_from_object(&sdk_obj)
        .map_err(|e| GrpcError::from(TryFromProtoError::invalid("coin", e)))
}

impl GetCoinsQuery {
    /// Filter by coin type, the inner type `T` of `Coin<T>`. If `None`, lists
    /// all coin types (with type `0x2::coin::Coin`).
    pub fn coin_type(mut self, coin_type: impl Into<Option<StructTag>>) -> Self {
        self.base_request.object_type = Some(coin_object_type(coin_type.into()));
        self
    }
}

fn coin_object_type(coin_type: Option<StructTag>) -> String {
    // Without a coin type, query for the generic `0x2::coin::Coin` (no type
    // params); the server returns all `Coin<T>` objects regardless of `T`.
    coin_type
        .map(StructTag::new_coin)
        .unwrap_or_else(|| {
            StructTag::new(
                Address::FRAMEWORK,
                Identifier::COIN_MODULE,
                Identifier::COIN,
                Vec::new(),
            )
        })
        .to_string()
}

impl GrpcClient {
    /// List coins owned by an address.
    ///
    /// Returns a query builder. Await it directly for a single page (with
    /// access to `next_page_token`), or call `.collect(limit)` to
    /// auto-paginate through all results. Filter by coin type with
    /// [`coin_type`](GetCoinsQuery::coin_type) and page with
    /// [`page_size`](GetCoinsQuery::page_size) and
    /// [`page_token`](GetCoinsQuery::page_token).
    ///
    /// Each returned [`Coin`] is converted from the underlying proto
    /// `Object`.
    ///
    /// # Parameters
    ///
    /// - `owner` - The address that owns the coins.
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
    /// let page = client.coins(owner).await?;
    /// for coin in &page.body().items {
    ///     println!("Coin {}: {}", coin.id(), coin.balance());
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
    /// let all = client.coins(owner).page_size(50).collect(500).await?;
    /// for coin in all.body() {
    ///     println!("Coin {}: {}", coin.id(), coin.balance());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn coins(&self, owner: Address) -> GetCoinsQuery {
        let base_request = ListOwnedObjectsRequest::default()
            .with_owner(ProtoAddress::default().with_address(Vec::from(owner)))
            .with_object_type(coin_object_type(None))
            .with_read_mask(OwnedObjectReadMask::default());

        GetCoinsQuery::new(
            self.state_service_client(),
            base_request,
            self.max_decoding_message_size(),
        )
    }
}

#[cfg(test)]
mod tests {
    use iota_types::{Address, StructTag};

    use crate::GrpcClient;

    #[tokio::test]
    async fn coins_without_a_coin_type_lists_every_coin_type() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.coins(Address::ZERO);
        assert_eq!(
            query.base_request.object_type.as_deref(),
            Some("0x2::coin::Coin")
        );
    }

    #[tokio::test]
    async fn coin_type_sets_the_coin_filter_and_none_resets_it() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client
            .coins(Address::ZERO)
            .coin_type("0x2::iota::IOTA".parse::<StructTag>().unwrap());
        assert_eq!(
            query.base_request.object_type.as_deref(),
            Some("0x2::coin::Coin<0x2::iota::IOTA>")
        );

        let query = query.coin_type(None);
        assert_eq!(
            query.base_request.object_type.as_deref(),
            Some("0x2::coin::Coin")
        );
    }
}
