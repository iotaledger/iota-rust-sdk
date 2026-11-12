// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for coin info queries.

use iota_grpc_types::v1::state_service::{
    GetCoinInfoRequest, GetCoinInfoResponse, state_service_client::StateServiceClient,
};
use iota_types::StructTag;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{GrpcResult, MetadataEnvelope, define_query},
};

define_query! {
    /// Query for [`GrpcClient::coin_info`]. Await it to send the request.
    pub struct GetCoinInfoQuery {
        service_client: StateServiceClient<InterceptedChannel>,
        coin_type: StructTag,
    }
    output: GrpcResult<MetadataEnvelope<GetCoinInfoResponse>>;
}

impl GetCoinInfoQuery {
    fn into_request(self) -> (StateServiceClient<InterceptedChannel>, GetCoinInfoRequest) {
        let request = GetCoinInfoRequest::default().with_coin_type(self.coin_type.to_string());
        (self.service_client, request)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<GetCoinInfoResponse>> {
        let (mut service_client, request) = self.into_request();
        let response = service_client.get_coin_info(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}

impl GrpcClient {
    /// Get information about a coin type.
    ///
    /// Returns the [`GetCoinInfoResponse`] proto type with metadata, treasury,
    /// and regulation information for the specified coin type.
    ///
    /// # Parameters
    ///
    /// - `coin_type` - The coin type as a [`StructTag`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::StructTag;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let coin_type: StructTag = "0x2::iota::IOTA".parse()?;
    ///
    /// let response = client.coin_info(coin_type).await?;
    /// let info = response.body();
    /// println!("Coin info: {:?}", info);
    /// # Ok(())
    /// # }
    /// ```
    pub fn coin_info(&self, coin_type: StructTag) -> GetCoinInfoQuery {
        GetCoinInfoQuery {
            service_client: self.state_service_client(),
            coin_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_types::StructTag;

    use crate::GrpcClient;

    #[tokio::test]
    async fn coin_info_keeps_the_coin_type() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let coin_type: StructTag = "0x2::iota::IOTA".parse().unwrap();
        let query = client.coin_info(coin_type.clone());
        assert_eq!(query.coin_type, coin_type);
    }

    #[tokio::test]
    async fn the_request_carries_the_coin_type() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .coin_info("0x2::iota::IOTA".parse().unwrap())
            .into_request();
        assert_eq!(request.coin_type.as_deref(), Some("0x2::iota::IOTA"));
    }
}
