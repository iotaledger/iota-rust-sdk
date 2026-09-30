// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for service info queries.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, ServiceInfoReadMask},
    v1::ledger_service::{
        GetServiceInfoRequest, GetServiceInfoResponse, ledger_service_client::LedgerServiceClient,
    },
};

use crate::{
    GrpcClient, InterceptedChannel,
    api::{GrpcResult, MetadataEnvelope, define_query},
};

define_query! {
    /// Request for [`GrpcClient::service_info`]. Await it to send the request.
    pub struct GetServiceInfoQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        read_mask: ServiceInfoReadMask,
    }
    output: GrpcResult<MetadataEnvelope<GetServiceInfoResponse>>;
}

impl GetServiceInfoQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ServiceInfoReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(
        self,
    ) -> (
        LedgerServiceClient<InterceptedChannel>,
        GetServiceInfoRequest,
    ) {
        let request = GetServiceInfoRequest::default().with_read_mask(self.read_mask);
        (self.service_client, request)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<GetServiceInfoResponse>> {
        let (mut service_client, request) = self.into_request();
        let response = service_client.get_service_info(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}

impl GrpcClient {
    /// Get service info from the node.
    ///
    /// Returns the [`GetServiceInfoResponse`] proto type with fields populated
    /// according to the read mask. Without
    /// [`read_mask`](GetServiceInfoQuery::read_mask), the default mask is
    /// used. Pass a
    /// [`ServiceInfoReadMask`](iota_grpc_types::read_mask_fields::ServiceInfoReadMask)
    /// built from a
    /// [`ServiceInfoField`](iota_grpc_types::read_mask_fields::ServiceInfoField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ServiceInfoField, ServiceInfoReadMask};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    ///
    /// let info = client.service_info().await?;
    /// println!("Chain ID: {:?}", info.body().chain_id);
    /// println!("Epoch: {:?}", info.body().epoch);
    ///
    /// // With a custom mask.
    /// let info = client
    ///     .service_info()
    ///     .read_mask(ServiceInfoReadMask::from([
    ///         ServiceInfoField::CHAIN_ID,
    ///         ServiceInfoField::EPOCH,
    ///     ]))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn service_info(&self) -> GetServiceInfoQuery {
        GetServiceInfoQuery {
            service_client: self.ledger_service_client(),
            read_mask: ServiceInfoReadMask::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{ServiceInfoField, ServiceInfoReadMask};

    use crate::GrpcClient;

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.service_info();
        assert_eq!(
            query.read_mask.as_str(),
            ServiceInfoReadMask::default().as_str()
        );

        let query = query.read_mask(ServiceInfoField::CHAIN_ID);
        assert_eq!(
            query.read_mask.as_str(),
            ServiceInfoReadMask::from(ServiceInfoField::CHAIN_ID).as_str()
        );
    }

    #[tokio::test]
    async fn the_request_carries_the_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .service_info()
            .read_mask(ServiceInfoField::CHAIN_ID)
            .into_request();
        assert_eq!(
            request.read_mask,
            Some(ServiceInfoReadMask::from(ServiceInfoField::CHAIN_ID).into())
        );
    }
}
