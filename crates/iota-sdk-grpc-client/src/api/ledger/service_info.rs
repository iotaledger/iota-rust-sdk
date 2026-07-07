// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for service info queries.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, ServiceInfoReadMask},
    v1::ledger_service::{GetServiceInfoRequest, GetServiceInfoResponse},
};

use crate::{
    Client,
    api::{MetadataEnvelope, Result},
};

impl Client {
    /// Get service info from the node.
    ///
    /// Returns the [`GetServiceInfoResponse`] proto type populated with the
    /// default field mask `ServiceInfoReadMask::default()`. Use
    /// [`get_service_info_masked`](Self::get_service_info_masked) to specify a
    /// custom mask.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// let info = client.get_service_info().await?;
    /// println!("Chain ID: {:?}", info.body().chain_id);
    /// println!("Epoch: {:?}", info.body().epoch);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_service_info(&self) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        self.get_service_info_internal(Default::default()).await
    }

    /// Get service info from the node, with a custom read mask.
    ///
    /// Pass a
    /// [`ServiceInfoField`](iota_grpc_types::read_mask_fields::ServiceInfoField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::ServiceInfoField;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// let info = client
    ///     .get_service_info_masked([ServiceInfoField::CHAIN_ID, ServiceInfoField::EPOCH])
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_service_info_masked(
        &self,
        read_mask: impl IntoReadMask<ServiceInfoReadMask>,
    ) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        self.get_service_info_internal(read_mask.into_read_mask())
            .await
    }

    async fn get_service_info_internal(
        &self,
        read_mask: ServiceInfoReadMask,
    ) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        let request = GetServiceInfoRequest::default().with_read_mask(read_mask);

        let mut client = self.ledger_service_client();
        let response = client.get_service_info(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}
