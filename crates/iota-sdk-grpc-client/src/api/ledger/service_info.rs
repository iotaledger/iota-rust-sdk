// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for service info queries.

use iota_grpc_types::v1::ledger_service::{GetServiceInfoRequest, GetServiceInfoResponse};

use crate::{
    Client,
    api::{
        GET_SERVICE_INFO_READ_MASK, MetadataEnvelope, ReadMask, Result, field_mask_with_default,
    },
};

impl Client {
    /// Get service info from the node.
    ///
    /// Returns the [`GetServiceInfoResponse`] proto type with fields populated
    /// according to the default read mask [`GET_SERVICE_INFO_READ_MASK`]. Use
    /// [`get_service_info_masked`](Self::get_service_info_masked) to specify a
    /// custom field mask.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000").await?;
    ///
    /// let info = client.get_service_info().await?;
    /// println!("Chain ID: {:?}", info.body().chain_id);
    /// println!("Epoch: {:?}", info.body().epoch);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_service_info(&self) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        self.get_service_info_internal(None).await
    }

    /// Get service info from the node, with a custom read mask.
    ///
    /// Returns the [`GetServiceInfoResponse`] proto type with fields populated
    /// according to `read_mask`.
    ///
    /// Use [`ServiceInfoField`](iota_grpc_types::read_mask_fields::ServiceInfoField)
    /// constants with [`ReadMask::from`] for field selection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{Client, ReadMask};
    /// # use iota_sdk_grpc_client::read_mask_fields::ServiceInfoField;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000").await?;
    ///
    /// let info = client
    ///     .get_service_info_masked(ReadMask::from(&[
    ///         ServiceInfoField::CHAIN_ID,
    ///         ServiceInfoField::EPOCH,
    ///     ]))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_service_info_masked(
        &self,
        read_mask: ReadMask<'_>,
    ) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        self.get_service_info_internal(Some(read_mask)).await
    }

    async fn get_service_info_internal(
        &self,
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        let request = GetServiceInfoRequest::default().with_read_mask(field_mask_with_default(
            read_mask,
            GET_SERVICE_INFO_READ_MASK,
        ));

        let mut client = self.ledger_service_client();
        let response = client.get_service_info(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}
