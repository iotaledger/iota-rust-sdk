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
    /// Returns the [`GetServiceInfoResponse`] proto type with fields populated
    /// according to the `read_mask`; use `ServiceInfoReadMask::default()` for
    /// the default read mask, or pass a
    /// [`ServiceInfoReadMask`](iota_grpc_types::read_mask_fields::ServiceInfoReadMask)
    /// built from a
    /// [`ServiceInfoField`](iota_grpc_types::read_mask_fields::ServiceInfoField)
    /// or any slice/array/vec of fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ServiceInfoField, ServiceInfoReadMask};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// let info = client.service_info(ServiceInfoReadMask::default()).await?;
    /// println!("Chain ID: {:?}", info.body().chain_id);
    /// println!("Epoch: {:?}", info.body().epoch);
    ///
    /// // With a custom mask.
    /// let info = client
    ///     .service_info(ServiceInfoReadMask::from([
    ///         ServiceInfoField::CHAIN_ID,
    ///         ServiceInfoField::EPOCH,
    ///     ]))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn service_info(
        &self,
        read_mask: impl IntoReadMask<ServiceInfoReadMask>,
    ) -> Result<MetadataEnvelope<GetServiceInfoResponse>> {
        let read_mask = read_mask.into_read_mask();
        let request = GetServiceInfoRequest::default().with_read_mask(read_mask);

        let mut client = self.ledger_service_client();
        let response = client.get_service_info(request).await?;

        Ok(MetadataEnvelope::from(response))
    }
}
