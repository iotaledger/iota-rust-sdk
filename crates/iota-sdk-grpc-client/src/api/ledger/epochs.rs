// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for epoch queries.

use iota_grpc_types::{
    field::FieldMask,
    v1::{epoch::Epoch, ledger_service::GetEpochRequest},
};

use crate::{
    Client,
    api::{
        GET_EPOCH_READ_MASK, MetadataEnvelope, ReadMask, Result, TryFromProtoError,
        field_mask_with_default,
    },
};

impl Client {
    /// Get epoch information.
    ///
    /// Returns the [`Epoch`] proto type with fields populated according to the
    /// `read_mask`.
    ///
    /// # Parameters
    ///
    /// * `epoch` - The epoch to query. If `None`, returns the current epoch.
    /// * `read_mask` - Optional field mask specifying which fields to include.
    ///   If `None`, uses [`GET_EPOCH_READ_MASK`].
    ///
    /// # Read Mask
    ///
    /// Use [`EpochField`](iota_grpc_types::read_mask_fields::EpochField)
    /// constants with [`ReadMask::from`] for field selection. For individual
    /// protocol config map entries, use
    /// [`EpochField::feature_flag`](iota_grpc_types::read_mask_fields::EpochField::feature_flag)
    /// and
    /// [`EpochField::attribute`](iota_grpc_types::read_mask_fields::EpochField::attribute).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{Client, ReadMask};
    /// # use iota_sdk_grpc_client::read_mask_fields::EpochField;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000")?;
    ///
    /// // Get current epoch with default fields
    /// let epoch = client.get_epoch(None, None).await?;
    /// println!("Epoch: {:?}", epoch.body().epoch);
    ///
    /// // Get specific epoch with custom fields
    /// let epoch = client
    ///     .get_epoch(
    ///         Some(0),
    ///         Some(ReadMask::from(&[
    ///             EpochField::EPOCH,
    ///             EpochField::REFERENCE_GAS_PRICE,
    ///             EpochField::FIRST_CHECKPOINT,
    ///         ])),
    ///     )
    ///     .await?;
    ///
    /// // Get all feature flags for the current epoch
    /// let epoch = client
    ///     .get_epoch(
    ///         None,
    ///         Some(ReadMask::from(EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS)),
    ///     )
    ///     .await?
    ///     .into_inner();
    /// let flags = epoch.protocol_config.unwrap().feature_flags.unwrap().flags;
    ///
    /// // Get a single named feature flag
    /// let flag_field = EpochField::feature_flag("enable_vdf");
    /// let epoch = client
    ///     .get_epoch(None, Some(ReadMask::from(flag_field.as_str())))
    ///     .await?;
    ///
    /// // Get all protocol attributes for the current epoch
    /// let epoch = client
    ///     .get_epoch(
    ///         None,
    ///         Some(ReadMask::from(EpochField::PROTOCOL_CONFIG_ATTRIBUTES)),
    ///     )
    ///     .await?
    ///     .into_inner();
    /// let attributes = epoch
    ///     .protocol_config
    ///     .unwrap()
    ///     .attributes
    ///     .unwrap()
    ///     .attributes;
    ///
    /// // Get a single named attribute
    /// let attr_field = EpochField::attribute("max_tx_gas");
    /// let epoch = client
    ///     .get_epoch(None, Some(ReadMask::from(attr_field.as_str())))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_epoch(
        &self,
        epoch: Option<u64>,
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<Epoch>> {
        let mut request = GetEpochRequest::default()
            .with_read_mask(field_mask_with_default(read_mask, GET_EPOCH_READ_MASK));

        if let Some(epoch) = epoch {
            request = request.with_epoch(epoch);
        }

        let mut client = self.ledger_service_client();
        let response = client.get_epoch(request).await?;

        MetadataEnvelope::from(response).try_map(|r| {
            r.epoch
                .ok_or_else(|| TryFromProtoError::missing("epoch").into())
        })
    }

    /// Get the reference gas price for the current epoch.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000")?;
    /// let gas_price = client.get_reference_gas_price().await?.into_inner();
    /// println!("Reference gas price: {gas_price} NANOS");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_reference_gas_price(&self) -> Result<MetadataEnvelope<u64>> {
        self.get_epoch_field("reference_gas_price", |e| e.reference_gas_price)
            .await
    }

    /// Internal helper to fetch a single field from the current epoch.
    async fn get_epoch_field<T>(
        &self,
        field: &str,
        extractor: impl FnOnce(Epoch) -> Option<T>,
    ) -> Result<MetadataEnvelope<T>> {
        // Current epoch (no epoch field set)
        let request = GetEpochRequest::default().with_read_mask(FieldMask {
            paths: vec![field.to_string()],
        });

        let mut client = self.ledger_service_client();
        let response = client.get_epoch(request).await?;

        MetadataEnvelope::from(response).try_map(|r| {
            r.epoch
                .and_then(extractor)
                .ok_or_else(|| TryFromProtoError::missing(field).into())
        })
    }
}
