// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for epoch queries.

use iota_grpc_types::{
    field::FieldMask,
    read_mask_fields::{EpochReadMask, IntoReadMask},
    v1::{epoch::Epoch, ledger_service::GetEpochRequest},
};

use crate::{
    Client,
    api::{MetadataEnvelope, Result, TryFromProtoError},
};

impl Client {
    /// Get epoch information.
    ///
    /// Returns the [`Epoch`] proto type with fields populated according to the
    /// `read_mask`; use `EpochReadMask::default()` for the default field mask.
    /// Pass an
    /// [`EpochReadMask`](iota_grpc_types::read_mask_fields::EpochReadMask)
    /// built from an
    /// [`EpochField`](iota_grpc_types::read_mask_fields::EpochField) or any
    /// slice/array/vec of fields. For individual protocol config map entries,
    /// use
    /// [`EpochField::feature_flag`](iota_grpc_types::read_mask_fields::EpochField::feature_flag)
    /// and
    /// [`EpochField::attribute`](iota_grpc_types::read_mask_fields::EpochField::attribute).
    ///
    /// # Parameters
    ///
    /// * `epoch` - The epoch to query. If `None`, returns the current epoch.
    /// * `read_mask` - Field mask controlling the returned fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::{EpochField, EpochReadMask};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// // Current epoch with the default mask.
    /// let epoch = client.epoch(None, EpochReadMask::default()).await?;
    /// println!("Epoch: {:?}", epoch.body().epoch);
    ///
    /// // Specific epoch with selected fields.
    /// let epoch = client
    ///     .epoch(
    ///         Some(0),
    ///         EpochReadMask::from([
    ///             EpochField::EPOCH,
    ///             EpochField::REFERENCE_GAS_PRICE,
    ///             EpochField::FIRST_CHECKPOINT,
    ///         ]),
    ///     )
    ///     .await?;
    ///
    /// // All feature flags for the current epoch.
    /// let epoch = client
    ///     .epoch(
    ///         None,
    ///         EpochReadMask::from(EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS),
    ///     )
    ///     .await?
    ///     .into_inner();
    /// let flags = epoch.protocol_config.unwrap().feature_flags.unwrap().flags;
    ///
    /// // A single named feature flag.
    /// let epoch = client
    ///     .epoch(
    ///         None,
    ///         EpochReadMask::from(EpochField::feature_flag("enable_vdf")),
    ///     )
    ///     .await?;
    ///
    /// // A single named attribute.
    /// let epoch = client
    ///     .epoch(
    ///         None,
    ///         EpochReadMask::from(EpochField::attribute("max_tx_gas")),
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn epoch(
        &self,
        epoch: impl Into<Option<u64>>,
        read_mask: impl IntoReadMask<EpochReadMask>,
    ) -> Result<MetadataEnvelope<Epoch>> {
        let read_mask = read_mask.into_read_mask();
        let mut request = GetEpochRequest::default().with_read_mask(read_mask);

        if let Some(epoch) = epoch.into() {
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
    /// let client = Client::new_localnet()?;
    /// let gas_price = client.reference_gas_price().await?.into_inner();
    /// println!("Reference gas price: {gas_price} NANOS");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn reference_gas_price(&self) -> Result<MetadataEnvelope<u64>> {
        self.epoch_field("reference_gas_price", |e| e.reference_gas_price)
            .await
    }

    /// Internal helper to fetch a single field from the current epoch.
    async fn epoch_field<T>(
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
