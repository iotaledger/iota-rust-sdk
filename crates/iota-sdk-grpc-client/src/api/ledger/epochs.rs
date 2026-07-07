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
    /// Returns the [`Epoch`] proto type populated with the default field mask
    /// `EpochReadMask::default()`. Use
    /// [`get_epoch_masked`](Self::get_epoch_masked) to specify a custom mask.
    ///
    /// # Parameters
    ///
    /// * `epoch` - The epoch to query. If `None`, returns the current epoch.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// // Get current epoch
    /// let epoch = client.get_epoch(None).await?;
    /// println!("Epoch: {:?}", epoch.body().epoch);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_epoch(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<MetadataEnvelope<Epoch>> {
        self.get_epoch_internal(epoch.into(), Default::default())
            .await
    }

    /// Get epoch information, with a custom read mask.
    ///
    /// Returns the [`Epoch`] proto type with fields populated according to
    /// `read_mask`. Pass an
    /// [`EpochField`](iota_grpc_types::read_mask_fields::EpochField) or any
    /// slice/array/vec of fields — conversion is automatic. For individual
    /// protocol config map entries, use
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
    /// # use iota_sdk_grpc_client::read_mask_fields::EpochField;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// // Current epoch with the default mask.
    /// let epoch = client.get_epoch(None).await?;
    /// println!("Epoch: {:?}", epoch.body().epoch);
    ///
    /// // Specific epoch with selected fields.
    /// let epoch = client
    ///     .get_epoch_masked(
    ///         Some(0),
    ///         [
    ///             EpochField::EPOCH,
    ///             EpochField::REFERENCE_GAS_PRICE,
    ///             EpochField::FIRST_CHECKPOINT,
    ///         ],
    ///     )
    ///     .await?;
    ///
    /// // All feature flags for the current epoch.
    /// let epoch = client
    ///     .get_epoch_masked(None, EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS)
    ///     .await?
    ///     .into_inner();
    /// let flags = epoch.protocol_config.unwrap().feature_flags.unwrap().flags;
    ///
    /// // A single named feature flag.
    /// let epoch = client
    ///     .get_epoch_masked(None, EpochField::feature_flag("enable_vdf"))
    ///     .await?;
    ///
    /// // A single named attribute.
    /// let epoch = client
    ///     .get_epoch_masked(None, EpochField::attribute("max_tx_gas"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_epoch_masked(
        &self,
        epoch: impl Into<Option<u64>>,
        read_mask: impl IntoReadMask<EpochReadMask>,
    ) -> Result<MetadataEnvelope<Epoch>> {
        self.get_epoch_internal(epoch.into(), read_mask.into_read_mask())
            .await
    }

    async fn get_epoch_internal(
        &self,
        epoch: Option<u64>,
        read_mask: EpochReadMask,
    ) -> Result<MetadataEnvelope<Epoch>> {
        let mut request = GetEpochRequest::default().with_read_mask(read_mask);

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
    /// let client = Client::new_localnet()?;
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
