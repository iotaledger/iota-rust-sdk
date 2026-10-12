// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for epoch queries.

use iota_grpc_types::{
    read_mask_fields::{EpochField, EpochReadMask, IntoReadMask},
    v1::{
        epoch::Epoch,
        ledger_service::{GetEpochRequest, ledger_service_client::LedgerServiceClient},
    },
};

use crate::{
    GrpcClient, InterceptedChannel,
    api::{GrpcResult, MetadataEnvelope, TryFromProtoError, define_query},
};

define_query! {
    /// Query for [`GrpcClient::epoch`]. Await it to send the request.
    pub struct GetEpochQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        epoch: Option<u64>,
        read_mask: EpochReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Epoch>>;
}

impl GetEpochQuery {
    /// Set the number of the epoch to query. Without it, queries the current
    /// epoch.
    pub fn epoch_number(mut self, epoch_number: u64) -> Self {
        self.epoch = Some(epoch_number);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<EpochReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(self) -> (LedgerServiceClient<InterceptedChannel>, GetEpochRequest) {
        let mut request = GetEpochRequest::default().with_read_mask(self.read_mask);

        if let Some(epoch) = self.epoch {
            request = request.with_epoch(epoch);
        }

        (self.service_client, request)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<Epoch>> {
        let (mut service_client, request) = self.into_request();
        let response = service_client.get_epoch(request).await?;

        MetadataEnvelope::from(response).try_map(|r| {
            r.epoch
                .ok_or_else(|| TryFromProtoError::missing("epoch").into())
        })
    }
}

define_query! {
    /// Query for [`GrpcClient::reference_gas_price`]. Await it to send the
    /// request.
    pub struct GetReferenceGasPriceQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
    }
    output: GrpcResult<MetadataEnvelope<u64>>;
}

impl GetReferenceGasPriceQuery {
    fn into_request(self) -> (LedgerServiceClient<InterceptedChannel>, GetEpochRequest) {
        let request = GetEpochRequest::default()
            .with_read_mask(EpochReadMask::from(EpochField::REFERENCE_GAS_PRICE));
        (self.service_client, request)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<u64>> {
        let (mut service_client, request) = self.into_request();
        let response = service_client.get_epoch(request).await?;

        MetadataEnvelope::from(response).try_map(|r| Ok(r.epoch()?.gas_price()?))
    }
}

impl GrpcClient {
    /// Get epoch information.
    ///
    /// Returns the [`Epoch`] proto type of the current epoch, or of the one set
    /// with [`epoch_number`](GetEpochQuery::epoch_number), with fields
    /// populated according to the read mask. Without
    /// [`read_mask`](GetEpochQuery::read_mask), the default mask is used.
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
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::{EpochField, EpochReadMask};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    ///
    /// // Current epoch with the default mask.
    /// let epoch = client.epoch().await?;
    /// println!("Epoch: {:?}", epoch.body().epoch);
    ///
    /// // Specific epoch with selected fields.
    /// let epoch = client
    ///     .epoch()
    ///     .epoch_number(0)
    ///     .read_mask(EpochReadMask::from([
    ///         EpochField::EPOCH,
    ///         EpochField::REFERENCE_GAS_PRICE,
    ///         EpochField::FIRST_CHECKPOINT,
    ///     ]))
    ///     .await?;
    ///
    /// // All feature flags for the current epoch.
    /// let epoch = client
    ///     .epoch()
    ///     .read_mask(EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS)
    ///     .await?
    ///     .into_inner();
    /// let flags = epoch.protocol_config.unwrap().feature_flags.unwrap().flags;
    ///
    /// // A single named feature flag.
    /// let epoch = client
    ///     .epoch()
    ///     .read_mask(EpochField::feature_flag("enable_vdf"))
    ///     .await?;
    ///
    /// // A single named attribute.
    /// let epoch = client
    ///     .epoch()
    ///     .read_mask(EpochField::attribute("max_tx_gas"))
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn epoch(&self) -> GetEpochQuery {
        GetEpochQuery {
            service_client: self.ledger_service_client(),
            epoch: None,
            read_mask: EpochReadMask::default(),
        }
    }

    /// Get the reference gas price for the current epoch.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let gas_price = client.reference_gas_price().await?.into_inner();
    /// println!("Reference gas price: {gas_price} NANOS");
    /// # Ok(())
    /// # }
    /// ```
    pub fn reference_gas_price(&self) -> GetReferenceGasPriceQuery {
        GetReferenceGasPriceQuery {
            service_client: self.ledger_service_client(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{EpochField, EpochReadMask};

    use crate::GrpcClient;

    #[tokio::test]
    async fn epoch_defaults_to_the_current_epoch_and_the_setter_picks_one() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.epoch();
        assert_eq!(query.epoch, None);
        assert_eq!(query.read_mask.as_str(), EpochReadMask::default().as_str());

        let query = query
            .epoch_number(5)
            .read_mask(EpochField::REFERENCE_GAS_PRICE);
        assert_eq!(query.epoch, Some(5));
        assert_eq!(
            query.read_mask.as_str(),
            EpochReadMask::from(EpochField::REFERENCE_GAS_PRICE).as_str()
        );
    }

    #[tokio::test]
    async fn the_request_carries_the_epoch_and_the_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .epoch()
            .epoch_number(5)
            .read_mask(EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS)
            .into_request();
        assert_eq!(request.epoch, Some(5));
        assert_eq!(
            request.read_mask,
            Some(EpochReadMask::from(EpochField::PROTOCOL_CONFIG_FEATURE_FLAGS).into())
        );

        let (_, request) = client.epoch().into_request();
        assert_eq!(request.epoch, None);
    }

    #[tokio::test]
    async fn reference_gas_price_asks_the_current_epoch_for_the_price_only() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client.reference_gas_price().into_request();
        assert_eq!(request.epoch, None);
        assert_eq!(
            request.read_mask.map(|mask| mask.paths),
            Some(vec!["reference_gas_price".to_owned()])
        );
    }
}
