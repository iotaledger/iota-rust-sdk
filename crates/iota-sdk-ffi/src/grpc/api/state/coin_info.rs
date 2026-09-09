// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Coin info API implementation.

use std::sync::Arc;

use iota_sdk::grpc_types::v1 as proto;

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::{move_core::StructTag, object::ObjectId},
};

/// The state of the `MetadataCap` of a coin type.
#[derive(uniffi::Enum)]
pub enum MetadataCapState {
    /// The state of the `MetadataCap` is unknown.
    Unknown,
    /// The `MetadataCap` has been claimed.
    Claimed,
    /// The `MetadataCap` has not been claimed.
    Unclaimed,
    /// The `MetadataCap` has been deleted.
    Deleted,
}

impl From<proto::coin::coin_metadata::MetadataCapState> for MetadataCapState {
    fn from(value: proto::coin::coin_metadata::MetadataCapState) -> Self {
        match value {
            proto::coin::coin_metadata::MetadataCapState::Claimed => Self::Claimed,
            proto::coin::coin_metadata::MetadataCapState::Unclaimed => Self::Unclaimed,
            proto::coin::coin_metadata::MetadataCapState::Deleted => Self::Deleted,
            _ => Self::Unknown,
        }
    }
}

/// The metadata of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinMetadata {
    /// The id of the `0x2::coin::CoinMetadata` object or
    /// `Currency` object (when registered with the `CoinRegistry`).
    pub id: Option<Arc<ObjectId>>,
    /// Number of decimal places the coin uses.
    pub decimals: Option<u32>,
    /// Name for the token.
    pub name: Option<String>,
    /// Symbol for the token.
    pub symbol: Option<String>,
    /// Description of the token.
    pub description: Option<String>,
    /// URL for the token logo.
    pub icon_url: Option<String>,
    /// The `MetadataCap` id if it has been claimed for the coin type.
    pub metadata_cap_id: Option<Arc<ObjectId>>,
    /// State of the `MetadataCap` for the coin type.
    pub metadata_cap_state: Option<MetadataCapState>,
}

impl TryFrom<&proto::coin::CoinMetadata> for GrpcCoinMetadata {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::CoinMetadata) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            decimals: value.decimals,
            name: value.name.clone(),
            symbol: value.symbol.clone(),
            description: value.description.clone(),
            icon_url: value.icon_url.clone(),
            metadata_cap_id: value
                .metadata_cap_id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            metadata_cap_state: value
                .metadata_cap_state
                .and_then(|state| {
                    proto::coin::coin_metadata::MetadataCapState::try_from(state).ok()
                })
                .map(Into::into),
        })
    }
}

/// The supply state of a coin type.
#[derive(uniffi::Enum)]
pub enum SupplyState {
    /// The supply is unknown or the `TreasuryCap` still exists (minting still
    /// possible).
    Unknown,
    /// The supply is fixed (the `TreasuryCap` was consumed, no more minting
    /// possible).
    Fixed,
    /// The supply can only be burned.
    BurnOnly,
}

impl From<proto::coin::coin_treasury::SupplyState> for SupplyState {
    fn from(value: proto::coin::coin_treasury::SupplyState) -> Self {
        match value {
            proto::coin::coin_treasury::SupplyState::Fixed => Self::Fixed,
            proto::coin::coin_treasury::SupplyState::BurnOnly => Self::BurnOnly,
            _ => Self::Unknown,
        }
    }
}

/// The treasury of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinTreasury {
    /// The id of the `0x2::coin::TreasuryCap` object.
    pub id: Option<Arc<ObjectId>>,
    /// Total available supply for the coin type.
    pub total_supply: Option<u64>,
    /// Supply state indicating if the supply is fixed or can still be minted.
    pub supply_state: Option<SupplyState>,
}

impl TryFrom<&proto::coin::CoinTreasury> for GrpcCoinTreasury {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::CoinTreasury) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            total_supply: value.total_supply,
            supply_state: value
                .supply_state
                .and_then(|state| proto::coin::coin_treasury::SupplyState::try_from(state).ok())
                .map(Into::into),
        })
    }
}

/// The regulated state of a coin type.
#[derive(uniffi::Enum)]
pub enum CoinRegulatedState {
    /// The regulated state of the coin is unknown.
    Unknown,
    /// The coin is regulated.
    Regulated,
    /// The coin is not regulated.
    Unregulated,
}

impl From<proto::coin::regulated_coin_metadata::CoinRegulatedState> for CoinRegulatedState {
    fn from(value: proto::coin::regulated_coin_metadata::CoinRegulatedState) -> Self {
        match value {
            proto::coin::regulated_coin_metadata::CoinRegulatedState::Regulated => Self::Regulated,
            proto::coin::regulated_coin_metadata::CoinRegulatedState::Unregulated => {
                Self::Unregulated
            }
            _ => Self::Unknown,
        }
    }
}

/// The regulated metadata of a coin type.
#[derive(uniffi::Record)]
pub struct GrpcRegulatedCoinMetadata {
    /// The id of the `0x2::coin::RegulatedCoinMetadata` object.
    pub id: Option<Arc<ObjectId>>,
    /// The id of the coin's `CoinMetadata` or `CoinData` object.
    pub coin_metadata_object: Option<Arc<ObjectId>>,
    /// The id of the coin's `DenyCap` object.
    pub deny_cap_object: Option<Arc<ObjectId>>,
    /// Whether the coin can be globally paused.
    pub allow_global_pause: Option<bool>,
    /// Variant of the regulated coin metadata.
    pub variant: Option<u32>,
    /// The coin's regulated state.
    pub coin_regulated_state: Option<CoinRegulatedState>,
}

impl TryFrom<&proto::coin::RegulatedCoinMetadata> for GrpcRegulatedCoinMetadata {
    type Error = SdkFfiError;

    fn try_from(value: &proto::coin::RegulatedCoinMetadata) -> Result<Self> {
        Ok(Self {
            id: value
                .id
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            coin_metadata_object: value
                .coin_metadata_object
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            deny_cap_object: value
                .deny_cap_object
                .as_ref()
                .map(iota_sdk::types::ObjectId::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            allow_global_pause: value.allow_global_pause,
            variant: value.variant,
            coin_regulated_state: value
                .coin_regulated_state
                .and_then(|state| {
                    proto::coin::regulated_coin_metadata::CoinRegulatedState::try_from(state).ok()
                })
                .map(Into::into),
        })
    }
}

/// Information about a coin type.
#[derive(uniffi::Record)]
pub struct GrpcCoinInfo {
    /// The coin type.
    pub coin_type: Option<String>,
    /// Information about the coin type's `0x2::coin::CoinMetadata`, if it
    /// exists and has not been wrapped.
    pub metadata: Option<GrpcCoinMetadata>,
    /// Information about the coin type's `0x2::coin::TreasuryCap`, if it
    /// exists and has not been wrapped.
    pub treasury: Option<GrpcCoinTreasury>,
    /// Information about the coin type's regulated metadata, if the coin is
    /// regulated.
    pub regulated_metadata: Option<GrpcRegulatedCoinMetadata>,
}

impl TryFrom<&proto::state_service::GetCoinInfoResponse> for GrpcCoinInfo {
    type Error = SdkFfiError;

    fn try_from(value: &proto::state_service::GetCoinInfoResponse) -> Result<Self> {
        Ok(Self {
            coin_type: value.coin_type.clone(),
            metadata: value.metadata.as_ref().map(TryInto::try_into).transpose()?,
            treasury: value.treasury.as_ref().map(TryInto::try_into).transpose()?,
            regulated_metadata: value
                .regulated_metadata
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
        })
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get information about a coin type, including its metadata, treasury,
    /// and regulated metadata.
    pub async fn coin_info(&self, coin_type: &StructTag) -> Result<GrpcCoinInfo> {
        (&self
            .0
            .read()
            .await
            .coin_info(coin_type.0.clone())
            .await?
            .into_inner())
            .try_into()
    }
}
