// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Bindings for selected Rust mirrors of Move types.
//!
//! Each FFI shim wraps an inner [`iota_sdk::move_types`] type and exposes
//! the fields that non-Rust consumers typically need when decoding objects
//! returned by the GraphQL client. Currently the bindings cover:
//!
//! - **System types** (`0x3`): [`StakedIota`], [`TimelockedStakedIota`].
//! - **Framework types** (`0x2`): [`IotaCoinMetadata`] (the `Iota` prefix
//!   disambiguates this from the GraphQL-derived `CoinMetadata` record).
//! - **Stardust types** (`0x107a`): [`Nft`], [`Irc27Metadata`],
//!   [`BasicOutput`], [`NftOutput`], [`AliasOutput`], [`Alias`], plus the
//!   unlock-condition records [`TimelockUnlockCondition`],
//!   [`ExpirationUnlockCondition`], [`StorageDepositReturnUnlockCondition`].
//!
//! Generic Move types are exposed as their `<IOTA>` instantiations
//! (`BasicOutput<IOTA>`, `NftOutput<IOTA>`, `AliasOutput<IOTA>`,
//! `IotaCoinMetadata` wrapping `CoinMetadata<IOTA>`). The
//! `try_from_object` constructors validate the full on-chain type tag,
//! including that the coin marker is `0x2::iota::IOTA`.

use std::sync::Arc;

use iota_sdk::move_types::framework::iota::IOTA;

use crate::{
    error::Result,
    types::{
        address::Address,
        object::{Object, ObjectId},
    },
};

fn ascii_to_string(s: &iota_sdk::move_types::std::ascii::String) -> String {
    String::from_utf8_lossy(&s.bytes).into_owned()
}

fn move_string_to_string(s: &iota_sdk::move_types::std::string::String) -> String {
    String::from_utf8_lossy(&s.bytes).into_owned()
}

fn url_to_string(u: &iota_sdk::move_types::framework::url::Url) -> String {
    ascii_to_string(&u.url)
}

// =====================================================================
// 0x3 — IOTA system
// =====================================================================

/// A typed view of an on-chain `0x3::staking_pool::StakedIota` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct StakedIota(pub iota_sdk::move_types::iota_system::staking_pool::StakedIota);

#[uniffi::export]
impl StakedIota {
    /// Decode a `StakedIota` from an on-chain object, validating that the
    /// object's type tag matches `0x3::staking_pool::StakedIota`.
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::iota_system::staking_pool::StakedIota::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    /// Decode a `StakedIota` from raw BCS bytes. Skips type-tag validation;
    /// prefer [`Self::try_from_object`] when an [`Object`] is available.
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::iota_system::staking_pool::StakedIota::try_from_bcs(&bytes)?
                .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id()).into()
    }

    pub fn pool_id(&self) -> ObjectId {
        (*self.0.pool_id()).into()
    }

    pub fn stake_activation_epoch(&self) -> u64 {
        self.0.stake_activation_epoch()
    }

    /// Staked principal in nanos.
    pub fn principal(&self) -> u64 {
        self.0.principal()
    }
}

/// A typed view of an on-chain
/// `0x3::timelocked_staking::TimelockedStakedIota` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct TimelockedStakedIota(
    pub iota_sdk::move_types::iota_system::timelocked_staking::TimelockedStakedIota,
);

#[uniffi::export]
impl TimelockedStakedIota {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::iota_system::timelocked_staking::TimelockedStakedIota::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::iota_system::timelocked_staking::TimelockedStakedIota::try_from_bcs(
                &bytes,
            )?
            .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id()).into()
    }

    /// The wrapped `StakedIota` carrying the staked principal.
    pub fn staked_iota(&self) -> StakedIota {
        StakedIota(self.0.staked_iota.clone())
    }

    /// Epoch timestamp (ms) of when the lock expires.
    pub fn expiration_timestamp_ms(&self) -> u64 {
        self.0.expiration_timestamp_ms()
    }

    pub fn label(&self) -> Option<String> {
        self.0.label.as_ref().map(move_string_to_string)
    }
}

// =====================================================================
// 0x2 — IOTA framework
// =====================================================================

/// A typed view of an on-chain `0x2::coin::CoinMetadata<IOTA>` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct IotaCoinMetadata(pub iota_sdk::move_types::framework::coin::CoinMetadata<IOTA>);

#[uniffi::export]
impl IotaCoinMetadata {
    /// Decode a `CoinMetadata` from an on-chain object, validating that the
    /// object's type tag matches `0x2::coin::CoinMetadata`. The inner coin
    /// marker is not re-checked against `IOTA`.
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::framework::coin::CoinMetadata::<IOTA>::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::framework::coin::CoinMetadata::<IOTA>::try_from_bcs(&bytes)?
                .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    pub fn decimals(&self) -> u8 {
        self.0.decimals
    }

    pub fn name(&self) -> String {
        move_string_to_string(&self.0.name)
    }

    pub fn symbol(&self) -> String {
        ascii_to_string(&self.0.symbol)
    }

    pub fn description(&self) -> String {
        move_string_to_string(&self.0.description)
    }

    pub fn icon_url(&self) -> Option<String> {
        self.0.icon_url.as_ref().map(url_to_string)
    }
}

// =====================================================================
// 0x107a — Stardust
// =====================================================================

/// A typed view of an on-chain `0x107a::nft::Nft` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct Nft(pub iota_sdk::move_types::stardust::nft::Nft);

#[uniffi::export]
impl Nft {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(iota_sdk::move_types::stardust::nft::Nft::try_from_object(&object.0)?.into())
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(iota_sdk::move_types::stardust::nft::Nft::try_from_bcs(&bytes)?.into())
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    pub fn legacy_sender(&self) -> Option<Arc<Address>> {
        self.0.legacy_sender.map(|a| Arc::new(Address(a)))
    }

    pub fn metadata(&self) -> Option<Vec<u8>> {
        self.0.metadata.clone()
    }

    pub fn tag(&self) -> Option<Vec<u8>> {
        self.0.tag.clone()
    }

    pub fn immutable_issuer(&self) -> Option<Arc<Address>> {
        self.0.immutable_issuer.map(|a| Arc::new(Address(a)))
    }

    pub fn immutable_metadata(&self) -> Irc27Metadata {
        Irc27Metadata(self.0.immutable_metadata.clone())
    }
}

/// A typed view of `0x107a::irc27::Irc27Metadata` (usually nested inside an
/// [`Nft`]).
///
/// The `royalties`, `attributes`, and `non_standard_fields` `VecMap` fields
/// are not yet exposed across the FFI boundary — consumers that need them
/// can decode the inner type from BCS in Rust.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct Irc27Metadata(pub iota_sdk::move_types::stardust::irc27::Irc27Metadata);

#[uniffi::export]
impl Irc27Metadata {
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(iota_sdk::move_types::stardust::irc27::Irc27Metadata::try_from_bcs(&bytes)?.into())
    }

    pub fn version(&self) -> String {
        move_string_to_string(&self.0.version)
    }

    pub fn media_type(&self) -> String {
        move_string_to_string(&self.0.media_type)
    }

    pub fn uri(&self) -> String {
        url_to_string(&self.0.uri)
    }

    pub fn name(&self) -> String {
        move_string_to_string(&self.0.name)
    }

    pub fn collection_name(&self) -> Option<String> {
        self.0.collection_name.as_ref().map(move_string_to_string)
    }

    pub fn issuer_name(&self) -> Option<String> {
        self.0.issuer_name.as_ref().map(move_string_to_string)
    }

    pub fn description(&self) -> Option<String> {
        self.0.description.as_ref().map(move_string_to_string)
    }
}

/// A typed view of an on-chain
/// `0x107a::basic_output::BasicOutput<IOTA>` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct BasicOutput(pub iota_sdk::move_types::stardust::basic_output::BasicOutput<IOTA>);

#[uniffi::export]
impl BasicOutput {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::basic_output::BasicOutput::<IOTA>::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::basic_output::BasicOutput::<IOTA>::try_from_bcs(
                &bytes,
            )?
            .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    /// IOTA balance held by the output, in nanos.
    pub fn balance(&self) -> u64 {
        self.0.balance.value()
    }

    /// Object ID of the `Bag` of native tokens. Use the GraphQL client to
    /// list dynamic fields if you need to enumerate the tokens.
    pub fn native_tokens_bag_id(&self) -> ObjectId {
        (*self.0.native_tokens.id.object_id()).into()
    }

    pub fn storage_deposit_return_uc(&self) -> Option<Arc<StorageDepositReturnUnlockCondition>> {
        self.0
            .storage_deposit_return_uc
            .clone()
            .map(|c| Arc::new(StorageDepositReturnUnlockCondition(c)))
    }

    pub fn timelock_uc(&self) -> Option<Arc<TimelockUnlockCondition>> {
        self.0
            .timelock_uc
            .clone()
            .map(|c| Arc::new(TimelockUnlockCondition(c)))
    }

    pub fn expiration_uc(&self) -> Option<Arc<ExpirationUnlockCondition>> {
        self.0
            .expiration_uc
            .clone()
            .map(|c| Arc::new(ExpirationUnlockCondition(c)))
    }

    pub fn metadata(&self) -> Option<Vec<u8>> {
        self.0.metadata.clone()
    }

    pub fn tag(&self) -> Option<Vec<u8>> {
        self.0.tag.clone()
    }

    pub fn sender(&self) -> Option<Arc<Address>> {
        self.0.sender.map(|a| Arc::new(Address(a)))
    }
}

/// A typed view of an on-chain `0x107a::nft_output::NftOutput<IOTA>` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct NftOutput(pub iota_sdk::move_types::stardust::nft_output::NftOutput<IOTA>);

#[uniffi::export]
impl NftOutput {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::nft_output::NftOutput::<IOTA>::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::nft_output::NftOutput::<IOTA>::try_from_bcs(&bytes)?
                .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    pub fn balance(&self) -> u64 {
        self.0.balance.value()
    }

    pub fn native_tokens_bag_id(&self) -> ObjectId {
        (*self.0.native_tokens.id.object_id()).into()
    }

    pub fn storage_deposit_return_uc(&self) -> Option<Arc<StorageDepositReturnUnlockCondition>> {
        self.0
            .storage_deposit_return_uc
            .clone()
            .map(|c| Arc::new(StorageDepositReturnUnlockCondition(c)))
    }

    pub fn timelock_uc(&self) -> Option<Arc<TimelockUnlockCondition>> {
        self.0
            .timelock_uc
            .clone()
            .map(|c| Arc::new(TimelockUnlockCondition(c)))
    }

    pub fn expiration_uc(&self) -> Option<Arc<ExpirationUnlockCondition>> {
        self.0
            .expiration_uc
            .clone()
            .map(|c| Arc::new(ExpirationUnlockCondition(c)))
    }
}

/// A typed view of an on-chain
/// `0x107a::alias_output::AliasOutput<IOTA>` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct AliasOutput(pub iota_sdk::move_types::stardust::alias_output::AliasOutput<IOTA>);

#[uniffi::export]
impl AliasOutput {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::alias_output::AliasOutput::<IOTA>::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::stardust::alias_output::AliasOutput::<IOTA>::try_from_bcs(
                &bytes,
            )?
            .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    pub fn balance(&self) -> u64 {
        self.0.balance.value()
    }

    pub fn native_tokens_bag_id(&self) -> ObjectId {
        (*self.0.native_tokens.id.object_id()).into()
    }
}

/// A typed view of an on-chain `0x107a::alias::Alias` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct Alias(pub iota_sdk::move_types::stardust::alias::Alias);

#[uniffi::export]
impl Alias {
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(iota_sdk::move_types::stardust::alias::Alias::try_from_object(&object.0)?.into())
    }

    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(iota_sdk::move_types::stardust::alias::Alias::try_from_bcs(&bytes)?.into())
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    pub fn legacy_state_controller(&self) -> Address {
        Address(self.0.legacy_state_controller)
    }

    pub fn state_index(&self) -> u32 {
        self.0.state_index
    }

    pub fn state_metadata(&self) -> Option<Vec<u8>> {
        self.0.state_metadata.clone()
    }

    pub fn sender(&self) -> Option<Arc<Address>> {
        self.0.sender.map(|a| Arc::new(Address(a)))
    }

    pub fn metadata(&self) -> Option<Vec<u8>> {
        self.0.metadata.clone()
    }

    pub fn immutable_issuer(&self) -> Option<Arc<Address>> {
        self.0.immutable_issuer.map(|a| Arc::new(Address(a)))
    }

    pub fn immutable_metadata(&self) -> Option<Vec<u8>> {
        self.0.immutable_metadata.clone()
    }
}

// Unlock conditions used by `BasicOutput` and `NftOutput`.

/// A typed view of
/// `0x107a::timelock_unlock_condition::TimelockUnlockCondition`.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct TimelockUnlockCondition(
    pub iota_sdk::move_types::stardust::timelock_unlock_condition::TimelockUnlockCondition,
);

#[uniffi::export]
impl TimelockUnlockCondition {
    /// Unix time (seconds since the Unix epoch) from which the output can
    /// be consumed.
    pub fn unix_time(&self) -> u32 {
        self.0.unix_time
    }
}

/// A typed view of
/// `0x107a::expiration_unlock_condition::ExpirationUnlockCondition`.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct ExpirationUnlockCondition(
    pub iota_sdk::move_types::stardust::expiration_unlock_condition::ExpirationUnlockCondition,
);

#[uniffi::export]
impl ExpirationUnlockCondition {
    pub fn owner(&self) -> Address {
        Address(self.0.owner)
    }

    pub fn return_address(&self) -> Address {
        Address(self.0.return_address)
    }

    pub fn unix_time(&self) -> u32 {
        self.0.unix_time
    }
}

/// A typed view of
/// `0x107a::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition`.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct StorageDepositReturnUnlockCondition(
    pub iota_sdk::move_types::stardust::storage_deposit_return_unlock_condition::StorageDepositReturnUnlockCondition,
);

#[uniffi::export]
impl StorageDepositReturnUnlockCondition {
    pub fn return_address(&self) -> Address {
        Address(self.0.return_address)
    }

    pub fn return_amount(&self) -> u64 {
        self.0.return_amount
    }
}
