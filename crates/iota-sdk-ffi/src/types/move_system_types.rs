// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Bindings for selected Rust mirrors of Move system types.
//!
//! Currently exposes [`StakedIota`] (`0x3::staking_pool::StakedIota`); other
//! types from `iota-sdk-move-system-types` can be added here on demand.

use crate::{
    error::Result,
    types::object::{Object, ObjectId},
};

/// A typed view of an on-chain `0x3::staking_pool::StakedIota` object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct StakedIota(pub iota_move_system_types::iota_system::staking_pool::StakedIota);

#[uniffi::export]
impl StakedIota {
    /// Decode a `StakedIota` from an on-chain object, validating that the
    /// object's type tag matches `0x3::staking_pool::StakedIota`.
    #[uniffi::constructor]
    pub fn try_from_object(object: &Object) -> Result<Self> {
        Ok(
            iota_move_system_types::iota_system::staking_pool::StakedIota::try_from_object(
                &object.0,
            )?
            .into(),
        )
    }

    /// Decode a `StakedIota` from raw BCS bytes (e.g. the `contents` of an
    /// on-chain Move struct). Skips type-tag validation; prefer
    /// [`Self::try_from_object`] when an [`Object`] is available.
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_move_system_types::iota_system::staking_pool::StakedIota::try_from_bcs(&bytes)?
                .into(),
        )
    }

    pub fn id(&self) -> ObjectId {
        (*self.0.id()).into()
    }

    pub fn pool_id(&self) -> ObjectId {
        (*self.0.pool_id()).into()
    }

    pub fn activation_epoch(&self) -> u64 {
        self.0.activation_epoch()
    }

    /// Staked principal in nanos.
    pub fn principal(&self) -> u64 {
        self.0.principal()
    }
}
