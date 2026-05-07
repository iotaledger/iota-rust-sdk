// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA system package (`0x3`).
//!
//! The version-specific inner state types (`IotaSystemStateV1` / `V2`,
//! `ValidatorV1`, `ValidatorSetV1` / `V2`, `StakingPoolV1`, `StorageFundV1`,
//! `SystemEpochInfoEventV1` / `V2`, etc.) live alongside their on-chain
//! wrapper in [`crate::system_state`].

use iota_types::ObjectId;

use crate::framework::{Balance, ID, UID};

// ------------------------------------------------------------------
// iota_system::staking_pool
// ------------------------------------------------------------------

/// Rust version of the Move `iota_system::staking_pool::StakedIota` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StakedIota {
    pub id: UID,
    pub pool_id: ID,
    pub stake_activation_epoch: u64,
    pub principal: Balance,
}

impl StakedIota {
    pub fn new(
        id: ObjectId,
        pool_id: ObjectId,
        stake_activation_epoch: u64,
        principal: u64,
    ) -> Self {
        Self {
            id: UID::new(id),
            pool_id: ID::new(pool_id),
            stake_activation_epoch,
            principal: Balance::new(principal),
        }
    }

    pub fn id(&self) -> &ObjectId {
        self.id.object_id()
    }

    pub fn pool_id(&self) -> &ObjectId {
        &self.pool_id.bytes
    }

    pub fn activation_epoch(&self) -> u64 {
        self.stake_activation_epoch
    }

    pub fn principal(&self) -> u64 {
        self.principal.value()
    }
}

#[cfg(feature = "serde")]
impl StakedIota {
    /// Decode a [`StakedIota`] from BCS bytes (e.g. the `contents` of an
    /// on-chain Move struct) without verifying the on-chain type tag.
    pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
        bcs::from_bytes(bytes)
    }

    /// Decode a [`StakedIota`] from an on-chain object, validating that the
    /// object's type tag matches `0x3::staking_pool::StakedIota`.
    pub fn try_from_object(
        object: &iota_types::Object,
    ) -> Result<Self, StakedIotaFromObjectError> {
        let move_struct = object
            .as_struct_opt()
            .ok_or(StakedIotaFromObjectError::NotAMoveStruct)?;
        if !move_struct.type_.is_staked_iota() {
            return Err(StakedIotaFromObjectError::WrongType);
        }
        bcs::from_bytes(&move_struct.contents).map_err(StakedIotaFromObjectError::Bcs)
    }
}

/// Error returned by [`StakedIota::try_from_object`].
#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum StakedIotaFromObjectError {
    /// The object is a package, not a Move struct.
    NotAMoveStruct,
    /// The Move struct's type tag is not `0x3::staking_pool::StakedIota`.
    WrongType,
    /// BCS decoding of the struct contents failed.
    Bcs(bcs::Error),
}

#[cfg(feature = "serde")]
impl core::fmt::Display for StakedIotaFromObjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAMoveStruct => f.write_str("object is not a Move struct"),
            Self::WrongType => {
                f.write_str("object's type tag is not 0x3::staking_pool::StakedIota")
            }
            Self::Bcs(e) => write!(f, "bcs decoding failed: {e}"),
        }
    }
}

#[cfg(feature = "serde")]
impl core::error::Error for StakedIotaFromObjectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bcs(e) => Some(e),
            _ => None,
        }
    }
}

// ------------------------------------------------------------------
// iota_system::timelocked_staking
// ------------------------------------------------------------------

/// Rust version of the Move
/// `iota_system::timelocked_staking::TimelockedStakedIota` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimelockedStakedIota {
    pub id: UID,
    /// A self-custodial object holding the staked IOTA tokens.
    pub staked_iota: StakedIota,
    /// Epoch timestamp (ms) of when the lock expires.
    pub expiration_timestamp_ms: u64,
    /// Optional timelock-related label.
    pub label: Option<String>,
}

impl TimelockedStakedIota {
    pub fn id(&self) -> &ObjectId {
        self.id.object_id()
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    fn sample_object_id(byte: u8) -> ObjectId {
        ObjectId::new([byte; ObjectId::LENGTH])
    }

    #[test]
    fn staked_iota_bcs_roundtrip() {
        let staked = StakedIota::new(
            sample_object_id(0xa1),
            sample_object_id(0xb2),
            42,
            1_000_000_000,
        );
        let bytes = bcs::to_bytes(&staked).unwrap();
        let decoded: StakedIota = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(staked, decoded);
    }

    #[test]
    fn timelocked_staked_iota_bcs_roundtrip() {
        let tsi = TimelockedStakedIota {
            id: UID::new(sample_object_id(0xc3)),
            staked_iota: StakedIota::new(
                sample_object_id(0xa1),
                sample_object_id(0xb2),
                42,
                1_000_000_000,
            ),
            expiration_timestamp_ms: 1_700_000_000_000,
            label: Some("vested".to_owned()),
        };
        let bytes = bcs::to_bytes(&tsi).unwrap();
        let decoded: TimelockedStakedIota = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tsi, decoded);
    }

    #[test]
    fn timelocked_staked_iota_no_label_bcs_roundtrip() {
        let tsi = TimelockedStakedIota {
            id: UID::new(sample_object_id(0xc3)),
            staked_iota: StakedIota::new(sample_object_id(0xa1), sample_object_id(0xb2), 7, 42),
            expiration_timestamp_ms: 0,
            label: None,
        };
        let bytes = bcs::to_bytes(&tsi).unwrap();
        let decoded: TimelockedStakedIota = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tsi, decoded);
    }
}
