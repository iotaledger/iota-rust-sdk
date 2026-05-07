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
