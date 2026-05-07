// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Versioned IOTA system state types.
//!
//! These types live in the IOTA system package (`0x3`); they are gathered
//! here as their own module because they form one large interconnected graph
//! around the [`IotaSystemStateV1`] root.

use iota_types::Address;

use crate::framework::{
    Bag, Balance, ID, IotaSystemAdminCap, IotaTreasuryCap, Table, TableVec, UID, VecMap, VecSet,
    Versioned,
};

// ------------------------------------------------------------------
// iota_system::iota_system
// ------------------------------------------------------------------

/// Rust version of the Move `iota_system::iota_system::IotaSystemState` type.
///
/// This is the on-chain object at `Address::SYSTEM_STATE` (`0x5`); it is a
/// thin wrapper that points at the version-specific inner state (e.g.
/// [`IotaSystemStateV1`] or [`IotaSystemStateV2`]) stored in a dynamic field
/// keyed by [`Self::version`]. The Rust name carries the `Wrapper` suffix to
/// avoid confusion with those inner types — the Move type itself is just
/// `IotaSystemState`.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IotaSystemStateWrapper {
    pub id: UID,
    pub version: u64,
}

/// Rust version of the Move `iota_system::iota_system::SystemParametersV1`
/// type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemParametersV1 {
    /// The duration of an epoch, in milliseconds.
    pub epoch_duration_ms: u64,
    /// Minimum number of active validators at any moment.
    pub min_validator_count: u64,
    /// Maximum number of active validators at any moment.
    pub max_validator_count: u64,
    /// Lower-bound on the amount of stake required to become a validator.
    pub min_validator_joining_stake: u64,
    /// Validators with stake below this threshold are considered low-stake
    /// and escorted out after `validator_low_stake_grace_period` epochs.
    pub validator_low_stake_threshold: u64,
    /// Validators with stake below this threshold are removed immediately.
    pub validator_very_low_stake_threshold: u64,
    /// How many epochs a validator may stay below the low-stake threshold
    /// before being kicked out.
    pub validator_low_stake_grace_period: u64,
    pub extra_fields: Bag,
}

/// Rust version of the Move `iota_system::iota_system::IotaSystemStateV1` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IotaSystemStateV1 {
    pub epoch: u64,
    pub protocol_version: u64,
    pub system_state_version: u64,
    pub iota_treasury_cap: IotaTreasuryCap,
    pub validators: ValidatorSetV1,
    pub storage_fund: StorageFundV1,
    pub parameters: SystemParametersV1,
    pub iota_system_admin_cap: IotaSystemAdminCap,
    pub reference_gas_price: u64,
    pub validator_report_records: VecMap<Address, VecSet<Address>>,
    pub safe_mode: bool,
    pub safe_mode_storage_charges: Balance,
    pub safe_mode_computation_rewards: Balance,
    pub safe_mode_storage_rebates: u64,
    pub safe_mode_non_refundable_storage_fee: u64,
    pub epoch_start_timestamp_ms: u64,
    pub extra_fields: Bag,
}

/// Rust version of the Move `iota_system::iota_system::IotaSystemStateV2` type.
///
/// V2 differs from [`IotaSystemStateV1`] in three ways:
/// - the validator set is [`ValidatorSetV2`] (active set + committee indices)
///   instead of [`ValidatorSetV1`];
/// - `safe_mode_computation_rewards` is renamed to
///   [`Self::safe_mode_computation_charges`];
/// - a new field [`Self::safe_mode_computation_charges_burned`] tracks base
///   fees burned in safe mode under `protocol_defined_base_fee`.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IotaSystemStateV2 {
    pub epoch: u64,
    pub protocol_version: u64,
    pub system_state_version: u64,
    pub iota_treasury_cap: IotaTreasuryCap,
    pub validators: ValidatorSetV2,
    pub storage_fund: StorageFundV1,
    pub parameters: SystemParametersV1,
    pub iota_system_admin_cap: IotaSystemAdminCap,
    pub reference_gas_price: u64,
    pub validator_report_records: VecMap<Address, VecSet<Address>>,
    pub safe_mode: bool,
    pub safe_mode_storage_charges: Balance,
    pub safe_mode_computation_charges: Balance,
    pub safe_mode_computation_charges_burned: u64,
    pub safe_mode_storage_rebates: u64,
    pub safe_mode_non_refundable_storage_fee: u64,
    pub epoch_start_timestamp_ms: u64,
    pub extra_fields: Bag,
}

// ------------------------------------------------------------------
// iota_system::iota_system_state_inner
// ------------------------------------------------------------------

/// Rust version of the Move
/// `iota_system::iota_system_state_inner::SystemEpochInfoEventV1` type.
///
/// Emitted by `advance_epoch` for protocol versions 1–3.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemEpochInfoEventV1 {
    pub epoch: u64,
    pub protocol_version: u64,
    pub reference_gas_price: u64,
    pub total_stake: u64,
    pub storage_charge: u64,
    pub storage_rebate: u64,
    pub storage_fund_balance: u64,
    pub total_gas_fees: u64,
    pub total_stake_rewards_distributed: u64,
    pub burnt_tokens_amount: u64,
    pub minted_tokens_amount: u64,
}

/// Rust version of the Move
/// `iota_system::iota_system_state_inner::SystemEpochInfoEventV2` type.
///
/// Emitted by `advance_epoch` from protocol version 5 onward. V2 drops
/// `reference_gas_price` (replaced by `protocol_defined_base_fee`) and adds
/// [`Self::tips_amount`].
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SystemEpochInfoEventV2 {
    pub epoch: u64,
    pub protocol_version: u64,
    pub total_stake: u64,
    pub storage_charge: u64,
    pub storage_rebate: u64,
    pub storage_fund_balance: u64,
    pub total_gas_fees: u64,
    pub total_stake_rewards_distributed: u64,
    pub burnt_tokens_amount: u64,
    pub minted_tokens_amount: u64,
    pub tips_amount: u64,
}

// ------------------------------------------------------------------
// iota_system::staking_pool
// ------------------------------------------------------------------

/// Rust version of the Move
/// `iota_system::staking_pool::PoolTokenExchangeRate` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PoolTokenExchangeRate {
    pub iota_amount: u64,
    pub pool_token_amount: u64,
}

/// Rust version of the Move `iota_system::staking_pool::StakingPoolV1` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StakingPoolV1 {
    pub id: UID,
    pub activation_epoch: Option<u64>,
    pub deactivation_epoch: Option<u64>,
    pub iota_balance: u64,
    pub rewards_pool: Balance,
    pub pool_token_balance: u64,
    pub exchange_rates: Table,
    pub pending_stake: u64,
    pub pending_total_iota_withdraw: u64,
    pub pending_pool_token_withdraw: u64,
    pub extra_fields: Bag,
}

// ------------------------------------------------------------------
// iota_system::iota_system::storage_fund
// ------------------------------------------------------------------

/// Rust version of the Move `iota_system::storage_fund::StorageFundV1` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StorageFundV1 {
    pub total_object_storage_rebates: Balance,
    pub non_refundable_balance: Balance,
}

// ------------------------------------------------------------------
// iota_system::iota_system::validator
// ------------------------------------------------------------------

/// Rust version of the Move `iota_system::validator::ValidatorMetadataV1` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorMetadataV1 {
    pub iota_address: Address,
    pub authority_pubkey_bytes: Vec<u8>,
    pub network_pubkey_bytes: Vec<u8>,
    pub protocol_pubkey_bytes: Vec<u8>,
    pub proof_of_possession_bytes: Vec<u8>,
    pub name: String,
    pub description: String,
    pub image_url: String,
    pub project_url: String,
    pub net_address: String,
    pub p2p_address: String,
    pub primary_address: String,
    pub next_epoch_authority_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_proof_of_possession: Option<Vec<u8>>,
    pub next_epoch_network_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_protocol_pubkey_bytes: Option<Vec<u8>>,
    pub next_epoch_net_address: Option<String>,
    pub next_epoch_p2p_address: Option<String>,
    pub next_epoch_primary_address: Option<String>,
    pub extra_fields: Bag,
}

/// Rust version of the Move `iota_system::validator::ValidatorV1` type.
///
/// The node's mirror carries an extra `OnceCell<VerifiedValidatorMetadataV1>`
/// cache marked `#[serde(skip)]`; this SDK port drops the cache (and the
/// crypto-heavy verification logic that populates it) since neither affects
/// the BCS wire shape.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorV1 {
    pub metadata: ValidatorMetadataV1,
    pub voting_power: u64,
    pub operation_cap_id: ID,
    pub gas_price: u64,
    pub staking_pool: StakingPoolV1,
    pub commission_rate: u64,
    pub next_epoch_stake: u64,
    pub next_epoch_gas_price: u64,
    pub next_epoch_commission_rate: u64,
    pub extra_fields: Bag,
}

// ------------------------------------------------------------------
// iota_system::validator_cap
// ------------------------------------------------------------------

/// Rust version of the Move
/// `iota_system::validator_cap::UnverifiedValidatorOperationCap` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnverifiedValidatorOperationCap {
    pub id: UID,
    pub authorizer_validator_address: Address,
}

// ------------------------------------------------------------------
// iota_system::iota_system::validator_set
// ------------------------------------------------------------------

/// Rust version of the Move `iota_system::validator_set::ValidatorSetV1` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorSetV1 {
    pub total_stake: u64,
    pub active_validators: Vec<ValidatorV1>,
    pub pending_active_validators: TableVec,
    pub pending_removals: Vec<u64>,
    pub staking_pool_mappings: Table,
    pub inactive_validators: Table,
    pub validator_candidates: Table,
    pub at_risk_validators: VecMap<Address, u64>,
    pub extra_fields: Bag,
}

/// Rust version of the Move `iota_system::validator_set::ValidatorSetV2` type.
///
/// V2 extends [`ValidatorSetV1`] with a [`Self::committee_members`] vector of
/// indices into [`Self::active_validators`]; only the indexed validators
/// participate in consensus during the current epoch.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorSetV2 {
    pub total_stake: u64,
    pub active_validators: Vec<ValidatorV1>,
    pub committee_members: Vec<u64>,
    pub pending_active_validators: TableVec,
    pub pending_removals: Vec<u64>,
    pub staking_pool_mappings: Table,
    pub inactive_validators: Table,
    pub validator_candidates: Table,
    pub at_risk_validators: VecMap<Address, u64>,
    pub extra_fields: Bag,
}

// ------------------------------------------------------------------
// iota_system::iota_system::validator_wrapper
// ------------------------------------------------------------------

/// Rust version of the Move
/// `iota_system::validator_wrapper::Validator` type.
///
/// A thin wrapper around a [`Versioned`]; the `inner.version` selects which
/// concrete validator type (e.g. [`ValidatorV1`]) is stored in the wrapped
/// dynamic field.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ValidatorWrapper {
    pub inner: Versioned,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use iota_types::ObjectId;

    use super::*;

    fn sample_object_id(byte: u8) -> ObjectId {
        ObjectId::new([byte; ObjectId::LENGTH])
    }

    fn sample_address(byte: u8) -> Address {
        Address::new([byte; Address::LENGTH])
    }

    fn dummy_system_parameters() -> SystemParametersV1 {
        SystemParametersV1 {
            epoch_duration_ms: 86_400_000,
            min_validator_count: 4,
            max_validator_count: 150,
            min_validator_joining_stake: 2_000_000_000_000_000,
            validator_low_stake_threshold: 1_500_000_000_000_000,
            validator_very_low_stake_threshold: 1_000_000_000_000_000,
            validator_low_stake_grace_period: 7,
            extra_fields: Bag::default(),
        }
    }

    fn dummy_storage_fund() -> StorageFundV1 {
        StorageFundV1 {
            total_object_storage_rebates: Balance::new(123),
            non_refundable_balance: Balance::new(45),
        }
    }

    fn dummy_validator_metadata() -> ValidatorMetadataV1 {
        ValidatorMetadataV1 {
            iota_address: sample_address(0x01),
            authority_pubkey_bytes: vec![1, 2, 3],
            network_pubkey_bytes: vec![4, 5, 6],
            protocol_pubkey_bytes: vec![7, 8, 9],
            proof_of_possession_bytes: vec![10],
            name: "validator".to_owned(),
            description: "test".to_owned(),
            image_url: String::new(),
            project_url: String::new(),
            net_address: "/ip4/127.0.0.1/tcp/1".to_owned(),
            p2p_address: "/ip4/127.0.0.1/tcp/2".to_owned(),
            primary_address: "/ip4/127.0.0.1/tcp/3".to_owned(),
            next_epoch_authority_pubkey_bytes: None,
            next_epoch_proof_of_possession: None,
            next_epoch_network_pubkey_bytes: None,
            next_epoch_protocol_pubkey_bytes: Some(vec![11, 12]),
            next_epoch_net_address: None,
            next_epoch_p2p_address: None,
            next_epoch_primary_address: Some("/ip4/127.0.0.1/tcp/4".to_owned()),
            extra_fields: Bag::default(),
        }
    }

    fn dummy_staking_pool() -> StakingPoolV1 {
        StakingPoolV1 {
            id: UID::new(sample_object_id(0xa1)),
            activation_epoch: Some(1),
            deactivation_epoch: None,
            iota_balance: 1_000_000,
            rewards_pool: Balance::new(0),
            pool_token_balance: 1_000_000,
            exchange_rates: Table::default(),
            pending_stake: 0,
            pending_total_iota_withdraw: 0,
            pending_pool_token_withdraw: 0,
            extra_fields: Bag::default(),
        }
    }

    fn dummy_validator() -> ValidatorV1 {
        ValidatorV1 {
            metadata: dummy_validator_metadata(),
            voting_power: 100,
            operation_cap_id: ID::new(sample_object_id(0xb2)),
            gas_price: 1000,
            staking_pool: dummy_staking_pool(),
            commission_rate: 50,
            next_epoch_stake: 1_000_000,
            next_epoch_gas_price: 1000,
            next_epoch_commission_rate: 50,
            extra_fields: Bag::default(),
        }
    }

    fn dummy_validator_set() -> ValidatorSetV1 {
        ValidatorSetV1 {
            total_stake: 1_000_000,
            active_validators: vec![dummy_validator()],
            pending_active_validators: TableVec::default(),
            pending_removals: vec![],
            staking_pool_mappings: Table::default(),
            inactive_validators: Table::default(),
            validator_candidates: Table::default(),
            at_risk_validators: VecMap::default(),
            extra_fields: Bag::default(),
        }
    }

    fn dummy_validator_set_v2() -> ValidatorSetV2 {
        ValidatorSetV2 {
            total_stake: 1_000_000,
            active_validators: vec![dummy_validator()],
            committee_members: vec![0],
            pending_active_validators: TableVec::default(),
            pending_removals: vec![],
            staking_pool_mappings: Table::default(),
            inactive_validators: Table::default(),
            validator_candidates: Table::default(),
            at_risk_validators: VecMap::default(),
            extra_fields: Bag::default(),
        }
    }

    fn dummy_iota_treasury_cap() -> IotaTreasuryCap {
        IotaTreasuryCap {
            inner: crate::framework::TreasuryCap {
                id: UID::new(sample_object_id(0x10)),
                total_supply: crate::framework::Supply { value: 0 },
            },
        }
    }

    #[test]
    fn system_parameters_v1_bcs_roundtrip() {
        let params = dummy_system_parameters();
        let bytes = bcs::to_bytes(&params).unwrap();
        let decoded: SystemParametersV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(params, decoded);
    }

    #[test]
    fn storage_fund_v1_bcs_roundtrip() {
        let sf = dummy_storage_fund();
        let bytes = bcs::to_bytes(&sf).unwrap();
        let decoded: StorageFundV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(sf, decoded);
    }

    #[test]
    fn validator_metadata_v1_bcs_roundtrip() {
        let metadata = dummy_validator_metadata();
        let bytes = bcs::to_bytes(&metadata).unwrap();
        let decoded: ValidatorMetadataV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(metadata, decoded);
    }

    #[test]
    fn staking_pool_v1_bcs_roundtrip() {
        let pool = dummy_staking_pool();
        let bytes = bcs::to_bytes(&pool).unwrap();
        let decoded: StakingPoolV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(pool, decoded);
    }

    #[test]
    fn validator_v1_bcs_roundtrip() {
        let validator = dummy_validator();
        let bytes = bcs::to_bytes(&validator).unwrap();
        let decoded: ValidatorV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(validator, decoded);
    }

    #[test]
    fn validator_set_v1_bcs_roundtrip() {
        let set = dummy_validator_set();
        let bytes = bcs::to_bytes(&set).unwrap();
        let decoded: ValidatorSetV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(set, decoded);
    }

    #[test]
    fn unverified_validator_operation_cap_bcs_roundtrip() {
        let cap = UnverifiedValidatorOperationCap {
            id: UID::new(sample_object_id(0xff)),
            authorizer_validator_address: sample_address(0x42),
        };
        let bytes = bcs::to_bytes(&cap).unwrap();
        let decoded: UnverifiedValidatorOperationCap = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn iota_system_state_v1_bcs_roundtrip() {
        let state = IotaSystemStateV1 {
            epoch: 100,
            protocol_version: 1,
            system_state_version: 1,
            iota_treasury_cap: dummy_iota_treasury_cap(),
            validators: dummy_validator_set(),
            storage_fund: dummy_storage_fund(),
            parameters: dummy_system_parameters(),
            iota_system_admin_cap: IotaSystemAdminCap::default(),
            reference_gas_price: 1000,
            validator_report_records: VecMap::default(),
            safe_mode: false,
            safe_mode_storage_charges: Balance::new(0),
            safe_mode_computation_rewards: Balance::new(0),
            safe_mode_storage_rebates: 0,
            safe_mode_non_refundable_storage_fee: 0,
            epoch_start_timestamp_ms: 1_700_000_000_000,
            extra_fields: Bag::default(),
        };
        let bytes = bcs::to_bytes(&state).unwrap();
        let decoded: IotaSystemStateV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn iota_system_state_wrapper_bcs_roundtrip() {
        let wrapper = IotaSystemStateWrapper {
            id: UID::new(sample_object_id(0x05)),
            version: 2,
        };
        let bytes = bcs::to_bytes(&wrapper).unwrap();
        let decoded: IotaSystemStateWrapper = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn iota_system_state_v2_bcs_roundtrip() {
        let state = IotaSystemStateV2 {
            epoch: 200,
            protocol_version: 5,
            system_state_version: 2,
            iota_treasury_cap: dummy_iota_treasury_cap(),
            validators: dummy_validator_set_v2(),
            storage_fund: dummy_storage_fund(),
            parameters: dummy_system_parameters(),
            iota_system_admin_cap: IotaSystemAdminCap::default(),
            reference_gas_price: 1000,
            validator_report_records: VecMap::default(),
            safe_mode: false,
            safe_mode_storage_charges: Balance::new(0),
            safe_mode_computation_charges: Balance::new(0),
            safe_mode_computation_charges_burned: 0,
            safe_mode_storage_rebates: 0,
            safe_mode_non_refundable_storage_fee: 0,
            epoch_start_timestamp_ms: 1_700_000_000_000,
            extra_fields: Bag::default(),
        };
        let bytes = bcs::to_bytes(&state).unwrap();
        let decoded: IotaSystemStateV2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn validator_set_v2_bcs_roundtrip() {
        let set = dummy_validator_set_v2();
        let bytes = bcs::to_bytes(&set).unwrap();
        let decoded: ValidatorSetV2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(set, decoded);
    }

    #[test]
    fn validator_wrapper_bcs_roundtrip() {
        let wrapper = ValidatorWrapper {
            inner: Versioned {
                id: UID::new(sample_object_id(0xa5)),
                version: 1,
            },
        };
        let bytes = bcs::to_bytes(&wrapper).unwrap();
        let decoded: ValidatorWrapper = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper, decoded);
    }

    #[test]
    fn pool_token_exchange_rate_bcs_roundtrip() {
        let rate = PoolTokenExchangeRate {
            iota_amount: 1_000_000,
            pool_token_amount: 1_500_000,
        };
        let bytes = bcs::to_bytes(&rate).unwrap();
        let decoded: PoolTokenExchangeRate = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(rate, decoded);
    }

    #[test]
    fn system_epoch_info_event_v1_bcs_roundtrip() {
        let event = SystemEpochInfoEventV1 {
            epoch: 7,
            protocol_version: 3,
            reference_gas_price: 1000,
            total_stake: 1_000_000,
            storage_charge: 100,
            storage_rebate: 50,
            storage_fund_balance: 1_000_000,
            total_gas_fees: 100,
            total_stake_rewards_distributed: 100,
            burnt_tokens_amount: 1,
            minted_tokens_amount: 2,
        };
        let bytes = bcs::to_bytes(&event).unwrap();
        let decoded: SystemEpochInfoEventV1 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn system_epoch_info_event_v2_bcs_roundtrip() {
        let event = SystemEpochInfoEventV2 {
            epoch: 7,
            protocol_version: 5,
            total_stake: 1_000_000,
            storage_charge: 100,
            storage_rebate: 50,
            storage_fund_balance: 1_000_000,
            total_gas_fees: 100,
            total_stake_rewards_distributed: 100,
            burnt_tokens_amount: 1,
            minted_tokens_amount: 2,
            tips_amount: 9,
        };
        let bytes = bcs::to_bytes(&event).unwrap();
        let decoded: SystemEpochInfoEventV2 = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(event, decoded);
    }
}
