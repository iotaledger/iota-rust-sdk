// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA system package (`0x3`).

/// Types from `0x3::staking_pool`.
pub mod staking_pool {
    use iota_types::ObjectId;

    use crate::iota_framework::{
        bag::Bag,
        balance::Balance,
        iota::IOTA,
        object::{ID, UID},
        table::Table,
    };

    /// Rust version of the Move
    /// `iota_system::staking_pool::PoolTokenExchangeRate` type.
    ///
    /// Represents the exchange rate of the stake pool token to IOTA.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct PoolTokenExchangeRate {
        pub iota_amount: u64,
        pub pool_token_amount: u64,
    }

    impl PoolTokenExchangeRate {
        pub const fn new(iota_amount: u64, pool_token_amount: u64) -> Self {
            Self {
                iota_amount,
                pool_token_amount,
            }
        }
    }

    /// Rust version of the Move `iota_system::staking_pool::StakedIota` type.
    ///
    /// A self-custodial object holding the staked IOTA tokens.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct StakedIota {
        pub id: UID,
        /// ID of the staking pool we are staking with.
        pub pool_id: ID,
        /// The epoch at which the stake becomes active.
        pub stake_activation_epoch: u64,
        /// The staked IOTA tokens.
        #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "u64"))]
        pub principal: Balance<IOTA>,
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

        pub fn stake_activation_epoch(&self) -> u64 {
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
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }
    }

    impl_try_from_object!(StakedIota, is_staked_iota);

    /// Rust version of the Move `iota_system::staking_pool::StakingPoolV1`
    /// type.
    ///
    /// A staking pool embedded in each validator struct in the system state
    /// object.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct StakingPoolV1 {
        pub id: UID,
        /// The epoch at which this pool became active.
        ///
        /// `None` while pre-active; `Some(epoch)` once active or inactive.
        pub activation_epoch: Option<u64>,
        /// The epoch at which this pool ceased to be active.
        ///
        /// `None` while pre-active or active; `Some(epoch)` once inactive.
        pub deactivation_epoch: Option<u64>,
        /// The total number of IOTA tokens in this pool — including the
        /// `rewards_pool` and the principal of every `StakedIota` — updated
        /// at epoch boundaries.
        pub iota_balance: u64,
        /// Epoch stake rewards are added here at the end of each epoch.
        pub rewards_pool: Balance<IOTA>,
        /// Total number of pool tokens issued by the pool.
        pub pool_token_balance: u64,
        /// Exchange-rate history keyed by epoch number, starting from the
        /// `activation_epoch` and capturing the rate at the start of each
        /// epoch (after the previous epoch's rewards are deposited).
        pub exchange_rates: Table<u64, PoolTokenExchangeRate>,
        /// Pending stake amount for this epoch, emptied at epoch boundaries.
        pub pending_stake: u64,
        /// Pending stake withdrawn during the current epoch, including both
        /// principal and rewards; emptied at epoch boundaries.
        pub pending_total_iota_withdraw: u64,
        /// Pending pool tokens withdrawn during the current epoch, emptied
        /// at epoch boundaries.
        pub pending_pool_token_withdraw: u64,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    impl StakingPoolV1 {
        #[expect(clippy::too_many_arguments)]
        pub const fn new(
            id: UID,
            activation_epoch: Option<u64>,
            deactivation_epoch: Option<u64>,
            iota_balance: u64,
            rewards_pool: Balance<IOTA>,
            pool_token_balance: u64,
            exchange_rates: Table<u64, PoolTokenExchangeRate>,
            pending_stake: u64,
            pending_total_iota_withdraw: u64,
            pending_pool_token_withdraw: u64,
            extra_fields: Bag,
        ) -> Self {
            Self {
                id,
                activation_epoch,
                deactivation_epoch,
                iota_balance,
                rewards_pool,
                pool_token_balance,
                exchange_rates,
                pending_stake,
                pending_total_iota_withdraw,
                pending_pool_token_withdraw,
                extra_fields,
            }
        }
    }
}

/// Types from `0x3::voting_power`.
pub mod voting_power {
    /// Rust version of the Move `iota_system::voting_power::VotingPowerInfoV1`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct VotingPowerInfoV1 {
        pub validator_index: u64,
        pub voting_power: u64,
        pub stake: u64,
    }

    impl VotingPowerInfoV1 {
        pub const fn new(validator_index: u64, voting_power: u64, stake: u64) -> Self {
            Self {
                validator_index,
                voting_power,
                stake,
            }
        }
    }
}

/// Types from `0x3::validator_cap`.
pub mod validator_cap {
    use iota_types::Address;

    use crate::iota_framework::object::UID;

    /// Rust version of the Move
    /// `iota_system::validator_cap::UnverifiedValidatorOperationCap` type.
    ///
    /// Capability object created when a new validator is created or when a
    /// validator explicitly creates a new capability object for rotation or
    /// revocation. Verification is required before this can be converted
    /// into a [`ValidatorOperationCap`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct UnverifiedValidatorOperationCap {
        pub id: UID,
        pub authorizer_validator_address: Address,
    }

    impl UnverifiedValidatorOperationCap {
        pub const fn new(id: UID, authorizer_validator_address: Address) -> Self {
            Self {
                id,
                authorizer_validator_address,
            }
        }
    }

    impl_try_from_object!(
        UnverifiedValidatorOperationCap,
        is_unverified_validator_operation_cap
    );

    /// Rust version of the Move
    /// `iota_system::validator_cap::ValidatorOperationCap` type.
    ///
    /// Privileged operations require this cap. Only constructed after
    /// successful verification of an [`UnverifiedValidatorOperationCap`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorOperationCap {
        pub authorizer_validator_address: Address,
    }

    impl ValidatorOperationCap {
        pub const fn new(authorizer_validator_address: Address) -> Self {
            Self {
                authorizer_validator_address,
            }
        }
    }
}

/// Types from `0x3::validator_wrapper`.
pub mod validator_wrapper {
    use crate::iota_framework::versioned::Versioned;

    /// Rust version of the Move
    /// `iota_system::validator_wrapper::Validator` type.
    ///
    /// A thin wrapper carrying the on-chain inner `Validator` as a dynamic
    /// field keyed by version.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct Validator {
        pub inner: Versioned,
    }

    impl Validator {
        pub const fn new(inner: Versioned) -> Self {
            Self { inner }
        }
    }
}

/// Types from `0x3::validator`.
pub mod validator {
    use iota_types::Address;

    use super::staking_pool::StakingPoolV1;
    use crate::{
        iota_framework::{bag::Bag, object::ID, url::Url},
        move_stdlib::string,
    };

    /// Rust version of the Move
    /// `iota_system::validator::ValidatorMetadataV1` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorMetadataV1 {
        /// The IOTA Address of the validator.
        pub iota_address: Address,
        /// Public key bytes for signing transactions (also serves as
        /// `AuthorityName`).
        pub authority_pubkey_bytes: Vec<u8>,
        /// Public key bytes for TLS connections.
        pub network_pubkey_bytes: Vec<u8>,
        /// Public key bytes for signing consensus blocks.
        pub protocol_pubkey_bytes: Vec<u8>,
        /// Proof that the validator owns the private key.
        pub proof_of_possession: Vec<u8>,
        /// A unique human-readable validator name.
        pub name: string::String,
        pub description: string::String,
        pub image_url: Url,
        pub project_url: Url,
        /// Network address of the validator.
        pub net_address: string::String,
        /// Address of the validator used for p2p activities such as state
        /// sync.
        pub p2p_address: string::String,
        /// Primary address of the consensus.
        pub primary_address: string::String,
        /// `next_epoch_*` metadata only takes effect in the next epoch. If
        /// `None`, the current value stays unchanged.
        pub next_epoch_authority_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_proof_of_possession: Option<Vec<u8>>,
        pub next_epoch_network_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_protocol_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_net_address: Option<string::String>,
        pub next_epoch_p2p_address: Option<string::String>,
        pub next_epoch_primary_address: Option<string::String>,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move `iota_system::validator::ValidatorV1` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorV1 {
        /// Summary of the validator.
        pub metadata: ValidatorMetadataV1,
        /// The voting power of this validator, which may differ from its
        /// stake amount.
        pub voting_power: u64,
        /// The ID of this validator's current valid
        /// `UnverifiedValidatorOperationCap`.
        pub operation_cap_id: ID,
        /// Gas price quote, updated only at end of epoch.
        pub gas_price: u64,
        /// Staking pool for this validator.
        pub staking_pool: StakingPoolV1,
        /// Commission rate of the validator, in basis points.
        pub commission_rate: u64,
        /// Total amount of stake that would be active in the next epoch.
        pub next_epoch_stake: u64,
        /// This validator's gas price quote for the next epoch.
        pub next_epoch_gas_price: u64,
        /// The commission rate of the validator starting next epoch, in
        /// basis points.
        pub next_epoch_commission_rate: u64,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move `iota_system::validator::StakingRequestEvent`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct StakingRequestEvent {
        pub pool_id: ID,
        pub validator_address: Address,
        pub staker_address: Address,
        pub epoch: u64,
        pub amount: u64,
    }

    /// Rust version of the Move
    /// `iota_system::validator::UnstakingRequestEvent` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct UnstakingRequestEvent {
        pub pool_id: ID,
        pub validator_address: Address,
        pub staker_address: Address,
        pub stake_activation_epoch: u64,
        pub unstaking_epoch: u64,
        pub principal_amount: u64,
        pub reward_amount: u64,
    }
}

/// Types from `0x3::validator_set`.
pub mod validator_set {
    use iota_types::Address;

    use super::{
        staking_pool::PoolTokenExchangeRate, validator::ValidatorV1, validator_wrapper::Validator,
    };
    use crate::iota_framework::{
        bag::Bag, object::ID, table::Table, table_vec::TableVec, vec_map::VecMap,
    };

    /// Rust version of the Move `iota_system::validator_set::ValidatorSetV1`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorSetV1 {
        /// Total stake from all active validators at the beginning of the
        /// epoch.
        pub total_stake: u64,
        /// The current list of active validators.
        pub active_validators: Vec<ValidatorV1>,
        /// New validator candidates added during the current epoch; processed
        /// at the end of the epoch.
        pub pending_active_validators: TableVec<ValidatorV1>,
        /// Removal requests; each element is an index into `active_validators`.
        pub pending_removals: Vec<u64>,
        /// Staking-pool-ID → validator address.
        pub staking_pool_mappings: Table<ID, Address>,
        /// Inactive validators keyed by staking-pool ID. Once a validator is
        /// deactivated, it is moved here so stakers can keep withdrawing.
        pub inactive_validators: Table<ID, Validator>,
        /// Pre-active / candidate validators keyed by address.
        pub validator_candidates: Table<Address, Validator>,
        /// Number of epochs each validator has had stake below the low-stake
        /// threshold.
        pub at_risk_validators: VecMap<Address, u64>,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move `iota_system::validator_set::ValidatorSetV2`
    /// type.
    ///
    /// Extends [`ValidatorSetV1`] with a `committee_members` vector listing
    /// the subset of `active_validators` that take part in consensus for the
    /// current epoch.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorSetV2 {
        /// Total stake from all committee validators at the beginning of the
        /// epoch.
        pub total_stake: u64,
        /// The current list of active validators.
        pub active_validators: Vec<ValidatorV1>,
        /// Subset of validators responsible for consensus; each element is
        /// an index into `active_validators`.
        pub committee_members: Vec<u64>,
        /// New validator candidates added during the current epoch; processed
        /// at the end of the epoch.
        pub pending_active_validators: TableVec<ValidatorV1>,
        /// Removal requests; each element is an index into `active_validators`.
        pub pending_removals: Vec<u64>,
        /// Staking-pool-ID → validator address.
        pub staking_pool_mappings: Table<ID, Address>,
        /// Inactive validators keyed by staking-pool ID.
        pub inactive_validators: Table<ID, Validator>,
        /// Pre-active / candidate validators keyed by address.
        pub validator_candidates: Table<Address, Validator>,
        /// Number of epochs each validator has had stake below the low-stake
        /// threshold.
        pub at_risk_validators: VecMap<Address, u64>,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::ValidatorEpochInfoEventV1` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorEpochInfoEventV1 {
        pub epoch: u64,
        pub validator_address: Address,
        pub reference_gas_survey_quote: u64,
        pub stake: u64,
        pub voting_power: u64,
        pub commission_rate: u64,
        pub pool_staking_reward: u64,
        pub pool_token_exchange_rate: PoolTokenExchangeRate,
        pub tallying_rule_reporters: Vec<Address>,
        pub tallying_rule_global_score: u64,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::ValidatorJoinEvent` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorJoinEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::ValidatorLeaveEvent` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct ValidatorLeaveEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
        pub is_voluntary: bool,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::CommitteeValidatorJoinEvent` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct CommitteeValidatorJoinEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::CommitteeValidatorLeaveEvent` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct CommitteeValidatorLeaveEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }
}

/// Types from `0x3::iota_system_state_inner`.
pub mod iota_system_state_inner {
    use iota_types::Address;

    use super::{
        storage_fund::StorageFundV1,
        validator_set::{ValidatorSetV1, ValidatorSetV2},
    };
    use crate::iota_framework::{
        bag::Bag,
        balance::Balance,
        iota::{IOTA, IotaTreasuryCap},
        system_admin_cap::IotaSystemAdminCap,
        vec_map::VecMap,
        vec_set::VecSet,
    };

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::SystemParametersV1` type.
    ///
    /// A list of system config parameters.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct SystemParametersV1 {
        /// The duration of an epoch, in milliseconds.
        pub epoch_duration_ms: u64,
        /// Minimum number of active validators at any moment.
        pub min_validator_count: u64,
        /// Maximum number of active validators at any moment.
        pub max_validator_count: u64,
        /// Lower bound on the amount of stake required to become a validator.
        pub min_validator_joining_stake: u64,
        /// Validators with stake below this threshold are considered to have
        /// low stake and may be removed from the validator set.
        pub validator_low_stake_threshold: u64,
        /// Validators with stake below this threshold are removed immediately
        /// at epoch change with no grace period.
        pub validator_very_low_stake_threshold: u64,
        /// A validator can have stake below `validator_low_stake_threshold`
        /// for this many epochs before being removed.
        pub validator_low_stake_grace_period: u64,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::IotaSystemStateV1` type.
    ///
    /// The top-level object containing all information of the IOTA system.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct IotaSystemStateV1 {
        /// The current epoch ID, starting from 0.
        pub epoch: u64,
        /// The current protocol version, starting from 1.
        pub protocol_version: u64,
        /// The current version of the system state data structure type.
        pub system_state_version: u64,
        /// The IOTA `TreasuryCap`.
        pub iota_treasury_cap: IotaTreasuryCap,
        /// Information about the validators.
        pub validators: ValidatorSetV1,
        /// The storage fund.
        pub storage_fund: StorageFundV1,
        /// A list of system config parameters.
        pub parameters: SystemParametersV1,
        /// Capability to perform privileged IOTA system operations.
        pub iota_system_admin_cap: IotaSystemAdminCap,
        /// The reference gas price for the current epoch.
        pub reference_gas_price: u64,
        /// Validator → set of validators that have reported it. Persists
        /// across epochs.
        pub validator_report_records: VecMap<Address, VecSet<Address>>,
        /// Whether the system is running in a downgraded safe mode.
        pub safe_mode: bool,
        pub safe_mode_storage_charges: Balance<IOTA>,
        pub safe_mode_computation_rewards: Balance<IOTA>,
        pub safe_mode_storage_rebates: u64,
        pub safe_mode_non_refundable_storage_fee: u64,
        /// Unix timestamp of the current epoch start.
        pub epoch_start_timestamp_ms: u64,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::IotaSystemStateV2` type.
    ///
    /// Evolves [`IotaSystemStateV1`]: adds
    /// `safe_mode_computation_charges_burned` (to support burning base fees in
    /// safe mode when `protocol_defined_base_fee` is enabled), renames
    /// `safe_mode_computation_rewards` to `safe_mode_computation_charges`, and
    /// upgrades `validators` from `ValidatorSetV1` to `ValidatorSetV2`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
        pub safe_mode_storage_charges: Balance<IOTA>,
        pub safe_mode_computation_charges: Balance<IOTA>,
        pub safe_mode_computation_charges_burned: u64,
        pub safe_mode_storage_rebates: u64,
        pub safe_mode_non_refundable_storage_fee: u64,
        pub epoch_start_timestamp_ms: u64,
        pub extra_fields: Bag,
    }

    #[cfg(feature = "serde")]
    impl IotaSystemStateV2 {
        /// Decode an [`IotaSystemStateV2`] from BCS bytes.
        ///
        /// There is no `try_from_object` constructor: the inner state is
        /// stored as a dynamic field of the `0x5`
        /// [`IotaSystemState`](super::iota_system::IotaSystemState)
        /// wrapper, not as a top-level object with its own type tag.
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }
    }

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::SystemEpochInfoEventV1` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
    /// Adds `tips_amount` over V1 to show how much of the total gas fees
    /// were paid to validators as tips rather than burned.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
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
}

/// Types from `0x3::iota_system`.
#[expect(clippy::module_inception)]
pub mod iota_system {
    use crate::iota_framework::object::UID;

    /// Rust version of the Move `iota_system::iota_system::IotaSystemState`
    /// type.
    ///
    /// A thin wrapper around an inner versioned state object (e.g.
    /// [`IotaSystemStateV1`](super::iota_system_state_inner::IotaSystemStateV1))
    /// stored as a dynamic field keyed by `version`. The wrapper object
    /// itself has a fixed ID of `0x5`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct IotaSystemState {
        pub id: UID,
        pub version: u64,
    }

    impl IotaSystemState {
        pub const fn new(id: UID, version: u64) -> Self {
            Self { id, version }
        }
    }

    #[cfg(feature = "serde")]
    impl IotaSystemState {
        /// Decode an [`IotaSystemState`] from BCS bytes without verifying
        /// the on-chain type tag.
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }
    }

    impl_try_from_object!(IotaSystemState, is_iota_system_state);
}

/// Types from `0x3::storage_fund`.
pub mod storage_fund {
    use crate::iota_framework::{balance::Balance, iota::IOTA};

    /// Rust version of the Move `iota_system::storage_fund::StorageFundV1`
    /// type.
    ///
    /// Carries two balances. `total_object_storage_rebates` always equals
    /// the sum of `storage_rebate` of all on-chain objects.
    /// `non_refundable_balance` holds the storage-fund inflow that should
    /// not be paid back out.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct StorageFundV1 {
        pub total_object_storage_rebates: Balance<IOTA>,
        pub non_refundable_balance: Balance<IOTA>,
    }

    impl StorageFundV1 {
        pub const fn new(
            total_object_storage_rebates: Balance<IOTA>,
            non_refundable_balance: Balance<IOTA>,
        ) -> Self {
            Self {
                total_object_storage_rebates,
                non_refundable_balance,
            }
        }
    }
}

/// Types from `0x3::timelocked_staking`.
pub mod timelocked_staking {
    use iota_types::ObjectId;

    use super::staking_pool::StakedIota;
    use crate::{iota_framework::object::UID, move_stdlib::string};

    /// Rust version of the Move
    /// `iota_system::timelocked_staking::TimelockedStakedIota` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct TimelockedStakedIota {
        pub id: UID,
        /// A self-custodial object holding the staked IOTA tokens.
        pub staked_iota: StakedIota,
        /// Epoch timestamp (ms) of when the lock expires.
        pub expiration_timestamp_ms: u64,
        /// Optional timelock-related label.
        pub label: Option<string::String>,
    }

    impl TimelockedStakedIota {
        pub fn id(&self) -> &ObjectId {
            self.id.object_id()
        }

        pub fn expiration_timestamp_ms(&self) -> u64 {
            self.expiration_timestamp_ms
        }
    }

    #[cfg(feature = "serde")]
    impl TimelockedStakedIota {
        /// Decode a [`TimelockedStakedIota`] from BCS bytes (e.g. the
        /// `contents` of an on-chain Move struct) without verifying the
        /// on-chain type tag.
        pub fn from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }
    }

    impl_try_from_object!(TimelockedStakedIota, is_timelocked_staked_iota);
}

/// Types from `0x3::genesis`.
pub mod genesis {
    use iota_types::Address;

    /// Rust version of the Move
    /// `iota_system::genesis::GenesisValidatorMetadata` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct GenesisValidatorMetadata {
        pub name: Vec<u8>,
        pub description: Vec<u8>,
        pub image_url: Vec<u8>,
        pub project_url: Vec<u8>,
        pub iota_address: Address,
        pub gas_price: u64,
        pub commission_rate: u64,
        pub authority_public_key: Vec<u8>,
        pub proof_of_possession: Vec<u8>,
        pub network_public_key: Vec<u8>,
        pub protocol_public_key: Vec<u8>,
        pub network_address: Vec<u8>,
        pub p2p_address: Vec<u8>,
        pub primary_address: Vec<u8>,
    }

    /// Rust version of the Move `iota_system::genesis::GenesisChainParameters`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct GenesisChainParameters {
        pub protocol_version: u64,
        pub chain_start_timestamp_ms: u64,
        pub epoch_duration_ms: u64,
        pub max_validator_count: u64,
        pub min_validator_joining_stake: u64,
        pub validator_low_stake_threshold: u64,
        pub validator_very_low_stake_threshold: u64,
        pub validator_low_stake_grace_period: u64,
    }

    /// Rust version of the Move `iota_system::genesis::TokenAllocation` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct TokenAllocation {
        pub recipient_address: Address,
        pub amount_nanos: u64,
        /// Indicates whether this allocation should be staked at genesis and
        /// with which validator.
        pub staked_with_validator: Option<Address>,
        /// Indicates whether this allocation should be staked with a
        /// timelock at genesis, and the timelock's expiration.
        pub staked_with_timelock_expiration: Option<u64>,
    }

    /// Rust version of the Move
    /// `iota_system::genesis::TokenDistributionSchedule` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(
        all(test, not(target_arch = "wasm32")),
        derive(iota_bcs_schema::MoveShape)
    )]
    pub struct TokenDistributionSchedule {
        pub pre_minted_supply: u64,
        pub allocations: Vec<TokenAllocation>,
    }
}
