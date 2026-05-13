// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA system package (`0x3`).

/// Types from `0x3::staking_pool`.
pub mod staking_pool {
    use iota_types::ObjectId;

    use crate::framework::bag::Bag;
    use crate::framework::balance::Balance;
    use crate::framework::iota::IOTA;
    use crate::framework::object::{ID, UID};
    use crate::framework::table::Table;

    /// Rust version of the Move
    /// `iota_system::staking_pool::PoolTokenExchangeRate` type.
    ///
    /// Represents the exchange rate of the stake pool token to IOTA.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

        /// Decode a [`StakedIota`] from an on-chain object, validating that
        /// the object's type tag matches `0x3::staking_pool::StakedIota`.
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

    /// Rust version of the Move `iota_system::staking_pool::StakingPoolV1`
    /// type.
    ///
    /// A staking pool embedded in each validator struct in the system state
    /// object.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        #[allow(clippy::too_many_arguments)]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::table::Table;

        fn sample_object_id(byte: u8) -> ObjectId {
            ObjectId::new([byte; ObjectId::LENGTH])
        }

        #[test]
        fn pool_token_exchange_rate_bcs_roundtrip() {
            let r = PoolTokenExchangeRate::new(1_000, 999);
            let bytes = bcs::to_bytes(&r).unwrap();
            let decoded: PoolTokenExchangeRate = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(r, decoded);
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
        fn staking_pool_v1_bcs_roundtrip() {
            let pool = StakingPoolV1::new(
                UID::new(sample_object_id(0x01)),
                Some(10),
                None,
                1_000_000,
                Balance::new(50_000),
                500_000,
                Table::new(UID::new(sample_object_id(0x02)), 3),
                123,
                0,
                0,
                Bag::new(UID::new(sample_object_id(0x03)), 0),
            );
            let bytes = bcs::to_bytes(&pool).unwrap();
            let decoded: StakingPoolV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(pool, decoded);
        }
    }
}

/// Types from `0x3::voting_power`.
pub mod voting_power {
    /// Rust version of the Move `iota_system::voting_power::VotingPowerInfoV1`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn voting_power_info_v1_bcs_roundtrip() {
            let v = VotingPowerInfoV1::new(0, 100, 1_000);
            let bytes = bcs::to_bytes(&v).unwrap();
            let decoded: VotingPowerInfoV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(v, decoded);
        }
    }
}

/// Types from `0x3::validator_cap`.
pub mod validator_cap {
    use iota_types::Address;

    use crate::framework::object::UID;

    /// Rust version of the Move
    /// `iota_system::validator_cap::UnverifiedValidatorOperationCap` type.
    ///
    /// Capability object created when a new validator is created or when a
    /// validator explicitly creates a new capability object for rotation or
    /// revocation. Verification is required before this can be converted
    /// into a [`ValidatorOperationCap`].
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    /// Rust version of the Move
    /// `iota_system::validator_cap::ValidatorOperationCap` type.
    ///
    /// Privileged operations require this cap. Only constructed after
    /// successful verification of an [`UnverifiedValidatorOperationCap`].
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn unverified_validator_operation_cap_bcs_roundtrip() {
            let cap = UnverifiedValidatorOperationCap::new(
                UID::new(ObjectId::ZERO),
                Address::new([0xab; 32]),
            );
            let bytes = bcs::to_bytes(&cap).unwrap();
            let decoded: UnverifiedValidatorOperationCap = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(cap, decoded);
        }

        #[test]
        fn validator_operation_cap_bcs_roundtrip() {
            let cap = ValidatorOperationCap::new(Address::new([0xcd; 32]));
            let bytes = bcs::to_bytes(&cap).unwrap();
            let decoded: ValidatorOperationCap = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(cap, decoded);
        }
    }
}

/// Types from `0x3::validator_wrapper`.
pub mod validator_wrapper {
    use crate::framework::versioned::Versioned;

    /// Rust version of the Move
    /// `iota_system::validator_wrapper::Validator` type.
    ///
    /// A thin wrapper carrying the on-chain inner `Validator` as a dynamic
    /// field keyed by version.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Validator {
        pub inner: Versioned,
    }

    impl Validator {
        pub const fn new(inner: Versioned) -> Self {
            Self { inner }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::object::UID;
        use iota_types::ObjectId;

        #[test]
        fn validator_bcs_roundtrip() {
            let v = Validator::new(Versioned::new(UID::new(ObjectId::ZERO), 1));
            let bytes = bcs::to_bytes(&v).unwrap();
            let decoded: Validator = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(v, decoded);
        }
    }
}

/// Types from `0x3::validator`.
pub mod validator {
    use iota_types::Address;

    use super::staking_pool::StakingPoolV1;
    use crate::framework::bag::Bag;
    use crate::framework::object::ID;
    use crate::framework::url::Url;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move
    /// `iota_system::validator::ValidatorMetadataV1` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
        pub name: MoveString,
        pub description: MoveString,
        pub image_url: Url,
        pub project_url: Url,
        /// Network address of the validator.
        pub net_address: MoveString,
        /// Address of the validator used for p2p activities such as state
        /// sync.
        pub p2p_address: MoveString,
        /// Primary address of the consensus.
        pub primary_address: MoveString,
        /// `next_epoch_*` metadata only takes effect in the next epoch. If
        /// `None`, the current value stays unchanged.
        pub next_epoch_authority_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_proof_of_possession: Option<Vec<u8>>,
        pub next_epoch_network_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_protocol_pubkey_bytes: Option<Vec<u8>>,
        pub next_epoch_net_address: Option<MoveString>,
        pub next_epoch_p2p_address: Option<MoveString>,
        pub next_epoch_primary_address: Option<MoveString>,
        /// Any extra fields not defined statically.
        pub extra_fields: Bag,
    }

    /// Rust version of the Move `iota_system::validator::ValidatorV1` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct StakingRequestEvent {
        pub pool_id: ID,
        pub validator_address: Address,
        pub staker_address: Address,
        pub epoch: u64,
        pub amount: u64,
    }

    /// Rust version of the Move
    /// `iota_system::validator::UnstakingRequestEvent` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct UnstakingRequestEvent {
        pub pool_id: ID,
        pub validator_address: Address,
        pub staker_address: Address,
        pub stake_activation_epoch: u64,
        pub unstaking_epoch: u64,
        pub principal_amount: u64,
        pub reward_amount: u64,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::object::UID;
        use crate::std::ascii;
        use iota_types::ObjectId;

        fn sample_metadata() -> ValidatorMetadataV1 {
            ValidatorMetadataV1 {
                iota_address: Address::new([0xab; 32]),
                authority_pubkey_bytes: vec![0; 96],
                network_pubkey_bytes: vec![0; 32],
                protocol_pubkey_bytes: vec![0; 32],
                proof_of_possession: vec![0; 48],
                name: MoveString::new(b"alice".to_vec()),
                description: MoveString::new(b"a validator".to_vec()),
                image_url: Url::new(ascii::String::new(b"https://iota.org/a.png".to_vec())),
                project_url: Url::new(ascii::String::new(b"https://iota.org/".to_vec())),
                net_address: MoveString::new(b"/ip4/127.0.0.1/tcp/1".to_vec()),
                p2p_address: MoveString::new(b"/ip4/127.0.0.1/tcp/2".to_vec()),
                primary_address: MoveString::new(b"/ip4/127.0.0.1/tcp/3".to_vec()),
                next_epoch_authority_pubkey_bytes: None,
                next_epoch_proof_of_possession: None,
                next_epoch_network_pubkey_bytes: None,
                next_epoch_protocol_pubkey_bytes: None,
                next_epoch_net_address: None,
                next_epoch_p2p_address: None,
                next_epoch_primary_address: None,
                extra_fields: Bag::new(UID::new(ObjectId::ZERO), 0),
            }
        }

        #[test]
        fn validator_metadata_v1_bcs_roundtrip() {
            let m = sample_metadata();
            let bytes = bcs::to_bytes(&m).unwrap();
            let decoded: ValidatorMetadataV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(m, decoded);
        }

        #[test]
        fn staking_request_event_bcs_roundtrip() {
            let e = StakingRequestEvent {
                pool_id: ID::new(ObjectId::ZERO),
                validator_address: Address::new([0; 32]),
                staker_address: Address::new([1; 32]),
                epoch: 7,
                amount: 1_000_000,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: StakingRequestEvent = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }

        #[test]
        fn unstaking_request_event_bcs_roundtrip() {
            let e = UnstakingRequestEvent {
                pool_id: ID::new(ObjectId::ZERO),
                validator_address: Address::new([0; 32]),
                staker_address: Address::new([1; 32]),
                stake_activation_epoch: 7,
                unstaking_epoch: 10,
                principal_amount: 1_000_000,
                reward_amount: 12_345,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: UnstakingRequestEvent = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }
}

/// Types from `0x3::validator_set`.
pub mod validator_set {
    use iota_types::Address;

    use super::staking_pool::PoolTokenExchangeRate;
    use super::validator::ValidatorV1;
    use super::validator_wrapper::Validator;
    use crate::framework::bag::Bag;
    use crate::framework::object::ID;
    use crate::framework::table::Table;
    use crate::framework::table_vec::TableVec;
    use crate::framework::vec_map::VecMap;

    /// Rust version of the Move `iota_system::validator_set::ValidatorSetV1`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ValidatorJoinEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::ValidatorLeaveEvent` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ValidatorLeaveEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
        pub is_voluntary: bool,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::CommitteeValidatorJoinEvent` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct CommitteeValidatorJoinEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }

    /// Rust version of the Move
    /// `iota_system::validator_set::CommitteeValidatorLeaveEvent` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct CommitteeValidatorLeaveEvent {
        pub epoch: u64,
        pub validator_address: Address,
        pub staking_pool_id: ID,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn validator_epoch_info_event_v1_bcs_roundtrip() {
            let e = ValidatorEpochInfoEventV1 {
                epoch: 1,
                validator_address: Address::new([0; 32]),
                reference_gas_survey_quote: 100,
                stake: 1_000_000,
                voting_power: 50,
                commission_rate: 5,
                pool_staking_reward: 1_234,
                pool_token_exchange_rate: PoolTokenExchangeRate::new(1, 1),
                tallying_rule_reporters: vec![Address::new([1; 32])],
                tallying_rule_global_score: 99,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: ValidatorEpochInfoEventV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }

        #[test]
        fn validator_join_event_bcs_roundtrip() {
            let e = ValidatorJoinEvent {
                epoch: 1,
                validator_address: Address::new([0; 32]),
                staking_pool_id: ID::new(ObjectId::ZERO),
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: ValidatorJoinEvent = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }

        #[test]
        fn validator_leave_event_bcs_roundtrip() {
            let e = ValidatorLeaveEvent {
                epoch: 1,
                validator_address: Address::new([0; 32]),
                staking_pool_id: ID::new(ObjectId::ZERO),
                is_voluntary: true,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: ValidatorLeaveEvent = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }
}

/// Types from `0x3::iota_system_state_inner`.
pub mod iota_system_state_inner {
    use iota_types::Address;

    use super::storage_fund::StorageFundV1;
    use super::validator_set::{ValidatorSetV1, ValidatorSetV2};
    use crate::framework::bag::Bag;
    use crate::framework::balance::Balance;
    use crate::framework::iota::{IOTA, IotaTreasuryCap};
    use crate::framework::system_admin_cap::IotaSystemAdminCap;
    use crate::framework::vec_map::VecMap;
    use crate::framework::vec_set::VecSet;

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::SystemParametersV1` type.
    ///
    /// A list of system config parameters.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// Adds `safe_mode_computation_charges_burned` over [`IotaSystemStateV1`]
    /// to support burning base fees in safe mode when
    /// `protocol_defined_base_fee` is enabled.
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
        pub safe_mode_storage_charges: Balance<IOTA>,
        pub safe_mode_computation_charges: Balance<IOTA>,
        pub safe_mode_computation_charges_burned: u64,
        pub safe_mode_storage_rebates: u64,
        pub safe_mode_non_refundable_storage_fee: u64,
        pub epoch_start_timestamp_ms: u64,
        pub extra_fields: Bag,
    }

    /// Rust version of the Move
    /// `iota_system::iota_system_state_inner::SystemEpochInfoEventV1` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::object::UID;
        use iota_types::ObjectId;

        #[test]
        fn system_parameters_v1_bcs_roundtrip() {
            let p = SystemParametersV1 {
                epoch_duration_ms: 86_400_000,
                min_validator_count: 4,
                max_validator_count: 150,
                min_validator_joining_stake: 30_000_000,
                validator_low_stake_threshold: 25_000_000,
                validator_very_low_stake_threshold: 20_000_000,
                validator_low_stake_grace_period: 7,
                extra_fields: Bag::new(UID::new(ObjectId::ZERO), 0),
            };
            let bytes = bcs::to_bytes(&p).unwrap();
            let decoded: SystemParametersV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(p, decoded);
        }

        #[test]
        fn system_epoch_info_event_v1_bcs_roundtrip() {
            let e = SystemEpochInfoEventV1 {
                epoch: 1,
                protocol_version: 1,
                reference_gas_price: 1_000,
                total_stake: 1_000_000_000,
                storage_charge: 10_000,
                storage_rebate: 8_000,
                storage_fund_balance: 100_000,
                total_gas_fees: 10_000,
                total_stake_rewards_distributed: 1_000,
                burnt_tokens_amount: 0,
                minted_tokens_amount: 0,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: SystemEpochInfoEventV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }

        #[test]
        fn system_epoch_info_event_v2_bcs_roundtrip() {
            let e = SystemEpochInfoEventV2 {
                epoch: 1,
                protocol_version: 1,
                total_stake: 1_000_000_000,
                storage_charge: 10_000,
                storage_rebate: 8_000,
                storage_fund_balance: 100_000,
                total_gas_fees: 10_000,
                total_stake_rewards_distributed: 1_000,
                burnt_tokens_amount: 0,
                minted_tokens_amount: 0,
                tips_amount: 42,
            };
            let bytes = bcs::to_bytes(&e).unwrap();
            let decoded: SystemEpochInfoEventV2 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(e, decoded);
        }
    }
}

/// Types from `0x3::iota_system`.
pub mod iota_system {
    use crate::framework::object::UID;

    /// Rust version of the Move `iota_system::iota_system::IotaSystemState`
    /// type.
    ///
    /// A thin wrapper around an inner versioned state object (e.g.
    /// [`IotaSystemStateV1`](super::iota_system_state_inner::IotaSystemStateV1))
    /// stored as a dynamic field keyed by `version`. The wrapper object
    /// itself has a fixed ID of `0x5`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct IotaSystemState {
        pub id: UID,
        pub version: u64,
    }

    impl IotaSystemState {
        pub const fn new(id: UID, version: u64) -> Self {
            Self { id, version }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn iota_system_state_bcs_roundtrip() {
            let s = IotaSystemState::new(UID::new(ObjectId::ZERO), 1);
            let bytes = bcs::to_bytes(&s).unwrap();
            let decoded: IotaSystemState = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }
    }
}

/// Types from `0x3::storage_fund`.
pub mod storage_fund {
    use crate::framework::balance::Balance;
    use crate::framework::iota::IOTA;

    /// Rust version of the Move `iota_system::storage_fund::StorageFundV1`
    /// type.
    ///
    /// Carries two balances. `total_object_storage_rebates` always equals
    /// the sum of `storage_rebate` of all on-chain objects.
    /// `non_refundable_balance` holds the storage-fund inflow that should
    /// not be paid back out.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn storage_fund_v1_bcs_roundtrip() {
            let f = StorageFundV1::new(Balance::new(1_000_000), Balance::new(500));
            let bytes = bcs::to_bytes(&f).unwrap();
            let decoded: StorageFundV1 = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(f, decoded);
        }
    }
}

/// Types from `0x3::timelocked_staking`.
pub mod timelocked_staking {
    use iota_types::ObjectId;

    use super::staking_pool::StakedIota;
    use crate::framework::object::UID;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move
    /// `iota_system::timelocked_staking::TimelockedStakedIota` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TimelockedStakedIota {
        pub id: UID,
        /// A self-custodial object holding the staked IOTA tokens.
        pub staked_iota: StakedIota,
        /// Epoch timestamp (ms) of when the lock expires.
        pub expiration_timestamp_ms: u64,
        /// Optional timelock-related label.
        pub label: Option<MoveString>,
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
                label: Some(MoveString::new(b"vested".to_vec())),
            };
            let bytes = bcs::to_bytes(&tsi).unwrap();
            let decoded: TimelockedStakedIota = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(tsi, decoded);
        }

        #[test]
        fn timelocked_staked_iota_no_label_bcs_roundtrip() {
            let tsi = TimelockedStakedIota {
                id: UID::new(sample_object_id(0xc3)),
                staked_iota: StakedIota::new(
                    sample_object_id(0xa1),
                    sample_object_id(0xb2),
                    7,
                    42,
                ),
                expiration_timestamp_ms: 0,
                label: None,
            };
            let bytes = bcs::to_bytes(&tsi).unwrap();
            let decoded: TimelockedStakedIota = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(tsi, decoded);
        }
    }
}

/// Types from `0x3::genesis`.
pub mod genesis {
    use iota_types::Address;

    /// Rust version of the Move `iota_system::genesis::GenesisValidatorMetadata`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TokenDistributionSchedule {
        pub pre_minted_supply: u64,
        pub allocations: Vec<TokenAllocation>,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn genesis_validator_metadata_bcs_roundtrip() {
            let m = GenesisValidatorMetadata {
                name: b"alice".to_vec(),
                description: b"a validator".to_vec(),
                image_url: b"https://iota.org/a.png".to_vec(),
                project_url: b"https://iota.org/".to_vec(),
                iota_address: Address::new([0xab; 32]),
                gas_price: 1_000,
                commission_rate: 5,
                authority_public_key: vec![0; 96],
                proof_of_possession: vec![0; 48],
                network_public_key: vec![0; 32],
                protocol_public_key: vec![0; 32],
                network_address: b"/ip4/127.0.0.1/tcp/1".to_vec(),
                p2p_address: b"/ip4/127.0.0.1/tcp/2".to_vec(),
                primary_address: b"/ip4/127.0.0.1/tcp/3".to_vec(),
            };
            let bytes = bcs::to_bytes(&m).unwrap();
            let decoded: GenesisValidatorMetadata = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(m, decoded);
        }

        #[test]
        fn token_distribution_schedule_bcs_roundtrip() {
            let s = TokenDistributionSchedule {
                pre_minted_supply: 1_000_000_000,
                allocations: vec![TokenAllocation {
                    recipient_address: Address::new([0; 32]),
                    amount_nanos: 1_000_000,
                    staked_with_validator: Some(Address::new([1; 32])),
                    staked_with_timelock_expiration: Some(1_700_000_000_000),
                }],
            };
            let bytes = bcs::to_bytes(&s).unwrap();
            let decoded: TokenDistributionSchedule = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }
    }
}
