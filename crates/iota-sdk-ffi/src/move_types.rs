// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Bindings for selected Rust mirrors of Move types.
//!
//! Each FFI shim wraps an inner [`iota_sdk::move_types`] type and exposes
//! the fields that non-Rust consumers typically need when decoding objects
//! returned by the GraphQL client. Currently the bindings cover:
//!
//! - **System types** (`0x3`): [`StakedIota`], [`TimelockedStakedIota`],
//!   [`IotaSystemState`], [`IotaSystemStateV2`] (with its embedded
//!   [`ValidatorSetV2`], [`ValidatorV1`], [`ValidatorMetadataV1`],
//!   [`StakingPoolV1`], [`SystemParametersV1`], and [`StorageFundV1`]),
//!   [`UnverifiedValidatorOperationCap`].
//! - **Framework types** (`0x2`): [`IotaCoinMetadata`] (the `Iota` prefix
//!   disambiguates this from the GraphQL-derived `CoinMetadata` record),
//!   [`ImmutableCoinMetadata`], [`Clock`], [`TimelockedIotaBalance`],
//!   [`UpgradeCap`], [`Publisher`], [`Kiosk`], [`KioskOwnerCap`], [`DenyList`],
//!   [`Random`] (with [`RandomInner`]), [`AuthenticatorState`] (with
//!   [`AuthenticatorStateInner`] and its [`ActiveJwk`] records),
//!   [`PackageMetadataV1`] (with its [`ModuleMetadataV1`] and
//!   [`AuthenticatorMetadataV1`] records), [`ModuleMetadata`], [`TreasuryCap`],
//!   [`RegulatedCoinMetadata`], [`DenyCapV1`], [`Display`], [`CoinManager`],
//!   [`CoinManagerTreasuryCap`], [`CoinManagerMetadataCap`], [`Token`],
//!   [`TokenPolicyCap`], [`TokenPolicy`], [`Config`], [`TransferPolicy`],
//!   [`TransferPolicyCap`], [`LabelerCap`], [`PurchaseCap`].
//! - **Stardust types** (`0x107a`): [`Nft`], [`Irc27Metadata`],
//!   [`BasicOutput`], [`NftOutput`], [`AliasOutput`], [`Alias`], plus the
//!   unlock-condition records [`TimelockUnlockCondition`],
//!   [`ExpirationUnlockCondition`], [`StorageDepositReturnUnlockCondition`].
//!
//! Generic Move types are exposed as their `<IOTA>` instantiations
//! (`BasicOutput<IOTA>`, `NftOutput<IOTA>`, `AliasOutput<IOTA>`,
//! `IotaCoinMetadata` wrapping `CoinMetadata<IOTA>`, and
//! [`TimelockedIotaBalance`] wrapping `TimeLock<Balance<IOTA>>`). The
//! `try_from_object` constructors validate the full on-chain type tag,
//! including that the coin marker is `0x2::iota::IOTA`.
//!
//! `0x2::coin::Coin` deliberately has no shim here: the existing
//! [`Coin`](crate::types::coin::Coin) binding already decodes coin objects
//! of any coin type.
//!
//! Move **event** mirrors are exposed the same way but via `ffi_move_event!`,
//! which generates only a `try_from_bcs` constructor (events are not objects,
//! so there is no `try_from_object` or `id`); decode them from the BCS
//! `contents` of an event query result.

use std::{collections::HashMap, sync::Arc};

use iota_sdk::move_types::iota_framework::iota::IOTA;

use crate::{
    error::Result,
    types::{address::Address, object::ObjectId},
};

fn ascii_to_string(s: &iota_sdk::move_types::move_stdlib::ascii::String) -> String {
    String::from_utf8_lossy(&s.bytes).into_owned()
}

fn move_string_to_string(s: &iota_sdk::move_types::move_stdlib::string::String) -> String {
    String::from_utf8_lossy(&s.bytes).into_owned()
}

fn url_to_string(u: &iota_sdk::move_types::iota_framework::url::Url) -> String {
    ascii_to_string(&u.url)
}

// =====================================================================
// 0x3 — IOTA system
// =====================================================================

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x3::staking_pool::StakedIota` object.
    StakedIota(iota_sdk::move_types::iota_system::staking_pool::StakedIota) {
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
}

crate::ffi_move_object! {
    /// A typed view of an on-chain
    /// `0x3::timelocked_staking::TimelockedStakedIota` object.
    TimelockedStakedIota(iota_sdk::move_types::iota_system::timelocked_staking::TimelockedStakedIota) {
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
}

crate::ffi_move_object! {
    /// A typed view of the on-chain `0x3::iota_system::IotaSystemState` object
    /// (the `0x5` singleton).
    ///
    /// This is only the versioned wrapper; the actual state lives in a dynamic
    /// field holding e.g. an `IotaSystemStateV2`.
    IotaSystemState(iota_sdk::move_types::iota_system::iota_system::IotaSystemState) {
        /// Version selecting which inner state layout the dynamic field holds.
        pub fn version(&self) -> u64 {
            self.0.version
        }
    }
}

/// A typed view of the `0x3::iota_system_state_inner::IotaSystemStateV2`
/// inner system state.
///
/// Exposes the scalar epoch parameters plus the nested validator set
/// ([`ValidatorSetV2`]), storage fund ([`StorageFundV1`]), system parameters
/// ([`SystemParametersV1`]), and the treasury's total supply.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct IotaSystemStateV2(
    pub iota_sdk::move_types::iota_system::iota_system_state_inner::IotaSystemStateV2,
);

#[uniffi::export]
impl IotaSystemStateV2 {
    /// Decode an `IotaSystemStateV2` from raw BCS bytes.
    ///
    /// There is no object-based constructor: the inner state is stored as
    /// a dynamic field of the `0x5` wrapper, not as a top-level object
    /// with its own type tag.
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            iota_sdk::move_types::iota_system::iota_system_state_inner::IotaSystemStateV2::from_bcs(
                &bytes,
            )?
            .into(),
        )
    }

    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    pub fn protocol_version(&self) -> u64 {
        self.0.protocol_version
    }

    pub fn system_state_version(&self) -> u64 {
        self.0.system_state_version
    }

    /// The reference gas price for the current epoch, in nanos.
    pub fn reference_gas_price(&self) -> u64 {
        self.0.reference_gas_price
    }

    /// Whether the system is running in a downgraded safe mode.
    pub fn safe_mode(&self) -> bool {
        self.0.safe_mode
    }

    /// Unix timestamp (ms) of the current epoch start.
    pub fn epoch_start_timestamp_ms(&self) -> u64 {
        self.0.epoch_start_timestamp_ms
    }

    /// Total IOTA supply controlled by the system treasury, in nanos.
    pub fn iota_total_supply(&self) -> u64 {
        self.0.iota_treasury_cap.inner.total_supply.value
    }

    /// The validator set.
    pub fn validators(&self) -> ValidatorSetV2 {
        ValidatorSetV2(self.0.validators.clone())
    }

    /// The storage fund.
    pub fn storage_fund(&self) -> StorageFundV1 {
        StorageFundV1(self.0.storage_fund.clone())
    }

    /// The system parameters.
    pub fn parameters(&self) -> SystemParametersV1 {
        SystemParametersV1(self.0.parameters.clone())
    }

    /// Validator report records: each reported validator's address mapped to
    /// the addresses of the validators reporting it.
    pub fn validator_report_records(&self) -> HashMap<Arc<Address>, Vec<Arc<Address>>> {
        self.0
            .validator_report_records
            .contents
            .iter()
            .map(|e| {
                (
                    Arc::new(Address(e.key)),
                    e.value
                        .contents
                        .iter()
                        .map(|a| Arc::new(Address(*a)))
                        .collect(),
                )
            })
            .collect()
    }

    /// Storage charges accumulated during safe mode, in nanos.
    pub fn safe_mode_storage_charges(&self) -> u64 {
        self.0.safe_mode_storage_charges.value()
    }

    /// Computation charges accumulated during safe mode, in nanos.
    pub fn safe_mode_computation_charges(&self) -> u64 {
        self.0.safe_mode_computation_charges.value()
    }

    /// Computation charges burned during safe mode, in nanos.
    pub fn safe_mode_computation_charges_burned(&self) -> u64 {
        self.0.safe_mode_computation_charges_burned
    }

    /// Storage rebates accumulated during safe mode, in nanos.
    pub fn safe_mode_storage_rebates(&self) -> u64 {
        self.0.safe_mode_storage_rebates
    }

    /// Non-refundable storage fees accumulated during safe mode, in nanos.
    pub fn safe_mode_non_refundable_storage_fee(&self) -> u64 {
        self.0.safe_mode_non_refundable_storage_fee
    }
}

/// A typed view of the `0x3::validator_set::ValidatorSetV2` embedded in the
/// system state.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct ValidatorSetV2(pub iota_sdk::move_types::iota_system::validator_set::ValidatorSetV2);

#[uniffi::export]
impl ValidatorSetV2 {
    /// Total stake from all committee validators at the beginning of the
    /// epoch, in nanos.
    pub fn total_stake(&self) -> u64 {
        self.0.total_stake
    }

    /// The current list of active validators.
    pub fn active_validators(&self) -> Vec<Arc<ValidatorV1>> {
        self.0
            .active_validators
            .iter()
            .map(|v| Arc::new(ValidatorV1(v.clone())))
            .collect()
    }

    /// Indices into `active_validators` of the validators responsible for
    /// consensus.
    pub fn committee_members(&self) -> Vec<u64> {
        self.0.committee_members.clone()
    }

    /// Indices into `active_validators` with pending removal requests.
    pub fn pending_removals(&self) -> Vec<u64> {
        self.0.pending_removals.clone()
    }

    /// Number of pending validator candidates. The candidates themselves are
    /// stored in dynamic fields and are not part of this struct's contents.
    pub fn pending_active_validators_size(&self) -> u64 {
        self.0.pending_active_validators.contents.size
    }

    /// Number of epochs each at-risk validator has had stake below the
    /// low-stake threshold.
    pub fn at_risk_validators(&self) -> HashMap<Arc<Address>, u64> {
        self.0
            .at_risk_validators
            .contents
            .iter()
            .map(|e| (Arc::new(Address(e.key)), e.value))
            .collect()
    }

    // `staking_pool_mappings`, `inactive_validators` and
    // `validator_candidates` are table handles whose entries live in dynamic
    // fields, not in this struct's contents.
}

/// A typed view of a `0x3::validator::ValidatorV1` from the active validator
/// set.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct ValidatorV1(pub iota_sdk::move_types::iota_system::validator::ValidatorV1);

#[uniffi::export]
impl ValidatorV1 {
    /// The validator's metadata (addresses, keys, and descriptive info).
    pub fn metadata(&self) -> ValidatorMetadataV1 {
        ValidatorMetadataV1(self.0.metadata.clone())
    }

    /// The voting power of this validator, which may differ from its stake
    /// amount.
    pub fn voting_power(&self) -> u64 {
        self.0.voting_power
    }

    /// Object ID of this validator's current valid
    /// `UnverifiedValidatorOperationCap`.
    pub fn operation_cap_id(&self) -> ObjectId {
        self.0.operation_cap_id.bytes.into()
    }

    /// Gas price quote, updated only at end of epoch.
    pub fn gas_price(&self) -> u64 {
        self.0.gas_price
    }

    /// Staking pool for this validator.
    pub fn staking_pool(&self) -> StakingPoolV1 {
        StakingPoolV1(self.0.staking_pool.clone())
    }

    /// Commission rate of the validator, in basis points.
    pub fn commission_rate(&self) -> u64 {
        self.0.commission_rate
    }

    /// Total amount of stake that would be active in the next epoch, in
    /// nanos.
    pub fn next_epoch_stake(&self) -> u64 {
        self.0.next_epoch_stake
    }

    /// This validator's gas price quote for the next epoch.
    pub fn next_epoch_gas_price(&self) -> u64 {
        self.0.next_epoch_gas_price
    }

    /// The commission rate of the validator starting next epoch, in basis
    /// points.
    pub fn next_epoch_commission_rate(&self) -> u64 {
        self.0.next_epoch_commission_rate
    }
}

/// A typed view of a `0x3::validator::ValidatorMetadataV1`.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct ValidatorMetadataV1(
    pub iota_sdk::move_types::iota_system::validator::ValidatorMetadataV1,
);

#[uniffi::export]
impl ValidatorMetadataV1 {
    /// The IOTA address of the validator.
    pub fn iota_address(&self) -> Address {
        Address(self.0.iota_address)
    }

    /// Public key bytes for signing transactions (also serves as the
    /// authority name).
    pub fn authority_pubkey_bytes(&self) -> Vec<u8> {
        self.0.authority_pubkey_bytes.clone()
    }

    /// Public key bytes for TLS connections.
    pub fn network_pubkey_bytes(&self) -> Vec<u8> {
        self.0.network_pubkey_bytes.clone()
    }

    /// Public key bytes for signing consensus blocks.
    pub fn protocol_pubkey_bytes(&self) -> Vec<u8> {
        self.0.protocol_pubkey_bytes.clone()
    }

    /// Proof that the validator owns the private key.
    pub fn proof_of_possession(&self) -> Vec<u8> {
        self.0.proof_of_possession.clone()
    }

    /// A unique human-readable validator name.
    pub fn name(&self) -> String {
        move_string_to_string(&self.0.name)
    }

    pub fn description(&self) -> String {
        move_string_to_string(&self.0.description)
    }

    pub fn image_url(&self) -> String {
        url_to_string(&self.0.image_url)
    }

    pub fn project_url(&self) -> String {
        url_to_string(&self.0.project_url)
    }

    /// Network address of the validator.
    pub fn net_address(&self) -> String {
        move_string_to_string(&self.0.net_address)
    }

    /// Address of the validator used for p2p activities such as state sync.
    pub fn p2p_address(&self) -> String {
        move_string_to_string(&self.0.p2p_address)
    }

    /// Primary address of the consensus.
    pub fn primary_address(&self) -> String {
        move_string_to_string(&self.0.primary_address)
    }

    /// `next_epoch_*` metadata only takes effect in the next epoch. If
    /// `None`, the current value stays unchanged.
    pub fn next_epoch_authority_pubkey_bytes(&self) -> Option<Vec<u8>> {
        self.0.next_epoch_authority_pubkey_bytes.clone()
    }

    pub fn next_epoch_proof_of_possession(&self) -> Option<Vec<u8>> {
        self.0.next_epoch_proof_of_possession.clone()
    }

    pub fn next_epoch_network_pubkey_bytes(&self) -> Option<Vec<u8>> {
        self.0.next_epoch_network_pubkey_bytes.clone()
    }

    pub fn next_epoch_protocol_pubkey_bytes(&self) -> Option<Vec<u8>> {
        self.0.next_epoch_protocol_pubkey_bytes.clone()
    }

    pub fn next_epoch_net_address(&self) -> Option<String> {
        self.0
            .next_epoch_net_address
            .as_ref()
            .map(move_string_to_string)
    }

    pub fn next_epoch_p2p_address(&self) -> Option<String> {
        self.0
            .next_epoch_p2p_address
            .as_ref()
            .map(move_string_to_string)
    }

    pub fn next_epoch_primary_address(&self) -> Option<String> {
        self.0
            .next_epoch_primary_address
            .as_ref()
            .map(move_string_to_string)
    }
}

/// A typed view of a `0x3::staking_pool::StakingPoolV1` embedded in a
/// validator.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct StakingPoolV1(pub iota_sdk::move_types::iota_system::staking_pool::StakingPoolV1);

#[uniffi::export]
impl StakingPoolV1 {
    pub fn id(&self) -> ObjectId {
        (*self.0.id.object_id()).into()
    }

    /// The epoch at which this pool became active. `None` while pre-active;
    /// `Some(epoch)` once active or inactive.
    pub fn activation_epoch(&self) -> Option<u64> {
        self.0.activation_epoch
    }

    /// The epoch at which this pool ceased to be active. `None` while
    /// pre-active or active; `Some(epoch)` once inactive.
    pub fn deactivation_epoch(&self) -> Option<u64> {
        self.0.deactivation_epoch
    }

    /// The total number of IOTA tokens in this pool, including the rewards
    /// and the principal of every `StakedIota`, in nanos; updated at epoch
    /// boundaries.
    pub fn iota_balance(&self) -> u64 {
        self.0.iota_balance
    }

    /// Epoch stake rewards accumulated in the pool, in nanos.
    pub fn rewards_pool(&self) -> u64 {
        self.0.rewards_pool.value()
    }

    /// Total number of pool tokens issued by the pool.
    pub fn pool_token_balance(&self) -> u64 {
        self.0.pool_token_balance
    }

    /// Number of exchange-rate history entries. The entries themselves are
    /// stored in dynamic fields and are not part of this struct's contents.
    pub fn exchange_rates_size(&self) -> u64 {
        self.0.exchange_rates.size
    }

    /// Pending stake amount for this epoch, emptied at epoch boundaries.
    pub fn pending_stake(&self) -> u64 {
        self.0.pending_stake
    }

    /// Pending stake withdrawn during the current epoch, including both
    /// principal and rewards; emptied at epoch boundaries.
    pub fn pending_total_iota_withdraw(&self) -> u64 {
        self.0.pending_total_iota_withdraw
    }

    /// Pending pool tokens withdrawn during the current epoch, emptied at
    /// epoch boundaries.
    pub fn pending_pool_token_withdraw(&self) -> u64 {
        self.0.pending_pool_token_withdraw
    }
}

/// A typed view of the `0x3::iota_system_state_inner::SystemParametersV1`
/// embedded in the system state.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct SystemParametersV1(
    pub iota_sdk::move_types::iota_system::iota_system_state_inner::SystemParametersV1,
);

#[uniffi::export]
impl SystemParametersV1 {
    /// The duration of an epoch, in milliseconds.
    pub fn epoch_duration_ms(&self) -> u64 {
        self.0.epoch_duration_ms
    }

    /// Minimum number of active validators at any moment.
    pub fn min_validator_count(&self) -> u64 {
        self.0.min_validator_count
    }

    /// Maximum number of active validators at any moment.
    pub fn max_validator_count(&self) -> u64 {
        self.0.max_validator_count
    }

    /// Lower bound on the amount of stake required to become a validator, in
    /// nanos.
    pub fn min_validator_joining_stake(&self) -> u64 {
        self.0.min_validator_joining_stake
    }

    /// Validators with stake below this threshold (in nanos) are considered
    /// to have low stake and may be removed from the validator set.
    pub fn validator_low_stake_threshold(&self) -> u64 {
        self.0.validator_low_stake_threshold
    }

    /// Validators with stake below this threshold (in nanos) are removed
    /// immediately at epoch change with no grace period.
    pub fn validator_very_low_stake_threshold(&self) -> u64 {
        self.0.validator_very_low_stake_threshold
    }

    /// A validator can have stake below `validator_low_stake_threshold` for
    /// this many epochs before being removed.
    pub fn validator_low_stake_grace_period(&self) -> u64 {
        self.0.validator_low_stake_grace_period
    }
}

/// A typed view of the `0x3::storage_fund::StorageFundV1` embedded in the
/// system state.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct StorageFundV1(pub iota_sdk::move_types::iota_system::storage_fund::StorageFundV1);

#[uniffi::export]
impl StorageFundV1 {
    /// The sum of the storage rebates of all live objects, in nanos.
    pub fn total_object_storage_rebates(&self) -> u64 {
        self.0.total_object_storage_rebates.value()
    }

    /// The non-refundable portion of the storage fund, in nanos.
    pub fn non_refundable_balance(&self) -> u64 {
        self.0.non_refundable_balance.value()
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain
    /// `0x3::validator_cap::UnverifiedValidatorOperationCap` object.
    UnverifiedValidatorOperationCap(
        iota_sdk::move_types::iota_system::validator_cap::UnverifiedValidatorOperationCap
    ) {
        /// Address of the validator authorized to use this capability.
        pub fn authorizer_validator_address(&self) -> Address {
            Address(self.0.authorizer_validator_address)
        }
    }
}

// =====================================================================
// 0x2 — IOTA framework
// =====================================================================

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::coin::CoinMetadata<IOTA>` object.
    IotaCoinMetadata(iota_sdk::move_types::iota_framework::coin::CoinMetadata<IOTA>) {
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
}

/// A typed view of a `0x2::coin_manager::ImmutableCoinMetadata<IOTA>` — the
/// frozen metadata fallback embedded in a `CoinManager`. Reachable only via
/// `CoinManager::immutable_metadata`; it is not a standalone on-chain object.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct ImmutableCoinMetadata(
    pub iota_sdk::move_types::iota_framework::coin_manager::ImmutableCoinMetadata<IOTA>,
);

#[uniffi::export]
impl ImmutableCoinMetadata {
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

crate::ffi_move_object! {
    /// A typed view of the on-chain `0x2::clock::Clock` object (the `0x6`
    /// singleton carrying the consensus timestamp).
    Clock(iota_sdk::move_types::iota_framework::clock::Clock) {
        /// The clock's timestamp (ms), set by consensus every commit.
        pub fn timestamp_ms(&self) -> u64 {
            self.0.timestamp_ms
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::timelock::TimeLock<Balance<IOTA>>`
    /// object — a time-locked IOTA balance, e.g. Stardust vested rewards.
    TimelockedIotaBalance(
        iota_sdk::move_types::iota_framework::timelock::TimeLock<
            iota_sdk::move_types::iota_framework::balance::Balance<IOTA>,
        >
    ) {
        /// The locked IOTA amount in nanos.
        pub fn locked(&self) -> u64 {
            self.0.locked.value()
        }

        /// Epoch timestamp (ms) of when the lock expires.
        pub fn expiration_timestamp_ms(&self) -> u64 {
            self.0.expiration_timestamp_ms
        }

        pub fn label(&self) -> Option<String> {
            self.0.label.as_ref().map(move_string_to_string)
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::package::UpgradeCap` object.
    UpgradeCap(iota_sdk::move_types::iota_framework::package::UpgradeCap) {
        /// ID of the package that can be upgraded.
        pub fn package(&self) -> ObjectId {
            self.0.package.bytes.into()
        }

        /// Number of upgrades applied to the original package.
        pub fn version(&self) -> u64 {
            self.0.version
        }

        /// What kind of upgrades are allowed.
        pub fn policy(&self) -> u8 {
            self.0.policy
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::package::Publisher` object.
    Publisher(iota_sdk::move_types::iota_framework::package::Publisher) {
        pub fn package(&self) -> String {
            ascii_to_string(&self.0.package)
        }

        pub fn module_name(&self) -> String {
            ascii_to_string(&self.0.module_name)
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::kiosk::Kiosk` object.
    Kiosk(iota_sdk::move_types::iota_framework::kiosk::Kiosk) {
        /// Accumulated sale profits in nanos.
        pub fn profits(&self) -> u64 {
            self.0.profits.value()
        }

        pub fn owner(&self) -> Arc<Address> {
            Arc::new(Address(self.0.owner))
        }

        /// Number of items stored in the kiosk.
        pub fn item_count(&self) -> u32 {
            self.0.item_count
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::kiosk::KioskOwnerCap` object.
    KioskOwnerCap(iota_sdk::move_types::iota_framework::kiosk::KioskOwnerCap) {
        /// ID of the kiosk this cap controls (the Move `for` field).
        pub fn kiosk_id(&self) -> ObjectId {
            self.0.r#for.bytes.into()
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::deny_list::DenyList` object (the
    /// `0x403` singleton tracking regulated-coin deny lists).
    DenyList(iota_sdk::move_types::iota_framework::deny_list::DenyList) {
        /// Object ID of the `Bag` holding the per-coin deny lists.
        pub fn lists_id(&self) -> ObjectId {
            (*self.0.lists.id.object_id()).into()
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of the on-chain `0x2::random::Random` object (the `0x8`
    /// singleton holding the global randomness state).
    Random(iota_sdk::move_types::iota_framework::random::Random) {
        // `inner` is a `Versioned` handle whose state lives in a dynamic
        // field, not in this object's contents, so it cannot be surfaced here.
        // Decode that field's contents with [`RandomInner::try_from_bcs`].
    }
}

/// A typed view of the `0x2::random::RandomInner` state held in the dynamic
/// field of the [`Random`] singleton.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct RandomInner(pub iota_sdk::move_types::iota_framework::random::RandomInner);

#[uniffi::export]
impl RandomInner {
    /// Decode a `RandomInner` from raw BCS bytes.
    ///
    /// There is no object-based constructor: the state is stored as a dynamic
    /// field of the `0x8` wrapper, not as a top-level object with its own type
    /// tag.
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(
            bcs::from_bytes::<iota_sdk::move_types::iota_framework::random::RandomInner>(&bytes)?
                .into(),
        )
    }

    pub fn version(&self) -> u64 {
        self.0.version
    }

    pub fn epoch(&self) -> u64 {
        self.0.epoch
    }

    /// The randomness round the current `random_bytes` were produced for.
    pub fn randomness_round(&self) -> u64 {
        self.0.randomness_round
    }

    pub fn random_bytes(&self) -> Vec<u8> {
        self.0.random_bytes.clone()
    }
}

crate::ffi_move_object! {
    /// A typed view of the on-chain
    /// `0x2::authenticator_state::AuthenticatorState` object (the `0x7`
    /// singleton tracking active JWKs).
    AuthenticatorState(
        iota_sdk::move_types::iota_framework::authenticator_state::AuthenticatorState
    ) {
        /// Version selecting which inner state layout the dynamic field holds.
        ///
        /// Decode that field's contents with
        /// [`AuthenticatorStateInner::try_from_bcs`].
        pub fn version(&self) -> u64 {
            self.0.version
        }
    }
}

/// A typed view of the `0x2::authenticator_state::AuthenticatorStateInner`
/// state held in the dynamic field of the [`AuthenticatorState`] singleton.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct AuthenticatorStateInner(
    pub iota_sdk::move_types::iota_framework::authenticator_state::AuthenticatorStateInner,
);

#[uniffi::export]
impl AuthenticatorStateInner {
    /// Decode an `AuthenticatorStateInner` from raw BCS bytes.
    ///
    /// There is no object-based constructor: the state is stored as a dynamic
    /// field of the `0x7` wrapper, not as a top-level object with its own type
    /// tag.
    #[uniffi::constructor]
    pub fn try_from_bcs(bytes: Vec<u8>) -> Result<Self> {
        Ok(bcs::from_bytes::<
            iota_sdk::move_types::iota_framework::authenticator_state::AuthenticatorStateInner,
        >(&bytes)?
        .into())
    }

    pub fn version(&self) -> u64 {
        self.0.version
    }

    /// The currently active JWKs, ordered as stored on chain.
    pub fn active_jwks(&self) -> Vec<ActiveJwk> {
        self.0.active_jwks.iter().map(Into::into).collect()
    }
}

/// A JWK active in a given epoch (`0x2::authenticator_state::ActiveJwk`).
#[derive(uniffi::Record)]
pub struct ActiveJwk {
    pub jwk_id: JwkId,
    pub jwk: Jwk,
    /// The epoch the key was added in.
    pub epoch: u64,
}

impl From<&iota_sdk::move_types::iota_framework::authenticator_state::ActiveJwk> for ActiveJwk {
    fn from(jwk: &iota_sdk::move_types::iota_framework::authenticator_state::ActiveJwk) -> Self {
        Self {
            jwk_id: (&jwk.jwk_id).into(),
            jwk: (&jwk.jwk).into(),
            epoch: jwk.epoch,
        }
    }
}

/// Identifier of a JWK (`0x2::authenticator_state::JwkId`).
#[derive(uniffi::Record)]
pub struct JwkId {
    /// The OIDC provider that issued the key.
    pub iss: String,
    /// The key ID within the issuer's key set.
    pub kid: String,
}

impl From<&iota_sdk::move_types::iota_framework::authenticator_state::JwkId> for JwkId {
    fn from(id: &iota_sdk::move_types::iota_framework::authenticator_state::JwkId) -> Self {
        Self {
            iss: move_string_to_string(&id.iss),
            kid: move_string_to_string(&id.kid),
        }
    }
}

/// An RSA JWK as stored on chain (`0x2::authenticator_state::JWK`).
#[derive(uniffi::Record)]
pub struct Jwk {
    pub kty: String,
    pub e: String,
    pub n: String,
    pub alg: String,
}

impl From<&iota_sdk::move_types::iota_framework::authenticator_state::JWK> for Jwk {
    fn from(jwk: &iota_sdk::move_types::iota_framework::authenticator_state::JWK) -> Self {
        Self {
            kty: move_string_to_string(&jwk.kty),
            e: move_string_to_string(&jwk.e),
            n: move_string_to_string(&jwk.n),
            alg: move_string_to_string(&jwk.alg),
        }
    }
}

/// Metadata of a single module of a package
/// (`0x2::package_metadata::ModuleMetadataV1`).
#[derive(uniffi::Record)]
pub struct ModuleMetadataV1 {
    /// The authenticator functions the module declares.
    pub authenticator_metadata: Vec<AuthenticatorMetadataV1>,
}

impl From<&iota_sdk::move_types::iota_framework::package_metadata::ModuleMetadataV1>
    for ModuleMetadataV1
{
    fn from(m: &iota_sdk::move_types::iota_framework::package_metadata::ModuleMetadataV1) -> Self {
        Self {
            authenticator_metadata: m.authenticator_metadata.iter().map(Into::into).collect(),
        }
    }
}

/// An authenticator function declared by a module
/// (`0x2::package_metadata::AuthenticatorMetadataV1`).
#[derive(uniffi::Record)]
pub struct AuthenticatorMetadataV1 {
    /// Name of the authenticator function.
    pub function_name: String,
    /// Fully-qualified type name of the account type it authenticates.
    pub account_type: String,
}

impl From<&iota_sdk::move_types::iota_framework::package_metadata::AuthenticatorMetadataV1>
    for AuthenticatorMetadataV1
{
    fn from(
        m: &iota_sdk::move_types::iota_framework::package_metadata::AuthenticatorMetadataV1,
    ) -> Self {
        Self {
            function_name: ascii_to_string(&m.function_name),
            account_type: ascii_to_string(&m.account_type.name),
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain
    /// `0x2::package_metadata::PackageMetadataV1` object.
    PackageMetadataV1(
        iota_sdk::move_types::iota_framework::package_metadata::PackageMetadataV1
    ) {
        /// Storage ID of the package this metadata describes.
        pub fn storage_id(&self) -> ObjectId {
            self.0.storage_id.bytes.into()
        }

        /// Runtime ID of the package — the storage ID of its first version.
        pub fn runtime_id(&self) -> ObjectId {
            self.0.runtime_id.bytes.into()
        }

        pub fn package_version(&self) -> u64 {
            self.0.package_version
        }

        /// Per-module metadata, keyed by module name.
        pub fn modules_metadata(&self) -> HashMap<String, ModuleMetadataV1> {
            self.0
                .modules_metadata
                .contents
                .iter()
                .map(|e| (ascii_to_string(&e.key), (&e.value).into()))
                .collect()
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x2::module_metadata::ModuleMetadata`
    /// object, the per-module key-value store owned by a package's
    /// `PackageMetadataV1`.
    ModuleMetadata(iota_sdk::move_types::iota_framework::module_metadata::ModuleMetadata) {
        /// The number of key-value pairs stored in the metadata's dynamic
        /// fields. The entries themselves (e.g. the view-function names) live
        /// in dynamic fields, not in this object's contents.
        pub fn size(&self) -> u64 {
            self.0.size
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::coin::TreasuryCap<T>` object, the
    /// capability controlling a coin type's supply.
    TreasuryCap(iota_sdk::move_types::iota_framework::coin::TreasuryCap<IOTA>) {
        /// Total supply of the coin currently in circulation, in base units.
        pub fn total_supply(&self) -> u64 {
            self.0.total_supply.value
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::coin::RegulatedCoinMetadata<T>`
    /// object.
    RegulatedCoinMetadata(
        iota_sdk::move_types::iota_framework::coin::RegulatedCoinMetadata<IOTA>
    ) {
        /// Object ID of the coin's `CoinMetadata` object.
        pub fn coin_metadata_object(&self) -> ObjectId {
            self.0.coin_metadata_object.bytes.into()
        }

        /// Object ID of the coin's `DenyCap` object.
        pub fn deny_cap_object(&self) -> ObjectId {
            self.0.deny_cap_object.bytes.into()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::coin::DenyCapV1<T>` object, the
    /// capability for denying addresses from using a regulated coin.
    DenyCapV1(iota_sdk::move_types::iota_framework::coin::DenyCapV1<IOTA>) {
        /// Whether the bearer may also enable a global pause.
        pub fn allow_global_pause(&self) -> bool {
            self.0.allow_global_pause
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::display::Display<T>` object.
    Display(iota_sdk::move_types::iota_framework::display::Display<IOTA>) {
        /// Version, bumped manually by the publisher on each update.
        pub fn version(&self) -> u16 {
            self.0.version
        }

        /// The display template as key/value pairs (e.g. `name`, `link`,
        /// `image_url`, `description`).
        pub fn fields(&self) -> HashMap<String, String> {
            self.0
                .fields
                .contents
                .iter()
                .map(|e| (move_string_to_string(&e.key), move_string_to_string(&e.value)))
                .collect()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::coin_manager::CoinManager<T>` object.
    CoinManager(iota_sdk::move_types::iota_framework::coin_manager::CoinManager<IOTA>) {
        /// Optional maximum supply cap, in base units.
        pub fn maximum_supply(&self) -> Option<u64> {
            self.0.maximum_supply
        }

        /// Whether the supply is considered immutable.
        pub fn supply_immutable(&self) -> bool {
            self.0.supply_immutable
        }

        /// Whether the metadata is considered immutable.
        pub fn metadata_immutable(&self) -> bool {
            self.0.metadata_immutable
        }

        /// The embedded `TreasuryCap` controlling the coin's supply.
        pub fn treasury_cap(&self) -> TreasuryCap {
            TreasuryCap(self.0.treasury_cap.clone())
        }

        /// The coin's `CoinMetadata`, if still held by the manager.
        pub fn metadata(&self) -> Option<Arc<IotaCoinMetadata>> {
            self.0
                .metadata
                .clone()
                .map(|m| Arc::new(IotaCoinMetadata(m)))
        }

        /// Frozen fallback metadata, used only if the original metadata has
        /// been frozen.
        pub fn immutable_metadata(&self) -> Option<Arc<ImmutableCoinMetadata>> {
            self.0
                .immutable_metadata
                .clone()
                .map(|m| Arc::new(ImmutableCoinMetadata(m)))
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain
    /// `0x2::coin_manager::CoinManagerTreasuryCap<T>` object.
    CoinManagerTreasuryCap(
        iota_sdk::move_types::iota_framework::coin_manager::CoinManagerTreasuryCap<IOTA>
    ) {
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain
    /// `0x2::coin_manager::CoinManagerMetadataCap<T>` object.
    CoinManagerMetadataCap(
        iota_sdk::move_types::iota_framework::coin_manager::CoinManagerMetadataCap<IOTA>
    ) {
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::token::Token<T>` object.
    Token(iota_sdk::move_types::iota_framework::token::Token<IOTA>) {
        /// The token's balance, in base units.
        pub fn balance(&self) -> u64 {
            self.0.balance.value()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::token::TokenPolicyCap<T>` object.
    TokenPolicyCap(iota_sdk::move_types::iota_framework::token::TokenPolicyCap<IOTA>) {
        /// Object ID of the `TokenPolicy` this cap controls (the Move `for`
        /// field).
        pub fn policy_id(&self) -> ObjectId {
            self.0.r#for.bytes.into()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::token::TokenPolicy<T>` object.
    TokenPolicy(iota_sdk::move_types::iota_framework::token::TokenPolicy<IOTA>) {
        /// Balance spent on the `spend` action, in base units.
        pub fn spent_balance(&self) -> u64 {
            self.0.spent_balance.value()
        }

        /// Fully-qualified type names of the rules attached to each action,
        /// keyed by action name.
        pub fn rules(&self) -> HashMap<String, Vec<String>> {
            self.0
                .rules
                .contents
                .iter()
                .map(|e| {
                    (
                        move_string_to_string(&e.key),
                        e.value.contents.iter().map(|t| ascii_to_string(&t.name)).collect(),
                    )
                })
                .collect()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::config::Config<WriteCap>` object,
    /// where `WriteCap` is the phantom type parameter from the Move
    /// declaration, not a concrete type.
    Config(iota_sdk::move_types::iota_framework::config::Config<IOTA>) {
        // The config's settings live in dynamic fields off its `UID`, not in
        // the struct itself.
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain
    /// `0x2::transfer_policy::TransferPolicy<T>` object.
    TransferPolicy(
        iota_sdk::move_types::iota_framework::transfer_policy::TransferPolicy<IOTA>
    ) {
        /// IOTA balance collected by the policy, in nanos.
        pub fn balance(&self) -> u64 {
            self.0.balance.value()
        }

        /// Fully-qualified type names of the rules attached to this policy.
        pub fn rules(&self) -> Vec<String> {
            self.0.rules.contents.iter().map(|t| ascii_to_string(&t.name)).collect()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain
    /// `0x2::transfer_policy::TransferPolicyCap<T>` object.
    TransferPolicyCap(
        iota_sdk::move_types::iota_framework::transfer_policy::TransferPolicyCap<IOTA>
    ) {
        /// Object ID of the `TransferPolicy` this cap controls.
        pub fn policy_id(&self) -> ObjectId {
            self.0.policy_id.bytes.into()
        }
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::labeler::LabelerCap<L>` object.
    LabelerCap(iota_sdk::move_types::iota_framework::labeler::LabelerCap<IOTA>) {
    }
}

crate::ffi_move_object_generic! {
    /// A typed view of an on-chain `0x2::kiosk::PurchaseCap<T>` object.
    PurchaseCap(iota_sdk::move_types::iota_framework::kiosk::PurchaseCap<IOTA>) {
        /// Object ID of the kiosk the listed item belongs to.
        pub fn kiosk_id(&self) -> ObjectId {
            self.0.kiosk_id.bytes.into()
        }

        /// Object ID of the listed item.
        pub fn item_id(&self) -> ObjectId {
            self.0.item_id.bytes.into()
        }

        /// Minimum price the item may be purchased for, in nanos.
        pub fn min_price(&self) -> u64 {
            self.0.min_price
        }
    }
}

// =====================================================================
// 0x107a — Stardust
// =====================================================================

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x107a::nft::Nft` object.
    Nft(iota_sdk::move_types::stardust::nft::Nft) {
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
        Ok(iota_sdk::move_types::stardust::irc27::Irc27Metadata::from_bcs(&bytes)?.into())
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

crate::ffi_move_object! {
    /// A typed view of an on-chain
    /// `0x107a::basic_output::BasicOutput<IOTA>` object.
    BasicOutput(iota_sdk::move_types::stardust::basic_output::BasicOutput<IOTA>) {
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
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x107a::nft_output::NftOutput<IOTA>` object.
    NftOutput(iota_sdk::move_types::stardust::nft_output::NftOutput<IOTA>) {
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
}

crate::ffi_move_object! {
    /// A typed view of an on-chain
    /// `0x107a::alias_output::AliasOutput<IOTA>` object.
    AliasOutput(iota_sdk::move_types::stardust::alias_output::AliasOutput<IOTA>) {
        pub fn balance(&self) -> u64 {
            self.0.balance.value()
        }

        pub fn native_tokens_bag_id(&self) -> ObjectId {
            (*self.0.native_tokens.id.object_id()).into()
        }
    }
}

crate::ffi_move_object! {
    /// A typed view of an on-chain `0x107a::alias::Alias` object.
    Alias(iota_sdk::move_types::stardust::alias::Alias) {
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

// =====================================================================
// Event mirrors
//
// Events are not objects (no `key`, no `UID`); they are decoded from the
// BCS `contents` of an event query result via `ffi_move_event!`. Generic
// events carry a phantom (`serde(skip)`) type parameter, so their BCS layout
// is instantiation-independent and they are wrapped at `<IOTA>` like the
// generic object shims.
// =====================================================================

/// A reference to an authenticator function
/// (`0x2::authenticator_function::AuthenticatorFunctionRefV1`), carried by the
/// account-abstraction events.
#[derive(uniffi::Record)]
pub struct AuthenticatorFunctionRef {
    /// Object ID of the package declaring the function.
    pub package: Arc<ObjectId>,
    pub module_name: String,
    pub function_name: String,
}

impl<Account>
    From<
        &iota_sdk::move_types::iota_framework::authenticator_function::AuthenticatorFunctionRefV1<
            Account,
        >,
    > for AuthenticatorFunctionRef
{
    fn from(
        r: &iota_sdk::move_types::iota_framework::authenticator_function::AuthenticatorFunctionRefV1<Account>,
    ) -> Self {
        Self {
            package: Arc::new(r.package.bytes.into()),
            module_name: ascii_to_string(&r.module_name),
            function_name: ascii_to_string(&r.function_name),
        }
    }
}

/// A validator's pool-token exchange rate at an epoch boundary
/// (`0x3::staking_pool::PoolTokenExchangeRate`).
#[derive(uniffi::Record)]
pub struct PoolTokenExchangeRate {
    pub iota_amount: u64,
    pub pool_token_amount: u64,
}

impl From<&iota_sdk::move_types::iota_system::staking_pool::PoolTokenExchangeRate>
    for PoolTokenExchangeRate
{
    fn from(r: &iota_sdk::move_types::iota_system::staking_pool::PoolTokenExchangeRate) -> Self {
        Self {
            iota_amount: r.iota_amount,
            pool_token_amount: r.pool_token_amount,
        }
    }
}

/// Key identifying a per-type deny-list config
/// (`0x2::deny_list::ConfigKey`).
#[derive(uniffi::Record)]
pub struct ConfigKey {
    pub per_type_index: u64,
    pub per_type_key: Vec<u8>,
}

impl From<&iota_sdk::move_types::iota_framework::deny_list::ConfigKey> for ConfigKey {
    fn from(k: &iota_sdk::move_types::iota_framework::deny_list::ConfigKey) -> Self {
        Self {
            per_type_index: k.per_type_index,
            per_type_key: k.per_type_key.clone(),
        }
    }
}

// --- 0x3 events ---

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator::StakingRequestEvent`.
    StakingRequestEvent(iota_sdk::move_types::iota_system::validator::StakingRequestEvent) {
        pub fn pool_id(&self) -> ObjectId {
            self.0.pool_id.bytes.into()
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staker_address(&self) -> Address {
            Address(self.0.staker_address)
        }
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        /// Staked amount, in nanos.
        pub fn amount(&self) -> u64 {
            self.0.amount
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator::UnstakingRequestEvent`.
    UnstakingRequestEvent(iota_sdk::move_types::iota_system::validator::UnstakingRequestEvent) {
        pub fn pool_id(&self) -> ObjectId {
            self.0.pool_id.bytes.into()
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staker_address(&self) -> Address {
            Address(self.0.staker_address)
        }
        pub fn stake_activation_epoch(&self) -> u64 {
            self.0.stake_activation_epoch
        }
        pub fn unstaking_epoch(&self) -> u64 {
            self.0.unstaking_epoch
        }
        /// Withdrawn principal, in nanos.
        pub fn principal_amount(&self) -> u64 {
            self.0.principal_amount
        }
        /// Withdrawn reward, in nanos.
        pub fn reward_amount(&self) -> u64 {
            self.0.reward_amount
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a
    /// `0x3::iota_system_state_inner::SystemEpochInfoEventV1`.
    SystemEpochInfoEventV1(
        iota_sdk::move_types::iota_system::iota_system_state_inner::SystemEpochInfoEventV1
    ) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn protocol_version(&self) -> u64 {
            self.0.protocol_version
        }
        /// Reference gas price for the epoch, in nanos.
        pub fn reference_gas_price(&self) -> u64 {
            self.0.reference_gas_price
        }
        pub fn total_stake(&self) -> u64 {
            self.0.total_stake
        }
        pub fn storage_charge(&self) -> u64 {
            self.0.storage_charge
        }
        pub fn storage_rebate(&self) -> u64 {
            self.0.storage_rebate
        }
        pub fn storage_fund_balance(&self) -> u64 {
            self.0.storage_fund_balance
        }
        pub fn total_gas_fees(&self) -> u64 {
            self.0.total_gas_fees
        }
        pub fn total_stake_rewards_distributed(&self) -> u64 {
            self.0.total_stake_rewards_distributed
        }
        pub fn burnt_tokens_amount(&self) -> u64 {
            self.0.burnt_tokens_amount
        }
        pub fn minted_tokens_amount(&self) -> u64 {
            self.0.minted_tokens_amount
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a
    /// `0x3::iota_system_state_inner::SystemEpochInfoEventV2`.
    SystemEpochInfoEventV2(
        iota_sdk::move_types::iota_system::iota_system_state_inner::SystemEpochInfoEventV2
    ) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn protocol_version(&self) -> u64 {
            self.0.protocol_version
        }
        pub fn total_stake(&self) -> u64 {
            self.0.total_stake
        }
        pub fn storage_charge(&self) -> u64 {
            self.0.storage_charge
        }
        pub fn storage_rebate(&self) -> u64 {
            self.0.storage_rebate
        }
        pub fn storage_fund_balance(&self) -> u64 {
            self.0.storage_fund_balance
        }
        pub fn total_gas_fees(&self) -> u64 {
            self.0.total_gas_fees
        }
        pub fn total_stake_rewards_distributed(&self) -> u64 {
            self.0.total_stake_rewards_distributed
        }
        pub fn burnt_tokens_amount(&self) -> u64 {
            self.0.burnt_tokens_amount
        }
        pub fn minted_tokens_amount(&self) -> u64 {
            self.0.minted_tokens_amount
        }
        pub fn tips_amount(&self) -> u64 {
            self.0.tips_amount
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator_set::ValidatorEpochInfoEventV1`.
    ValidatorEpochInfoEventV1(
        iota_sdk::move_types::iota_system::validator_set::ValidatorEpochInfoEventV1
    ) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn reference_gas_survey_quote(&self) -> u64 {
            self.0.reference_gas_survey_quote
        }
        pub fn stake(&self) -> u64 {
            self.0.stake
        }
        pub fn voting_power(&self) -> u64 {
            self.0.voting_power
        }
        pub fn commission_rate(&self) -> u64 {
            self.0.commission_rate
        }
        pub fn pool_staking_reward(&self) -> u64 {
            self.0.pool_staking_reward
        }
        pub fn pool_token_exchange_rate(&self) -> PoolTokenExchangeRate {
            (&self.0.pool_token_exchange_rate).into()
        }
        /// Addresses of the validators that reported this one this epoch.
        pub fn tallying_rule_reporters(&self) -> Vec<Arc<Address>> {
            self.0
                .tallying_rule_reporters
                .iter()
                .map(|a| Arc::new(Address(*a)))
                .collect()
        }
        pub fn tallying_rule_global_score(&self) -> u64 {
            self.0.tallying_rule_global_score
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator_set::ValidatorJoinEvent`.
    ValidatorJoinEvent(iota_sdk::move_types::iota_system::validator_set::ValidatorJoinEvent) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staking_pool_id(&self) -> ObjectId {
            self.0.staking_pool_id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator_set::ValidatorLeaveEvent`.
    ValidatorLeaveEvent(iota_sdk::move_types::iota_system::validator_set::ValidatorLeaveEvent) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staking_pool_id(&self) -> ObjectId {
            self.0.staking_pool_id.bytes.into()
        }
        /// Whether the validator left voluntarily (vs. being removed).
        pub fn is_voluntary(&self) -> bool {
            self.0.is_voluntary
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator_set::CommitteeValidatorJoinEvent`.
    CommitteeValidatorJoinEvent(
        iota_sdk::move_types::iota_system::validator_set::CommitteeValidatorJoinEvent
    ) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staking_pool_id(&self) -> ObjectId {
            self.0.staking_pool_id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x3::validator_set::CommitteeValidatorLeaveEvent`.
    CommitteeValidatorLeaveEvent(
        iota_sdk::move_types::iota_system::validator_set::CommitteeValidatorLeaveEvent
    ) {
        pub fn epoch(&self) -> u64 {
            self.0.epoch
        }
        pub fn validator_address(&self) -> Address {
            Address(self.0.validator_address)
        }
        pub fn staking_pool_id(&self) -> ObjectId {
            self.0.staking_pool_id.bytes.into()
        }
    }
}

// --- 0x2 events ---

crate::ffi_move_event! {
    /// A typed view of a `0x2::account::ImmutableAccountCreated`.
    ImmutableAccountCreated(
        iota_sdk::move_types::iota_framework::account::ImmutableAccountCreated<IOTA>
    ) {
        pub fn account_id(&self) -> ObjectId {
            self.0.account_id.bytes.into()
        }
        pub fn authenticator(&self) -> AuthenticatorFunctionRef {
            (&self.0.authenticator).into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::account::MutableAccountCreated`.
    MutableAccountCreated(
        iota_sdk::move_types::iota_framework::account::MutableAccountCreated<IOTA>
    ) {
        pub fn account_id(&self) -> ObjectId {
            self.0.account_id.bytes.into()
        }
        pub fn authenticator(&self) -> AuthenticatorFunctionRef {
            (&self.0.authenticator).into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::account::AuthenticatorFunctionRefV1Rotated`.
    AuthenticatorFunctionRefV1Rotated(
        iota_sdk::move_types::iota_framework::account::AuthenticatorFunctionRefV1Rotated<IOTA>
    ) {
        pub fn account_id(&self) -> ObjectId {
            self.0.account_id.bytes.into()
        }
        /// The authenticator function reference before the rotation.
        pub fn from_ref(&self) -> AuthenticatorFunctionRef {
            (&self.0.from).into()
        }
        /// The authenticator function reference after the rotation.
        pub fn to_ref(&self) -> AuthenticatorFunctionRef {
            (&self.0.to).into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::coin_manager::CoinManaged`.
    CoinManaged(iota_sdk::move_types::iota_framework::coin_manager::CoinManaged) {
        pub fn coin_name(&self) -> String {
            ascii_to_string(&self.0.coin_name)
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::coin_manager::TreasuryOwnershipRenounced`.
    TreasuryOwnershipRenounced(
        iota_sdk::move_types::iota_framework::coin_manager::TreasuryOwnershipRenounced
    ) {
        pub fn coin_name(&self) -> String {
            ascii_to_string(&self.0.coin_name)
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::coin_manager::MetadataOwnershipRenounced`.
    MetadataOwnershipRenounced(
        iota_sdk::move_types::iota_framework::coin_manager::MetadataOwnershipRenounced
    ) {
        pub fn coin_name(&self) -> String {
            ascii_to_string(&self.0.coin_name)
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::deny_list::PerTypeConfigCreated`.
    PerTypeConfigCreated(iota_sdk::move_types::iota_framework::deny_list::PerTypeConfigCreated) {
        pub fn key(&self) -> ConfigKey {
            (&self.0.key).into()
        }
        pub fn config_id(&self) -> ObjectId {
            self.0.config_id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::display::DisplayCreated`.
    DisplayCreated(iota_sdk::move_types::iota_framework::display::DisplayCreated<IOTA>) {
        /// Object ID of the created `Display`.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::display::VersionUpdated`.
    VersionUpdated(iota_sdk::move_types::iota_framework::display::VersionUpdated<IOTA>) {
        /// Object ID of the `Display`.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
        pub fn version(&self) -> u16 {
            self.0.version
        }
        /// The display template as key/value pairs.
        pub fn fields(&self) -> HashMap<String, String> {
            self.0
                .fields
                .contents
                .iter()
                .map(|e| (move_string_to_string(&e.key), move_string_to_string(&e.value)))
                .collect()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::kiosk::ItemListed`.
    ItemListed(iota_sdk::move_types::iota_framework::kiosk::ItemListed<IOTA>) {
        /// Object ID of the kiosk.
        pub fn kiosk(&self) -> ObjectId {
            self.0.kiosk.bytes.into()
        }
        /// Object ID of the listed item.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
        /// Listing price, in nanos.
        pub fn price(&self) -> u64 {
            self.0.price
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::kiosk::ItemPurchased`.
    ItemPurchased(iota_sdk::move_types::iota_framework::kiosk::ItemPurchased<IOTA>) {
        pub fn kiosk(&self) -> ObjectId {
            self.0.kiosk.bytes.into()
        }
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
        /// Purchase price, in nanos.
        pub fn price(&self) -> u64 {
            self.0.price
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::kiosk::ItemDelisted`.
    ItemDelisted(iota_sdk::move_types::iota_framework::kiosk::ItemDelisted<IOTA>) {
        pub fn kiosk(&self) -> ObjectId {
            self.0.kiosk.bytes.into()
        }
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::token::TokenPolicyCreated`.
    TokenPolicyCreated(iota_sdk::move_types::iota_framework::token::TokenPolicyCreated<IOTA>) {
        /// Object ID of the created `TokenPolicy`.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
        pub fn is_mutable(&self) -> bool {
            self.0.is_mutable
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::transfer_policy::TransferPolicyCreated`.
    TransferPolicyCreated(
        iota_sdk::move_types::iota_framework::transfer_policy::TransferPolicyCreated<IOTA>
    ) {
        /// Object ID of the created `TransferPolicy`.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
    }
}

crate::ffi_move_event! {
    /// A typed view of a `0x2::transfer_policy::TransferPolicyDestroyed`.
    TransferPolicyDestroyed(
        iota_sdk::move_types::iota_framework::transfer_policy::TransferPolicyDestroyed<IOTA>
    ) {
        /// Object ID of the destroyed `TransferPolicy`.
        pub fn id(&self) -> ObjectId {
            self.0.id.bytes.into()
        }
    }
}
