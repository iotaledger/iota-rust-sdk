// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, BigInt, DateTime, ObjectId, ProtocolConfigs, schema};

// ===========================================================================
// Epoch Queries
// ===========================================================================
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EpochArgs")]
pub struct EpochQuery {
    #[arguments(id: $id)]
    pub epoch: Option<Epoch>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "EpochArgs")]
pub struct EpochSummaryQuery {
    #[arguments(id: $id)]
    pub epoch: Option<EpochSummary>,
}

// ===========================================================================
// Epoch Summary Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct EpochArgs {
    pub id: Option<u64>,
}

/// A summary of the epoch.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Epoch")]
pub struct EpochSummary {
    /// The epoch number.
    pub epoch_id: u64,
    /// The reference gas price throughout this epoch.
    pub reference_gas_price: Option<BigInt>,
    /// The total number of checkpoints in this epoch.
    pub total_checkpoints: Option<u64>,
    /// The total number of transactions in this epoch.
    pub total_transactions: Option<u64>,
}

// ===========================================================================
// Epoch Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "Epoch")]
pub struct Epoch {
    /// The epoch's id as a sequence number that starts at 0 and is incremented
    /// by one at every epoch change.
    pub epoch_id: u64,
    /// The minimum gas price that a quorum of validators are guaranteed to sign
    /// a transaction for.
    pub reference_gas_price: Option<BigInt>,
    /// Validator related properties, including the active validators.
    pub validator_set: Option<ValidatorSet>,
    /// The epoch's starting timestamp.
    pub start_timestamp: DateTime,
    /// The epoch's ending timestamp. Note that this is available only on epochs
    /// that have ended.
    pub end_timestamp: Option<DateTime>,
    /// The total number of checkpoints in this epoch.
    pub total_checkpoints: Option<u64>,
    /// The total number of transaction blocks in this epoch.
    pub total_transactions: Option<u64>,
    /// The total amount of gas fees (in NANOS) that were paid in this epoch.
    pub total_gas_fees: Option<BigInt>,
    /// The total NANOS rewarded as stake.
    pub total_stake_rewards: Option<BigInt>,
    /// The storage fund available in this epoch.
    /// This fund is used to redistribute storage fees from past transactions
    /// to future validators.
    pub fund_size: Option<BigInt>,
    /// The difference between the fund inflow and outflow, representing
    /// the net amount of storage fees accumulated in this epoch.
    pub net_inflow: Option<BigInt>,
    /// The storage fees paid for transactions executed during the epoch.
    pub fund_inflow: Option<BigInt>,
    /// The storage fee rebates paid to users who deleted the data associated
    /// with past transactions.
    pub fund_outflow: Option<BigInt>,
    /// The epoch's corresponding protocol configuration, including the feature
    /// flags and the configuration options.
    pub protocol_configs: Option<ProtocolConfigs>,
    /// IOTA set aside to account for objects stored on-chain, at the start of
    /// the epoch. This is also used for storage rebates.
    pub storage_fund: Option<StorageFund>,
    /// Information about whether this epoch was started in safe mode, which
    /// happens if the full epoch change logic fails for some reason.
    pub safe_mode: Option<SafeMode>,
    /// The value of the `version` field of `0x5`, the
    /// `0x3::iota::IotaSystemState` object.  This version changes whenever
    /// the fields contained in the system state object (held in a dynamic
    /// field attached to `0x5`) change.
    pub system_state_version: Option<u64>,
    /// The total IOTA supply.
    pub iota_total_supply: Option<u64>,
    /// The treasury-cap id.
    pub iota_treasury_cap_id: Option<Address>,
    /// Details of the system that are decided during genesis.
    pub system_parameters: Option<SystemParameters>,
    /// A commitment by the committee at the end of epoch on the contents of the
    /// live object set at that time. This can be used to verify state
    /// snapshots.
    pub live_object_set_digest: Option<String>,
}

/// Representation of `0x3::validator_set::ValidatorSet`.
/// This is a minimal version used in Epoch queries that excludes the validator
/// lists to keep query sizes manageable.
#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "ValidatorSet")]
pub struct ValidatorSet {
    // ///The current set of active validators.
    // pub active_validators: crate::query_types::ValidatorConnection,
    // /// The current set of committee members.
    // pub committee_members: crate::query_types::ValidatorConnection,
    /// Object ID of the `Table` storing the inactive staking pools.
    pub inactive_pools_id: Option<ObjectId>,
    /// Size of the inactive pools `Table`.
    pub inactive_pools_size: Option<i32>,
    /// Object ID of the wrapped object `TableVec` storing the pending active
    /// validators.
    pub pending_active_validators_id: Option<ObjectId>,
    /// Size of the pending active validators table.
    pub pending_active_validators_size: Option<i32>,
    /// Validators that are pending removal from the active validator set,
    /// expressed as indices in to `activeValidators`.
    pub pending_removals: Option<Vec<i32>>,
    /// Object ID of the `Table` storing the mapping from staking pool ids to
    /// the addresses of the corresponding validators. This is needed
    /// because a validator's address can potentially change but the object
    /// ID of its pool will not.
    pub staking_pool_mappings_id: Option<ObjectId>,
    /// Size of the stake pool mappings `Table`.
    pub staking_pool_mappings_size: Option<i32>,
    /// Total amount of stake for all active validators at the beginning of the
    /// epoch.
    pub total_stake: Option<BigInt>,
    /// Size of the validator candidates `Table`.
    pub validator_candidates_size: Option<i32>,
    /// Object ID of the `Table` storing the validator candidates.
    pub validator_candidates_id: Option<ObjectId>,
}

/// Information about whether epoch changes are using safe mode.
#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "SafeMode")]
pub struct SafeMode {
    /// Whether safe mode was used for the last epoch change. The system will
    /// retry a full epoch change on every epoch boundary and automatically
    /// reset this flag if so.
    pub enabled: Option<bool>,
    /// Accumulated fees for computation and cost that have not been added to
    /// the various reward pools, because the full epoch change did not happen.
    pub gas_summary: Option<crate::query_types::GasCostSummary>,
}

/// IOTA set aside to account for objects stored on-chain.
#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "StorageFund")]
pub struct StorageFund {
    /// Sum of storage rebates of live objects on chain.
    pub total_object_storage_rebates: Option<BigInt>,
    /// The portion of the storage fund that will never be refunded through
    /// storage rebates.
    /// The system maintains an invariant that the sum of
    /// all storage fees into the storage fund is equal to the sum of of all
    /// storage rebates out, the total storage rebates remaining, and the
    /// non-refundable balance.
    pub non_refundable_balance: Option<BigInt>,
}

/// Details of the system that are decided during genesis.
#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "SystemParameters")]
pub struct SystemParameters {
    /// Target duration of an epoch, in milliseconds.
    pub duration_ms: Option<BigInt>,
    /// The minimum number of active validators that the system supports.
    pub min_validator_count: Option<i32>,
    /// The maximum number of active validators that the system supports.
    pub max_validator_count: Option<i32>,
    /// Minimum stake needed to become a new validator.
    pub min_validator_joining_stake: Option<BigInt>,
    /// Validators with stake below this threshold will enter the grace period
    /// (see `validator_low_stake_grace_period`), after which they are removed
    /// from the active validator set.
    pub validator_low_stake_threshold: Option<BigInt>,
    /// Validators with stake below this threshold will be removed from the
    /// active validator set at the next epoch boundary, without a grace period.
    pub validator_very_low_stake_threshold: Option<BigInt>,
    /// The number of epochs that a validator has to recover from having less
    /// than `validator_low_stake_threshold` stake.
    pub validator_low_stake_grace_period: Option<BigInt>,
}
