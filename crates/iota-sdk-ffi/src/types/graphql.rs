// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use base64ct::Encoding;
use iota_sdk::{
    graphql_client::{
        pagination::{Direction, PaginationFilter},
        query_types::{
            Base64, BigInt, Feature, MoveAbility, MoveEnum, MoveEnumConnection, MoveEnumVariant,
            MoveField, MoveFunctionTypeParameter, MoveObject, MoveStructConnection,
            MoveStructQuery, MoveStructTypeParameter, MoveVisibility, OpenMoveType, PageInfo,
            ProtocolConfigAttr, ProtocolConfigFeatureFlag, ProtocolConfigs, ServiceConfig,
            TransactionBlockKindInput, ValidatorCredentials,
        },
    },
    types::{Digest, Identifier, StructTag},
};

use crate::types::{
    address::Address,
    object::ObjectId,
    transaction::{SignedTransaction, TransactionEffects},
    type_tag::TypeTag,
};

#[derive(uniffi::Record)]
pub struct TransactionMetadata {
    #[uniffi(default = None)]
    pub gas_budget: Option<u64>,
    #[uniffi(default = None)]
    pub gas_objects: Option<Vec<ObjectRef>>,
    #[uniffi(default = None)]
    pub gas_price: Option<u64>,
    #[uniffi(default = None)]
    pub gas_sponsor: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub sender: Option<Arc<Address>>,
}

impl From<iota_sdk::graphql_client::query_types::TransactionMetadata> for TransactionMetadata {
    fn from(value: iota_sdk::graphql_client::query_types::TransactionMetadata) -> Self {
        Self {
            gas_budget: value.gas_budget,
            gas_objects: value
                .gas_objects
                .map(|v| v.into_iter().map(Into::into).collect()),
            gas_price: value.gas_price,
            gas_sponsor: value.gas_sponsor.map(Into::into).map(Arc::new),
            sender: value.sender.map(Into::into).map(Arc::new),
        }
    }
}

impl From<TransactionMetadata> for iota_sdk::graphql_client::query_types::TransactionMetadata {
    fn from(value: TransactionMetadata) -> Self {
        Self {
            gas_budget: value.gas_budget,
            gas_objects: value
                .gas_objects
                .map(|v| v.into_iter().map(Into::into).collect()),
            gas_price: value.gas_price,
            gas_sponsor: value.gas_sponsor.map(|a| **a),
            sender: value.sender.map(|a| **a),
        }
    }
}

#[derive(uniffi::Record)]
pub struct TransactionDataEffects {
    pub tx: SignedTransaction,
    pub effects: Arc<TransactionEffects>,
}

impl From<iota_sdk::graphql_client::TransactionDataEffects> for TransactionDataEffects {
    fn from(value: iota_sdk::graphql_client::TransactionDataEffects) -> Self {
        Self {
            tx: value.tx.into(),
            effects: Arc::new(value.effects.into()),
        }
    }
}

impl From<TransactionDataEffects> for iota_sdk::graphql_client::TransactionDataEffects {
    fn from(value: TransactionDataEffects) -> Self {
        Self {
            tx: value.tx.into(),
            effects: value.effects.0.clone(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct TransactionsFilter {
    #[uniffi(default = None)]
    pub function: Option<String>,
    #[uniffi(default = None)]
    pub kind: Option<TransactionBlockKindInput>,
    #[uniffi(default = None)]
    pub after_checkpoint: Option<u64>,
    #[uniffi(default = None)]
    pub at_checkpoint: Option<u64>,
    #[uniffi(default = None)]
    pub before_checkpoint: Option<u64>,
    #[uniffi(default = None)]
    pub sign_address: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub recv_address: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub input_object: Option<Arc<ObjectId>>,
    #[uniffi(default = None)]
    pub changed_object: Option<Arc<ObjectId>>,
    #[uniffi(default = None)]
    pub transaction_ids: Option<Vec<String>>,
    #[uniffi(default = None)]
    pub wrapped_or_deleted_object: Option<Arc<ObjectId>>,
}

impl From<iota_sdk::graphql_client::query_types::TransactionsFilter> for TransactionsFilter {
    fn from(value: iota_sdk::graphql_client::query_types::TransactionsFilter) -> Self {
        Self {
            function: value.function,
            kind: value.kind,
            after_checkpoint: value.after_checkpoint,
            at_checkpoint: value.at_checkpoint,
            before_checkpoint: value.before_checkpoint,
            sign_address: value.sign_address.map(Into::into).map(Arc::new),
            recv_address: value.recv_address.map(Into::into).map(Arc::new),
            input_object: value.input_object.map(Into::into).map(Arc::new),
            changed_object: value.changed_object.map(Into::into).map(Arc::new),
            transaction_ids: value.transaction_ids,
            wrapped_or_deleted_object: value
                .wrapped_or_deleted_object
                .map(Into::into)
                .map(Arc::new),
        }
    }
}

impl From<TransactionsFilter> for iota_sdk::graphql_client::query_types::TransactionsFilter {
    fn from(value: TransactionsFilter) -> Self {
        Self {
            function: value.function,
            kind: value.kind,
            after_checkpoint: value.after_checkpoint,
            at_checkpoint: value.at_checkpoint,
            before_checkpoint: value.before_checkpoint,
            sign_address: value.sign_address.map(|v| **v),
            recv_address: value.recv_address.map(|v| **v),
            input_object: value.input_object.map(|v| **v),
            changed_object: value.changed_object.map(|v| **v),
            transaction_ids: value.transaction_ids,
            wrapped_or_deleted_object: value.wrapped_or_deleted_object.map(|v| **v),
        }
    }
}

#[derive(uniffi::Record)]
pub struct ObjectRef {
    pub address: Arc<ObjectId>,
    pub digest: String,
    pub version: u64,
}

impl From<iota_sdk::graphql_client::query_types::ObjectRef> for ObjectRef {
    fn from(value: iota_sdk::graphql_client::query_types::ObjectRef) -> Self {
        Self {
            address: Arc::new(value.address.into()),
            digest: value.digest.to_string(),
            version: value.version,
        }
    }
}

impl From<ObjectRef> for iota_sdk::graphql_client::query_types::ObjectRef {
    fn from(value: ObjectRef) -> Self {
        Self {
            address: (**value.address),
            digest: value.digest,
            version: value.version,
        }
    }
}

#[derive(uniffi::Record)]
pub struct Epoch {
    /// The epoch's id as a sequence number that starts at 0 and is incremented
    /// by one at every epoch change.
    pub epoch_id: u64,
    /// The storage fees paid for transactions executed during the epoch.
    #[uniffi(default = None)]
    pub fund_inflow: Option<String>,
    /// The storage fee rebates paid to users who deleted the data associated
    /// with past transactions.
    #[uniffi(default = None)]
    pub fund_outflow: Option<String>,
    /// The storage fund available in this epoch.
    /// This fund is used to redistribute storage fees from past transactions
    /// to future validators.
    #[uniffi(default = None)]
    pub fund_size: Option<String>,
    /// A commitment by the committee at the end of epoch on the contents of the
    /// live object set at that time. This can be used to verify state
    /// snapshots.
    #[uniffi(default = None)]
    pub live_object_set_digest: Option<String>,
    /// The difference between the fund inflow and outflow, representing
    /// the net amount of storage fees accumulated in this epoch.
    #[uniffi(default = None)]
    pub net_inflow: Option<String>,
    /// The epoch's corresponding protocol configuration, including the feature
    /// flags and the configuration options.
    #[uniffi(default = None)]
    pub protocol_configs: Option<ProtocolConfigs>,
    /// The minimum gas price that a quorum of validators are guaranteed to sign
    /// a transaction for.
    #[uniffi(default = None)]
    pub reference_gas_price: Option<String>,
    /// The epoch's starting timestamp.
    pub start_timestamp: u64,
    /// The epoch's ending timestamp. Note that this is available only on epochs
    /// that have ended.
    #[uniffi(default = None)]
    pub end_timestamp: Option<u64>,
    /// The value of the `version` field of `0x5`, the
    /// `0x3::iota::IotaSystemState` object.  This version changes whenever
    /// the fields contained in the system state object (held in a dynamic
    /// field attached to `0x5`) change.
    #[uniffi(default = None)]
    pub system_state_version: Option<u64>,
    /// The total number of checkpoints in this epoch.
    #[uniffi(default = None)]
    pub total_checkpoints: Option<u64>,
    /// The total amount of gas fees (in IOTA) that were paid in this epoch.
    #[uniffi(default = None)]
    pub total_gas_fees: Option<String>,
    /// The total IOTA rewarded as stake.
    #[uniffi(default = None)]
    pub total_stake_rewards: Option<String>,
    /// The total number of transaction in this epoch.
    #[uniffi(default = None)]
    pub total_transactions: Option<u64>,
    /// Validator related properties. For active validators, see
    /// `active_validators` API.
    /// For epochs other than the current the data provided refer to the start
    /// of the epoch.
    #[uniffi(default = None)]
    pub validator_set: Option<ValidatorSet>,
}

impl From<iota_sdk::graphql_client::query_types::Epoch> for Epoch {
    fn from(value: iota_sdk::graphql_client::query_types::Epoch) -> Self {
        Self {
            epoch_id: value.epoch_id,
            fund_inflow: value.fund_inflow.map(|v| v.0),
            fund_outflow: value.fund_outflow.map(|v| v.0),
            fund_size: value.fund_size.map(|v| v.0),
            live_object_set_digest: value.live_object_set_digest,
            net_inflow: value.net_inflow.map(|v| v.0),
            protocol_configs: value.protocol_configs,
            reference_gas_price: value.reference_gas_price.map(|v| v.0),
            start_timestamp: value.start_timestamp.0.parse().unwrap_or(0),
            end_timestamp: value.end_timestamp.map(|dt| dt.0.parse().unwrap_or(0)),
            system_state_version: value.system_state_version,
            total_checkpoints: value.total_checkpoints,
            total_gas_fees: value.total_gas_fees.map(|v| v.0),
            total_stake_rewards: value.total_stake_rewards.map(|v| v.0),
            total_transactions: value.total_transactions,
            validator_set: value.validator_set.map(|vs| ValidatorSet {
                inactive_pools_id: vs.inactive_pools_id.map(Into::into).map(Arc::new),
                inactive_pools_size: vs.inactive_pools_size,
                pending_active_validators_id: vs
                    .pending_active_validators_id
                    .map(Into::into)
                    .map(Arc::new),
                pending_active_validators_size: vs.pending_active_validators_size,
                pending_removals: vs.pending_removals,
                staking_pool_mappings_id: vs.staking_pool_mappings_id.map(Into::into).map(Arc::new),
                staking_pool_mappings_size: vs.staking_pool_mappings_size,
                total_stake: vs.total_stake.map(|v| v.0),
                validator_candidates_size: vs.validator_candidates_size,
                validator_candidates_id: vs.validator_candidates_id.map(Into::into).map(Arc::new),
            }),
        }
    }
}

impl From<Epoch> for iota_sdk::graphql_client::query_types::Epoch {
    fn from(value: Epoch) -> Self {
        Self {
            epoch_id: value.epoch_id,
            fund_inflow: value.fund_inflow.map(|v| v.into()),
            fund_outflow: value.fund_outflow.map(|v| v.into()),
            fund_size: value.fund_size.map(|v| v.into()),
            live_object_set_digest: value.live_object_set_digest,
            net_inflow: value.net_inflow.map(|v| v.into()),
            protocol_configs: value.protocol_configs,
            reference_gas_price: value.reference_gas_price.map(|v| v.into()),
            start_timestamp: iota_sdk::graphql_client::query_types::DateTime(
                value.start_timestamp.to_string(),
            ),
            end_timestamp: value
                .end_timestamp
                .map(|ts| iota_sdk::graphql_client::query_types::DateTime(ts.to_string())),
            system_state_version: value.system_state_version,
            total_checkpoints: value.total_checkpoints,
            total_gas_fees: value.total_gas_fees.map(|v| v.into()),
            total_stake_rewards: value.total_stake_rewards.map(|v| v.into()),
            total_transactions: value.total_transactions,
            validator_set: value.validator_set.map(Into::into),
        }
    }
}

#[derive(uniffi::Record)]
pub struct ValidatorSet {
    /// Object ID of the `Table` storing the inactive staking pools.
    #[uniffi(default = None)]
    pub inactive_pools_id: Option<Arc<ObjectId>>,
    /// Size of the inactive pools `Table`.
    #[uniffi(default = None)]
    pub inactive_pools_size: Option<i32>,
    /// Object ID of the wrapped object `TableVec` storing the pending active
    /// validators.
    #[uniffi(default = None)]
    pub pending_active_validators_id: Option<Arc<ObjectId>>,
    /// Size of the pending active validators table.
    #[uniffi(default = None)]
    pub pending_active_validators_size: Option<i32>,
    /// Validators that are pending removal from the active validator set,
    /// expressed as indices in to `activeValidators`.
    #[uniffi(default = None)]
    pub pending_removals: Option<Vec<i32>>,
    /// Object ID of the `Table` storing the mapping from staking pool ids to
    /// the addresses of the corresponding validators. This is needed
    /// because a validator's address can potentially change but the object
    /// ID of its pool will not.
    #[uniffi(default = None)]
    pub staking_pool_mappings_id: Option<Arc<ObjectId>>,
    /// Size of the stake pool mappings `Table`.
    #[uniffi(default = None)]
    pub staking_pool_mappings_size: Option<i32>,
    /// Total amount of stake for all active validators at the beginning of the
    /// epoch.
    #[uniffi(default = None)]
    pub total_stake: Option<String>,
    /// Size of the validator candidates `Table`.
    #[uniffi(default = None)]
    pub validator_candidates_size: Option<i32>,
    /// Object ID of the `Table` storing the validator candidates.
    #[uniffi(default = None)]
    pub validator_candidates_id: Option<Arc<ObjectId>>,
}

impl From<iota_sdk::graphql_client::query_types::ValidatorSet> for ValidatorSet {
    fn from(value: iota_sdk::graphql_client::query_types::ValidatorSet) -> Self {
        Self {
            inactive_pools_id: value.inactive_pools_id.map(Into::into).map(Arc::new),
            inactive_pools_size: value.inactive_pools_size,
            pending_active_validators_id: value
                .pending_active_validators_id
                .map(Into::into)
                .map(Arc::new),
            pending_active_validators_size: value.pending_active_validators_size,
            pending_removals: value.pending_removals,
            staking_pool_mappings_id: value.staking_pool_mappings_id.map(Into::into).map(Arc::new),
            staking_pool_mappings_size: value.staking_pool_mappings_size,
            total_stake: value.total_stake.map(|v| v.0),
            validator_candidates_size: value.validator_candidates_size,
            validator_candidates_id: value.validator_candidates_id.map(Into::into).map(Arc::new),
        }
    }
}

impl From<ValidatorSet> for iota_sdk::graphql_client::query_types::ValidatorSet {
    fn from(value: ValidatorSet) -> Self {
        Self {
            inactive_pools_id: value.inactive_pools_id.map(|v| **v),
            inactive_pools_size: value.inactive_pools_size,
            pending_active_validators_id: value.pending_active_validators_id.map(|v| **v),
            pending_active_validators_size: value.pending_active_validators_size,
            pending_removals: value.pending_removals,
            staking_pool_mappings_id: value.staking_pool_mappings_id.map(|v| **v),
            staking_pool_mappings_size: value.staking_pool_mappings_size,
            total_stake: value.total_stake.map(|v| v.into()),
            validator_candidates_size: value.validator_candidates_size,
            validator_candidates_id: value.validator_candidates_id.map(|v| **v),
        }
    }
}

#[derive(uniffi::Record)]
pub struct EventFilter {
    #[uniffi(default = None)]
    pub emitting_module: Option<String>,
    #[uniffi(default = None)]
    pub event_type: Option<String>,
    #[uniffi(default = None)]
    pub sender: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub transaction_digest: Option<String>,
}

impl From<iota_sdk::graphql_client::query_types::EventFilter> for EventFilter {
    fn from(value: iota_sdk::graphql_client::query_types::EventFilter) -> Self {
        Self {
            emitting_module: value.emitting_module,
            event_type: value.event_type,
            sender: value.sender.map(Into::into).map(Arc::new),
            transaction_digest: value.transaction_digest,
        }
    }
}

impl From<EventFilter> for iota_sdk::graphql_client::query_types::EventFilter {
    fn from(value: EventFilter) -> Self {
        Self {
            emitting_module: value.emitting_module,
            event_type: value.event_type,
            sender: value.sender.map(|a| **a),
            transaction_digest: value.transaction_digest,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ObjectFilter {
    #[uniffi(default = None)]
    pub type_tag: Option<String>,
    #[uniffi(default = None)]
    pub owner: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub object_ids: Option<Vec<Arc<ObjectId>>>,
}

impl From<iota_sdk::graphql_client::query_types::ObjectFilter> for ObjectFilter {
    fn from(value: iota_sdk::graphql_client::query_types::ObjectFilter) -> Self {
        Self {
            type_tag: value.type_,
            owner: value.owner.map(Into::into).map(Arc::new),
            object_ids: value
                .object_ids
                .map(|v| v.into_iter().map(Into::into).map(Arc::new).collect()),
        }
    }
}

impl From<ObjectFilter> for iota_sdk::graphql_client::query_types::ObjectFilter {
    fn from(value: ObjectFilter) -> Self {
        Self {
            type_: value.type_tag,
            owner: value.owner.map(|v| **v),
            object_ids: value
                .object_ids
                .map(|v| v.into_iter().map(|v| **v).collect()),
        }
    }
}

/// The output of a dynamic field query, that includes the name, value, and
/// value's json representation.
#[derive(uniffi::Record)]
pub struct DynamicFieldOutput {
    /// The name of the dynamic field
    pub name: DynamicFieldName,
    /// The dynamic field value typename and bcs
    #[uniffi(default = None)]
    pub value: Option<DynamicFieldValue>,
    /// The json representation of the dynamic field value object
    #[uniffi(default = None)]
    pub value_as_json: Option<serde_json::Value>,
}

impl From<iota_sdk::graphql_client::DynamicFieldOutput> for DynamicFieldOutput {
    fn from(value: iota_sdk::graphql_client::DynamicFieldOutput) -> Self {
        Self {
            name: value.name.into(),
            value: value.value.map(Into::into),
            value_as_json: value.value_as_json,
        }
    }
}

impl From<DynamicFieldOutput> for iota_sdk::graphql_client::DynamicFieldOutput {
    fn from(value: DynamicFieldOutput) -> Self {
        Self {
            name: value.name.into(),
            value: value.value.map(Into::into),
            value_as_json: value.value_as_json,
        }
    }
}

/// The name part of a dynamic field, including its type, bcs, and json
/// representation.
#[derive(uniffi::Record)]
pub struct DynamicFieldName {
    /// The type name of this dynamic field name
    pub type_tag: Arc<TypeTag>,
    /// The bcs bytes of this dynamic field name
    pub bcs: Vec<u8>,
    /// The json representation of the dynamic field name
    #[uniffi(default = None)]
    pub json: Option<serde_json::Value>,
}

impl From<iota_sdk::graphql_client::DynamicFieldName> for DynamicFieldName {
    fn from(value: iota_sdk::graphql_client::DynamicFieldName) -> Self {
        Self {
            type_tag: Arc::new(value.type_.into()),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

impl From<DynamicFieldName> for iota_sdk::graphql_client::DynamicFieldName {
    fn from(value: DynamicFieldName) -> Self {
        Self {
            type_: value.type_tag.0.clone(),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

/// The value part of a dynamic field.
#[derive(uniffi::Record)]
pub struct DynamicFieldValue {
    pub type_tag: Arc<TypeTag>,
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DynamicFieldValue> for DynamicFieldValue {
    fn from(value: iota_sdk::graphql_client::DynamicFieldValue) -> Self {
        Self {
            type_tag: Arc::new(value.type_.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DynamicFieldValue> for iota_sdk::graphql_client::DynamicFieldValue {
    fn from(value: DynamicFieldValue) -> Self {
        Self {
            type_: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// Represents a validator in the system.
#[derive(uniffi::Record)]
pub struct Validator {
    /// The APY of this validator in basis points.
    /// To get the APY in percentage, divide by 100.
    #[uniffi(default = None)]
    pub apy: Option<i32>,
    /// The validator's address.
    pub address: Arc<Address>,
    /// The fee charged by the validator for staking services.
    #[uniffi(default = None)]
    pub commission_rate: Option<i32>,
    /// Validator's credentials.
    #[uniffi(default = None)]
    pub credentials: Option<ValidatorCredentials>,
    /// Validator's description.
    #[uniffi(default = None)]
    pub description: Option<String>,
    /// Number of exchange rates in the table.
    #[uniffi(default = None)]
    pub exchange_rates_size: Option<u64>,
    /// The reference gas price for this epoch.
    #[uniffi(default = None)]
    pub gas_price: Option<u64>,
    /// Validator's name.
    #[uniffi(default = None)]
    pub name: Option<String>,
    /// Validator's url containing their custom image.
    #[uniffi(default = None)]
    pub image_url: Option<String>,
    /// The proposed next epoch fee for the validator's staking services.
    #[uniffi(default = None)]
    pub next_epoch_commission_rate: Option<i32>,
    /// Validator's credentials for the next epoch.
    #[uniffi(default = None)]
    pub next_epoch_credentials: Option<ValidatorCredentials>,
    /// The validator's gas price quote for the next epoch.
    #[uniffi(default = None)]
    pub next_epoch_gas_price: Option<u64>,
    /// The total number of IOTA tokens in this pool plus
    /// the pending stake amount for this epoch.
    #[uniffi(default = None)]
    pub next_epoch_stake: Option<u64>,
    /// The validator's current valid `Cap` object. Validators can delegate
    /// the operation ability to another address. The address holding this `Cap`
    /// object can then update the reference gas price and tallying rule on
    /// behalf of the validator.
    #[uniffi(default = None)]
    pub operation_cap: Option<Vec<u8>>,
    /// Pending pool token withdrawn during the current epoch, emptied at epoch
    /// boundaries. Zero for past epochs.
    #[uniffi(default = None)]
    pub pending_pool_token_withdraw: Option<u64>,
    /// Pending stake amount for the current epoch, emptied at epoch boundaries.
    /// Zero for past epochs.
    #[uniffi(default = None)]
    pub pending_stake: Option<u64>,
    /// Pending stake withdrawn during the current epoch, emptied at epoch
    /// boundaries. Zero for past epochs.
    #[uniffi(default = None)]
    pub pending_total_iota_withdraw: Option<u64>,
    /// Total number of pool tokens issued by the pool.
    #[uniffi(default = None)]
    pub pool_token_balance: Option<u64>,
    /// Validator's homepage URL.
    #[uniffi(default = None)]
    pub project_url: Option<String>,
    /// The epoch stake rewards will be added here at the end of each epoch.
    #[uniffi(default = None)]
    pub rewards_pool: Option<u64>,
    /// The epoch at which this pool became active.
    #[uniffi(default = None)]
    pub staking_pool_activation_epoch: Option<u64>,
    /// The ID of this validator's `0x3::staking_pool::StakingPool`.
    pub staking_pool_id: Arc<ObjectId>,
    /// The total number of IOTA tokens in this pool.
    #[uniffi(default = None)]
    pub staking_pool_iota_balance: Option<u64>,
    /// The voting power of this validator in basis points (e.g., 100 = 1%
    /// voting power).
    #[uniffi(default = None)]
    pub voting_power: Option<i32>,
}

impl From<iota_sdk::graphql_client::query_types::Validator> for Validator {
    fn from(value: iota_sdk::graphql_client::query_types::Validator) -> Self {
        Self {
            apy: value.apy,
            address: Arc::new(value.address.address.into()),
            commission_rate: value.commission_rate,
            credentials: value.credentials,
            description: value.description,
            exchange_rates_size: value.exchange_rates_size,
            gas_price: value.gas_price.map(|v| v.0.parse().unwrap()),
            name: value.name,
            image_url: value.image_url,
            next_epoch_commission_rate: value.next_epoch_commission_rate,
            next_epoch_credentials: value.next_epoch_credentials,
            next_epoch_gas_price: value.next_epoch_gas_price.map(|v| v.0.parse().unwrap()),
            next_epoch_stake: value.next_epoch_stake.map(|v| v.0.parse().unwrap()),
            operation_cap: value
                .operation_cap
                .and_then(|o| o.bcs.map(|b| base64ct::Base64::decode_vec(&b.0).unwrap())),
            pending_pool_token_withdraw: value
                .pending_pool_token_withdraw
                .map(|v| v.0.parse().unwrap()),
            pending_stake: value.pending_stake.map(|v| v.0.parse().unwrap()),
            pending_total_iota_withdraw: value
                .pending_total_iota_withdraw
                .map(|v| v.0.parse().unwrap()),
            pool_token_balance: value.pool_token_balance.map(|v| v.0.parse().unwrap()),
            project_url: value.project_url,
            rewards_pool: value.rewards_pool.map(|v| v.0.parse().unwrap()),
            staking_pool_activation_epoch: value.staking_pool_activation_epoch,
            staking_pool_id: Arc::new(value.staking_pool_id.into()),
            staking_pool_iota_balance: value
                .staking_pool_iota_balance
                .map(|v| v.0.parse().unwrap()),
            voting_power: value.voting_power,
        }
    }
}

impl From<Validator> for iota_sdk::graphql_client::query_types::Validator {
    fn from(value: Validator) -> Self {
        Self {
            apy: value.apy,
            address: GQLAddress {
                address: value.address.clone(),
            }
            .into(),
            commission_rate: value.commission_rate,
            credentials: value.credentials,
            description: value.description,
            exchange_rates_size: value.exchange_rates_size,
            gas_price: value.gas_price.map(|v| v.to_string().into()),
            name: value.name,
            image_url: value.image_url,
            next_epoch_commission_rate: value.next_epoch_commission_rate,
            next_epoch_credentials: value.next_epoch_credentials,
            next_epoch_gas_price: value.next_epoch_gas_price.map(|v| v.to_string().into()),
            next_epoch_stake: value.next_epoch_stake.map(|v| v.to_string().into()),
            operation_cap: value.operation_cap.map(|o| MoveObject {
                bcs: Some(Base64(base64ct::Base64::encode_string(&o))),
            }),
            pending_pool_token_withdraw: value
                .pending_pool_token_withdraw
                .map(|v| v.to_string().into()),
            pending_stake: value.pending_stake.map(|v| v.to_string().into()),
            pending_total_iota_withdraw: value
                .pending_total_iota_withdraw
                .map(|v| v.to_string().into()),
            pool_token_balance: value.pool_token_balance.map(|v| v.to_string().into()),
            project_url: value.project_url,
            rewards_pool: value.rewards_pool.map(|v| v.to_string().into()),
            staking_pool_activation_epoch: value.staking_pool_activation_epoch,
            staking_pool_id: (**value.staking_pool_id),
            staking_pool_iota_balance: value
                .staking_pool_iota_balance
                .map(|v| v.to_string().into()),
            voting_power: value.voting_power,
        }
    }
}

/// The credentials related fields associated with a validator.
#[uniffi::remote(Record)]
pub struct ValidatorCredentials {
    #[uniffi(default = None)]
    pub authority_pub_key: Option<Base64>,
    #[uniffi(default = None)]
    pub network_pub_key: Option<Base64>,
    #[uniffi(default = None)]
    pub protocol_pub_key: Option<Base64>,
    #[uniffi(default = None)]
    pub proof_of_possession: Option<Base64>,
    #[uniffi(default = None)]
    pub net_address: Option<String>,
    #[uniffi(default = None)]
    pub p2p_address: Option<String>,
    #[uniffi(default = None)]
    pub primary_address: Option<String>,
}

#[uniffi::remote(Enum)]
pub enum TransactionBlockKindInput {
    SystemTx,
    ProgrammableTx,
    Genesis,
    ConsensusCommitPrologueV1,
    AuthenticatorStateUpdateV1,
    RandomnessStateUpdate,
    EndOfEpochTx,
}

/// Information about pagination in a connection.
#[uniffi::remote(Record)]
pub struct PageInfo {
    /// When paginating backwards, are there more items?
    pub has_previous_page: bool,
    /// Are there more items when paginating forwards?
    pub has_next_page: bool,
    /// When paginating backwards, the cursor to continue.
    #[uniffi(default = None)]
    pub start_cursor: Option<String>,
    /// When paginating forwards, the cursor to continue.
    #[uniffi(default = None)]
    pub end_cursor: Option<String>,
}

/// Pagination options for querying the GraphQL server. It defaults to forward
/// pagination with the GraphQL server's max page size.
#[uniffi::remote(Record)]
pub struct PaginationFilter {
    /// The direction of pagination.
    pub direction: Direction,
    /// An opaque cursor used for pagination.
    #[uniffi(default = None)]
    pub cursor: Option<String>,
    /// The maximum number of items to return. If this is omitted, it will
    /// lazily query the service configuration for the max page size.
    #[uniffi(default = None)]
    pub limit: Option<i32>,
}

/// Pagination direction.
#[uniffi::remote(Enum)]
pub enum Direction {
    #[default]
    Forward,
    Backward,
}

#[derive(uniffi::Record)]
pub struct ValidatorConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<Validator>,
}

impl From<iota_sdk::graphql_client::query_types::ValidatorConnection> for ValidatorConnection {
    fn from(value: iota_sdk::graphql_client::query_types::ValidatorConnection) -> Self {
        ValidatorConnection {
            page_info: value.page_info,
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ValidatorConnection> for iota_sdk::graphql_client::query_types::ValidatorConnection {
    fn from(value: ValidatorConnection) -> Self {
        iota_sdk::graphql_client::query_types::ValidatorConnection {
            page_info: value.page_info,
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct GQLAddress {
    pub address: Arc<Address>,
}

impl From<iota_sdk::graphql_client::query_types::GQLAddress> for GQLAddress {
    fn from(value: iota_sdk::graphql_client::query_types::GQLAddress) -> Self {
        GQLAddress {
            address: Arc::new(value.address.into()),
        }
    }
}

impl From<GQLAddress> for iota_sdk::graphql_client::query_types::GQLAddress {
    fn from(value: GQLAddress) -> Self {
        iota_sdk::graphql_client::query_types::GQLAddress {
            address: (**value.address),
        }
    }
}

#[uniffi::remote(Record)]
pub struct MoveObject {
    #[uniffi(default = None)]
    pub bcs: Option<Base64>,
}

/// Information about the configuration of the protocol.
/// Constants that control how the chain operates.
/// These can only change during protocol upgrades which happen on epoch
/// boundaries.
#[uniffi::remote(Record)]
pub struct ProtocolConfigs {
    /// The protocol is not required to change on every epoch boundary, so the
    /// protocol version tracks which change to the protocol these configs
    /// are from.
    pub protocol_version: u64,
    /// List all available feature flags and their values. Feature flags are a
    /// form of boolean configuration that are usually used to gate features
    /// while they are in development. Once a flag has been enabled, it is
    /// rare for it to be disabled.
    pub feature_flags: Vec<ProtocolConfigFeatureFlag>,
    /// List all available configurations and their values. These configurations
    /// can take any value (but they will all be represented in string
    /// form), and do not include feature flags.
    pub configs: Vec<ProtocolConfigAttr>,
}

/// Feature flags are a form of boolean configuration that are usually used to
/// gate features while they are in development. Once a lag has been enabled, it
/// is rare for it to be disabled.
#[uniffi::remote(Record)]
pub struct ProtocolConfigFeatureFlag {
    pub key: String,
    pub value: bool,
}

/// A key-value protocol configuration attribute.
#[uniffi::remote(Record)]
pub struct ProtocolConfigAttr {
    pub key: String,
    pub value: Option<String>,
}

/// The coin metadata associated with the given coin type.
#[derive(uniffi::Record)]
pub struct CoinMetadata {
    /// The CoinMetadata object ID.
    pub address: Arc<ObjectId>,
    /// The number of decimal places used to represent the token.
    #[uniffi(default = None)]
    pub decimals: Option<i32>,
    /// Optional description of the token, provided by the creator of the token.
    #[uniffi(default = None)]
    pub description: Option<String>,
    /// Icon URL of the coin.
    #[uniffi(default = None)]
    pub icon_url: Option<String>,
    /// Full, official name of the token.
    #[uniffi(default = None)]
    pub name: Option<String>,
    /// The token's identifying abbreviation.
    #[uniffi(default = None)]
    pub symbol: Option<String>,
    /// The overall quantity of tokens that will be issued.
    #[uniffi(default = None)]
    pub supply: Option<BigInt>,
    /// Version of the token.
    pub version: u64,
}

impl From<iota_sdk::graphql_client::query_types::CoinMetadata> for CoinMetadata {
    fn from(value: iota_sdk::graphql_client::query_types::CoinMetadata) -> Self {
        Self {
            address: Arc::new(value.address.into()),
            decimals: value.decimals,
            description: value.description,
            icon_url: value.icon_url,
            name: value.name,
            symbol: value.symbol,
            supply: value.supply,
            version: value.version,
        }
    }
}

impl From<CoinMetadata> for iota_sdk::graphql_client::query_types::CoinMetadata {
    fn from(value: CoinMetadata) -> Self {
        Self {
            address: **value.address,
            decimals: value.decimals,
            description: value.description,
            icon_url: value.icon_url,
            name: value.name,
            symbol: value.symbol,
            supply: value.supply,
            version: value.version,
        }
    }
}

#[derive(derive_more::From, derive_more::Display, uniffi::Object)]
#[uniffi::export(Display)]
pub struct MoveFunction(iota_sdk::graphql_client::query_types::MoveFunction);

#[uniffi::export]
impl MoveFunction {
    pub fn is_entry(&self) -> bool {
        self.0.is_entry.is_some_and(|v| v)
    }

    pub fn name(&self) -> String {
        self.0.name.clone()
    }

    pub fn parameters(&self) -> Option<Vec<OpenMoveType>> {
        self.0.parameters.clone()
    }

    pub fn return_type(&self) -> Option<Vec<OpenMoveType>> {
        self.0.return_.clone()
    }

    pub fn type_parameters(&self) -> Option<Vec<MoveFunctionTypeParameter>> {
        self.0.type_parameters.clone()
    }

    pub fn visibility(&self) -> Option<MoveVisibility> {
        self.0.visibility
    }
}

#[uniffi::remote(Enum)]
pub enum MoveVisibility {
    Public,
    Private,
    Friend,
}

#[uniffi::remote(Enum)]
pub enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

#[uniffi::remote(Record)]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

#[uniffi::remote(Record)]
pub struct OpenMoveType {
    pub repr: String,
}

#[derive(uniffi::Record)]
pub struct MoveModule {
    pub file_format_version: i32,
    #[uniffi(default = None)]
    pub enums: Option<MoveEnumConnection>,
    pub friends: MoveModuleConnection,
    #[uniffi(default = None)]
    pub functions: Option<MoveFunctionConnection>,
    #[uniffi(default = None)]
    pub structs: Option<MoveStructConnection>,
}

impl From<iota_sdk::graphql_client::query_types::MoveModule> for MoveModule {
    fn from(value: iota_sdk::graphql_client::query_types::MoveModule) -> Self {
        Self {
            file_format_version: value.file_format_version,
            enums: value.enums,
            friends: value.friends.into(),
            functions: value.functions.map(Into::into),
            structs: value.structs,
        }
    }
}

impl From<MoveModule> for iota_sdk::graphql_client::query_types::MoveModule {
    fn from(value: MoveModule) -> Self {
        Self {
            file_format_version: value.file_format_version,
            enums: value.enums,
            friends: value.friends.into(),
            functions: value.functions.map(Into::into),
            structs: value.structs,
        }
    }
}

#[derive(uniffi::Record)]
pub struct MoveModuleConnection {
    pub nodes: Vec<MoveModuleQuery>,
    pub page_info: PageInfo,
}

impl From<iota_sdk::graphql_client::query_types::MoveModuleConnection> for MoveModuleConnection {
    fn from(value: iota_sdk::graphql_client::query_types::MoveModuleConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info,
        }
    }
}

impl From<MoveModuleConnection> for iota_sdk::graphql_client::query_types::MoveModuleConnection {
    fn from(value: MoveModuleConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info,
        }
    }
}

#[derive(uniffi::Record)]
pub struct MovePackageQuery {
    pub address: Arc<Address>,
    #[uniffi(default = None)]
    pub bcs: Option<Base64>,
}

impl From<iota_sdk::graphql_client::query_types::MovePackageQuery> for MovePackageQuery {
    fn from(value: iota_sdk::graphql_client::query_types::MovePackageQuery) -> Self {
        Self {
            address: Arc::new(value.address.into()),
            bcs: value.bcs,
        }
    }
}

impl From<MovePackageQuery> for iota_sdk::graphql_client::query_types::MovePackageQuery {
    fn from(value: MovePackageQuery) -> Self {
        Self {
            address: (**value.address),
            bcs: value.bcs,
        }
    }
}

#[derive(uniffi::Record)]
pub struct MoveModuleQuery {
    pub package: MovePackageQuery,
    pub name: String,
}

impl From<iota_sdk::graphql_client::query_types::MoveModuleQuery> for MoveModuleQuery {
    fn from(value: iota_sdk::graphql_client::query_types::MoveModuleQuery) -> Self {
        Self {
            package: value.package.into(),
            name: value.name,
        }
    }
}

impl From<MoveModuleQuery> for iota_sdk::graphql_client::query_types::MoveModuleQuery {
    fn from(value: MoveModuleQuery) -> Self {
        Self {
            package: value.package.into(),
            name: value.name,
        }
    }
}

#[uniffi::remote(Record)]
pub struct MoveStructTypeParameter {
    pub constraints: Vec<MoveAbility>,
    pub is_phantom: bool,
}

#[uniffi::remote(Record)]
pub struct MoveField {
    pub name: String,
    #[uniffi::field(name = "type")]
    #[uniffi(default = None)]
    pub type_: Option<OpenMoveType>,
}

#[uniffi::remote(Record)]
pub struct MoveStructQuery {
    #[uniffi(default = None)]
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    #[uniffi(default = None)]
    pub fields: Option<Vec<MoveField>>,
    #[uniffi(default = None)]
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
}

#[uniffi::remote(Record)]
pub struct MoveStructConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<MoveStructQuery>,
}

#[derive(uniffi::Record)]
pub struct MoveFunctionConnection {
    pub nodes: Vec<Arc<MoveFunction>>,
    pub page_info: PageInfo,
}

impl From<iota_sdk::graphql_client::query_types::MoveFunctionConnection>
    for MoveFunctionConnection
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveFunctionConnection) -> Self {
        Self {
            nodes: value
                .nodes
                .iter()
                .cloned()
                .map(Into::into)
                .map(Arc::new)
                .collect(),
            page_info: value.page_info,
        }
    }
}

impl From<MoveFunctionConnection>
    for iota_sdk::graphql_client::query_types::MoveFunctionConnection
{
    fn from(value: MoveFunctionConnection) -> Self {
        Self {
            nodes: value.nodes.iter().map(|v| v.0.clone()).collect(),
            page_info: value.page_info,
        }
    }
}

#[uniffi::remote(Record)]
pub struct MoveEnumConnection {
    pub nodes: Vec<MoveEnum>,
    pub page_info: PageInfo,
}

#[uniffi::remote(Record)]
pub struct MoveEnumVariant {
    #[uniffi(default = None)]
    pub fields: Option<Vec<MoveField>>,
    pub name: String,
}

#[uniffi::remote(Record)]
pub struct MoveEnum {
    #[uniffi(default = None)]
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    #[uniffi(default = None)]
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
    #[uniffi(default = None)]
    pub variants: Option<Vec<MoveEnumVariant>>,
}

// Information about the configuration of the GraphQL service.
#[uniffi::remote(Record)]
pub struct ServiceConfig {
    /// Default number of elements allowed on a single page of a connection.
    pub default_page_size: i32,
    /// List of all features that are enabled on this RPC service.
    pub enabled_features: Vec<Feature>,
    // TODO This field is retrieved as a string, instead of i32
    /// Maximum estimated cost of a database query used to serve a GraphQL
    /// request.  This is measured in the same units that the database uses
    /// in EXPLAIN queries.
    // pub max_db_query_cost: i32,
    /// Maximum nesting allowed in struct fields when calculating the layout of
    /// a single Move Type.
    pub max_move_value_depth: i32,
    /// The maximum number of output nodes in a GraphQL response.
    /// Non-connection nodes have a count of 1, while connection nodes are
    /// counted as the specified 'first' or 'last' number of items, or the
    /// default_page_size as set by the server if those arguments are not
    /// set. Counts accumulate multiplicatively down the query tree. For
    /// example, if a query starts with a connection of first: 10 and has a
    /// field to a connection with last: 20, the count at the second level
    /// would be 200 nodes. This is then summed to the count of 10 nodes
    /// at the first level, for a total of 210 nodes.
    pub max_output_nodes: i32,
    /// Maximum number of elements allowed on a single page of a connection.
    pub max_page_size: i32,
    /// The maximum depth a GraphQL query can be to be accepted by this service.
    pub max_query_depth: i32,
    /// The maximum number of nodes (field names) the service will accept in a
    /// single query.
    pub max_query_nodes: i32,
    /// Maximum length of a query payload string.
    pub max_query_payload_size: i32,
    /// Maximum nesting allowed in type arguments in Move Types resolved by this
    /// service.
    pub max_type_argument_depth: i32,
    /// Maximum number of type arguments passed into a generic instantiation of
    /// a Move Type resolved by this service.
    pub max_type_argument_width: i32,
    /// Maximum number of structs that need to be processed when calculating the
    /// layout of a single Move Type.
    pub max_type_nodes: i32,
    /// Maximum time in milliseconds spent waiting for a response from fullnode
    /// after issuing a a transaction to execute. Note that the transaction
    /// may still succeed even in the case of a timeout. Transactions are
    /// idempotent, so a transaction that times out should be resubmitted
    /// until the network returns a definite response (success or failure, not
    /// timeout).
    pub mutation_timeout_ms: i32,
    /// Maximum time in milliseconds that will be spent to serve one query
    /// request.
    pub request_timeout_ms: i32,
}

#[uniffi::remote(Enum)]
pub enum Feature {
    Analytics,
    Coins,
    DynamicFields,
    Subscriptions,
    SystemState,
}
