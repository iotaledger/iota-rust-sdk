// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use base64ct::Encoding;
use iota_graphql_client::{
    pagination::{Direction, PaginationFilter},
    query_types::{
        Base64, GQLAddress, MoveObject, PageInfo, TransactionBlockKindInput, ValidatorCredentials,
    },
};

use crate::types::{
    address::Address,
    object::ObjectId,
    transaction::{SignedTransaction, TransactionEffects},
    type_tag::TypeTag,
};

#[derive(Clone, Debug, uniffi::Record)]
pub struct TransactionMetadata {
    #[uniffi(default = None)]
    pub gas_budget: Option<u64>,
    #[uniffi(default = None)]
    pub gas_objects: Option<Vec<Arc<ObjectRef>>>,
    #[uniffi(default = None)]
    pub gas_price: Option<u64>,
    #[uniffi(default = None)]
    pub gas_sponsor: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub sender: Option<Arc<Address>>,
}

impl From<iota_graphql_client::query_types::TransactionMetadata> for TransactionMetadata {
    fn from(value: iota_graphql_client::query_types::TransactionMetadata) -> Self {
        Self {
            gas_budget: value.gas_budget,
            gas_objects: value
                .gas_objects
                .map(|v| v.into_iter().map(Into::into).map(Arc::new).collect()),
            gas_price: value.gas_price,
            gas_sponsor: value.gas_sponsor.map(Into::into).map(Arc::new),
            sender: value.sender.map(Into::into).map(Arc::new),
        }
    }
}

impl From<TransactionMetadata> for iota_graphql_client::query_types::TransactionMetadata {
    fn from(value: TransactionMetadata) -> Self {
        Self {
            gas_budget: value.gas_budget,
            gas_objects: value
                .gas_objects
                .map(|v| v.into_iter().map(|o| o.0.clone()).collect()),
            gas_price: value.gas_price,
            gas_sponsor: value.gas_sponsor.map(|a| **a),
            sender: value.sender.map(|a| **a),
        }
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionDataEffects(pub iota_graphql_client::TransactionDataEffects);

#[uniffi::export]
impl TransactionDataEffects {
    #[uniffi::constructor]
    pub fn new(tx: &SignedTransaction, effects: &TransactionEffects) -> Self {
        Self(iota_graphql_client::TransactionDataEffects {
            tx: tx.0.clone(),
            effects: effects.0.clone(),
        })
    }

    pub fn tx(&self) -> SignedTransaction {
        self.0.tx.clone().into()
    }

    pub fn effects(&self) -> TransactionEffects {
        self.0.effects.clone().into()
    }
}

#[derive(Clone, Debug, uniffi::Record)]
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

impl From<iota_graphql_client::query_types::TransactionsFilter> for TransactionsFilter {
    fn from(value: iota_graphql_client::query_types::TransactionsFilter) -> Self {
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

impl From<TransactionsFilter> for iota_graphql_client::query_types::TransactionsFilter {
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

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct DryRunResult(pub iota_graphql_client::DryRunResult);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Event(pub iota_types::Event);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectRef(pub iota_graphql_client::query_types::ObjectRef);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Epoch(pub iota_graphql_client::query_types::Epoch);

#[derive(Clone, Debug, uniffi::Record)]
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

impl From<iota_graphql_client::query_types::EventFilter> for EventFilter {
    fn from(value: iota_graphql_client::query_types::EventFilter) -> Self {
        Self {
            emitting_module: value.emitting_module,
            event_type: value.event_type,
            sender: value.sender.map(Into::into).map(Arc::new),
            transaction_digest: value.transaction_digest,
        }
    }
}

impl From<EventFilter> for iota_graphql_client::query_types::EventFilter {
    fn from(value: EventFilter) -> Self {
        Self {
            emitting_module: value.emitting_module,
            event_type: value.event_type,
            sender: value.sender.map(|a| **a),
            transaction_digest: value.transaction_digest,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ObjectFilter {
    pub type_tag: Option<String>,
    pub owner: Option<Arc<Address>>,
    pub object_ids: Option<Vec<Arc<ObjectId>>>,
}

impl From<iota_graphql_client::query_types::ObjectFilter> for ObjectFilter {
    fn from(value: iota_graphql_client::query_types::ObjectFilter) -> Self {
        Self {
            type_tag: value.type_,
            owner: value.owner.map(Into::into).map(Arc::new),
            object_ids: value
                .object_ids
                .map(|v| v.into_iter().map(Into::into).map(Arc::new).collect()),
        }
    }
}

impl From<ObjectFilter> for iota_graphql_client::query_types::ObjectFilter {
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
#[derive(Clone, Debug, uniffi::Record)]
pub struct DynamicFieldOutput {
    /// The name of the dynamic field
    pub name: DynamicFieldName,
    /// The dynamic field value typename and bcs
    pub value: Option<DynamicFieldValue>,
    /// The json representation of the dynamic field value object
    pub value_as_json: Option<serde_json::Value>,
}

impl From<iota_graphql_client::DynamicFieldOutput> for DynamicFieldOutput {
    fn from(value: iota_graphql_client::DynamicFieldOutput) -> Self {
        Self {
            name: value.name.into(),
            value: value.value.map(Into::into),
            value_as_json: value.value_as_json,
        }
    }
}

impl From<DynamicFieldOutput> for iota_graphql_client::DynamicFieldOutput {
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
#[derive(Clone, Debug, uniffi::Record)]
pub struct DynamicFieldName {
    /// The type name of this dynamic field name
    pub type_tag: Arc<TypeTag>,
    /// The bcs bytes of this dynamic field name
    pub bcs: Vec<u8>,
    /// The json representation of the dynamic field name
    pub json: Option<serde_json::Value>,
}

impl From<iota_graphql_client::DynamicFieldName> for DynamicFieldName {
    fn from(value: iota_graphql_client::DynamicFieldName) -> Self {
        Self {
            type_tag: Arc::new(value.type_.into()),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

impl From<DynamicFieldName> for iota_graphql_client::DynamicFieldName {
    fn from(value: DynamicFieldName) -> Self {
        Self {
            type_: value.type_tag.0.clone(),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

/// The value part of a dynamic field.
#[derive(Clone, Debug, uniffi::Record)]
pub struct DynamicFieldValue {
    pub type_tag: Arc<TypeTag>,
    pub bcs: Vec<u8>,
}

impl From<iota_graphql_client::DynamicFieldValue> for DynamicFieldValue {
    fn from(value: iota_graphql_client::DynamicFieldValue) -> Self {
        Self {
            type_tag: Arc::new(value.type_.into()),
            bcs: value.bcs,
        }
    }
}

impl From<DynamicFieldValue> for iota_graphql_client::DynamicFieldValue {
    fn from(value: DynamicFieldValue) -> Self {
        Self {
            type_: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// Represents a validator in the system.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Validator {
    /// The APY of this validator in basis points.
    /// To get the APY in percentage, divide by 100.
    pub apy: Option<i32>,
    /// The validator's address.
    pub address: Arc<Address>,
    /// The fee charged by the validator for staking services.
    pub commission_rate: Option<i32>,
    /// Validator's credentials.
    pub credentials: Option<ValidatorCredentials>,
    /// Validator's description.
    pub description: Option<String>,
    /// Number of exchange rates in the table.
    pub exchange_rates_size: Option<u64>,
    /// The reference gas price for this epoch.
    pub gas_price: Option<u64>,
    /// Validator's name.
    pub name: Option<String>,
    /// Validator's url containing their custom image.
    pub image_url: Option<String>,
    /// The proposed next epoch fee for the validator's staking services.
    pub next_epoch_commission_rate: Option<i32>,
    /// Validator's credentials for the next epoch.
    pub next_epoch_credentials: Option<ValidatorCredentials>,
    /// The validator's gas price quote for the next epoch.
    pub next_epoch_gas_price: Option<u64>,
    /// The total number of IOTA tokens in this pool plus
    /// the pending stake amount for this epoch.
    pub next_epoch_stake: Option<u64>,
    /// The validator's current valid `Cap` object. Validators can delegate
    /// the operation ability to another address. The address holding this `Cap`
    /// object can then update the reference gas price and tallying rule on
    /// behalf of the validator.
    pub operation_cap: Option<Vec<u8>>,
    /// Pending pool token withdrawn during the current epoch, emptied at epoch
    /// boundaries.
    pub pending_pool_token_withdraw: Option<u64>,
    /// Pending stake amount for this epoch.
    pub pending_stake: Option<u64>,
    /// Pending stake withdrawn during the current epoch, emptied at epoch
    /// boundaries.
    pub pending_total_iota_withdraw: Option<u64>,
    /// Total number of pool tokens issued by the pool.
    pub pool_token_balance: Option<u64>,
    /// Validator's homepage URL.
    pub project_url: Option<String>,
    /// The epoch stake rewards will be added here at the end of each epoch.
    pub rewards_pool: Option<u64>,
    /// The epoch at which this pool became active.
    pub staking_pool_activation_epoch: Option<u64>,
    /// The ID of this validator's `0x3::staking_pool::StakingPool`.
    pub staking_pool_id: Arc<ObjectId>,
    /// The total number of IOTA tokens in this pool.
    pub staking_pool_iota_balance: Option<u64>,
    /// The voting power of this validator in basis points (e.g., 100 = 1%
    /// voting power).
    pub voting_power: Option<i32>,
}

impl From<iota_graphql_client::query_types::Validator> for Validator {
    fn from(value: iota_graphql_client::query_types::Validator) -> Self {
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

impl From<Validator> for iota_graphql_client::query_types::Validator {
    fn from(value: Validator) -> Self {
        Self {
            apy: value.apy,
            address: GQLAddress {
                address: **value.address,
            },
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
                bcs: Some(base64ct::Base64::encode_string(&o).into()),
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
            staking_pool_id: **value.staking_pool_id,
            staking_pool_iota_balance: value
                .staking_pool_iota_balance
                .map(|v| v.to_string().into()),
            voting_power: value.voting_power,
        }
    }
}

#[uniffi::remote(Record)]
pub struct ValidatorCredentials {
    pub authority_pub_key: Option<Base64>,
    pub network_pub_key: Option<Base64>,
    pub protocol_pub_key: Option<Base64>,
    pub proof_of_possession: Option<Base64>,
    pub net_address: Option<String>,
    pub p2p_address: Option<String>,
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

#[uniffi::remote(Record)]
pub struct PageInfo {
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub start_cursor: Option<String>,
    pub end_cursor: Option<String>,
}

#[uniffi::remote(Record)]
pub struct PaginationFilter {
    pub direction: Direction,
    #[uniffi(default = None)]
    pub cursor: Option<String>,
    #[uniffi(default = None)]
    pub limit: Option<i32>,
}

#[uniffi::remote(Enum)]
pub enum Direction {
    #[default]
    Forward,
    Backward,
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ProtocolConfigs(pub iota_graphql_client::query_types::ProtocolConfigs);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct CoinMetadata(pub iota_graphql_client::query_types::CoinMetadata);

#[derive(Debug, derive_more::From, uniffi::Object)]
pub struct MoveFunction(pub iota_graphql_client::query_types::MoveFunction);

#[derive(Debug, derive_more::From, uniffi::Object)]
pub struct MoveModule(pub iota_graphql_client::query_types::MoveModule);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ServiceConfig(pub iota_graphql_client::query_types::ServiceConfig);
