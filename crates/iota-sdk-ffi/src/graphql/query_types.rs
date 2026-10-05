// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use base64ct::Encoding;
use iota_sdk::graphql_client::query_types::{
    AddressTransactionRelationship as SdkAddressTransactionRelationship, Base64, BigInt,
    TransactionBlockKindInput as SdkTransactionBlockKindInput,
};

use crate::{
    error::SdkFfiError,
    types::{
        address::Address,
        digest::TransactionDigest,
        move_core::TypeTag,
        object::ObjectId,
        transaction::{SignedTransaction, TransactionEffects},
    },
};

uniffi::custom_type!(Base64, String, {
    remote,
    lower: |val| val.0,
    try_lift: |s| Ok(Base64(s)),
});

#[derive(uniffi::Record)]
pub struct GraphQLTransactionMetadata {
    #[uniffi(default = None)]
    pub gas_budget: Option<u64>,
    #[uniffi(default = None)]
    pub gas_objects: Option<Vec<GraphQLObjectRef>>,
    #[uniffi(default = None)]
    pub gas_price: Option<u64>,
    #[uniffi(default = None)]
    pub gas_sponsor: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub sender: Option<Arc<Address>>,
}

impl From<iota_sdk::graphql_client::query_types::TransactionMetadata>
    for GraphQLTransactionMetadata
{
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

impl From<GraphQLTransactionMetadata>
    for iota_sdk::graphql_client::query_types::TransactionMetadata
{
    fn from(value: GraphQLTransactionMetadata) -> Self {
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
pub struct GraphQLTransactionDataEffects {
    pub signed_transaction: SignedTransaction,
    pub effects: Arc<TransactionEffects>,
}

impl From<iota_sdk::graphql_client::TransactionDataEffects> for GraphQLTransactionDataEffects {
    fn from(value: iota_sdk::graphql_client::TransactionDataEffects) -> Self {
        Self {
            signed_transaction: value.signed_transaction.into(),
            effects: Arc::new(value.effects.into()),
        }
    }
}

impl From<GraphQLTransactionDataEffects> for iota_sdk::graphql_client::TransactionDataEffects {
    fn from(value: GraphQLTransactionDataEffects) -> Self {
        Self {
            signed_transaction: value.signed_transaction.into(),
            effects: value.effects.0.clone(),
        }
    }
}

/// Filter for transaction queries.
///
/// Holds at most one of the function, kind, address and object filters that
/// the GraphQL service can only serve one of at a time, so each of those
/// setters replaces whichever was set before; the sender, checkpoint and
/// digest filters can be combined with them and with each other freely.
#[derive(Default, uniffi::Object)]
pub struct GraphQLTransactionsFilter(
    RwLock<iota_sdk::graphql_client::query_types::TransactionsFilter>,
);

impl GraphQLTransactionsFilter {
    fn update(
        &self,
        f: impl FnOnce(
            iota_sdk::graphql_client::query_types::TransactionsFilter,
        ) -> iota_sdk::graphql_client::query_types::TransactionsFilter,
    ) {
        let mut lock = self.0.write().expect("error writing to filter");
        *lock = f(std::mem::take(&mut *lock));
    }
}

impl From<&GraphQLTransactionsFilter>
    for iota_sdk::graphql_client::query_types::TransactionsFilter
{
    fn from(value: &GraphQLTransactionsFilter) -> Self {
        value.0.read().expect("error reading from filter").clone()
    }
}

#[uniffi::export]
impl GraphQLTransactionsFilter {
    /// Create a filter that selects on nothing.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self::default()
    }

    /// Select by package, module, or function name, e.g. `"0x03"`,
    /// `"0x03::iota_system"`, or `"0x03::iota_system::request_add_stake"`.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_function(self: Arc<Self>, function: String) -> Arc<Self> {
        self.update(|filter| filter.with_function(function));
        self
    }

    /// Select by transaction kind.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_kind(self: Arc<Self>, kind: GraphQLTransactionBlockKindInput) -> Arc<Self> {
        let kind = SdkTransactionBlockKindInput::from(kind);
        self.update(|filter| filter.with_kind(kind));
        self
    }

    /// Select transactions that sent an object to the given address.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_recv_address(self: Arc<Self>, recv_address: &Address) -> Arc<Self> {
        self.update(|filter| filter.with_recv_address(**recv_address));
        self
    }

    /// Select transactions that affected the given address.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_affected_address(self: Arc<Self>, affected_address: &Address) -> Arc<Self> {
        self.update(|filter| filter.with_affected_address(**affected_address));
        self
    }

    /// Select transactions that used the given object as an input.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_input_object(self: Arc<Self>, input_object: &ObjectId) -> Arc<Self> {
        self.update(|filter| filter.with_input_object(**input_object));
        self
    }

    /// Select transactions that output a version of the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_changed_object(self: Arc<Self>, changed_object: &ObjectId) -> Arc<Self> {
        self.update(|filter| filter.with_changed_object(**changed_object));
        self
    }

    /// Select transactions that wrapped or deleted the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_wrapped_or_deleted_object(
        self: Arc<Self>,
        wrapped_or_deleted_object: &ObjectId,
    ) -> Arc<Self> {
        self.update(|filter| filter.with_wrapped_or_deleted_object(**wrapped_or_deleted_object));
        self
    }

    /// Filter by sender address.
    pub fn with_sent_address(self: Arc<Self>, sent_address: &Address) -> Arc<Self> {
        self.update(|filter| filter.with_sent_address(**sent_address));
        self
    }

    /// Limit to transactions executed after the given checkpoint, exclusive.
    pub fn with_after_checkpoint(self: Arc<Self>, after_checkpoint: u64) -> Arc<Self> {
        self.update(|filter| filter.with_after_checkpoint(after_checkpoint));
        self
    }

    /// Limit to transactions executed in the given checkpoint.
    pub fn with_at_checkpoint(self: Arc<Self>, at_checkpoint: u64) -> Arc<Self> {
        self.update(|filter| filter.with_at_checkpoint(at_checkpoint));
        self
    }

    /// Limit to transactions executed before the given checkpoint, exclusive.
    pub fn with_before_checkpoint(self: Arc<Self>, before_checkpoint: u64) -> Arc<Self> {
        self.update(|filter| filter.with_before_checkpoint(before_checkpoint));
        self
    }

    /// Select by transaction digests.
    pub fn with_transaction_ids(
        self: Arc<Self>,
        transaction_ids: Vec<Arc<TransactionDigest>>,
    ) -> Arc<Self> {
        self.update(|filter| {
            filter.with_transaction_ids(transaction_ids.into_iter().map(|id| **id))
        });
        self
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLObjectRef {
    pub address: Arc<ObjectId>,
    pub digest: String,
    pub version: u64,
}

impl From<iota_sdk::graphql_client::query_types::ObjectRef> for GraphQLObjectRef {
    fn from(value: iota_sdk::graphql_client::query_types::ObjectRef) -> Self {
        Self {
            address: Arc::new(value.address.into()),
            digest: value.digest.to_string(),
            version: value.version,
        }
    }
}

impl From<GraphQLObjectRef> for iota_sdk::graphql_client::query_types::ObjectRef {
    fn from(value: GraphQLObjectRef) -> Self {
        Self {
            address: (**value.address),
            digest: value.digest,
            version: value.version,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLEpoch {
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
    /// The minimum gas price that a quorum of validators are guaranteed to sign
    /// a transaction for.
    #[uniffi(default = None)]
    pub reference_gas_price: Option<String>,
    /// The epoch's starting timestamp. RFC3339 in UTC with format:
    /// YYYY-MM-DDTHH:MM:SS.mmmZ
    pub start_timestamp: String,
    /// The epoch's ending timestamp. Note that this is available only on epochs
    /// that have ended. RFC3339 in UTC with format: YYYY-MM-DDTHH:MM:SS.mmmZ
    #[uniffi(default = None)]
    pub end_timestamp: Option<String>,
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
    pub validator_set: Option<GraphQLValidatorSet>,
}

impl From<iota_sdk::graphql_client::query_types::Epoch> for GraphQLEpoch {
    fn from(value: iota_sdk::graphql_client::query_types::Epoch) -> Self {
        Self {
            epoch_id: value.epoch_id,
            fund_inflow: value.fund_inflow.map(|v| v.0),
            fund_outflow: value.fund_outflow.map(|v| v.0),
            fund_size: value.fund_size.map(|v| v.0),
            live_object_set_digest: value.live_object_set_digest,
            net_inflow: value.net_inflow.map(|v| v.0),
            reference_gas_price: value.reference_gas_price.map(|v| v.0),
            start_timestamp: value.start_timestamp.0,
            end_timestamp: value.end_timestamp.map(|dt| dt.0),
            system_state_version: value.system_state_version,
            total_checkpoints: value.total_checkpoints,
            total_gas_fees: value.total_gas_fees.map(|v| v.0),
            total_stake_rewards: value.total_stake_rewards.map(|v| v.0),
            total_transactions: value.total_transactions,
            validator_set: value.validator_set.map(|vs| GraphQLValidatorSet {
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

impl From<GraphQLEpoch> for iota_sdk::graphql_client::query_types::Epoch {
    fn from(value: GraphQLEpoch) -> Self {
        Self {
            epoch_id: value.epoch_id,
            fund_inflow: value.fund_inflow.map(|v| v.into()),
            fund_outflow: value.fund_outflow.map(|v| v.into()),
            fund_size: value.fund_size.map(|v| v.into()),
            live_object_set_digest: value.live_object_set_digest,
            net_inflow: value.net_inflow.map(|v| v.into()),
            reference_gas_price: value.reference_gas_price.map(|v| v.into()),
            start_timestamp: iota_sdk::graphql_client::query_types::DateTime(value.start_timestamp),
            end_timestamp: value
                .end_timestamp
                .map(iota_sdk::graphql_client::query_types::DateTime),
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
pub struct GraphQLValidatorSet {
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

impl From<iota_sdk::graphql_client::query_types::ValidatorSet> for GraphQLValidatorSet {
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

impl From<GraphQLValidatorSet> for iota_sdk::graphql_client::query_types::ValidatorSet {
    fn from(value: GraphQLValidatorSet) -> Self {
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
pub struct GraphQLEventFilter {
    #[uniffi(default = None)]
    pub emitting_module: Option<String>,
    #[uniffi(default = None)]
    pub event_type: Option<String>,
    #[uniffi(default = None)]
    pub sender: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub transaction_digest: Option<String>,
}

impl From<iota_sdk::graphql_client::query_types::EventFilter> for GraphQLEventFilter {
    fn from(value: iota_sdk::graphql_client::query_types::EventFilter) -> Self {
        Self {
            emitting_module: value.emitting_module,
            event_type: value.event_type,
            sender: value.sender.map(Into::into).map(Arc::new),
            transaction_digest: value.transaction_digest,
        }
    }
}

impl From<GraphQLEventFilter> for iota_sdk::graphql_client::query_types::EventFilter {
    fn from(value: GraphQLEventFilter) -> Self {
        Self::default()
            .with_emitting_module(value.emitting_module)
            .with_event_type(value.event_type)
            .with_sender(value.sender.map(|a| **a))
            .with_transaction_digest(value.transaction_digest)
    }
}

/// An event as returned by the GraphQL `events` query.
///
/// This is a faithful view of the GraphQL response, distinct from the chain
/// [`Event`](crate::types::events::Event). Three fields are optional, for two
/// different reasons:
///
/// - `package_id`, `module` and `sender` are absent for events emitted by the
///   system or at genesis (e.g. the genesis validator
///   `0x3::validator::StakingRequestEvent`s): on chain their sender is the zero
///   address and their emitting module can't be resolved, both of which the
///   GraphQL server reports as `null`.
/// - `timestamp` is absent for events not yet included in a checkpoint (e.g.
///   from a dry run or a just-executed transaction).
///
/// `move_type`, `contents`, `data` and `json` are always present (non-null in
/// the GraphQL schema). Unlike the chain `Event`, this type is not
/// BCS/JSON-serializable as a chain event.
#[derive(uniffi::Record)]
pub struct GraphQLEvent {
    /// Package id of the top-level function invoked by a MoveCall command which
    /// triggered this event to be emitted. `None` for system events.
    pub package_id: Option<Arc<ObjectId>>,
    /// Module name of the top-level function invoked by a MoveCall command
    /// which triggered this event to be emitted. `None` for system events.
    pub module: Option<String>,
    /// Address of the account that sent the transaction where this event was
    /// emitted. `None` for system events.
    pub sender: Option<Arc<Address>>,
    /// The type of the event emitted
    pub move_type: String,
    /// BCS serialized bytes of the event
    pub contents: Vec<u8>,
    /// UTC timestamp in milliseconds since epoch (1/1/1970)
    pub timestamp: Option<String>,
    /// Structured contents of a Move value
    pub data: String,
    /// Representation of a Move value in JSON
    pub json: String,
}

impl TryFrom<iota_sdk::graphql_client::query_types::Event> for GraphQLEvent {
    type Error = crate::error::SdkFfiError;

    fn try_from(value: iota_sdk::graphql_client::query_types::Event) -> crate::error::Result<Self> {
        let (package_id, module) = match value.sending_module {
            Some(sending_module) => (
                Some(Arc::new(ObjectId(iota_sdk::types::ObjectId::from(
                    sending_module.package.address,
                )))),
                Some(sending_module.name),
            ),
            None => (None, None),
        };
        Ok(Self {
            package_id,
            module,
            sender: value.sender.map(|s| Arc::new(Address(s.address))),
            move_type: value.move_type.repr,
            contents: base64ct::Base64::decode_vec(&value.bcs.0)
                .map_err(crate::error::SdkFfiError::custom)?,
            timestamp: value.timestamp.map(|t| t.0),
            data: value.data.0.to_string(),
            json: value.json.to_string(),
        })
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLObjectFilter {
    #[uniffi(default = None)]
    pub type_tag: Option<String>,
    #[uniffi(default = None)]
    pub owner: Option<Arc<Address>>,
    #[uniffi(default = None)]
    pub object_ids: Option<Vec<Arc<ObjectId>>>,
}

impl From<iota_sdk::graphql_client::query_types::ObjectFilter> for GraphQLObjectFilter {
    fn from(value: iota_sdk::graphql_client::query_types::ObjectFilter) -> Self {
        Self {
            type_tag: value.type_tag,
            owner: value.owner.map(Into::into).map(Arc::new),
            object_ids: value
                .object_ids
                .map(|v| v.into_iter().map(Into::into).map(Arc::new).collect()),
        }
    }
}

impl From<GraphQLObjectFilter> for iota_sdk::graphql_client::query_types::ObjectFilter {
    fn from(value: GraphQLObjectFilter) -> Self {
        Self::default()
            .with_type(value.type_tag)
            .with_owner(value.owner.map(|v| **v))
            .with_object_ids(
                value
                    .object_ids
                    .map(|v| v.into_iter().map(|v| **v).collect()),
            )
    }
}

/// The output of a dynamic field query, that includes the name, value, and
/// value's json representation.
#[derive(uniffi::Record)]
pub struct GraphQLDynamicFieldOutput {
    /// The name of the dynamic field
    pub name: GraphQLDynamicFieldName,
    /// The dynamic field value typename and bcs
    #[uniffi(default = None)]
    pub value: Option<GraphQLDynamicFieldValue>,
    /// The json representation of the dynamic field value object
    #[uniffi(default = None)]
    pub value_as_json: Option<serde_json::Value>,
}

impl From<iota_sdk::graphql_client::DynamicFieldOutput> for GraphQLDynamicFieldOutput {
    fn from(value: iota_sdk::graphql_client::DynamicFieldOutput) -> Self {
        Self {
            name: value.name.into(),
            value: value.value.map(Into::into),
            value_as_json: value.value_as_json,
        }
    }
}

impl From<GraphQLDynamicFieldOutput> for iota_sdk::graphql_client::DynamicFieldOutput {
    fn from(value: GraphQLDynamicFieldOutput) -> Self {
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
pub struct GraphQLDynamicFieldName {
    /// The type name of this dynamic field name
    pub type_tag: Arc<TypeTag>,
    /// The bcs bytes of this dynamic field name
    pub bcs: Vec<u8>,
    /// The json representation of the dynamic field name
    #[uniffi(default = None)]
    pub json: Option<serde_json::Value>,
}

impl From<iota_sdk::graphql_client::DynamicFieldName> for GraphQLDynamicFieldName {
    fn from(value: iota_sdk::graphql_client::DynamicFieldName) -> Self {
        Self {
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

impl From<GraphQLDynamicFieldName> for iota_sdk::graphql_client::DynamicFieldName {
    fn from(value: GraphQLDynamicFieldName) -> Self {
        Self {
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
            json: value.json,
        }
    }
}

/// The value part of a dynamic field.
#[derive(uniffi::Record)]
pub struct GraphQLDynamicFieldValue {
    pub type_tag: Arc<TypeTag>,
    pub bcs: Vec<u8>,
}

impl From<iota_sdk::graphql_client::DynamicFieldValue> for GraphQLDynamicFieldValue {
    fn from(value: iota_sdk::graphql_client::DynamicFieldValue) -> Self {
        Self {
            type_tag: Arc::new(value.type_tag.into()),
            bcs: value.bcs,
        }
    }
}

impl From<GraphQLDynamicFieldValue> for iota_sdk::graphql_client::DynamicFieldValue {
    fn from(value: GraphQLDynamicFieldValue) -> Self {
        Self {
            type_tag: value.type_tag.0.clone(),
            bcs: value.bcs,
        }
    }
}

/// Represents a validator in the system.
#[derive(uniffi::Record)]
pub struct GraphQLValidator {
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
    pub credentials: Option<GraphQLValidatorCredentials>,
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
    pub next_epoch_credentials: Option<GraphQLValidatorCredentials>,
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

impl From<iota_sdk::graphql_client::query_types::Validator> for GraphQLValidator {
    fn from(value: iota_sdk::graphql_client::query_types::Validator) -> Self {
        Self {
            apy: value.apy,
            address: Arc::new(value.address.address.into()),
            commission_rate: value.commission_rate,
            credentials: value.credentials.map(Into::into),
            description: value.description,
            exchange_rates_size: value.exchange_rates_size,
            gas_price: value.gas_price.map(|v| v.0.parse().unwrap()),
            name: value.name,
            image_url: value.image_url,
            next_epoch_commission_rate: value.next_epoch_commission_rate,
            next_epoch_credentials: value.next_epoch_credentials.map(Into::into),
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

impl From<GraphQLValidator> for iota_sdk::graphql_client::query_types::Validator {
    fn from(value: GraphQLValidator) -> Self {
        Self {
            apy: value.apy,
            address: GraphQLAddress {
                address: value.address.clone(),
            }
            .into(),
            commission_rate: value.commission_rate,
            credentials: value.credentials.map(Into::into),
            description: value.description,
            exchange_rates_size: value.exchange_rates_size,
            gas_price: value.gas_price.map(|v| v.to_string().into()),
            name: value.name,
            image_url: value.image_url,
            next_epoch_commission_rate: value.next_epoch_commission_rate,
            next_epoch_credentials: value.next_epoch_credentials.map(Into::into),
            next_epoch_gas_price: value.next_epoch_gas_price.map(|v| v.to_string().into()),
            next_epoch_stake: value.next_epoch_stake.map(|v| v.to_string().into()),
            operation_cap: value.operation_cap.map(|o| {
                GraphQLMoveObject {
                    bcs: Some(Base64(base64ct::Base64::encode_string(&o))),
                }
                .into()
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
#[derive(uniffi::Record)]
pub struct GraphQLValidatorCredentials {
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

impl From<iota_sdk::graphql_client::query_types::ValidatorCredentials>
    for GraphQLValidatorCredentials
{
    fn from(value: iota_sdk::graphql_client::query_types::ValidatorCredentials) -> Self {
        Self {
            authority_pub_key: value.authority_pub_key,
            network_pub_key: value.network_pub_key,
            protocol_pub_key: value.protocol_pub_key,
            proof_of_possession: value.proof_of_possession,
            net_address: value.net_address,
            p2p_address: value.p2p_address,
            primary_address: value.primary_address,
        }
    }
}

impl From<GraphQLValidatorCredentials>
    for iota_sdk::graphql_client::query_types::ValidatorCredentials
{
    fn from(value: GraphQLValidatorCredentials) -> Self {
        Self {
            authority_pub_key: value.authority_pub_key,
            network_pub_key: value.network_pub_key,
            protocol_pub_key: value.protocol_pub_key,
            proof_of_possession: value.proof_of_possession,
            net_address: value.net_address,
            p2p_address: value.p2p_address,
            primary_address: value.primary_address,
        }
    }
}

/// The kind of a transaction, used to filter transaction queries.
#[derive(uniffi::Enum)]
pub enum GraphQLTransactionBlockKindInput {
    SystemTx,
    ProgrammableTx,
    Genesis,
    ConsensusCommitPrologueV1,
    RandomnessStateUpdate,
    EndOfEpochTx,
}

impl From<SdkTransactionBlockKindInput> for GraphQLTransactionBlockKindInput {
    fn from(value: SdkTransactionBlockKindInput) -> Self {
        match value {
            SdkTransactionBlockKindInput::SystemTx => Self::SystemTx,
            SdkTransactionBlockKindInput::ProgrammableTx => Self::ProgrammableTx,
            SdkTransactionBlockKindInput::Genesis => Self::Genesis,
            SdkTransactionBlockKindInput::ConsensusCommitPrologueV1 => {
                Self::ConsensusCommitPrologueV1
            }
            SdkTransactionBlockKindInput::RandomnessStateUpdate => Self::RandomnessStateUpdate,
            SdkTransactionBlockKindInput::EndOfEpochTx => Self::EndOfEpochTx,
            _ => unimplemented!(
                "a new TransactionBlockKindInput enum variant was added and needs to be handled"
            ),
        }
    }
}

impl From<GraphQLTransactionBlockKindInput> for SdkTransactionBlockKindInput {
    fn from(value: GraphQLTransactionBlockKindInput) -> Self {
        match value {
            GraphQLTransactionBlockKindInput::SystemTx => Self::SystemTx,
            GraphQLTransactionBlockKindInput::ProgrammableTx => Self::ProgrammableTx,
            GraphQLTransactionBlockKindInput::Genesis => Self::Genesis,
            GraphQLTransactionBlockKindInput::ConsensusCommitPrologueV1 => {
                Self::ConsensusCommitPrologueV1
            }
            GraphQLTransactionBlockKindInput::RandomnessStateUpdate => Self::RandomnessStateUpdate,
            GraphQLTransactionBlockKindInput::EndOfEpochTx => Self::EndOfEpochTx,
        }
    }
}

/// The relationship between an address and a transaction.
#[derive(uniffi::Enum)]
pub enum GraphQLAddressTransactionRelationship {
    /// Transactions the address has sent.
    Sent,
    /// Transactions that sent objects to the address.
    Recv,
    /// Transactions that affected the address: it is the sender, a recipient,
    /// or the owner of the gas payment.
    Affected,
}

impl From<SdkAddressTransactionRelationship> for GraphQLAddressTransactionRelationship {
    fn from(value: SdkAddressTransactionRelationship) -> Self {
        match value {
            SdkAddressTransactionRelationship::Sent => Self::Sent,
            SdkAddressTransactionRelationship::Recv => Self::Recv,
            SdkAddressTransactionRelationship::Affected => Self::Affected,
            _ => unimplemented!(
                "a new AddressTransactionRelationship enum variant was added and needs to be handled"
            ),
        }
    }
}

impl From<GraphQLAddressTransactionRelationship> for SdkAddressTransactionRelationship {
    fn from(value: GraphQLAddressTransactionRelationship) -> Self {
        match value {
            GraphQLAddressTransactionRelationship::Sent => Self::Sent,
            GraphQLAddressTransactionRelationship::Recv => Self::Recv,
            GraphQLAddressTransactionRelationship::Affected => Self::Affected,
        }
    }
}

/// Information about pagination in a connection.
#[derive(uniffi::Record)]
pub struct GraphQLPageInfo {
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

impl From<iota_sdk::graphql_client::query_types::PageInfo> for GraphQLPageInfo {
    fn from(value: iota_sdk::graphql_client::query_types::PageInfo) -> Self {
        Self {
            has_previous_page: value.has_previous_page,
            has_next_page: value.has_next_page,
            start_cursor: value.start_cursor,
            end_cursor: value.end_cursor,
        }
    }
}

impl From<GraphQLPageInfo> for iota_sdk::graphql_client::query_types::PageInfo {
    fn from(value: GraphQLPageInfo) -> Self {
        Self {
            has_previous_page: value.has_previous_page,
            has_next_page: value.has_next_page,
            start_cursor: value.start_cursor,
            end_cursor: value.end_cursor,
        }
    }
}

/// Pagination options for querying the GraphQL server. It defaults to forward
/// pagination with the GraphQL server's max page size.
#[derive(uniffi::Record)]
pub struct GraphQLPaginationFilter {
    /// The direction of pagination.
    pub direction: GraphQLDirection,
    /// An opaque cursor used for pagination.
    #[uniffi(default = None)]
    pub cursor: Option<String>,
    /// The maximum number of items to return. If this is omitted, it will
    /// lazily query the service configuration for the max page size.
    #[uniffi(default = None)]
    pub limit: Option<i32>,
}

impl From<GraphQLPaginationFilter> for iota_sdk::graphql_client::pagination::PaginationFilter {
    fn from(value: GraphQLPaginationFilter) -> Self {
        Self {
            direction: value.direction.into(),
            cursor: value.cursor,
            limit: value.limit,
        }
    }
}

/// Pagination direction.
#[derive(uniffi::Enum)]
pub enum GraphQLDirection {
    Forward,
    Backward,
}

impl From<GraphQLDirection> for iota_sdk::graphql_client::pagination::Direction {
    fn from(value: GraphQLDirection) -> Self {
        match value {
            GraphQLDirection::Forward => Self::Forward,
            GraphQLDirection::Backward => Self::Backward,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLValidatorConnection {
    pub page_info: GraphQLPageInfo,
    pub nodes: Vec<GraphQLValidator>,
}

impl From<iota_sdk::graphql_client::query_types::ValidatorConnection>
    for GraphQLValidatorConnection
{
    fn from(value: iota_sdk::graphql_client::query_types::ValidatorConnection) -> Self {
        GraphQLValidatorConnection {
            page_info: value.page_info.into(),
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<GraphQLValidatorConnection>
    for iota_sdk::graphql_client::query_types::ValidatorConnection
{
    fn from(value: GraphQLValidatorConnection) -> Self {
        iota_sdk::graphql_client::query_types::ValidatorConnection {
            page_info: value.page_info.into(),
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLAddress {
    pub address: Arc<Address>,
}

impl From<iota_sdk::graphql_client::query_types::GraphQLAddress> for GraphQLAddress {
    fn from(value: iota_sdk::graphql_client::query_types::GraphQLAddress) -> Self {
        GraphQLAddress {
            address: Arc::new(value.address.into()),
        }
    }
}

impl From<GraphQLAddress> for iota_sdk::graphql_client::query_types::GraphQLAddress {
    fn from(value: GraphQLAddress) -> Self {
        iota_sdk::graphql_client::query_types::GraphQLAddress {
            address: (**value.address),
        }
    }
}

/// The BCS contents of an on-chain Move object.
#[derive(uniffi::Record)]
pub struct GraphQLMoveObject {
    #[uniffi(default = None)]
    pub bcs: Option<Base64>,
}

impl From<GraphQLMoveObject> for iota_sdk::graphql_client::query_types::MoveObject {
    fn from(value: GraphQLMoveObject) -> Self {
        Self { bcs: value.bcs }
    }
}

/// Information about the configuration of the protocol.
/// Constants that control how the chain operates.
/// These can only change during protocol upgrades which happen on epoch
/// boundaries.
#[derive(uniffi::Record)]
pub struct GraphQLProtocolConfigs {
    /// The protocol is not required to change on every epoch boundary, so the
    /// protocol version tracks which change to the protocol these configs
    /// are from.
    pub protocol_version: u64,
    /// List all available feature flags and their values. Feature flags are a
    /// form of boolean configuration that are usually used to gate features
    /// while they are in development. Once a flag has been enabled, it is
    /// rare for it to be disabled.
    pub feature_flags: Vec<GraphQLProtocolConfigFeatureFlag>,
    /// List all available configurations and their values. These configurations
    /// can take any value (but they will all be represented in string
    /// form), and do not include feature flags.
    pub configs: Vec<GraphQLProtocolConfigAttr>,
}

impl From<iota_sdk::graphql_client::query_types::ProtocolConfigs> for GraphQLProtocolConfigs {
    fn from(value: iota_sdk::graphql_client::query_types::ProtocolConfigs) -> Self {
        Self {
            protocol_version: value.protocol_version,
            feature_flags: value.feature_flags.into_iter().map(Into::into).collect(),
            configs: value.configs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<GraphQLProtocolConfigs> for iota_sdk::graphql_client::query_types::ProtocolConfigs {
    fn from(value: GraphQLProtocolConfigs) -> Self {
        Self {
            protocol_version: value.protocol_version,
            feature_flags: value.feature_flags.into_iter().map(Into::into).collect(),
            configs: value.configs.into_iter().map(Into::into).collect(),
        }
    }
}

/// Feature flags are a form of boolean configuration that are usually used to
/// gate features while they are in development. Once a lag has been enabled, it
/// is rare for it to be disabled.
#[derive(uniffi::Record)]
pub struct GraphQLProtocolConfigFeatureFlag {
    pub key: String,
    pub value: bool,
}

impl From<iota_sdk::graphql_client::query_types::ProtocolConfigFeatureFlag>
    for GraphQLProtocolConfigFeatureFlag
{
    fn from(value: iota_sdk::graphql_client::query_types::ProtocolConfigFeatureFlag) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<GraphQLProtocolConfigFeatureFlag>
    for iota_sdk::graphql_client::query_types::ProtocolConfigFeatureFlag
{
    fn from(value: GraphQLProtocolConfigFeatureFlag) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

/// A key-value protocol configuration attribute.
#[derive(uniffi::Record)]
pub struct GraphQLProtocolConfigAttr {
    pub key: String,
    pub value: Option<String>,
}

impl From<iota_sdk::graphql_client::query_types::ProtocolConfigAttr> for GraphQLProtocolConfigAttr {
    fn from(value: iota_sdk::graphql_client::query_types::ProtocolConfigAttr) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<GraphQLProtocolConfigAttr> for iota_sdk::graphql_client::query_types::ProtocolConfigAttr {
    fn from(value: GraphQLProtocolConfigAttr) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

/// The coin metadata associated with the given coin type.
#[derive(uniffi::Record)]
pub struct GraphQLCoinMetadata {
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
    pub supply: Option<u64>,
    /// Version of the token.
    pub version: u64,
}

impl TryFrom<iota_sdk::graphql_client::query_types::CoinMetadata> for GraphQLCoinMetadata {
    type Error = SdkFfiError;

    fn try_from(
        value: iota_sdk::graphql_client::query_types::CoinMetadata,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            address: Arc::new(value.address.into()),
            decimals: value.decimals,
            description: value.description,
            icon_url: value.icon_url,
            name: value.name,
            symbol: value.symbol,
            // The GraphQL `BigInt` scalar carries the supply as a decimal
            // string; on-chain a coin's supply is a `u64`, so parse it into one
            // to expose a native integer (e.g. `bigint` in TS) to bindings.
            supply: value.supply.map(u64::try_from).transpose()?,
            version: value.version,
        })
    }
}

impl From<GraphQLCoinMetadata> for iota_sdk::graphql_client::query_types::CoinMetadata {
    fn from(value: GraphQLCoinMetadata) -> Self {
        Self {
            address: **value.address,
            decimals: value.decimals,
            description: value.description,
            icon_url: value.icon_url,
            name: value.name,
            symbol: value.symbol,
            supply: value.supply.map(|supply| BigInt(supply.to_string())),
            version: value.version,
        }
    }
}

#[derive(Debug, derive_more::Display, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug, Display)]
pub struct GraphQLMoveFunction(iota_sdk::graphql_client::query_types::MoveFunction);

#[uniffi::export]
impl GraphQLMoveFunction {
    pub fn is_entry(&self) -> bool {
        self.0.is_entry.is_some_and(|v| v)
    }

    pub fn name(&self) -> String {
        self.0.name.clone()
    }

    pub fn parameters(&self) -> Option<Vec<GraphQLOpenMoveType>> {
        self.0
            .parameters
            .clone()
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    pub fn return_type(&self) -> Option<Vec<GraphQLOpenMoveType>> {
        self.0
            .return_
            .clone()
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    pub fn type_parameters(&self) -> Option<Vec<GraphQLMoveFunctionTypeParameter>> {
        self.0
            .type_parameters
            .clone()
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    pub fn visibility(&self) -> Option<GraphQLMoveVisibility> {
        self.0.visibility.map(Into::into)
    }
}

/// The visibility of a Move function.
#[derive(uniffi::Enum)]
pub enum GraphQLMoveVisibility {
    Public,
    Private,
    Friend,
}

impl From<iota_sdk::graphql_client::query_types::MoveVisibility> for GraphQLMoveVisibility {
    fn from(value: iota_sdk::graphql_client::query_types::MoveVisibility) -> Self {
        match value {
            iota_sdk::graphql_client::query_types::MoveVisibility::Public => Self::Public,
            iota_sdk::graphql_client::query_types::MoveVisibility::Private => Self::Private,
            iota_sdk::graphql_client::query_types::MoveVisibility::Friend => Self::Friend,
            _ => unimplemented!(
                "a new MoveVisibility enum variant was added and needs to be handled"
            ),
        }
    }
}

/// An ability a Move type can have.
#[derive(uniffi::Enum)]
pub enum GraphQLMoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

impl From<iota_sdk::graphql_client::query_types::MoveAbility> for GraphQLMoveAbility {
    fn from(value: iota_sdk::graphql_client::query_types::MoveAbility) -> Self {
        match value {
            iota_sdk::graphql_client::query_types::MoveAbility::Copy => Self::Copy,
            iota_sdk::graphql_client::query_types::MoveAbility::Drop => Self::Drop,
            iota_sdk::graphql_client::query_types::MoveAbility::Key => Self::Key,
            iota_sdk::graphql_client::query_types::MoveAbility::Store => Self::Store,
            _ => unimplemented!("a new MoveAbility enum variant was added and needs to be handled"),
        }
    }
}

impl From<GraphQLMoveAbility> for iota_sdk::graphql_client::query_types::MoveAbility {
    fn from(value: GraphQLMoveAbility) -> Self {
        match value {
            GraphQLMoveAbility::Copy => Self::Copy,
            GraphQLMoveAbility::Drop => Self::Drop,
            GraphQLMoveAbility::Key => Self::Key,
            GraphQLMoveAbility::Store => Self::Store,
        }
    }
}

/// A type parameter of a Move function, with the abilities it is constrained
/// to.
#[derive(uniffi::Record)]
pub struct GraphQLMoveFunctionTypeParameter {
    pub constraints: Vec<GraphQLMoveAbility>,
}

impl From<iota_sdk::graphql_client::query_types::MoveFunctionTypeParameter>
    for GraphQLMoveFunctionTypeParameter
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveFunctionTypeParameter) -> Self {
        Self {
            constraints: value.constraints.into_iter().map(Into::into).collect(),
        }
    }
}

/// A Move type that may still have unbound type parameters.
#[derive(uniffi::Record)]
pub struct GraphQLOpenMoveType {
    pub repr: String,
}

impl From<iota_sdk::graphql_client::query_types::OpenMoveType> for GraphQLOpenMoveType {
    fn from(value: iota_sdk::graphql_client::query_types::OpenMoveType) -> Self {
        Self { repr: value.repr }
    }
}

impl From<GraphQLOpenMoveType> for iota_sdk::graphql_client::query_types::OpenMoveType {
    fn from(value: GraphQLOpenMoveType) -> Self {
        Self { repr: value.repr }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLMoveModule {
    pub file_format_version: i32,
    #[uniffi(default = None)]
    pub enums: Option<GraphQLMoveEnumConnection>,
    pub friends: GraphQLMoveModuleConnection,
    #[uniffi(default = None)]
    pub functions: Option<GraphQLMoveFunctionConnection>,
    #[uniffi(default = None)]
    pub structs: Option<GraphQLMoveStructConnection>,
}

impl From<iota_sdk::graphql_client::query_types::MoveModule> for GraphQLMoveModule {
    fn from(value: iota_sdk::graphql_client::query_types::MoveModule) -> Self {
        Self {
            file_format_version: value.file_format_version,
            enums: value.enums.map(Into::into),
            friends: value.friends.into(),
            functions: value.functions.map(Into::into),
            structs: value.structs.map(Into::into),
        }
    }
}

impl From<GraphQLMoveModule> for iota_sdk::graphql_client::query_types::MoveModule {
    fn from(value: GraphQLMoveModule) -> Self {
        Self {
            file_format_version: value.file_format_version,
            enums: value.enums.map(Into::into),
            friends: value.friends.into(),
            functions: value.functions.map(Into::into),
            structs: value.structs.map(Into::into),
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLMoveModuleConnection {
    pub nodes: Vec<GraphQLMoveModuleQuery>,
    pub page_info: GraphQLPageInfo,
}

impl From<iota_sdk::graphql_client::query_types::MoveModuleConnection>
    for GraphQLMoveModuleConnection
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveModuleConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info.into(),
        }
    }
}

impl From<GraphQLMoveModuleConnection>
    for iota_sdk::graphql_client::query_types::MoveModuleConnection
{
    fn from(value: GraphQLMoveModuleConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info.into(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLMovePackageQuery {
    pub address: Arc<Address>,
    #[uniffi(default = None)]
    pub bcs: Option<Base64>,
}

impl From<iota_sdk::graphql_client::query_types::MovePackageQueryFragment>
    for GraphQLMovePackageQuery
{
    fn from(value: iota_sdk::graphql_client::query_types::MovePackageQueryFragment) -> Self {
        Self {
            address: Arc::new(value.address.into()),
            bcs: value.bcs,
        }
    }
}

impl From<GraphQLMovePackageQuery>
    for iota_sdk::graphql_client::query_types::MovePackageQueryFragment
{
    fn from(value: GraphQLMovePackageQuery) -> Self {
        Self {
            address: (**value.address),
            bcs: value.bcs,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLMoveModuleQuery {
    pub package: GraphQLMovePackageQuery,
    pub name: String,
}

impl From<iota_sdk::graphql_client::query_types::MoveModuleQueryFragment>
    for GraphQLMoveModuleQuery
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveModuleQueryFragment) -> Self {
        Self {
            package: GraphQLMovePackageQuery {
                address: Arc::new(value.package.address.into()),
                bcs: None,
            },
            name: value.name,
        }
    }
}

impl From<GraphQLMoveModuleQuery>
    for iota_sdk::graphql_client::query_types::MoveModuleQueryFragment
{
    fn from(value: GraphQLMoveModuleQuery) -> Self {
        Self {
            package: iota_sdk::graphql_client::query_types::MovePackageAddress {
                address: **value.package.address,
            },
            name: value.name,
        }
    }
}

/// A type parameter of a Move struct, with the abilities it is constrained to.
#[derive(uniffi::Record)]
pub struct GraphQLMoveStructTypeParameter {
    pub constraints: Vec<GraphQLMoveAbility>,
    pub is_phantom: bool,
}

impl From<iota_sdk::graphql_client::query_types::MoveStructTypeParameter>
    for GraphQLMoveStructTypeParameter
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveStructTypeParameter) -> Self {
        Self {
            constraints: value.constraints.into_iter().map(Into::into).collect(),
            is_phantom: value.is_phantom,
        }
    }
}

impl From<GraphQLMoveStructTypeParameter>
    for iota_sdk::graphql_client::query_types::MoveStructTypeParameter
{
    fn from(value: GraphQLMoveStructTypeParameter) -> Self {
        Self {
            constraints: value.constraints.into_iter().map(Into::into).collect(),
            is_phantom: value.is_phantom,
        }
    }
}

/// A field of a Move struct or enum variant.
#[derive(uniffi::Record)]
pub struct GraphQLMoveField {
    pub name: String,
    #[uniffi(default = None)]
    pub move_type: Option<GraphQLOpenMoveType>,
}

impl From<iota_sdk::graphql_client::query_types::MoveField> for GraphQLMoveField {
    fn from(value: iota_sdk::graphql_client::query_types::MoveField) -> Self {
        Self {
            name: value.name,
            move_type: value.move_type.map(Into::into),
        }
    }
}

impl From<GraphQLMoveField> for iota_sdk::graphql_client::query_types::MoveField {
    fn from(value: GraphQLMoveField) -> Self {
        Self {
            name: value.name,
            move_type: value.move_type.map(Into::into),
        }
    }
}

/// A Move struct definition.
#[derive(uniffi::Record)]
pub struct GraphQLMoveStructQuery {
    #[uniffi(default = None)]
    pub abilities: Option<Vec<GraphQLMoveAbility>>,
    pub name: String,
    #[uniffi(default = None)]
    pub fields: Option<Vec<GraphQLMoveField>>,
    #[uniffi(default = None)]
    pub type_parameters: Option<Vec<GraphQLMoveStructTypeParameter>>,
}

impl From<iota_sdk::graphql_client::query_types::MoveStructQueryFragment>
    for GraphQLMoveStructQuery
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveStructQueryFragment) -> Self {
        Self {
            abilities: value
                .abilities
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
            fields: value
                .fields
                .map(|v| v.into_iter().map(Into::into).collect()),
            type_parameters: value
                .type_parameters
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<GraphQLMoveStructQuery>
    for iota_sdk::graphql_client::query_types::MoveStructQueryFragment
{
    fn from(value: GraphQLMoveStructQuery) -> Self {
        Self {
            abilities: value
                .abilities
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
            fields: value
                .fields
                .map(|v| v.into_iter().map(Into::into).collect()),
            type_parameters: value
                .type_parameters
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

/// A page of Move struct definitions.
#[derive(uniffi::Record)]
pub struct GraphQLMoveStructConnection {
    pub page_info: GraphQLPageInfo,
    pub nodes: Vec<GraphQLMoveStructQuery>,
}

impl From<iota_sdk::graphql_client::query_types::MoveStructConnection>
    for GraphQLMoveStructConnection
{
    fn from(value: iota_sdk::graphql_client::query_types::MoveStructConnection) -> Self {
        Self {
            page_info: value.page_info.into(),
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<GraphQLMoveStructConnection>
    for iota_sdk::graphql_client::query_types::MoveStructConnection
{
    fn from(value: GraphQLMoveStructConnection) -> Self {
        Self {
            page_info: value.page_info.into(),
            nodes: value.nodes.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct GraphQLMoveFunctionConnection {
    pub nodes: Vec<Arc<GraphQLMoveFunction>>,
    pub page_info: GraphQLPageInfo,
}

impl From<iota_sdk::graphql_client::query_types::MoveFunctionConnection>
    for GraphQLMoveFunctionConnection
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
            page_info: value.page_info.into(),
        }
    }
}

impl From<GraphQLMoveFunctionConnection>
    for iota_sdk::graphql_client::query_types::MoveFunctionConnection
{
    fn from(value: GraphQLMoveFunctionConnection) -> Self {
        Self {
            nodes: value.nodes.iter().map(|v| v.0.clone()).collect(),
            page_info: value.page_info.into(),
        }
    }
}

/// A page of Move enum definitions.
#[derive(uniffi::Record)]
pub struct GraphQLMoveEnumConnection {
    pub nodes: Vec<GraphQLMoveEnum>,
    pub page_info: GraphQLPageInfo,
}

impl From<iota_sdk::graphql_client::query_types::MoveEnumConnection> for GraphQLMoveEnumConnection {
    fn from(value: iota_sdk::graphql_client::query_types::MoveEnumConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info.into(),
        }
    }
}

impl From<GraphQLMoveEnumConnection> for iota_sdk::graphql_client::query_types::MoveEnumConnection {
    fn from(value: GraphQLMoveEnumConnection) -> Self {
        Self {
            nodes: value.nodes.into_iter().map(Into::into).collect(),
            page_info: value.page_info.into(),
        }
    }
}

/// A variant of a Move enum.
#[derive(uniffi::Record)]
pub struct GraphQLMoveEnumVariant {
    #[uniffi(default = None)]
    pub fields: Option<Vec<GraphQLMoveField>>,
    pub name: String,
}

impl From<iota_sdk::graphql_client::query_types::MoveEnumVariant> for GraphQLMoveEnumVariant {
    fn from(value: iota_sdk::graphql_client::query_types::MoveEnumVariant) -> Self {
        Self {
            fields: value
                .fields
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
        }
    }
}

impl From<GraphQLMoveEnumVariant> for iota_sdk::graphql_client::query_types::MoveEnumVariant {
    fn from(value: GraphQLMoveEnumVariant) -> Self {
        Self {
            fields: value
                .fields
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
        }
    }
}

/// A Move enum definition.
#[derive(uniffi::Record)]
pub struct GraphQLMoveEnum {
    #[uniffi(default = None)]
    pub abilities: Option<Vec<GraphQLMoveAbility>>,
    pub name: String,
    #[uniffi(default = None)]
    pub type_parameters: Option<Vec<GraphQLMoveStructTypeParameter>>,
    #[uniffi(default = None)]
    pub variants: Option<Vec<GraphQLMoveEnumVariant>>,
}

impl From<iota_sdk::graphql_client::query_types::MoveEnum> for GraphQLMoveEnum {
    fn from(value: iota_sdk::graphql_client::query_types::MoveEnum) -> Self {
        Self {
            abilities: value
                .abilities
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
            type_parameters: value
                .type_parameters
                .map(|v| v.into_iter().map(Into::into).collect()),
            variants: value
                .variants
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

impl From<GraphQLMoveEnum> for iota_sdk::graphql_client::query_types::MoveEnum {
    fn from(value: GraphQLMoveEnum) -> Self {
        Self {
            abilities: value
                .abilities
                .map(|v| v.into_iter().map(Into::into).collect()),
            name: value.name,
            type_parameters: value
                .type_parameters
                .map(|v| v.into_iter().map(Into::into).collect()),
            variants: value
                .variants
                .map(|v| v.into_iter().map(Into::into).collect()),
        }
    }
}

/// The result of executing a Move View Function.
///
/// Execution errors are captured in the `error` field, in which case the
/// `results` field will be `None`. On success, the `results` field will contain
/// the return values of the Move view function, and the `error` field will be
/// `None`.
#[derive(uniffi::Record)]
pub struct GraphQLMoveViewResult {
    /// Execution error from executing the Move view function.
    #[uniffi(default = None)]
    pub error: Option<String>,
    /// The return values of the Move view function, resolved and formatted as
    /// JSON.
    #[uniffi(default = None)]
    pub results: Option<Vec<String>>,
}

impl From<iota_sdk::graphql_client::query_types::MoveViewResult> for GraphQLMoveViewResult {
    fn from(value: iota_sdk::graphql_client::query_types::MoveViewResult) -> Self {
        Self {
            error: value.error,
            results: value.results.map(|v| {
                v.into_iter()
                    .map(|json| serde_json::to_string(&json).unwrap_or_default())
                    .collect()
            }),
        }
    }
}

// Information about the configuration of the GraphQL service.
#[derive(uniffi::Record)]
pub struct GraphQLServiceConfig {
    /// Default number of elements allowed on a single page of a connection.
    pub default_page_size: i32,
    /// List of all features that are enabled on this RPC service.
    pub enabled_features: Vec<GraphQLFeature>,
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
    /// after issuing a transaction to execute. Note that the transaction
    /// may still succeed even in the case of a timeout. Transactions are
    /// idempotent, so a transaction that times out should be resubmitted
    /// until the network returns a definite response (success or failure, not
    /// timeout).
    pub mutation_timeout_ms: i32,
    /// Maximum time in milliseconds that will be spent to serve one query
    /// request.
    pub request_timeout_ms: i32,
}

impl From<iota_sdk::graphql_client::query_types::ServiceConfig> for GraphQLServiceConfig {
    fn from(value: iota_sdk::graphql_client::query_types::ServiceConfig) -> Self {
        Self {
            default_page_size: value.default_page_size,
            enabled_features: value.enabled_features.into_iter().map(Into::into).collect(),
            max_move_value_depth: value.max_move_value_depth,
            max_output_nodes: value.max_output_nodes,
            max_page_size: value.max_page_size,
            max_query_depth: value.max_query_depth,
            max_query_nodes: value.max_query_nodes,
            max_query_payload_size: value.max_query_payload_size,
            max_type_argument_depth: value.max_type_argument_depth,
            max_type_argument_width: value.max_type_argument_width,
            max_type_nodes: value.max_type_nodes,
            mutation_timeout_ms: value.mutation_timeout_ms,
            request_timeout_ms: value.request_timeout_ms,
        }
    }
}

/// A feature an RPC service can have enabled.
#[derive(uniffi::Enum)]
pub enum GraphQLFeature {
    Analytics,
    Coins,
    DynamicFields,
    Subscriptions,
    SystemState,
}

impl From<iota_sdk::graphql_client::query_types::Feature> for GraphQLFeature {
    fn from(value: iota_sdk::graphql_client::query_types::Feature) -> Self {
        match value {
            iota_sdk::graphql_client::query_types::Feature::Analytics => Self::Analytics,
            iota_sdk::graphql_client::query_types::Feature::Coins => Self::Coins,
            iota_sdk::graphql_client::query_types::Feature::DynamicFields => Self::DynamicFields,
            iota_sdk::graphql_client::query_types::Feature::Subscriptions => Self::Subscriptions,
            iota_sdk::graphql_client::query_types::Feature::SystemState => Self::SystemState,
            _ => unimplemented!("a new Feature enum variant was added and needs to be handled"),
        }
    }
}
