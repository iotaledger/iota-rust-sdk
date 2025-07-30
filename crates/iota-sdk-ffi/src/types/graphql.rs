// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{
    address::Address,
    object::ObjectId,
    transaction::{SignedTransaction, TransactionEffects},
};

#[derive(Clone, Debug, derive_more::From, uniffi::Record)]
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
            gas_sponsor: value.gas_sponsor.map(|a| a.0.clone()),
            sender: value.sender.map(|a| a.0.clone()),
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

#[derive(Clone, Debug, derive_more::From, uniffi::Record)]
pub struct TransactionsFilter {
    pub function: Option<String>,
    pub kind: Option<TransactionBlockKindInput>,
    pub after_checkpoint: Option<u64>,
    pub at_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
    pub affected_address: Option<Arc<Address>>,
    pub sent_address: Option<Arc<Address>>,
    pub input_object: Option<Arc<ObjectId>>,
    pub changed_object: Option<Arc<ObjectId>>,
    pub transaction_ids: Option<Vec<String>>,
}

impl From<iota_graphql_client::query_types::TransactionsFilter> for TransactionsFilter {
    fn from(value: iota_graphql_client::query_types::TransactionsFilter) -> Self {
        Self {
            function: value.function,
            kind: value.kind.map(Into::into),
            after_checkpoint: value.after_checkpoint,
            at_checkpoint: value.at_checkpoint,
            before_checkpoint: value.before_checkpoint,
            affected_address: value.affected_address.map(Into::into).map(Arc::new),
            sent_address: value.sent_address.map(Into::into).map(Arc::new),
            input_object: value.input_object.map(Into::into).map(Arc::new),
            changed_object: value.changed_object.map(Into::into).map(Arc::new),
            transaction_ids: value.transaction_ids,
        }
    }
}

impl From<TransactionsFilter> for iota_graphql_client::query_types::TransactionsFilter {
    fn from(value: TransactionsFilter) -> Self {
        Self {
            function: value.function,
            kind: value.kind.map(Into::into),
            after_checkpoint: value.after_checkpoint,
            at_checkpoint: value.at_checkpoint,
            before_checkpoint: value.before_checkpoint,
            affected_address: value.affected_address.map(|v| **v),
            sent_address: value.sent_address.map(|v| **v),
            input_object: value.input_object.map(|v| **v),
            changed_object: value.changed_object.map(|v| **v),
            transaction_ids: value.transaction_ids,
        }
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct DryRunResult(pub iota_graphql_client::DryRunResult);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct TransactionEvent(pub iota_graphql_client::TransactionEvent);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectRef(pub iota_graphql_client::query_types::ObjectRef);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Epoch(pub iota_graphql_client::query_types::Epoch);

#[derive(Clone, Debug, derive_more::From, uniffi::Record)]
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
            sender: value.sender.map(|s| s.0.clone()),
            transaction_digest: value.transaction_digest,
        }
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectFilter(pub iota_graphql_client::query_types::ObjectFilter);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct DynamicFieldOutput(pub iota_graphql_client::DynamicFieldOutput);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Validator(pub iota_graphql_client::query_types::Validator);

#[derive(Copy, Clone, Debug, derive_more::From, uniffi::Enum)]
pub enum TransactionBlockKindInput {
    SystemTx,
    ProgrammableTx,
}

impl From<iota_graphql_client::query_types::TransactionBlockKindInput>
    for TransactionBlockKindInput
{
    fn from(value: iota_graphql_client::query_types::TransactionBlockKindInput) -> Self {
        match value {
            iota_graphql_client::query_types::TransactionBlockKindInput::SystemTx => Self::SystemTx,
            iota_graphql_client::query_types::TransactionBlockKindInput::ProgrammableTx => {
                Self::ProgrammableTx
            }
        }
    }
}

impl From<TransactionBlockKindInput>
    for iota_graphql_client::query_types::TransactionBlockKindInput
{
    fn from(value: TransactionBlockKindInput) -> Self {
        match value {
            TransactionBlockKindInput::SystemTx => Self::SystemTx,
            TransactionBlockKindInput::ProgrammableTx => Self::ProgrammableTx,
        }
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct PageInfo(pub iota_graphql_client::query_types::PageInfo);

/// Pagination options for querying the GraphQL server. It defaults to forward
/// pagination with the GraphQL server's max page size.
#[derive(Clone, Debug, Default, uniffi::Record)]
pub struct PaginationFilter {
    /// The direction of pagination.
    pub direction: Direction,
    /// An opaque cursor used for pagination.
    pub cursor: Option<String>,
    /// The maximum number of items to return. If this is ommitted, it will
    /// lazily query the service configuration for the max page size.
    pub limit: Option<i32>,
}

impl From<iota_graphql_client::pagination::PaginationFilter> for PaginationFilter {
    fn from(value: iota_graphql_client::pagination::PaginationFilter) -> Self {
        Self {
            direction: value.direction.into(),
            cursor: value.cursor,
            limit: value.limit,
        }
    }
}

impl From<PaginationFilter> for iota_graphql_client::pagination::PaginationFilter {
    fn from(value: PaginationFilter) -> Self {
        Self {
            direction: value.direction.into(),
            cursor: value.cursor,
            limit: value.limit,
        }
    }
}

/// Pagination direction.
#[derive(Clone, Debug, Default, uniffi::Enum)]
pub enum Direction {
    #[default]
    Forward,
    Backward,
}

impl From<iota_graphql_client::pagination::Direction> for Direction {
    fn from(value: iota_graphql_client::pagination::Direction) -> Self {
        match value {
            iota_graphql_client::pagination::Direction::Forward => Self::Forward,
            iota_graphql_client::pagination::Direction::Backward => Self::Backward,
        }
    }
}

impl From<Direction> for iota_graphql_client::pagination::Direction {
    fn from(value: Direction) -> Self {
        match value {
            Direction::Forward => Self::Forward,
            Direction::Backward => Self::Backward,
        }
    }
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
