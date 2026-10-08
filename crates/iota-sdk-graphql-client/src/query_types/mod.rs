// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod active_validators;
mod balance;
mod chain;
mod checkpoint;
mod coin;
mod dry_run;
mod dynamic_fields;
mod epoch;
mod events;
mod execute_transaction;
mod iota_names;
mod move_view_call;
mod normalized_move;
mod object;
mod packages;
mod protocol_config;
mod service_config;
mod subscriptions;
mod transaction;

pub(crate) use active_validators::{ActiveValidatorsArgs, ActiveValidatorsQueryFragment};
pub use active_validators::{Validator, ValidatorCredentials};
pub(crate) use balance::{BalanceArgs, BalanceQueryFragment};
pub(crate) use chain::ChainIdentifierQueryFragment;
pub(crate) use checkpoint::{
    CheckpointArgs, CheckpointId, CheckpointQueryFragment, CheckpointTotalTxQueryFragment,
    CheckpointsArgs, CheckpointsQueryFragment,
};
pub use coin::CoinMetadata;
pub(crate) use coin::{CoinMetadataArgs, CoinMetadataQueryFragment};
use cynic::impl_scalar;
pub(crate) use dry_run::{
    DryRunArgs, DryRunEffect, DryRunMutation, DryRunQueryFragment, DryRunReturn, GasCoin,
    TransactionArgument,
};
pub use dry_run::{ObjectRef, TransactionMetadata};
pub(crate) use dynamic_fields::{
    DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldName, DynamicFieldQueryFragment,
    DynamicFieldsOwnerQueryFragment, DynamicObjectFieldQueryFragment,
};
pub use epoch::{Epoch, ValidatorSet};
pub(crate) use epoch::{EpochArgs, EpochQueryFragment, EpochSummaryQueryFragment};
pub use events::{Event, EventFilter};
pub(crate) use events::{EventsQueryArgs, EventsQueryFragment};
pub(crate) use execute_transaction::{ExecuteTransactionArgs, ExecuteTransactionQueryFragment};
pub(crate) use iota_names::{
    IotaNamesAddressDefaultNameQueryFragment, IotaNamesAddressRegistrationsQueryFragment,
    IotaNamesDefaultNameArgs, IotaNamesDefaultNameQueryFragment, IotaNamesRegistrationsArgs,
    IotaNamesRegistrationsQueryFragment, ResolveIotaNamesAddressArgs,
    ResolveIotaNamesAddressQueryFragment,
};
use iota_types::{Address, ObjectId};
pub use move_view_call::MoveViewResult;
pub(crate) use move_view_call::{MoveViewCallArgs, MoveViewCallQueryFragment};
pub use normalized_move::MoveModuleQueryFragment;
pub(crate) use normalized_move::{
    MoveAbility, MoveEnum, MoveEnumVariant, MoveField, MoveFunction, MoveFunctionTypeParameter,
    MoveModuleIdQueryFragment, MoveStructQueryFragment, MoveStructTypeParameter, MoveVisibility,
    NormalizedMoveFunctionQueryArgs, NormalizedMoveFunctionQueryFragment,
    NormalizedMoveModuleQueryArgs, NormalizedMoveModuleQueryFragment, OpenMoveType,
};
pub use object::ObjectFilter;
pub(crate) use object::{
    ObjectQueryArgs, ObjectQueryFragment, ObjectsQueryArgs, ObjectsQueryFragment,
};
pub use packages::MovePackageQueryFragment;
pub(crate) use packages::{
    LatestPackageQueryFragment, MovePackageVersionFilter, PackageArgs, PackageCheckpointFilter,
    PackageQueryFragment, PackageVersionsArgs, PackageVersionsQueryFragment, PackagesQueryArgs,
    PackagesQueryFragment,
};
pub use protocol_config::{ProtocolConfigAttr, ProtocolConfigFeatureFlag, ProtocolConfigs};
pub(crate) use protocol_config::{ProtocolConfigQueryFragment, ProtocolVersionArgs};
use serde_json::Value as JsonValue;
pub(crate) use service_config::ServiceConfigQueryFragment;
pub use service_config::{Feature, ServiceConfig};
pub(crate) use subscriptions::{
    EventSubscriptionPayload, EventsSubscription, EventsSubscriptionArgs,
    TransactionBlockSubscriptionPayload, TransactionsSubscription, TransactionsSubscriptionArgs,
};
pub use subscriptions::{SubscriptionEventFilter, SubscriptionTransactionFilter};
pub(crate) use transaction::{
    AddressTransactionBlocksQueryFragment, AddressTransactionsQueryArgs,
    AddressTransactionsQueryFragment, TransactionBlockArgs,
    TransactionBlockCheckpointQueryFragment, TransactionBlockEffectsQueryFragment,
    TransactionBlockIndexedQueryFragment, TransactionBlockQueryFragment,
    TransactionBlockWithEffectsQueryFragment, TransactionBlocksEffectsQueryFragment,
    TransactionBlocksQueryArgs, TransactionBlocksQueryFragment,
    TransactionBlocksWithEffectsQueryFragment,
};
pub use transaction::{
    AddressTransactionRelationship, TransactionBlockKindInput, TransactionsFilter,
    TransactionsSelector,
};

use crate::error;

#[cynic::schema("rpc")]
pub mod schema {}

// ===========================================================================
// Scalars
// ===========================================================================

impl_scalar!(Address, schema::IotaAddress);
impl_scalar!(ObjectId, schema::IotaAddress);
impl_scalar!(u64, schema::UInt53);
impl_scalar!(JsonValue, schema::JSON);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "Base64")]
pub struct Base64(pub String);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "BigInt")]
pub struct BigInt(pub String);

#[derive(Clone, cynic::Scalar, Debug)]
#[cynic(graphql_type = "DateTime")]
pub struct DateTime(pub String);

#[derive(Clone, cynic::Scalar, Debug, derive_more::From)]
#[cynic(graphql_type = "MoveData")]
pub struct MoveData(pub serde_json::Value);

// ===========================================================================
// Types used in several queries
// ===========================================================================

#[derive(Clone, Copy, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub struct GraphQLAddress {
    pub address: Address,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub struct MoveObject {
    pub bcs: Option<Base64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub(crate) struct MoveObjectContents {
    pub contents: Option<MoveValue>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub(crate) struct MoveValue {
    #[cynic(rename = "type")]
    pub move_type: MoveType,
    pub bcs: Base64,
    pub json: Option<JsonValue>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveType")]
pub struct MoveType {
    pub repr: String,
}

// ===========================================================================
// Utility Types
// ===========================================================================

#[derive(Clone, cynic::QueryFragment, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "PageInfo")]
/// Information about pagination in a connection.
pub struct PageInfo {
    /// When paginating backwards, are there more items?
    pub has_previous_page: bool,
    /// Are there more items when paginating forwards?
    pub has_next_page: bool,
    /// When paginating backwards, the cursor to continue.
    pub start_cursor: Option<String>,
    /// When paginating forwards, the cursor to continue.
    pub end_cursor: Option<String>,
}

impl TryFrom<BigInt> for u64 {
    type Error = error::GraphQLError;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(value.0.parse::<u64>()?)
    }
}
