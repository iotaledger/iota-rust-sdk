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
mod execute_tx;
mod normalized_move;
mod object;
mod packages;
mod protocol_config;
mod service_config;
mod transaction;

pub use active_validators::{
    ActiveValidatorsArgs, ActiveValidatorsQuery, EpochValidator, Validator, ValidatorConnection,
    ValidatorSet,
};
pub use balance::{Balance, BalanceArgs, BalanceQuery, Owner};
pub use chain::ChainIdentifierQuery;
pub use checkpoint::{
    CheckpointArgs, CheckpointId, CheckpointQuery, CheckpointTotalTxQuery, CheckpointsArgs,
    CheckpointsQuery,
};
pub use coin::{CoinMetadata, CoinMetadataArgs, CoinMetadataQuery};
use cynic::impl_scalar;
pub use dry_run::{DryRunArgs, DryRunQuery, DryRunResult, ObjectRef, TransactionMetadata};
pub use dynamic_fields::{
    DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldName, DynamicFieldQuery,
    DynamicFieldsOwnerQuery, DynamicObjectFieldQuery,
};
pub use epoch::{Epoch, EpochArgs, EpochQuery, EpochSummaryQuery};
pub use events::{Event, EventConnection, EventFilter, EventsQuery, EventsQueryArgs};
pub use execute_tx::{ExecuteTransactionArgs, ExecuteTransactionQuery, ExecutionResult};
use iota_types::{Address, ObjectId};
pub use normalized_move::{
    MoveAbility, MoveFunction, MoveFunctionTypeParameter, MoveModule, MoveVisibility,
    NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs, NormalizedMoveModuleQuery,
    NormalizedMoveModuleQueryArgs, OpenMoveType,
};
pub use object::{
    ObjectFilter, ObjectKey, ObjectQuery, ObjectQueryArgs, ObjectsQuery, ObjectsQueryArgs,
};
pub use packages::{
    LatestPackageQuery, MovePackageConnection, MovePackageQuery, MovePackageVersionFilter,
    PackageArgs, PackageCheckpointFilter, PackageQuery, PackageVersionsArgs, PackageVersionsQuery,
    PackagesQuery, PackagesQueryArgs,
};
pub use protocol_config::{ProtocolConfigQuery, ProtocolConfigs, ProtocolVersionArgs};
use serde_json::Value as JsonValue;
pub use service_config::{Feature, ServiceConfig, ServiceConfigQuery};
pub use transaction::{
    TransactionBlock, TransactionBlockArgs, TransactionBlockEffectsQuery,
    TransactionBlockKindInput, TransactionBlockQuery, TransactionBlockWithEffects,
    TransactionBlockWithEffectsQuery, TransactionBlocksEffectsQuery, TransactionBlocksQuery,
    TransactionBlocksQueryArgs, TransactionBlocksWithEffectsQuery, TransactionsFilter,
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

#[derive(cynic::Scalar, Debug, Clone, derive_more::From)]
#[cynic(graphql_type = "Base64")]
pub struct Base64(pub String);

#[derive(cynic::Scalar, Debug, Clone, derive_more::From)]
#[cynic(graphql_type = "BigInt")]
pub struct BigInt(pub String);

#[derive(cynic::Scalar, Debug, Clone)]
#[cynic(graphql_type = "DateTime")]
pub struct DateTime(pub String);

// ===========================================================================
// Types used in several queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug, Clone, Copy)]
#[cynic(schema = "rpc", graphql_type = "Address")]
pub struct GQLAddress {
    pub address: Address,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub struct MoveObject {
    pub bcs: Option<Base64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveObject")]
pub struct MoveObjectContents {
    pub contents: Option<MoveValue>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub struct MoveValue {
    pub type_: MoveType,
    pub bcs: Base64,
    pub json: Option<JsonValue>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveType")]
pub struct MoveType {
    pub repr: String,
}
// ===========================================================================
// Utility Types
// ===========================================================================

#[derive(Clone, Default, cynic::QueryFragment, Debug)]
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
    type Error = error::Error;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(value.0.parse::<u64>()?)
    }
}
