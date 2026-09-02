// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Query, mutation and subscription types for the IOTA GraphQL RPC, derived
//! with `cynic`.
//!
//! Names follow the GraphQL schema:
//!
//! - A root selection is named `<Stem>Query` (or `<Stem>Subscription`) and its
//!   variables `<Stem>Args`: [`CheckpointsQuery`] takes [`CheckpointsArgs`].
//! - A fragment selecting the fields of a GraphQL type is named after that type
//!   ([`Validator`], [`Event`]), as are enums and input objects
//!   ([`TransactionBlockKindInput`], [`EventFilter`]).
//! - A fragment that only descends through one field to reach a nested fragment
//!   is named `<GraphqlType><Field>`: `OwnerDynamicField` selects `Owner,
//!   OwnerBalance.dynamicField`, `TransactionBlockEffectsCheckpoint` selects
//!   `TransactionBlockEffects.checkpoint`.
//! - When one GraphQL type has several fragments, a suffix says what sets each
//!   apart ([`TransactionBlockWithEffects`], `EpochSummary`).
//!
//! Abbreviations such as `Tx` are spelled out.

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

pub use active_validators::{
    ActiveValidatorsArgs, ActiveValidatorsQuery, EpochValidatorSet, Validator, ValidatorConnection,
    ValidatorCredentials, ValidatorSetActiveValidators,
};
pub use balance::{Balance, BalanceArgs, BalanceQuery, OwnerBalance};
pub use chain::ChainIdentifierQuery;
pub use checkpoint::{
    CheckpointArgs, CheckpointId, CheckpointQuery, CheckpointTotalTxQuery, CheckpointsArgs,
    CheckpointsQuery,
};
pub use coin::{CoinMetadata, CoinMetadataArgs, CoinMetadataQuery};
use cynic::impl_scalar;
pub use dry_run::{
    DryRunArgs, DryRunEffect, DryRunMutation, DryRunQuery, DryRunResult, DryRunReturn, GasCoin,
    Input, ObjectRef, ResultArg, TransactionArgument, TransactionMetadata,
};
pub use dynamic_fields::{
    DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldName, DynamicFieldQuery,
    DynamicFieldsOwnerQuery, DynamicObjectFieldQuery,
};
pub use epoch::{Epoch, EpochArgs, EpochQuery, EpochSummaryQuery, ValidatorSet};
pub use events::{Event, EventConnection, EventFilter, EventsArgs, EventsQuery};
pub use execute_transaction::{ExecuteTransactionArgs, ExecuteTransactionQuery, ExecutionResult};
pub use iota_names::{
    AddressIotaNamesDefaultName, AddressIotaNamesRegistrations, IotaNamesAddressDefaultNameQuery,
    IotaNamesAddressRegistrationsQuery, IotaNamesDefaultNameArgs, IotaNamesRegistrationsArgs,
    NameRegistration, NameRegistrationConnection, ResolveIotaNamesAddressArgs,
    ResolveIotaNamesAddressQuery,
};
use iota_types::{Address, ObjectId};
pub use move_view_call::{MoveViewCallArgs, MoveViewCallQuery, MoveViewResult};
pub use normalized_move::{
    MoveAbility, MoveEnum, MoveEnumConnection, MoveEnumVariant, MoveField, MoveFunction,
    MoveFunctionConnection, MoveFunctionTypeParameter, MoveModule, MoveModuleConnection,
    MoveModuleRef, MoveStruct, MoveStructConnection, MoveStructTypeParameter, MoveVisibility,
    NormalizedMoveFunctionArgs, NormalizedMoveFunctionQuery, NormalizedMoveModuleArgs,
    NormalizedMoveModuleQuery, OpenMoveType,
};
pub use object::{ObjectArgs, ObjectFilter, ObjectKey, ObjectQuery, ObjectsArgs, ObjectsQuery};
pub use packages::{
    LatestPackageQuery, MovePackage, MovePackageCheckpointFilter, MovePackageConnection,
    MovePackageVersionFilter, PackageArgs, PackageQuery, PackageVersionsArgs, PackageVersionsQuery,
    PackagesArgs, PackagesQuery,
};
pub use protocol_config::{
    ProtocolConfigArgs, ProtocolConfigAttr, ProtocolConfigFeatureFlag, ProtocolConfigQuery,
    ProtocolConfigs,
};
use serde_json::Value as JsonValue;
pub use service_config::{Feature, ServiceConfig, ServiceConfigQuery};
pub use subscriptions::{
    EventSubscriptionPayload, EventsSubscription, EventsSubscriptionArgs, Lagged,
    SubscriptionEvent, SubscriptionEventFilter, SubscriptionTransactionBlock,
    SubscriptionTransactionFilter, TransactionBlockSubscriptionPayload, TransactionsSubscription,
    TransactionsSubscriptionArgs,
};
pub use transaction::{
    TransactionBlock, TransactionBlockArgs, TransactionBlockCheckpointQuery,
    TransactionBlockEffectsQuery, TransactionBlockFilter, TransactionBlockIndexedQuery,
    TransactionBlockKindInput, TransactionBlockQuery, TransactionBlockWithEffects,
    TransactionBlockWithEffectsQuery, TransactionBlocksArgs, TransactionBlocksEffectsQuery,
    TransactionBlocksQuery, TransactionBlocksWithEffectsQuery,
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
pub struct MoveObjectContents {
    pub contents: Option<MoveValue>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveValue")]
pub struct MoveValue {
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
    type Error = error::Error;

    fn try_from(value: BigInt) -> Result<Self, Self::Error> {
        Ok(value.0.parse::<u64>()?)
    }
}

// ===========================================================================
// Deprecated aliases
// ===========================================================================

#[deprecated(note = "renamed to `MovePackage`")]
pub type MovePackageQuery = MovePackage;

#[deprecated(note = "renamed to `MoveStruct`")]
pub type MoveStructQuery = MoveStruct;

#[deprecated(note = "renamed to `MoveModuleRef`")]
pub type MoveModuleQuery = MoveModuleRef;

#[deprecated(note = "renamed to `ValidatorSetActiveValidators`")]
pub type ValidatorSetQuery = ValidatorSetActiveValidators;

#[deprecated(note = "renamed to `EpochValidatorSet`")]
pub type EpochValidator = EpochValidatorSet;

#[deprecated(note = "renamed to `AddressIotaNamesRegistrations`")]
pub type IotaNamesRegistrationsQuery = AddressIotaNamesRegistrations;

#[deprecated(note = "renamed to `AddressIotaNamesDefaultName`")]
pub type IotaNamesDefaultNameQuery = AddressIotaNamesDefaultName;

#[deprecated(note = "renamed to `OwnerBalance`")]
pub type Owner = OwnerBalance;

#[deprecated(note = "renamed to `EventsArgs`")]
pub type EventsQueryArgs<'a> = EventsArgs<'a>;

#[deprecated(note = "renamed to `ObjectArgs`")]
pub type ObjectQueryArgs = ObjectArgs;

#[deprecated(note = "renamed to `ObjectsArgs`")]
pub type ObjectsQueryArgs = ObjectsArgs;

#[deprecated(note = "renamed to `PackagesArgs`")]
pub type PackagesQueryArgs<'a> = PackagesArgs<'a>;

#[deprecated(note = "renamed to `TransactionBlocksArgs`")]
pub type TransactionBlocksQueryArgs = TransactionBlocksArgs;

#[deprecated(note = "renamed to `NormalizedMoveFunctionArgs`")]
pub type NormalizedMoveFunctionQueryArgs<'a> = NormalizedMoveFunctionArgs<'a>;

#[deprecated(note = "renamed to `NormalizedMoveModuleArgs`")]
pub type NormalizedMoveModuleQueryArgs<'a> = NormalizedMoveModuleArgs<'a>;

#[deprecated(note = "renamed to `ProtocolConfigArgs`")]
pub type ProtocolVersionArgs = ProtocolConfigArgs;

#[deprecated(note = "renamed to `TransactionBlockFilter`")]
pub type TransactionsFilter = TransactionBlockFilter;

#[deprecated(note = "renamed to `MovePackageCheckpointFilter`")]
pub type PackageCheckpointFilter = MovePackageCheckpointFilter;
