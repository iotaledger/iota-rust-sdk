// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod active_validators;
mod balance;
mod chain;
mod checkpoint;
mod coin;
mod common;
mod dry_run;
mod dynamic_fields;
mod epoch;
mod events;
mod iota_names;
mod move_view_call;
mod normalized_move;
mod object;
mod packages;
mod protocol_config;
mod service_config;
mod transaction;

pub use active_validators::{
    ActiveValidatorsQuery, ActiveValidatorsQueryArgs, EpochValidator, Validator,
    ValidatorConnection, ValidatorCredentials, ValidatorSetQuery,
};
pub use balance::{Balance, BalanceQuery, BalanceQueryArgs, Owner};
pub use chain::ChainIdentifierQuery;
pub use checkpoint::{
    CheckpointId, CheckpointQuery, CheckpointQueryArgs, CheckpointTotalTxQuery, CheckpointsQuery,
    CheckpointsQueryArgs,
};
pub use coin::{CoinMetadata, CoinMetadataQuery, CoinMetadataQueryArgs};
pub use common::*;
pub use dry_run::{
    DryRunEffect, DryRunMutation, DryRunQuery, DryRunQueryArgs, DryRunResult, DryRunReturn,
    GasCoin, Input, ObjectRef, ResultArg, TransactionArgument, TransactionMetadata,
};
pub use dynamic_fields::{
    DynamicFieldName, DynamicFieldQuery, DynamicFieldQueryArgs, DynamicFieldsOwnerQuery,
    DynamicFieldsQueryArgs, DynamicObjectFieldQuery,
};
pub use epoch::{Epoch, EpochQuery, EpochQueryArgs, EpochSummaryQuery, ValidatorSet};
pub use events::{Event, EventConnection, EventFilter, EventsQuery, EventsQueryArgs};
pub use iota_names::{
    IotaNamesAddressDefaultNameQuery, IotaNamesAddressRegistrationsQuery,
    IotaNamesDefaultNameQuery, IotaNamesDefaultNameQueryArgs, IotaNamesRegistrationsQuery,
    IotaNamesRegistrationsQueryArgs, NameRegistration, NameRegistrationConnection,
    ResolveIotaNamesAddressQuery, ResolveIotaNamesAddressQueryArgs,
};
pub use move_view_call::{MoveViewCallQuery, MoveViewCallQueryArgs, MoveViewResult};
pub use normalized_move::{
    MoveAbility, MoveEnum, MoveEnumConnection, MoveEnumVariant, MoveField, MoveFunction,
    MoveFunctionConnection, MoveFunctionTypeParameter, MoveModule, MoveModuleConnection,
    MoveModuleQuery, MoveStructConnection, MoveStructQuery, MoveStructTypeParameter,
    MoveVisibility, NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs,
    NormalizedMoveModuleQuery, NormalizedMoveModuleQueryArgs, OpenMoveType,
};
pub use object::{
    ObjectFilter, ObjectKey, ObjectQuery, ObjectQueryArgs, ObjectsQuery, ObjectsQueryArgs,
};
pub use packages::{
    LatestPackageQuery, MovePackage, MovePackageConnection, MovePackageVersionFilter,
    PackageCheckpointFilter, PackageQuery, PackageQueryArgs, PackageVersionsQuery,
    PackageVersionsQueryArgs, PackagesQuery, PackagesQueryArgs,
};
pub use protocol_config::{
    ProtocolConfigAttr, ProtocolConfigFeatureFlag, ProtocolConfigQuery, ProtocolConfigQueryArgs,
    ProtocolConfigs,
};
pub use service_config::{Feature, ServiceConfig, ServiceConfigQuery};
pub use transaction::{
    ExecuteTransactionBlockEffects, ExecuteTransactionQuery, ExecuteTransactionQueryArgs,
    ExecutionResult, TransactionBlock, TransactionBlockCheckpointQuery,
    TransactionBlockEffectsQuery, TransactionBlockFilter, TransactionBlockIndexedQuery,
    TransactionBlockKindInput, TransactionBlockQuery, TransactionBlockQueryArgs,
    TransactionBlockWithEffects, TransactionBlockWithEffectsQuery, TransactionBlocksEffectsQuery,
    TransactionBlocksQuery, TransactionBlocksQueryArgs, TransactionBlocksWithEffectsQuery,
};

#[cynic::schema("rpc")]
pub mod schema {}

// ===========================================================================
// Deprecated Aliases (backward compatibility)
// ===========================================================================

#[deprecated(note = "renamed to ActiveValidatorsQueryArgs")]
pub type ActiveValidatorsArgs<'a> = ActiveValidatorsQueryArgs<'a>;

#[deprecated(note = "renamed to BalanceQueryArgs")]
pub type BalanceArgs = BalanceQueryArgs;

#[deprecated(note = "renamed to CheckpointQueryArgs")]
pub type CheckpointArgs = CheckpointQueryArgs;

#[deprecated(note = "renamed to CheckpointsQueryArgs")]
pub type CheckpointsArgs<'a> = CheckpointsQueryArgs<'a>;

#[deprecated(note = "renamed to CoinMetadataQueryArgs")]
pub type CoinMetadataArgs<'a> = CoinMetadataQueryArgs<'a>;

#[deprecated(note = "renamed to DryRunQueryArgs")]
pub type DryRunArgs = DryRunQueryArgs;

#[deprecated(note = "renamed to DynamicFieldQueryArgs")]
pub type DynamicFieldArgs = DynamicFieldQueryArgs;

#[deprecated(note = "renamed to DynamicFieldsQueryArgs")]
pub type DynamicFieldConnectionArgs<'a> = DynamicFieldsQueryArgs<'a>;

#[deprecated(note = "renamed to EpochQueryArgs")]
pub type EpochArgs = EpochQueryArgs;

#[deprecated(note = "renamed to ExecuteTransactionQueryArgs")]
pub type ExecuteTransactionArgs = ExecuteTransactionQueryArgs;

#[deprecated(note = "renamed to IotaNamesDefaultNameQueryArgs")]
pub type IotaNamesDefaultNameArgs = IotaNamesDefaultNameQueryArgs;

#[deprecated(note = "renamed to IotaNamesRegistrationsQueryArgs")]
pub type IotaNamesRegistrationsArgs = IotaNamesRegistrationsQueryArgs;

#[deprecated(note = "renamed to MoveViewCallQueryArgs")]
pub type MoveViewCallArgs = MoveViewCallQueryArgs;

#[deprecated(note = "renamed to PackageQueryArgs")]
pub type PackageArgs = PackageQueryArgs;

#[deprecated(note = "renamed to PackageVersionsQueryArgs")]
pub type PackageVersionsArgs<'a> = PackageVersionsQueryArgs<'a>;

#[deprecated(note = "renamed to ProtocolConfigQueryArgs")]
pub type ProtocolVersionArgs = ProtocolConfigQueryArgs;

#[deprecated(note = "renamed to ResolveIotaNamesAddressQueryArgs")]
pub type ResolveIotaNamesAddressArgs = ResolveIotaNamesAddressQueryArgs;

#[deprecated(note = "renamed to TransactionBlockQueryArgs")]
pub type TransactionBlockArgs = TransactionBlockQueryArgs;

#[deprecated(note = "renamed to TransactionBlockFilter")]
pub type TransactionsFilter = TransactionBlockFilter;

#[deprecated(note = "renamed to MovePackage")]
pub type MovePackageQuery = MovePackage;
