// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
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
mod execute_tx;
mod iota_names;
mod move_view_call;
mod normalized_move;
mod object;
mod packages;
mod protocol_config;
mod service_config;
mod transaction;

#[allow(deprecated)]
pub use active_validators::ValidatorSetQuery;
pub use active_validators::{
    ActiveValidatorSet, ActiveValidatorsArgs, ActiveValidatorsQuery, EpochValidator, Validator,
    ValidatorConnection, ValidatorCredentials,
};
pub use balance::{Balance, BalanceArgs, BalanceQuery, Owner};
pub use chain::ChainIdentifierQuery;
pub use checkpoint::{
    CheckpointArgs, CheckpointId, CheckpointQuery, CheckpointTotalTxQuery, CheckpointsArgs,
    CheckpointsQuery,
};
pub use coin::{CoinMetadata, CoinMetadataArgs, CoinMetadataQuery};
pub use common::{
    Address, Base64, BigInt, DateTime, GQLAddress, JsonValue, MoveData, MoveObject,
    MoveObjectContents, MoveType, MoveValue, ObjectId, PageInfo,
};
pub use dry_run::{
    DryRunArgs, DryRunEffect, DryRunMutation, DryRunQuery, DryRunResult, DryRunReturn, GasCoin,
    Input, ObjectRef, ResultArg, TransactionArgument, TransactionMetadata,
};
pub use dynamic_fields::{
    DynamicFieldArgs, DynamicFieldConnectionArgs, DynamicFieldName, DynamicFieldQuery,
    DynamicFieldsOwnerQuery, DynamicObjectFieldQuery,
};
pub use epoch::{Epoch, EpochArgs, EpochQuery, EpochSummaryQuery, ValidatorSet};
pub use events::{Event, EventConnection, EventFilter, EventsQuery, EventsQueryArgs};
pub use execute_tx::{ExecuteTransactionArgs, ExecuteTransactionQuery, ExecutionResult};
pub use iota_names::{
    IotaNamesAddressDefaultNameQuery, IotaNamesAddressRegistrationsQuery, IotaNamesDefaultNameArgs,
    IotaNamesDefaultNameQuery, IotaNamesRegistrationsArgs, IotaNamesRegistrationsQuery,
    NameRegistration, NameRegistrationConnection, ResolveIotaNamesAddressArgs,
    ResolveIotaNamesAddressQuery,
};
pub use move_view_call::{MoveViewCallArgs, MoveViewCallQuery, MoveViewResult};
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
    LatestPackageQuery, MovePackageConnection, MovePackageQuery, MovePackageVersionFilter,
    PackageArgs, PackageCheckpointFilter, PackageQuery, PackageVersionsArgs, PackageVersionsQuery,
    PackagesQuery, PackagesQueryArgs,
};
pub use protocol_config::{
    ProtocolConfigAttr, ProtocolConfigFeatureFlag, ProtocolConfigQuery, ProtocolConfigs,
    ProtocolVersionArgs,
};
pub use service_config::{Feature, ServiceConfig, ServiceConfigQuery};
pub use transaction::{
    TransactionBlock, TransactionBlockArgs, TransactionBlockCheckpointQuery,
    TransactionBlockEffectsQuery, TransactionBlockIndexedQuery, TransactionBlockKindInput,
    TransactionBlockQuery, TransactionBlockWithEffects, TransactionBlockWithEffectsQuery,
    TransactionBlocksEffectsQuery, TransactionBlocksQuery, TransactionBlocksQueryArgs,
    TransactionBlocksWithEffectsQuery, TransactionsFilter,
};

#[cynic::schema("rpc")]
pub mod schema {}
