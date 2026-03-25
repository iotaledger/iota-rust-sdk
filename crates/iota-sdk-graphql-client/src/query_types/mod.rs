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
mod move_schema;
mod move_view_call;
mod object;
mod packages;
mod protocol_config;
mod service_config;
mod transaction;

pub use active_validators::{
    ActiveValidatorSet, ActiveValidatorsQuery, ActiveValidatorsQueryArgs, EpochValidator,
    Validator, ValidatorConnection, ValidatorCredentials,
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
    IotaNamesDefaultNameLookup, IotaNamesDefaultNameQueryArgs, IotaNamesRegistrationsLookup,
    IotaNamesRegistrationsQueryArgs, NameRegistration, NameRegistrationConnection,
    ResolveIotaNamesAddressQuery, ResolveIotaNamesAddressQueryArgs,
};
pub use move_schema::{
    MoveAbility, MoveEnum, MoveEnumConnection, MoveEnumVariant, MoveField, MoveFunction,
    MoveFunctionConnection, MoveFunctionTypeParameter, MoveModule, MoveModuleConnection,
    MoveModuleRef, MoveSchemaFunctionQuery, MoveSchemaFunctionQueryArgs, MoveSchemaModuleQuery,
    MoveSchemaModuleQueryArgs, MoveStruct, MoveStructConnection, MoveStructTypeParameter,
    MoveVisibility, OpenMoveType,
};
pub use move_view_call::{MoveViewCallQuery, MoveViewCallQueryArgs, MoveViewResult};
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
    ExecuteTransactionBlockEffects, ExecuteTransactionMutation, ExecuteTransactionMutationArgs,
    ExecutionResult, TransactionBlock, TransactionBlockCheckpointQuery,
    TransactionBlockEffectsQuery, TransactionBlockFilter, TransactionBlockIndexedQuery,
    TransactionBlockKindInput, TransactionBlockQuery, TransactionBlockQueryArgs,
    TransactionBlockWithEffects, TransactionBlockWithEffectsQuery, TransactionBlocksEffectsQuery,
    TransactionBlocksQuery, TransactionBlocksQueryArgs, TransactionBlocksWithEffectsQuery,
};

#[cynic::schema("rpc")]
pub mod schema {}
