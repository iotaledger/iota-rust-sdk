// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod function;
mod module;

pub(crate) use function::{NormalizedMoveFunctionQueryArgs, NormalizedMoveFunctionQueryFragment};
pub(crate) use module::{
    MoveEnum, MoveEnumVariant, MoveField, MoveModuleIdQueryFragment, MoveStructQueryFragment,
    MoveStructTypeParameter, NormalizedMoveModuleQueryArgs, NormalizedMoveModuleQueryFragment,
};
pub use module::{MoveModuleQueryFragment, MovePackageAddress};

use crate::query_types::schema;

#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveAbility")]
pub(crate) enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveVisibility")]
pub(crate) enum MoveVisibility {
    Public,
    Private,
    Friend,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunction")]
pub(crate) struct MoveFunction {
    pub is_entry: Option<bool>,
    pub name: String,
    pub parameters: Option<Vec<OpenMoveType>>,
    #[cynic(rename = "return")]
    pub return_: Option<Vec<OpenMoveType>>,
    pub type_parameters: Option<Vec<MoveFunctionTypeParameter>>,
    pub visibility: Option<MoveVisibility>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunctionTypeParameter")]
pub(crate) struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "OpenMoveType")]
pub(crate) struct OpenMoveType {
    pub repr: String,
}
