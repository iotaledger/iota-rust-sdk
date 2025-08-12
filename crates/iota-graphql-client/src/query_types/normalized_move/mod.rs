// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod function;
mod module;

pub use function::{NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs};
pub use module::{
    MoveEnum, MoveEnumConnection, MoveEnumVariant, MoveField, MoveFunctionConnection, MoveModule,
    MoveModuleConnection, MoveModuleQuery, MoveStruct, MoveStructConnection,
    MoveStructTypeParameter, NormalizedMoveModuleQuery, NormalizedMoveModuleQueryArgs,
};

use crate::query_types::schema;

#[derive(cynic::Enum, Copy, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MoveAbility")]
pub enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

#[derive(cynic::Enum, Copy, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MoveVisibility")]
pub enum MoveVisibility {
    Public,
    Private,
    Friend,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MoveFunction")]
pub struct MoveFunction {
    pub is_entry: Option<bool>,
    pub name: String,
    pub parameters: Option<Vec<OpenMoveType>>,
    #[cynic(rename = "return")]
    pub return_: Option<Vec<OpenMoveType>>,
    pub type_parameters: Option<Vec<MoveFunctionTypeParameter>>,
    pub visibility: Option<MoveVisibility>,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "MoveFunctionTypeParameter")]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

#[derive(cynic::QueryFragment, Debug, Clone)]
#[cynic(schema = "rpc", graphql_type = "OpenMoveType")]
pub struct OpenMoveType {
    pub repr: String,
}
