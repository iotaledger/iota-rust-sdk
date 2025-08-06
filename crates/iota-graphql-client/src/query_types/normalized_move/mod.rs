// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod function;
mod module;

pub use function::{NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs};
pub use module::{
    MoveModule, MoveModuleQuery, NormalizedMoveModuleQuery, NormalizedMoveModuleQueryArgs,
};

use crate::query_types::schema;

#[derive(cynic::Enum, Clone, Copy, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveAbility")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

#[derive(cynic::Enum, Clone, Copy, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveVisibility")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MoveVisibility {
    Public,
    Private,
    Friend,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunction")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveFunction {
    pub is_entry: Option<bool>,
    pub name: String,
    pub parameters: Option<Vec<OpenMoveType>>,
    #[cynic(rename = "return")]
    pub return_: Option<Vec<OpenMoveType>>,
    pub type_parameters: Option<Vec<MoveFunctionTypeParameter>>,
    pub visibility: Option<MoveVisibility>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunctionTypeParameter")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "OpenMoveType")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OpenMoveType {
    pub repr: String,
}
