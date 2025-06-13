// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod function;
mod module;

pub use function::{NormalizedMoveFunctionQuery, NormalizedMoveFunctionQueryArgs};
pub use module::{MoveModule, NormalizedMoveModuleQuery, NormalizedMoveModuleQueryArgs};

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
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub is_entry: Option<bool>,
    pub name: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub parameters: Option<Vec<OpenMoveType>>,
    #[cynic(rename = "return")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub return_: Option<Vec<OpenMoveType>>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub type_parameters: Option<Vec<MoveFunctionTypeParameter>>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
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
