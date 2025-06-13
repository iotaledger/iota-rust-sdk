// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::query_types::{Address, MoveAbility, MoveFunction, OpenMoveType, PageInfo, schema};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "NormalizedMoveModuleQueryArgs"
)]
pub struct NormalizedMoveModuleQuery {
    #[arguments(address: $package, version: $version)]
    pub package: Option<MovePackage>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct NormalizedMoveModuleQueryArgs<'a> {
    pub package: Address,
    pub module: &'a str,
    pub version: Option<u64>,
    pub after_enums: Option<&'a str>,
    pub after_functions: Option<&'a str>,
    pub after_structs: Option<&'a str>,
    pub after_friends: Option<&'a str>,
    pub before_enums: Option<&'a str>,
    pub before_functions: Option<&'a str>,
    pub before_structs: Option<&'a str>,
    pub before_friends: Option<&'a str>,
    pub first_enums: Option<i32>,
    pub first_functions: Option<i32>,
    pub first_structs: Option<i32>,
    pub first_friends: Option<i32>,
    pub last_enums: Option<i32>,
    pub last_functions: Option<i32>,
    pub last_structs: Option<i32>,
    pub last_friends: Option<i32>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MovePackage",
    variables = "NormalizedMoveModuleQueryArgs"
)]
pub struct MovePackage {
    #[arguments(name: $module)]
    pub module: Option<MoveModule>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "MoveModule",
    variables = "NormalizedMoveModuleQueryArgs"
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveModule {
    pub file_format_version: i32,
    #[arguments(after: $after_enums, before:$before_enums, first: $first_enums, last: $last_enums)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub enums: Option<MoveEnumConnection>,
    #[arguments(after: $after_friends, before: $before_friends, first: $first_friends, last: $last_friends)]
    pub friends: MoveModuleConnection,
    #[arguments(after: $after_functions, before: $before_functions, first: $first_functions, last: $last_functions)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub functions: Option<MoveFunctionConnection>,
    #[arguments(after: $after_structs, before: $before_structs, first: $first_structs, last: $last_structs)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub structs: Option<MoveStructConnection>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveStructConnection")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveStructConnection {
    pub page_info: PageInfo,
    pub nodes: Vec<MoveStruct>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveStruct")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveStruct {
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub fields: Option<Vec<MoveField>>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveModuleConnection")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveModuleConnection {
    pub nodes: Vec<MoveModule2>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveModule")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveModule2 {
    pub name: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunctionConnection")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveFunctionConnection {
    pub nodes: Vec<MoveFunction>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveEnumConnection")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveEnumConnection {
    pub nodes: Vec<MoveEnum>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveEnum")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveEnum {
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub variants: Option<Vec<MoveEnumVariant>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveEnumVariant")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveEnumVariant {
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub fields: Option<Vec<MoveField>>,
    pub name: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveField")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveField {
    pub name: String,
    #[cynic(rename = "type")]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub type_: Option<OpenMoveType>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveStructTypeParameter")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MoveStructTypeParameter {
    pub constraints: Vec<MoveAbility>,
    pub is_phantom: bool,
}
