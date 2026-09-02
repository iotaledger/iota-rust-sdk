// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod function;
mod module;

pub use function::{NormalizedMoveFunctionArgs, NormalizedMoveFunctionQuery};
pub use module::{
    MoveEnum, MoveEnumConnection, MoveEnumVariant, MoveField, MoveFunctionConnection, MoveModule,
    MoveModuleConnection, MoveModuleRef, MoveStruct, MoveStructConnection, MoveStructTypeParameter,
    NormalizedMoveModuleArgs, NormalizedMoveModuleQuery,
};

use crate::query_types::schema;

#[derive(Clone, Copy, cynic::Enum, Debug, strum::Display)]
#[cynic(schema = "rpc", graphql_type = "MoveAbility")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

#[derive(Clone, Copy, cynic::Enum, Debug, strum::Display)]
#[cynic(schema = "rpc", graphql_type = "MoveVisibility")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum MoveVisibility {
    Public,
    Private,
    Friend,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
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

impl std::fmt::Display for MoveFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vis) = self.visibility {
            write!(f, "{vis} ")?;
        }
        if self.is_entry.is_some_and(|e| e) {
            write!(f, "entry ")?;
        }
        write!(f, "{}", self.name)?;
        if let Some(type_params) = &self.type_parameters
            && !type_params.is_empty()
        {
            write!(f, "<")?;
            for (i, param) in type_params.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "T{i}")?;
                if !param.constraints.is_empty() {
                    write!(
                        f,
                        ": {}",
                        param
                            .constraints
                            .iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(" + ")
                    )?;
                }
            }
            write!(f, ">")?;
        }
        write!(f, "(")?;
        if let Some(params) = &self.parameters {
            write!(
                f,
                "{}",
                params
                    .iter()
                    .map(|v| v.repr.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }
        write!(f, ")")?;
        if let Some(return_) = &self.return_
            && !return_.is_empty()
        {
            if return_.len() > 1 {
                write!(
                    f,
                    " -> ({})",
                    return_
                        .iter()
                        .map(|v| v.repr.replace("$", "T"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )?;
            } else {
                write!(f, " -> {}", return_.first().unwrap().repr.replace("$", "T"))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "MoveFunctionTypeParameter")]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

#[derive(Clone, cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "OpenMoveType")]
pub struct OpenMoveType {
    pub repr: String,
}
