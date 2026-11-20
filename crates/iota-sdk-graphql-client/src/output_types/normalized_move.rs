// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Address;

use crate::{
    error::{GraphQLError, GraphQLResult},
    query_types,
};

/// An ability a Move type can have.
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum MoveAbility {
    Copy,
    Drop,
    Key,
    Store,
}

/// The visibility of a Move function.
#[derive(Clone, Copy, Debug, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum MoveVisibility {
    Public,
    Private,
    Friend,
}

/// A Move type that may still have unbound type parameters, which are
/// rendered as `$0`, `$1`, ...
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OpenMoveType {
    pub repr: String,
}

/// A type parameter of a Move function, with the abilities it is constrained
/// to.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

/// A type parameter of a Move struct or enum, with the abilities it is
/// constrained to.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveStructTypeParameter {
    pub constraints: Vec<MoveAbility>,
    pub is_phantom: bool,
}

/// The signature of a Move function.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveFunction {
    pub is_entry: bool,
    pub name: String,
    pub parameters: Vec<OpenMoveType>,
    pub return_: Vec<OpenMoveType>,
    pub type_parameters: Vec<MoveFunctionTypeParameter>,
    pub visibility: MoveVisibility,
}

/// A field of a Move struct or enum variant.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveField {
    pub name: String,
    pub move_type: OpenMoveType,
}

/// A Move struct definition.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveStruct {
    pub abilities: Vec<MoveAbility>,
    pub name: String,
    pub fields: Vec<MoveField>,
    pub type_parameters: Vec<MoveStructTypeParameter>,
}

/// A Move enum definition.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveEnum {
    pub abilities: Vec<MoveAbility>,
    pub name: String,
    pub type_parameters: Vec<MoveStructTypeParameter>,
    pub variants: Vec<MoveEnumVariant>,
}

/// A variant of a Move enum.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveEnumVariant {
    pub fields: Vec<MoveField>,
    pub name: String,
}

/// A Move module identified by its package and name.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveModuleId {
    pub package: Address,
    pub name: String,
}

/// The normalized contents of a Move module.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveModule {
    pub file_format_version: i32,
    pub enums: Vec<MoveEnum>,
    pub friends: Vec<MoveModuleId>,
    pub functions: Vec<MoveFunction>,
    pub structs: Vec<MoveStruct>,
}

impl std::fmt::Display for MoveFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.visibility)?;
        if self.is_entry {
            write!(f, "entry ")?;
        }
        write!(f, "{}", self.name)?;
        if !self.type_parameters.is_empty() {
            write!(f, "<")?;
            for (i, param) in self.type_parameters.iter().enumerate() {
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
        write!(f, "({})", type_list(&self.parameters))?;
        match self.return_.as_slice() {
            [] => {}
            [return_] => write!(f, " -> {}", type_list(std::slice::from_ref(return_)))?,
            return_ => write!(f, " -> ({})", type_list(return_))?,
        }
        Ok(())
    }
}

/// Join `types` with `, `, naming type parameters `T0`, `T1`, ... as in the
/// function's type parameter list.
fn type_list(types: &[OpenMoveType]) -> String {
    types
        .iter()
        .map(|v| v.repr.replace('$', "T"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Unwrap a field the schema marks nullable but the server always sets.
fn required<T>(value: Option<T>, field: &'static str) -> GraphQLResult<T> {
    value.ok_or(GraphQLError::EmptyResponseField(field))
}

fn map_vec<T, U: From<T>>(v: Vec<T>) -> Vec<U> {
    v.into_iter().map(Into::into).collect()
}

fn try_map_vec<T, U: TryFrom<T, Error = GraphQLError>>(v: Vec<T>) -> GraphQLResult<Vec<U>> {
    v.into_iter().map(TryInto::try_into).collect()
}

impl From<query_types::MoveAbility> for MoveAbility {
    fn from(value: query_types::MoveAbility) -> Self {
        match value {
            query_types::MoveAbility::Copy => Self::Copy,
            query_types::MoveAbility::Drop => Self::Drop,
            query_types::MoveAbility::Key => Self::Key,
            query_types::MoveAbility::Store => Self::Store,
        }
    }
}

impl From<query_types::MoveVisibility> for MoveVisibility {
    fn from(value: query_types::MoveVisibility) -> Self {
        match value {
            query_types::MoveVisibility::Public => Self::Public,
            query_types::MoveVisibility::Private => Self::Private,
            query_types::MoveVisibility::Friend => Self::Friend,
        }
    }
}

impl From<query_types::OpenMoveType> for OpenMoveType {
    fn from(value: query_types::OpenMoveType) -> Self {
        Self { repr: value.repr }
    }
}

impl From<query_types::MoveFunctionTypeParameter> for MoveFunctionTypeParameter {
    fn from(value: query_types::MoveFunctionTypeParameter) -> Self {
        Self {
            constraints: map_vec(value.constraints),
        }
    }
}

impl From<query_types::MoveStructTypeParameter> for MoveStructTypeParameter {
    fn from(value: query_types::MoveStructTypeParameter) -> Self {
        Self {
            constraints: map_vec(value.constraints),
            is_phantom: value.is_phantom,
        }
    }
}

impl TryFrom<query_types::MoveFunction> for MoveFunction {
    type Error = GraphQLError;

    fn try_from(value: query_types::MoveFunction) -> GraphQLResult<Self> {
        Ok(Self {
            is_entry: required(value.is_entry, "move function isEntry")?,
            name: value.name,
            parameters: map_vec(required(value.parameters, "move function parameters")?),
            return_: map_vec(required(value.return_, "move function return")?),
            type_parameters: map_vec(required(
                value.type_parameters,
                "move function typeParameters",
            )?),
            visibility: required(value.visibility, "move function visibility")?.into(),
        })
    }
}

impl TryFrom<query_types::MoveField> for MoveField {
    type Error = GraphQLError;

    fn try_from(value: query_types::MoveField) -> GraphQLResult<Self> {
        Ok(Self {
            name: value.name,
            move_type: required(value.move_type, "move field type")?.into(),
        })
    }
}

impl TryFrom<query_types::MoveStructQueryFragment> for MoveStruct {
    type Error = GraphQLError;

    fn try_from(value: query_types::MoveStructQueryFragment) -> GraphQLResult<Self> {
        Ok(Self {
            abilities: map_vec(required(value.abilities, "move struct abilities")?),
            name: value.name,
            fields: try_map_vec(required(value.fields, "move struct fields")?)?,
            type_parameters: map_vec(required(
                value.type_parameters,
                "move struct typeParameters",
            )?),
        })
    }
}

impl TryFrom<query_types::MoveEnum> for MoveEnum {
    type Error = GraphQLError;

    fn try_from(value: query_types::MoveEnum) -> GraphQLResult<Self> {
        Ok(Self {
            abilities: map_vec(required(value.abilities, "move enum abilities")?),
            name: value.name,
            type_parameters: map_vec(required(value.type_parameters, "move enum typeParameters")?),
            variants: try_map_vec(required(value.variants, "move enum variants")?)?,
        })
    }
}

impl TryFrom<query_types::MoveEnumVariant> for MoveEnumVariant {
    type Error = GraphQLError;

    fn try_from(value: query_types::MoveEnumVariant) -> GraphQLResult<Self> {
        Ok(Self {
            fields: try_map_vec(required(value.fields, "move enum variant fields")?)?,
            name: value.name,
        })
    }
}

impl From<query_types::MoveModuleIdQueryFragment> for MoveModuleId {
    fn from(value: query_types::MoveModuleIdQueryFragment) -> Self {
        Self {
            package: value.package.address,
            name: value.name,
        }
    }
}

impl MoveModule {
    pub(crate) fn try_from_parts(
        file_format_version: i32,
        enums: Vec<query_types::MoveEnum>,
        friends: Vec<query_types::MoveModuleIdQueryFragment>,
        functions: Vec<query_types::MoveFunction>,
        structs: Vec<query_types::MoveStructQueryFragment>,
    ) -> GraphQLResult<Self> {
        Ok(Self {
            file_format_version,
            enums: try_map_vec(enums)?,
            friends: map_vec(friends),
            functions: try_map_vec(functions)?,
            structs: try_map_vec(structs)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_display_names_type_parameters_alike_in_parameters_and_return() {
        let repr = |repr: &str| OpenMoveType {
            repr: repr.to_owned(),
        };
        let function = MoveFunction {
            is_entry: true,
            name: "swap".to_owned(),
            parameters: vec![repr("$0"), repr("vector<$1>")],
            return_: vec![repr("$1"), repr("$0")],
            type_parameters: vec![
                MoveFunctionTypeParameter {
                    constraints: vec![MoveAbility::Copy, MoveAbility::Drop],
                },
                MoveFunctionTypeParameter {
                    constraints: Vec::new(),
                },
            ],
            visibility: MoveVisibility::Public,
        };

        assert_eq!(
            function.to_string(),
            "public entry swap<T0: copy + drop, T1>(T0, vector<T1>) -> (T1, T0)"
        );
    }
}
