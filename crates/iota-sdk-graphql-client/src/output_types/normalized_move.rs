// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::Address;

use crate::{Page, query_types};

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
pub struct OpenMoveType {
    pub repr: String,
}

/// A type parameter of a Move function, with the abilities it is constrained
/// to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveFunctionTypeParameter {
    pub constraints: Vec<MoveAbility>,
}

/// A type parameter of a Move struct or enum, with the abilities it is
/// constrained to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveStructTypeParameter {
    pub constraints: Vec<MoveAbility>,
    pub is_phantom: bool,
}

/// The signature of a Move function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveFunction {
    pub is_entry: Option<bool>,
    pub name: String,
    pub parameters: Option<Vec<OpenMoveType>>,
    pub return_: Option<Vec<OpenMoveType>>,
    pub type_parameters: Option<Vec<MoveFunctionTypeParameter>>,
    pub visibility: Option<MoveVisibility>,
}

/// A field of a Move struct or enum variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveField {
    pub name: String,
    pub move_type: Option<OpenMoveType>,
}

/// A Move struct definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveStruct {
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    pub fields: Option<Vec<MoveField>>,
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
}

/// A Move enum definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveEnum {
    pub abilities: Option<Vec<MoveAbility>>,
    pub name: String,
    pub type_parameters: Option<Vec<MoveStructTypeParameter>>,
    pub variants: Option<Vec<MoveEnumVariant>>,
}

/// A variant of a Move enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveEnumVariant {
    pub fields: Option<Vec<MoveField>>,
    pub name: String,
}

/// A Move module identified by its package and name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MoveModuleId {
    pub package: Address,
    pub name: String,
}

/// The normalized contents of a Move module. Each list is one page of the
/// module's items.
#[derive(Clone, Debug)]
pub struct MoveModule {
    pub file_format_version: i32,
    pub enums: Option<Page<MoveEnum>>,
    pub friends: Page<MoveModuleId>,
    pub functions: Option<Page<MoveFunction>>,
    pub structs: Option<Page<MoveStruct>>,
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

fn map_vec<T, U: From<T>>(v: Option<Vec<T>>) -> Option<Vec<U>> {
    v.map(|v| v.into_iter().map(Into::into).collect())
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
            constraints: value.constraints.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<query_types::MoveStructTypeParameter> for MoveStructTypeParameter {
    fn from(value: query_types::MoveStructTypeParameter) -> Self {
        Self {
            constraints: value.constraints.into_iter().map(Into::into).collect(),
            is_phantom: value.is_phantom,
        }
    }
}

impl From<query_types::MoveFunction> for MoveFunction {
    fn from(value: query_types::MoveFunction) -> Self {
        Self {
            is_entry: value.is_entry,
            name: value.name,
            parameters: map_vec(value.parameters),
            return_: map_vec(value.return_),
            type_parameters: map_vec(value.type_parameters),
            visibility: value.visibility.map(Into::into),
        }
    }
}

impl From<query_types::MoveField> for MoveField {
    fn from(value: query_types::MoveField) -> Self {
        Self {
            name: value.name,
            move_type: value.move_type.map(Into::into),
        }
    }
}

impl From<query_types::MoveStructQuery> for MoveStruct {
    fn from(value: query_types::MoveStructQuery) -> Self {
        Self {
            abilities: map_vec(value.abilities),
            name: value.name,
            fields: map_vec(value.fields),
            type_parameters: map_vec(value.type_parameters),
        }
    }
}

impl From<query_types::MoveEnum> for MoveEnum {
    fn from(value: query_types::MoveEnum) -> Self {
        Self {
            abilities: map_vec(value.abilities),
            name: value.name,
            type_parameters: map_vec(value.type_parameters),
            variants: map_vec(value.variants),
        }
    }
}

impl From<query_types::MoveEnumVariant> for MoveEnumVariant {
    fn from(value: query_types::MoveEnumVariant) -> Self {
        Self {
            fields: map_vec(value.fields),
            name: value.name,
        }
    }
}

impl From<query_types::MoveModuleIdQuery> for MoveModuleId {
    fn from(value: query_types::MoveModuleIdQuery) -> Self {
        Self {
            package: value.package.address,
            name: value.name,
        }
    }
}

impl From<query_types::MoveModule> for MoveModule {
    fn from(value: query_types::MoveModule) -> Self {
        Self {
            file_format_version: value.file_format_version,
            enums: value
                .enums
                .map(|c| Page::new(c.page_info, c.nodes).map(Into::into)),
            friends: Page::new(value.friends.page_info, value.friends.nodes).map(Into::into),
            functions: value
                .functions
                .map(|c| Page::new(c.page_info, c.nodes).map(Into::into)),
            structs: value
                .structs
                .map(|c| Page::new(c.page_info, c.nodes).map(Into::into)),
        }
    }
}
