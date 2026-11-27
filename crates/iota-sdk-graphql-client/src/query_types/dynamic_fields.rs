// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use iota_types::TypeTag;

use crate::{
    DynamicFieldOutput,
    error::{self, GraphQLError, GraphQLResult},
    query_types::{Address, Base64, JsonValue, MoveObjectContents, MoveValue, PageInfo, schema},
};

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "DynamicFieldConnectionArgs"
)]
pub(crate) struct DynamicFieldsOwnerQueryFragment {
    #[arguments(address: $address)]
    pub owner: Option<ObjectOwner>,
}
#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Owner",
    variables = "DynamicFieldConnectionArgs"
)]
pub(crate) struct ObjectOwner {
    #[arguments(after: $after, before: $before, first: $first, last: $last)]
    pub dynamic_fields: DynamicFieldConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DynamicFieldArgs")]
pub(crate) struct DynamicFieldQueryFragment {
    #[arguments(address: $address)]
    pub owner: Option<OwnerField>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Owner", variables = "DynamicFieldArgs")]
pub(crate) struct OwnerField {
    #[arguments(name: $name)]
    pub dynamic_field: Option<DynamicField>,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct DynamicFieldArgs {
    pub address: Address,
    pub name: DynamicFieldName,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct DynamicFieldConnectionArgs<'a> {
    pub address: Address,
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
    pub first: Option<i32>,
    pub last: Option<i32>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DynamicFieldConnection")]
pub(crate) struct DynamicFieldConnection {
    pub nodes: Vec<DynamicField>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DynamicField")]
pub(crate) struct DynamicField {
    pub value: Option<DynamicFieldValue>,
    pub name: Option<MoveValue>,
}

#[derive(cynic::InlineFragments, Debug)]
#[cynic(schema = "rpc", graphql_type = "DynamicFieldValue")]
#[non_exhaustive]
pub(crate) enum DynamicFieldValue {
    MoveObject(MoveObjectContents),
    MoveValue(MoveValue),
    #[cynic(fallback)]
    Unknown,
}

#[derive(cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "DynamicFieldName")]
pub(crate) struct DynamicFieldName {
    #[cynic(rename = "type")]
    pub type_tag: String,
    pub bcs: Base64,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Owner", variables = "DynamicFieldArgs")]
pub(crate) struct DynamicObjectField {
    #[arguments(name: $name)]
    pub dynamic_object_field: Option<DynamicField>,
}
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DynamicFieldArgs")]
pub(crate) struct DynamicObjectFieldQueryFragment {
    #[arguments(address: $address)]
    pub owner: Option<DynamicObjectField>,
}

impl DynamicFieldValue {
    /// Returns the JSON representation of the field value, if available.
    pub fn field_value_json(&self) -> Option<JsonValue> {
        match self {
            DynamicFieldValue::MoveObject(mo) => {
                mo.contents.as_ref().and_then(|mv| mv.json.clone())
            }
            DynamicFieldValue::MoveValue(mv) => mv.json.clone(),
            _ => None,
        }
    }

    /// Return the typename and bcs of this dynamic field value.
    pub fn type_bcs(&self) -> GraphQLResult<Option<crate::DynamicFieldValue>> {
        let value = match self {
            DynamicFieldValue::MoveObject(mo) => mo.contents.as_ref(),
            DynamicFieldValue::MoveValue(mv) => Some(mv),
            _ => None,
        };
        value
            .map(|v| {
                Ok(crate::DynamicFieldValue {
                    type_tag: TypeTag::from_str(&v.move_type.repr)?,
                    bcs: crate::base64::decode(&v.bcs.0)?,
                })
            })
            .transpose()
    }
}

impl DynamicField {
    /// Returns the JSON representation of the field value, if available.
    pub fn field_value_json(&self) -> Option<JsonValue> {
        self.value.as_ref().and_then(|v| v.field_value_json())
    }
}

impl TryFrom<DynamicField> for DynamicFieldOutput {
    type Error = error::GraphQLError;

    fn try_from(val: DynamicField) -> Result<Self, Self::Error> {
        let name = val
            .name
            .as_ref()
            .ok_or(GraphQLError::EmptyResponseField("dynamic field name"))?;
        Ok(DynamicFieldOutput {
            name: crate::DynamicFieldName {
                type_tag: TypeTag::from_str(&name.move_type.repr)?,
                bcs: crate::base64::decode(&name.bcs.0)?,
                json: name.json.clone(),
            },
            value_as_json: val.field_value_json(),
            value: val
                .value
                .as_ref()
                .map(|v| v.type_bcs())
                .transpose()?
                .flatten(),
        })
    }
}

#[cfg(test)]
mod tests {
    use iota_types::TypeParseError;

    use super::*;
    use crate::query_types::{MoveType, MoveValue};

    fn move_value(repr: &str, bcs: &str) -> MoveValue {
        MoveValue {
            move_type: MoveType {
                repr: repr.to_owned(),
            },
            bcs: Base64(bcs.to_owned()),
            json: None,
        }
    }

    #[test]
    fn missing_name_is_an_error() {
        let field = DynamicField {
            value: None,
            name: None,
        };
        assert!(matches!(
            DynamicFieldOutput::try_from(field),
            Err(GraphQLError::EmptyResponseField("dynamic field name"))
        ));
    }

    #[test]
    fn invalid_name_is_an_error() {
        let field = DynamicField {
            value: None,
            name: Some(move_value("not a type", "AQ==")),
        };
        assert!(matches!(
            DynamicFieldOutput::try_from(field),
            Err(GraphQLError::Parse(e)) if matches!(
                e.downcast_ref(),
                Some(TypeParseError::Parse { input, .. }) if input == "not a type"
            )
        ));

        let field = DynamicField {
            value: None,
            name: Some(move_value("u8", "not base64!")),
        };
        assert!(matches!(
            DynamicFieldOutput::try_from(field),
            Err(GraphQLError::Parse(e))
                if matches!(e.downcast_ref(), Some(base64ct::Error::InvalidEncoding))
        ));
    }

    #[test]
    fn invalid_value_is_an_error() {
        let field = DynamicField {
            value: Some(DynamicFieldValue::MoveValue(move_value(
                "not a type",
                "AQ==",
            ))),
            name: Some(move_value("u8", "AQ==")),
        };
        assert!(matches!(
            DynamicFieldOutput::try_from(field),
            Err(GraphQLError::Parse(e)) if matches!(
                e.downcast_ref(),
                Some(TypeParseError::Parse { input, .. }) if input == "not a type"
            )
        ));

        let field = DynamicField {
            value: Some(DynamicFieldValue::MoveObject(MoveObjectContents {
                contents: Some(move_value("u8", "not base64!")),
            })),
            name: Some(move_value("u8", "AQ==")),
        };
        assert!(matches!(
            DynamicFieldOutput::try_from(field),
            Err(GraphQLError::Parse(e))
                if matches!(e.downcast_ref(), Some(base64ct::Error::InvalidEncoding))
        ));
    }

    #[test]
    fn valid_field_converts() {
        let field = DynamicField {
            value: Some(DynamicFieldValue::MoveValue(move_value("u8", "Ag=="))),
            name: Some(move_value("u8", "AQ==")),
        };
        let output = DynamicFieldOutput::try_from(field).unwrap();
        assert_eq!(output.name.type_tag, TypeTag::U8);
        assert_eq!(output.name.bcs, vec![1]);
        let value = output.value.unwrap();
        assert_eq!(value.type_tag, TypeTag::U8);
        assert_eq!(value.bcs, vec![2]);
    }
}
