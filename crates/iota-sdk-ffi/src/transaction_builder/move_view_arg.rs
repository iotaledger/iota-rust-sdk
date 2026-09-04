// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::types::{address::Address, object::ObjectId};

/// An argument for a Move View Function call.
///
/// This enum represents the different types of values that can be passed
/// as arguments to a Move View Function.
#[derive(Clone, uniffi::Object)]
pub enum MoveViewArg {
    /// A boolean value.
    Bool(bool),
    /// An unsigned 8-bit integer.
    U8(u8),
    /// An unsigned 16-bit integer.
    U16(u16),
    /// An unsigned 32-bit integer.
    U32(u32),
    /// An unsigned 64-bit integer.
    U64(u64),
    /// An unsigned 128-bit integer (as string to avoid precision loss).
    U128(String),
    /// A string value.
    String(String),
    /// An object ID.
    ObjectId(iota_sdk::types::ObjectId),
    /// An address.
    Address(iota_sdk::types::Address),
    /// A vector/array of arguments.
    Vector(Vec<MoveViewArg>),
    /// An optional value (for Option types).
    Option(Option<Arc<MoveViewArg>>),
    /// A raw JSON value (as string, will be parsed).
    Json(String),
}

#[uniffi::export]
impl MoveViewArg {
    #[uniffi::constructor]
    pub fn bool(value: bool) -> Self {
        Self::Bool(value)
    }

    #[uniffi::constructor]
    pub fn u8(value: u8) -> Self {
        Self::U8(value)
    }

    #[uniffi::constructor]
    pub fn u16(value: u16) -> Self {
        Self::U16(value)
    }

    #[uniffi::constructor]
    pub fn u32(value: u32) -> Self {
        Self::U32(value)
    }

    #[uniffi::constructor]
    pub fn u64(value: u64) -> Self {
        Self::U64(value)
    }

    #[uniffi::constructor]
    pub fn u128(value: String) -> Self {
        Self::U128(value)
    }

    #[uniffi::constructor]
    pub fn string(value: String) -> Self {
        Self::String(value)
    }

    #[uniffi::constructor]
    pub fn object_id(value: &ObjectId) -> Self {
        Self::ObjectId(**value)
    }

    #[uniffi::constructor]
    pub fn address(value: &Address) -> Self {
        Self::Address(**value)
    }

    #[uniffi::constructor]
    pub fn option(value: Option<Arc<MoveViewArg>>) -> Self {
        Self::Option(value)
    }

    #[uniffi::constructor]
    pub fn null() -> Self {
        Self::Option(None)
    }

    #[uniffi::constructor]
    pub fn json(value: String) -> Self {
        Self::Json(value)
    }

    #[uniffi::constructor]
    pub fn u8_vec(values: Vec<u8>) -> Self {
        Self::Vector(values.into_iter().map(MoveViewArg::u8).collect())
    }

    #[uniffi::constructor]
    pub fn string_vec(values: Vec<String>) -> Self {
        Self::Vector(values.into_iter().map(MoveViewArg::string).collect())
    }
}

impl MoveViewArg {
    /// Convert this argument to a JSON value.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        match self {
            MoveViewArg::Bool(value) => serde_json::Value::Bool(*value),
            MoveViewArg::U8(value) => serde_json::Value::Number((*value).into()),
            MoveViewArg::U16(value) => serde_json::Value::Number((*value).into()),
            MoveViewArg::U32(value) => serde_json::Value::Number((*value).into()),
            MoveViewArg::U64(value) => serde_json::Value::String(value.to_string()),
            MoveViewArg::U128(value) => serde_json::Value::String(value.clone()),
            MoveViewArg::String(value) => serde_json::Value::String(value.clone()),
            MoveViewArg::ObjectId(value) => serde_json::Value::String(value.to_string()),
            MoveViewArg::Address(value) => serde_json::Value::String(value.to_string()),
            MoveViewArg::Vector(value) => {
                serde_json::Value::Array(value.iter().map(|v| v.to_json()).collect())
            }
            MoveViewArg::Option(value) => match value {
                Some(v) => v.to_json(),
                None => serde_json::Value::Null,
            },
            MoveViewArg::Json(value) => {
                serde_json::from_str(value).unwrap_or(serde_json::Value::String(value.clone()))
            }
        }
    }
}
