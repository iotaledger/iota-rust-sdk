// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::{
    error::Result,
    graphql::{client::GraphQLClient, query_types::MoveViewResult},
    types::{address::Address, move_core::TypeTag, object::ObjectId},
};

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
    fn to_json(&self) -> serde_json::Value {
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

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl GraphQLClient {
    /// Execute a Move View Function with raw JSON arguments.
    ///
    /// This is an alternative to [`GraphQLClient::move_view_call`] that accepts
    /// raw JSON values instead of typed arguments.
    ///
    /// A View Function is a function in a Move module with a return type that
    /// does not alter the state of the ledger. When using this interface,
    /// no transactions are submitted to the network for inclusion into the
    /// ledger.
    ///
    /// # Arguments
    /// * `function_name` - The Move function fully qualified name as
    ///   `<package_id>::<module_name>::<function_name>`, e.g.,
    ///   `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The arguments to be passed into the Move function, in
    ///   JSON format
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    #[uniffi::method(default(type_arguments = None, arguments = None))]
    pub async fn move_view_call_json(
        &self,
        function_name: String,
        type_arguments: Option<Vec<String>>,
        arguments: Option<Vec<serde_json::Value>>,
    ) -> Result<MoveViewResult> {
        Ok(self
            .0
            .read()
            .await
            .move_view_call_json(function_name, type_arguments, arguments)
            .await?
            .into())
    }

    /// Execute a Move View Function.
    ///
    /// A View Function is a function in a Move module with a return type that
    /// does not alter the state of the ledger. When using this interface,
    /// no transactions are submitted to the network for inclusion into the
    /// ledger.
    ///
    /// This method allows calling nearly any Move function with a return type
    /// and any arguments. The function's result values are provided and
    /// decoded using the appropriate Move type, then formatted in JSON.
    ///
    /// The use of this interface does not require signature checks (even for
    /// functions that take Owned Objects as input) or gas coins, as it does
    /// not alter ledger state. Spam attacks are dealt with at the RPC level
    /// rather than execution level.
    ///
    /// # Arguments
    /// * `function_name` - The Move function fully qualified name as
    ///   `<package_id>::<module_name>::<function_name>`, e.g.,
    ///   `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`
    /// * `type_arguments` - The type arguments of the Move function
    /// * `arguments` - The typed arguments to be passed into the Move function
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    #[uniffi::method(default(type_arguments = None, arguments = None))]
    pub async fn move_view_call(
        &self,
        function_name: String,
        type_arguments: Option<Vec<Arc<TypeTag>>>,
        arguments: Option<Vec<Arc<MoveViewArg>>>,
    ) -> Result<MoveViewResult> {
        let arguments = arguments.map(|args| args.iter().map(|arg| arg.to_json()).collect());
        let type_arguments =
            type_arguments.map(|tags| tags.iter().map(|t| t.to_string()).collect());

        self.move_view_call_json(function_name, type_arguments, arguments)
            .await
    }
}
