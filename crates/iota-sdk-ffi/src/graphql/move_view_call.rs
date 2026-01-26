// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::GraphQLClient;
use crate::{
    error::Result,
    types::{address::Address, graphql::MoveViewResult, object::ObjectId},
};

/// An argument for a Move View Function call.
///
/// This enum represents the different types of values that can be passed
/// as arguments to a Move View Function.
#[derive(uniffi::Enum)]
pub enum MoveViewArg {
    /// A boolean value.
    Bool { value: bool },
    /// An unsigned 8-bit integer.
    U8 { value: u8 },
    /// An unsigned 16-bit integer.
    U16 { value: u16 },
    /// An unsigned 32-bit integer.
    U32 { value: u32 },
    /// An unsigned 64-bit integer.
    U64 { value: u64 },
    /// An unsigned 128-bit integer (as string to avoid precision loss).
    U128 { value: String },
    /// A string value.
    Str { value: String },
    /// An object ID.
    Object { value: Arc<ObjectId> },
    /// An address.
    Addr { value: Arc<Address> },
    /// A vector/array of arguments.
    Array { value: Vec<MoveViewArg> },
    /// A null/none value (for Option::None).
    Null,
    /// A raw JSON value (as string, will be parsed).
    Json { value: String },
}

impl MoveViewArg {
    /// Convert this argument to a JSON value.
    fn to_json(&self) -> serde_json::Value {
        match self {
            MoveViewArg::Bool { value } => serde_json::Value::Bool(*value),
            MoveViewArg::U8 { value } => serde_json::Value::Number((*value).into()),
            MoveViewArg::U16 { value } => serde_json::Value::Number((*value).into()),
            MoveViewArg::U32 { value } => serde_json::Value::Number((*value).into()),
            MoveViewArg::U64 { value } => serde_json::Value::String(value.to_string()),
            MoveViewArg::U128 { value } => serde_json::Value::String(value.clone()),
            MoveViewArg::Str { value } => serde_json::Value::String(value.clone()),
            MoveViewArg::Object { value } => serde_json::Value::String(value.to_string()),
            MoveViewArg::Addr { value } => serde_json::Value::String(value.to_string()),
            MoveViewArg::Array { value } => {
                serde_json::Value::Array(value.iter().map(|v| v.to_json()).collect())
            }
            MoveViewArg::Null => serde_json::Value::Null,
            MoveViewArg::Json { value } => {
                serde_json::from_str(value).unwrap_or(serde_json::Value::String(value.clone()))
            }
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
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
    ///   `0x2::hash::blake2b256`
    /// * `type_args` - The type arguments of the Move function
    /// * `arguments` - The arguments to be passed into the Move function, in
    ///   JSON format
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    #[uniffi::method(default(type_args = None, arguments = None))]
    pub async fn move_view_call_json(
        &self,
        function_name: String,
        type_args: Option<Vec<String>>,
        arguments: Option<Vec<serde_json::Value>>,
    ) -> Result<MoveViewResult> {
        Ok(self
            .0
            .read()
            .await
            .move_view_call_json(function_name, type_args, arguments)
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
    ///   `0x2::hash::blake2b256`
    /// * `type_args` - The type arguments of the Move function
    /// * `arguments` - The typed arguments to be passed into the Move function
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    #[uniffi::method(default(type_args = None, arguments = None))]
    pub async fn move_view_call(
        &self,
        function_name: String,
        type_args: Option<Vec<String>>,
        arguments: Option<Vec<MoveViewArg>>,
    ) -> Result<MoveViewResult> {
        let arguments = arguments.map(|args| args.iter().map(|arg| arg.to_json()).collect());

        self.move_view_call_json(function_name, type_args, arguments)
            .await
    }
}
