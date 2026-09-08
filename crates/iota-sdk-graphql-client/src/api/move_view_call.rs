// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cynic::QueryBuilder;
use iota_types::{Address, ObjectId, ObjectReference, TypeTag};

use crate::{
    Client,
    error::Result,
    query_types::{MoveViewCallArgs, MoveViewCallQuery, MoveViewResult},
};

impl Client {
    /// Execute a Move View Function with raw JSON arguments.
    ///
    /// This is an alternative to [`Client::move_view_call`] that accepts raw
    /// JSON values instead of typed arguments.
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
    pub async fn move_view_call_json(
        &self,
        function_name: impl Into<String>,
        type_arguments: impl Into<Option<Vec<String>>>,
        arguments: impl Into<Option<Vec<serde_json::Value>>>,
    ) -> Result<MoveViewResult> {
        let operation = MoveViewCallQuery::build(MoveViewCallArgs {
            function_name: function_name.into(),
            type_arguments: type_arguments.into(),
            arguments: arguments.into(),
        });
        let response = self.run_query(&operation).await?;

        Ok(response.move_view_call)
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
    /// # Example
    /// ```rust,ignore
    /// // The `view_demo` package published on testnet, and the shared
    /// // `view_demo::shop::Shop` created when it was published.
    /// let package = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";
    /// let shop = ObjectId::from_str(
    ///     "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20",
    /// )?;
    ///
    /// // Single argument: wrap in a list or tuple
    /// let result = client
    ///     .move_view_call(format!("{package}::shop::total_revenue"), None, (shop,))
    ///     .await?;
    /// ```
    ///
    /// # Returns
    /// A `MoveViewResult` containing either execution results (return values)
    /// or an error.
    pub async fn move_view_call<A: MoveViewArgList>(
        &self,
        function_name: impl Into<String>,
        type_arguments: impl Into<Option<Vec<TypeTag>>>,
        arguments: A,
    ) -> Result<MoveViewResult> {
        let type_args_strings = type_arguments
            .into()
            .map(|tags| tags.into_iter().map(|t| t.to_string()).collect());
        self.move_view_call_json(
            function_name,
            type_args_strings,
            Some(arguments.to_json_vec()),
        )
        .await
    }
}

/// A trait which defines a single argument for a Move View Function call.
#[diagnostic::on_unimplemented(message = "Provided value is not a valid Move view argument.")]
pub trait MoveViewArg {
    /// Convert this argument to a JSON value for the GraphQL API.
    fn to_json(self) -> serde_json::Value;
}

// Macro for types that convert to JSON Number
macro_rules! impl_move_view_arg_number {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MoveViewArg for $ty {
                fn to_json(self) -> serde_json::Value {
                    serde_json::Value::Number(self.into())
                }
            }

            impl MoveViewArg for &$ty {
                fn to_json(self) -> serde_json::Value {
                    (*self).to_json()
                }
            }
        )*
    };
}

// Macro for types that convert to JSON String via to_string()
macro_rules! impl_move_view_arg_string {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MoveViewArg for $ty {
                fn to_json(self) -> serde_json::Value {
                    serde_json::Value::String(self.to_string())
                }
            }

            impl MoveViewArg for &$ty {
                fn to_json(self) -> serde_json::Value {
                    (*self).to_json()
                }
            }
        )*
    };
}

impl MoveViewArg for bool {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Bool(self)
    }
}

impl MoveViewArg for &bool {
    fn to_json(self) -> serde_json::Value {
        (*self).to_json()
    }
}

impl_move_view_arg_number!(u8, u16, u32);

// u64 and u128 must be represented as strings in JSON to avoid precision loss
impl_move_view_arg_string!(u64, u128, ObjectId, Address);

impl MoveViewArg for &str {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String((*self).to_owned())
    }
}

impl MoveViewArg for String {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self)
    }
}

impl MoveViewArg for &String {
    fn to_json(self) -> serde_json::Value {
        self.as_str().to_json()
    }
}

impl MoveViewArg for ObjectReference {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self.object_id.to_string())
    }
}

impl MoveViewArg for &ObjectReference {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self.object_id.to_string())
    }
}

// Collection implementations
impl<T: MoveViewArg> MoveViewArg for Vec<T> {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.into_iter().map(|v| v.to_json()).collect())
    }
}

impl<T> MoveViewArg for &[T]
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.iter().map(|v| v.to_json()).collect())
    }
}

impl<const N: usize, T: MoveViewArg> MoveViewArg for [T; N] {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.into_iter().map(|v| v.to_json()).collect())
    }
}

impl<T: MoveViewArg> MoveViewArg for Option<T> {
    fn to_json(self) -> serde_json::Value {
        match self {
            Some(v) => v.to_json(),
            None => serde_json::Value::Null,
        }
    }
}

// Smart pointer implementations
impl<T> MoveViewArg for std::sync::Arc<T>
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        self.as_ref().to_json()
    }
}

impl<T> MoveViewArg for Box<T>
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        self.as_ref().to_json()
    }
}

// Allow passing raw JSON values
impl MoveViewArg for serde_json::Value {
    fn to_json(self) -> serde_json::Value {
        self
    }
}

/// A trait which defines a list of arguments for a Move View Function call.
#[diagnostic::on_unimplemented(
    message = "Provided value is not a valid list of Move view arguments.",
    note = "Expected a tuple, vector, array, or slice of types that implement `MoveViewArg`."
)]
pub trait MoveViewArgList {
    /// Convert the arguments to a vector of JSON values.
    fn to_json_vec(self) -> Vec<serde_json::Value>;
}

// Single element tuple implementation
impl<T: MoveViewArg> MoveViewArgList for (T,) {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        vec![self.0.to_json()]
    }
}

impl<T: MoveViewArg> MoveViewArgList for Vec<T> {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.into_iter().map(|v| v.to_json()).collect()
    }
}

impl<const N: usize, T: MoveViewArg> MoveViewArgList for [T; N] {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.into_iter().map(|v| v.to_json()).collect()
    }
}

impl<T> MoveViewArgList for &[T]
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.iter().map(|v| v.to_json()).collect()
    }
}

// Tuple implementations using a macro
macro_rules! impl_move_view_args_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> MoveViewArgList for ($($T),+)
        where $($T: MoveViewArg),+
        {
            fn to_json_vec(self) -> Vec<serde_json::Value> {
                vec![
                    $(
                        self.$n.to_json()
                    ),+
                ]
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_move_view_args_tuple, 2, 15, T);
