// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use cynic::QueryBuilder;
use iota_transaction_builder::types::MoveTypes;
use iota_types::{Address, ObjectId, ObjectReference, TypeTag};

use crate::{
    GraphQLClient,
    api::define_query,
    error::GraphQLResult,
    query_types::{MoveViewCallArgs, MoveViewCallQueryFragment, MoveViewResult},
};

define_query! {
    /// Query for [`GraphQLClient::move_view_call_json`]. Await it to send the
    /// request, or clone it first to send the same call again.
    #[derive(Clone)]
    pub struct MoveViewCallJsonQuery {
        client: GraphQLClient,
        function_name: String,
        type_arguments: Option<Vec<String>>,
        arguments: Option<Vec<serde_json::Value>>,
    }
    output: GraphQLResult<MoveViewResult>;
}

impl MoveViewCallJsonQuery {
    /// Set the type arguments of the Move function.
    pub fn type_arguments(mut self, type_arguments: impl Into<Option<Vec<String>>>) -> Self {
        self.type_arguments = type_arguments.into();
        self
    }

    /// Set the arguments passed into the Move function, in JSON format.
    pub fn arguments(mut self, arguments: impl Into<Option<Vec<serde_json::Value>>>) -> Self {
        self.arguments = arguments.into();
        self
    }

    async fn send(self) -> GraphQLResult<MoveViewResult> {
        let operation = MoveViewCallQueryFragment::build(MoveViewCallArgs {
            function_name: self.function_name,
            type_arguments: self.type_arguments,
            arguments: self.arguments,
        });
        let response = self.client.run_query(&operation).await?;

        Ok(response.move_view_call)
    }
}

define_query! {
    /// Query for [`GraphQLClient::move_view_call`]. Await it to send the
    /// request, or clone it first to send the same call again.
    #[derive(Clone)]
    pub struct MoveViewCallQuery {
        client: GraphQLClient,
        function_name: String,
        type_arguments: Option<Vec<TypeTag>>,
        arguments: Option<Vec<serde_json::Value>>,
    }
    output: GraphQLResult<MoveViewResult>;
}

impl MoveViewCallQuery {
    /// Set the type arguments of the Move function.
    pub fn type_arguments(mut self, type_arguments: impl Into<Option<Vec<TypeTag>>>) -> Self {
        self.type_arguments = type_arguments.into();
        self
    }

    /// Set the type arguments of the Move function from Rust types, e.g.
    /// `generics::<(u64, String)>()`.
    pub fn generics<G: MoveTypes>(mut self) -> Self {
        self.type_arguments = Some(G::type_tags());
        self
    }

    /// Set the typed arguments passed into the Move function, replacing the
    /// ones set so far. A single argument is wrapped in a list or tuple.
    pub fn arguments(mut self, arguments: impl MoveViewArgList) -> Self {
        self.arguments = Some(arguments.to_json_vec());
        self
    }

    /// Append a single typed argument passed into the Move function.
    ///
    /// A collection is appended as one argument, i.e. a Move vector; use
    /// [`arguments`](Self::arguments) to pass a collection as the whole
    /// argument list.
    pub fn argument(mut self, argument: impl MoveViewArg) -> Self {
        self.arguments
            .get_or_insert_default()
            .push(argument.to_json());
        self
    }

    async fn send(self) -> GraphQLResult<MoveViewResult> {
        let type_arguments = self
            .type_arguments
            .map(|tags| tags.into_iter().map(|t| t.to_string()).collect());
        self.client
            .move_view_call_json(self.function_name)
            .type_arguments(type_arguments)
            .arguments(self.arguments)
            .await
    }
}

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
    /// `function_name` is the Move function's fully qualified name as
    /// `<package_id>::<module_name>::<function_name>`, e.g.,
    /// `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`.
    /// Set its type arguments with
    /// [`type_arguments`](MoveViewCallJsonQuery::type_arguments) and its JSON
    /// arguments with [`arguments`](MoveViewCallJsonQuery::arguments).
    ///
    /// Resolves to a `MoveViewResult` containing either execution results
    /// (return values) or an error.
    pub fn move_view_call_json(&self, function_name: impl Into<String>) -> MoveViewCallJsonQuery {
        MoveViewCallJsonQuery {
            client: self.clone(),
            function_name: function_name.into(),
            type_arguments: None,
            arguments: None,
        }
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
    /// `function_name` is the Move function's fully qualified name as
    /// `<package_id>::<module_name>::<function_name>`, e.g.,
    /// `0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4::shop::total_revenue`.
    /// Set its typed arguments with [`arguments`](MoveViewCallQuery::arguments)
    /// and its type arguments with
    /// [`type_arguments`](MoveViewCallQuery::type_arguments).
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
    ///     .move_view_call(format!("{package}::shop::total_revenue"))
    ///     .arguments((shop,))
    ///     .await?;
    /// ```
    ///
    /// Resolves to a `MoveViewResult` containing either execution results
    /// (return values) or an error.
    pub fn move_view_call(&self, function_name: impl Into<String>) -> MoveViewCallQuery {
        MoveViewCallQuery {
            client: self.clone(),
            function_name: function_name.into(),
            type_arguments: None,
            arguments: None,
        }
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
pub trait MoveViewArgList: sealed::Sealed {
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
        impl<$($T),+> sealed::Sealed for ($($T),+) {}

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

mod sealed {
    pub trait Sealed {}

    impl<T> Sealed for (T,) {}
    impl<T> Sealed for Vec<T> {}
    impl<const N: usize, T> Sealed for [T; N] {}
    impl<T> Sealed for &[T] {}
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use iota_types::TypeTag;

    use crate::test_utils::sent_variables;

    #[tokio::test]
    async fn move_view_calls_send_the_function_type_arguments_and_arguments() {
        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client
                .move_view_call("0x2::coin::value")
                .arguments((21u64,))
                .type_arguments(vec![TypeTag::U64])
                .await;
        })
        .await;
        assert_eq!(vars["functionName"], "0x2::coin::value");
        assert_eq!(vars["typeArguments"], serde_json::json!(["u64"]));
        assert_eq!(vars["arguments"], serde_json::json!(["21"]));

        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client
                .move_view_call_json("0x2::coin::value")
                .type_arguments(vec!["u64".to_owned()])
                .arguments(vec![serde_json::json!("21")])
                .await;
        })
        .await;
        assert_eq!(vars["functionName"], "0x2::coin::value");
        assert_eq!(vars["typeArguments"], serde_json::json!(["u64"]));
        assert_eq!(vars["arguments"], serde_json::json!(["21"]));

        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client.move_view_call("0x2::coin::value").await;
        })
        .await;
        assert!(vars["typeArguments"].is_null());
        assert!(vars["arguments"].is_null());

        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client.move_view_call_json("0x2::coin::value").await;
        })
        .await;
        assert!(vars["typeArguments"].is_null());
        assert!(vars["arguments"].is_null());
    }

    #[tokio::test]
    async fn move_view_calls_append_arguments_and_take_type_arguments_from_generics() {
        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client
                .move_view_call("0x2::coin::value")
                .arguments((1u8, "a"))
                .argument(u64::MAX)
                .argument(vec![2u8, 3])
                .generics::<(u64, String)>()
                .await;
        })
        .await;
        assert_eq!(
            vars["arguments"],
            serde_json::json!([1, "a", u64::MAX.to_string(), [2, 3]])
        );
        assert_eq!(
            vars["typeArguments"],
            serde_json::json!(["u64", "vector<u8>"])
        );

        let vars = sent_variables("MoveViewCallQueryFragment", |client| async move {
            let _ = client
                .move_view_call("0x2::coin::value")
                .argument(21u64)
                .await;
        })
        .await;
        assert_eq!(vars["arguments"], serde_json::json!(["21"]));
    }
}
