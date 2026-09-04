// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Builder for Move view calls.
//!
//! A view call runs a Move function annotated with `#[view]` on a node without
//! submitting a transaction, so it needs neither gas nor signatures. Any client
//! that can reach such an endpoint can drive the builder by implementing
//! [`MoveViewCallClient`].

use iota_types::{ObjectId, TypeTag};

use crate::{
    error::Error,
    types::{MoveTypes, MoveViewArg, MoveViewArgList},
};

pub mod client;

pub use client::MoveViewCallClient;

/// A builder for Move view calls, chainable via mutable references like the
/// [`TransactionBuilder`](crate::TransactionBuilder).
///
/// Arguments can be added one at a time or in bulk, typed or as raw JSON, and
/// the finished call can be executed more than once. The call is executed by
/// whichever client is passed to [`with_client`](Self::with_client); without
/// one, the builder still assembles the call for a caller that sends it
/// itself.
///
/// # Example
///
/// ```
/// # use iota_sdk_transaction_builder::TestClient;
/// use iota_sdk_transaction_builder::MoveViewCallBuilder;
/// use iota_types::ObjectId;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> eyre::Result<()> {
/// # let client = TestClient;
/// let mut call = MoveViewCallBuilder::new(ObjectId::FRAMEWORK, "shop", "discounted_price")
///     .with_client(client);
/// call.argument(100u64).argument(25u64);
///
/// let results = call.execute().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MoveViewCallBuilder<C = ()> {
    client: C,
    package: ObjectId,
    module: String,
    function: String,
    type_arguments: Vec<TypeTag>,
    arguments: Vec<serde_json::Value>,
}

impl MoveViewCallBuilder {
    /// Instantiate a new call to the given Move function.
    pub fn new(
        package: impl Into<ObjectId>,
        module: impl Into<String>,
        function: impl Into<String>,
    ) -> Self {
        Self {
            client: (),
            package: package.into(),
            module: module.into(),
            function: function.into(),
            type_arguments: Default::default(),
            arguments: Default::default(),
        }
    }

    /// Set the client the call is executed with.
    pub fn with_client<C>(self, client: C) -> MoveViewCallBuilder<C> {
        MoveViewCallBuilder {
            client,
            package: self.package,
            module: self.module,
            function: self.function,
            type_arguments: self.type_arguments,
            arguments: self.arguments,
        }
    }
}

impl<C> MoveViewCallBuilder<C> {
    /// Set the call arguments, replacing the ones set so far.
    pub fn arguments<A: MoveViewArgList>(&mut self, arguments: A) -> &mut Self {
        self.arguments = arguments.to_json_vec();
        self
    }

    /// Append a single call argument.
    ///
    /// A collection is appended as one argument, i.e. a Move vector; use
    /// [`arguments`](Self::arguments) to pass a collection as the whole
    /// argument list.
    pub fn argument<A: MoveViewArg>(&mut self, argument: A) -> &mut Self {
        self.arguments.push(argument.to_json());
        self
    }

    /// Set the call arguments as raw JSON, replacing the ones set so far.
    ///
    /// `u64` and larger integers have to be passed as JSON strings so that
    /// large values survive the round trip.
    pub fn json_arguments(
        &mut self,
        arguments: impl IntoIterator<Item = serde_json::Value>,
    ) -> &mut Self {
        self.arguments = arguments.into_iter().collect();
        self
    }

    /// Set the generic type arguments.
    pub fn generics<G: MoveTypes>(&mut self) -> &mut Self {
        self.type_arguments = G::type_tags();
        self
    }

    /// Set the type arguments manually.
    pub fn type_tags(&mut self, tags: impl IntoIterator<Item = TypeTag>) -> &mut Self {
        self.type_arguments = tags.into_iter().collect();
        self
    }

    /// The fully qualified name of the function being called, as
    /// `<package_id>::<module_name>::<function_name>`.
    pub fn function_name(&self) -> String {
        format!("{}::{}::{}", self.package, self.module, self.function)
    }

    /// The type arguments set so far.
    pub fn get_type_arguments(&self) -> &[TypeTag] {
        &self.type_arguments
    }

    /// The call arguments set so far, as the JSON values that are sent.
    pub fn get_arguments(&self) -> &[serde_json::Value] {
        &self.arguments
    }
}

impl<C: MoveViewCallClient> MoveViewCallBuilder<C> {
    /// Execute the call and return the function's return values. The builder is
    /// left as it is, so the same call can be executed again.
    pub async fn execute(&self) -> Result<Vec<serde_json::Value>, Error> {
        self.client
            .move_view_call(&self.function_name(), &self.type_arguments, &self.arguments)
            .await
            .map_err(Error::client)
    }

    /// Get the client.
    pub fn get_client(&self) -> &C {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use iota_types::Address;

    use super::*;
    use crate::TestClient;

    fn builder() -> MoveViewCallBuilder {
        MoveViewCallBuilder::new(Address::FRAMEWORK, "shop", "discounted_price")
    }

    #[test]
    fn function_name_is_fully_qualified() {
        assert_eq!(
            builder().function_name(),
            format!(
                "{}::shop::discounted_price",
                ObjectId::from(Address::FRAMEWORK)
            ),
        );
    }

    #[test]
    fn arguments_replace_and_argument_appends() {
        let mut builder = builder();
        builder.arguments((1u8, "a"));
        builder.argument(2u8);
        assert_eq!(
            builder.get_arguments(),
            [
                serde_json::json!(1),
                serde_json::json!("a"),
                serde_json::json!(2),
            ],
        );

        builder.arguments([3u8]);
        assert_eq!(builder.get_arguments(), [serde_json::json!(3)]);
    }

    #[test]
    fn a_collection_is_appended_as_a_single_argument() {
        let mut builder = builder();
        builder.argument(vec![1u8, 2]);
        assert_eq!(builder.get_arguments(), [serde_json::json!([1, 2])]);
    }

    #[test]
    fn large_integers_are_passed_as_strings() {
        let mut builder = builder();
        builder.arguments((u64::MAX, u128::MAX));
        assert_eq!(
            builder.get_arguments(),
            [
                serde_json::json!(u64::MAX.to_string()),
                serde_json::json!(u128::MAX.to_string()),
            ],
        );
    }

    #[test]
    fn json_arguments_replace_typed_ones() {
        let mut builder = builder();
        builder.argument(1u8);
        builder.json_arguments([serde_json::json!("21")]);
        assert_eq!(builder.get_arguments(), [serde_json::json!("21")]);
    }

    #[test]
    fn generics_and_type_tags_set_the_type_arguments() {
        let mut builder = builder();
        builder.generics::<(u64, String)>();
        assert_eq!(
            builder.get_type_arguments(),
            [TypeTag::U64, TypeTag::Vector(Box::new(TypeTag::U8))],
        );

        builder.type_tags([TypeTag::Bool]);
        assert_eq!(builder.get_type_arguments(), [TypeTag::Bool]);
    }

    #[tokio::test]
    async fn the_same_builder_can_be_executed_more_than_once() {
        let mut call = builder().with_client(TestClient);
        call.argument(100u64).argument(25u64);

        let expected = [serde_json::json!("100"), serde_json::json!("25")];
        assert_eq!(call.execute().await.unwrap(), expected);
        assert_eq!(call.execute().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn a_refused_call_surfaces_the_node_error() {
        struct RefusingClient;

        impl MoveViewCallClient for RefusingClient {
            type Error = crate::TestClientError;

            async fn move_view_call(
                &self,
                _function_name: &str,
                _type_arguments: &[TypeTag],
                _arguments: &[serde_json::Value],
            ) -> Result<Vec<serde_json::Value>, Self::Error> {
                Err(crate::TestClientError("not a view function".to_owned()))
            }
        }

        let error = builder()
            .with_client(RefusingClient)
            .execute()
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Client(_)));
        assert!(error.to_string().contains("not a view function"));
    }
}
