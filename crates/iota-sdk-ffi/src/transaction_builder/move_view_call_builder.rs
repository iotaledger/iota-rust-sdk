// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use crate::{
    error::Result,
    graphql::client::GraphQLClient,
    transaction_builder::move_view_arg::MoveViewArg,
    types::{move_core::TypeTag, object::ObjectId},
};

/// A builder for calling a Move view function. Use `with_client` to get a
/// builder that can execute the call.
#[derive(Debug, derive_more::From, uniffi::Object)]
#[uniffi::export(Debug)]
pub struct MoveViewCallBuilder(RwLock<iota_sdk::transaction_builder::MoveViewCallBuilder<()>>);

impl MoveViewCallBuilder {
    fn read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&iota_sdk::transaction_builder::MoveViewCallBuilder<()>) -> T,
    {
        let lock = self.0.read().expect("error reading from builder");
        f(&lock)
    }

    fn write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut iota_sdk::transaction_builder::MoveViewCallBuilder<()>) -> T,
    {
        let mut lock = self.0.write().expect("error writing to builder");
        f(&mut lock)
    }
}

#[uniffi::export]
impl MoveViewCallBuilder {
    /// Create a new builder for the given package, module, and function.
    #[uniffi::constructor]
    pub fn new(package: &ObjectId, module: String, function: String) -> Self {
        Self(
            iota_sdk::transaction_builder::MoveViewCallBuilder::new(**package, module, function)
                .into(),
        )
    }

    /// Set the client the call is executed with.
    pub fn with_client(&self, client: Arc<GraphQLClient>) -> ClientMoveViewCallBuilder {
        ClientMoveViewCallBuilder(
            self.read(|builder| builder.clone().with_client(client))
                .into(),
        )
    }

    /// Set the call arguments, replacing the ones set so far.
    pub fn arguments(self: Arc<Self>, arguments: Vec<Arc<MoveViewArg>>) -> Arc<Self> {
        self.write(|builder| {
            builder.json_arguments(arguments.iter().map(|arg| arg.to_json()));
        });
        self
    }

    /// Append a single call argument.
    pub fn argument(self: Arc<Self>, argument: &MoveViewArg) -> Arc<Self> {
        self.write(|builder| {
            builder.argument(argument.to_json());
        });
        self
    }

    /// Set the call arguments as raw JSON, replacing the ones set so far.
    ///
    /// `u64` and larger integers have to be passed as JSON strings so that
    /// large values survive the round trip.
    pub fn json_arguments(self: Arc<Self>, arguments: Vec<serde_json::Value>) -> Arc<Self> {
        self.write(|builder| {
            builder.json_arguments(arguments);
        });
        self
    }

    /// Set the type arguments of the call.
    pub fn type_tags(self: Arc<Self>, type_args: Vec<Arc<TypeTag>>) -> Arc<Self> {
        self.write(|builder| {
            builder.type_tags(type_args.into_iter().map(|tag| tag.0.clone()));
        });
        self
    }

    /// The fully qualified name of the function being called, as
    /// `<package_id>::<module_name>::<function_name>`.
    pub fn function_name(&self) -> String {
        self.read(|builder| builder.function_name())
    }

    /// The type arguments set so far.
    pub fn get_type_arguments(&self) -> Vec<Arc<TypeTag>> {
        self.read(|builder| {
            builder
                .get_type_arguments()
                .iter()
                .map(|tag| Arc::new(tag.clone().into()))
                .collect()
        })
    }

    /// The call arguments set so far, as the JSON values that are sent.
    pub fn get_arguments(&self) -> Vec<serde_json::Value> {
        self.read(|builder| builder.get_arguments().to_vec())
    }
}

/// A builder for calling a Move view function which uses a GraphQL client to
/// execute the call. Use `execute` to run it.
#[derive(derive_more::From, uniffi::Object)]
pub struct ClientMoveViewCallBuilder(
    pub RwLock<iota_sdk::transaction_builder::MoveViewCallBuilder<Arc<GraphQLClient>>>,
);

impl ClientMoveViewCallBuilder {
    fn read<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&iota_sdk::transaction_builder::MoveViewCallBuilder<Arc<GraphQLClient>>) -> T,
    {
        let lock = self.0.read().expect("error reading from builder");
        f(&lock)
    }

    fn write<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&mut iota_sdk::transaction_builder::MoveViewCallBuilder<Arc<GraphQLClient>>) -> T,
    {
        let mut lock = self.0.write().expect("error writing to builder");
        f(&mut lock)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), uniffi::export(async_runtime = "tokio"))]
#[cfg_attr(target_arch = "wasm32", uniffi::export)]
impl ClientMoveViewCallBuilder {
    /// Set the call arguments, replacing the ones set so far.
    pub fn arguments(self: Arc<Self>, arguments: Vec<Arc<MoveViewArg>>) -> Arc<Self> {
        self.write(|builder| {
            builder.json_arguments(arguments.iter().map(|arg| arg.to_json()));
        });
        self
    }

    /// Append a single call argument.
    pub fn argument(self: Arc<Self>, argument: &MoveViewArg) -> Arc<Self> {
        self.write(|builder| {
            builder.argument(argument.to_json());
        });
        self
    }

    /// Set the call arguments as raw JSON, replacing the ones set so far.
    ///
    /// `u64` and larger integers have to be passed as JSON strings so that
    /// large values survive the round trip.
    pub fn json_arguments(self: Arc<Self>, arguments: Vec<serde_json::Value>) -> Arc<Self> {
        self.write(|builder| {
            builder.json_arguments(arguments);
        });
        self
    }

    /// Set the type arguments of the call.
    pub fn type_tags(self: Arc<Self>, type_args: Vec<Arc<TypeTag>>) -> Arc<Self> {
        self.write(|builder| {
            builder.type_tags(type_args.into_iter().map(|tag| tag.0.clone()));
        });
        self
    }

    /// The fully qualified name of the function being called, as
    /// `<package_id>::<module_name>::<function_name>`.
    pub fn function_name(&self) -> String {
        self.read(|builder| builder.function_name())
    }

    /// The type arguments set so far.
    pub fn get_type_arguments(&self) -> Vec<Arc<TypeTag>> {
        self.read(|builder| {
            builder
                .get_type_arguments()
                .iter()
                .map(|tag| Arc::new(tag.clone().into()))
                .collect()
        })
    }

    /// The call arguments set so far, as the JSON values that are sent.
    pub fn get_arguments(&self) -> Vec<serde_json::Value> {
        self.read(|builder| builder.get_arguments().to_vec())
    }

    /// Execute the call and return the function's return values, formatted as
    /// JSON. The builder is left as it is, so the same call can be executed
    /// again.
    pub async fn execute(&self) -> Result<Vec<serde_json::Value>> {
        let call = self.read(|builder| builder.clone());
        Ok(call.execute().await?)
    }
}
