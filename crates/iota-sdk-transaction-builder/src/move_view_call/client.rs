// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The client interface used to execute Move view calls.

use iota_types::TypeTag;

/// A trait which defines the method needed from the client for the
/// [`MoveViewCallBuilder`](crate::MoveViewCallBuilder).
pub trait MoveViewCallClient {
    /// The error type for this client.
    type Error: 'static + std::error::Error + Send + Sync;

    /// Call a Move view function and return its return values, resolved and
    /// formatted as JSON.
    ///
    /// The arguments are the JSON encoding of the Move values the function
    /// takes, where `u64` and larger integers are encoded as strings. A view
    /// function the node refused to run is reported through `Self::Error`, like
    /// any other failed call.
    fn move_view_call(
        &self,
        function_name: &str,
        type_arguments: &[TypeTag],
        arguments: &[serde_json::Value],
    ) -> impl std::future::Future<Output = Result<Vec<serde_json::Value>, Self::Error>>;
}

impl<T: MoveViewCallClient> MoveViewCallClient for &T {
    type Error = T::Error;

    fn move_view_call(
        &self,
        function_name: &str,
        type_arguments: &[TypeTag],
        arguments: &[serde_json::Value],
    ) -> impl std::future::Future<Output = Result<Vec<serde_json::Value>, Self::Error>> {
        (*self).move_view_call(function_name, type_arguments, arguments)
    }
}
