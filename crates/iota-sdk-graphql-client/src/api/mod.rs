// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! API implementations for the GraphQL client.

mod balance;
pub(crate) mod checkpoints;
pub(crate) mod coins;
mod dry_run;
pub(crate) mod dynamic_fields;
mod epochs;
pub(crate) mod events;
pub(crate) mod iota_names;
#[cfg(feature = "move-types")]
pub(crate) mod move_objects;
pub(crate) mod move_view_call;
pub(crate) mod network;
pub(crate) mod objects;
pub(crate) mod package;
pub(crate) mod transactions;

#[cfg(not(target_arch = "wasm32"))]
pub(crate) type QueryFuture<T> = futures::future::BoxFuture<'static, T>;
// The HTTP client's futures are not `Send` on wasm32.
#[cfg(target_arch = "wasm32")]
pub(crate) type QueryFuture<T> = futures::future::LocalBoxFuture<'static, T>;

/// Generate a query object: a struct that runs its query when awaited.
///
/// The struct's [`IntoFuture`](std::future::IntoFuture) boxes the future of
/// `send(self) -> $output`, which each invocation writes by hand in an
/// inherent impl.
macro_rules! define_query {
    (
        $(#[$meta:meta])*
        pub struct $name:ident $(<$generic:ident: $bound:path>)? {
            $($field:ident: $field_ty:ty),* $(,)?
        }
        output: $output:ty;
    ) => {
        $(#[$meta])*
        #[must_use]
        pub struct $name $(<$generic>)? {
            $($field: $field_ty,)*
        }

        impl $(<$generic: $bound + 'static>)? ::std::future::IntoFuture for $name $(<$generic>)? {
            type Output = $output;
            type IntoFuture = $crate::api::QueryFuture<Self::Output>;

            fn into_future(self) -> Self::IntoFuture {
                Box::pin(self.send())
            }
        }
    };
}

pub(crate) use define_query;
