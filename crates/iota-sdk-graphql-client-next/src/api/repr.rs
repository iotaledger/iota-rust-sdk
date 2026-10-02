// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! How a query returns what it fetches.
//!
//! A query that can return its result in more than one form takes one of
//! these as a type parameter, set through its request's methods. Each form
//! selects only the fields it is decoded from:
//!
//! ```rust,ignore
//! let object: Option<Object> = client.object(id).await?;
//! let contents: Option<serde_json::Value> = client.object(id).json().await?;
//! ```

#[cfg(feature = "move-types")]
use std::marker::PhantomData;

/// Objects as [`iota_types::Object`], decoded from their BCS. The default of
/// [`GraphQLClient::object`](crate::GraphQLClient::object) and
/// [`GraphQLClient::objects`](crate::GraphQLClient::objects).
#[derive(Clone, Copy, Debug, Default)]
pub struct Bcs;

/// Move objects as the JSON rendering of their contents.
#[derive(Clone, Copy, Debug, Default)]
pub struct Json;

/// Move objects decoded into `T`, the Rust mirror of their type.
#[cfg(feature = "move-types")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "move-types")))]
#[derive(Debug)]
pub struct Decoded<T>(PhantomData<fn() -> T>);

#[cfg(feature = "move-types")]
impl<T> Clone for Decoded<T> {
    fn clone(&self) -> Self {
        *self
    }
}

#[cfg(feature = "move-types")]
impl<T> Copy for Decoded<T> {}

/// Transactions as [`iota_types::SignedTransaction`]. The default of
/// [`GraphQLClient::transaction`](crate::GraphQLClient::transaction) and
/// [`GraphQLClient::transactions`](crate::GraphQLClient::transactions).
#[derive(Clone, Copy, Debug, Default)]
pub struct Signed;

/// Transactions' [`iota_types::TransactionEffects`] alone.
#[derive(Clone, Copy, Debug, Default)]
pub struct Effects;

/// Transactions together with their effects, as
/// [`ExecutedTransaction`](crate::ExecutedTransaction).
#[derive(Clone, Copy, Debug, Default)]
pub struct WithEffects;
