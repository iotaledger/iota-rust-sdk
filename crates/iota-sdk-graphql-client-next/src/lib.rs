// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![warn(missing_docs)]

mod api;
mod client;
mod client_api;
mod error;
mod pagination;
mod query;
mod retry;
mod time;
pub mod transport;
mod version;
mod wire;

pub use cynic;
pub use iota_client_api;
pub use iota_types;

pub use self::{
    api::*,
    client::{ClientBuilder, GraphQLClient, USER_AGENT},
    error::{
        Error, MalformedResponse, Result, ServerError, ServerErrors, TransportError,
        TransportErrorKind,
    },
    pagination::{Cursor, Page, PageArgs, Paginated},
    query::{Query, Request},
    retry::RetryPolicy,
    version::ServerVersion,
};
