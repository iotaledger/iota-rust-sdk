// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for gRPC client operations.
//!
//! The gRPC API lets callers control which fields the server returns via read
//! masks. Fields that were not requested (or that the server did not populate)
//! are `None` in the corresponding record.
//!
//! Complex types (transactions, effects, events, objects, ...) are eagerly
//! deserialized from their BCS representation, so the read mask must include
//! the corresponding `bcs` sub-fields for those record fields to be
//! populated.

pub mod ledger;

/// Convert an optional list of field paths into an endpoint read mask,
/// falling back to the endpoint's default mask when no paths are given.
pub(crate) fn read_mask<M: Default + From<String>>(paths: &Option<Vec<String>>) -> M {
    match paths {
        Some(paths) => M::from(paths.join(",")),
        None => M::default(),
    }
}
