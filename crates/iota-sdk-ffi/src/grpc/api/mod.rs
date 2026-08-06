// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod checkpoints;
pub mod coins;
pub mod dynamic_fields;
pub mod epochs;
pub mod execution;
pub mod network;
pub mod objects;
pub mod owned_objects;
pub mod package_versions;
pub mod transactions;

/// Convert an optional list of field paths into an endpoint read mask,
/// falling back to the endpoint's default mask when no paths are given.
pub(crate) fn read_mask<M: Default + From<String>>(paths: &Option<Vec<String>>) -> M {
    match paths {
        Some(paths) => M::from(paths.join(",")),
        None => M::default(),
    }
}
