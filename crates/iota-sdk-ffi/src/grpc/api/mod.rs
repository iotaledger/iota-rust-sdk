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

/// Convert an optional list of field paths into a [`ReadMask`].
///
/// [`ReadMask`]: iota_sdk::grpc_client::ReadMask
pub(crate) fn read_mask(
    paths: &Option<Vec<String>>,
) -> Option<iota_sdk::grpc_client::ReadMask<'_>> {
    paths.as_ref().map(|paths| {
        let paths = paths.iter().map(String::as_str).collect::<Vec<_>>();
        iota_sdk::grpc_client::ReadMask::from(paths.as_slice())
    })
}
