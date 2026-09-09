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
/// falling back to the endpoint's default mask when no paths are given
/// (`None` or an empty list).
pub(crate) fn read_mask<M: Default + From<String>>(paths: &Option<Vec<String>>) -> M {
    match paths {
        Some(paths) if !paths.is_empty() => M::from(paths.join(",")),
        _ => M::default(),
    }
}

#[cfg(test)]
mod tests {
    use iota_sdk::grpc_client::read_mask_fields::EpochReadMask;

    use super::read_mask;

    #[test]
    fn read_mask_falls_back_to_the_default_without_paths() {
        let default = EpochReadMask::default();
        assert_eq!(read_mask::<EpochReadMask>(&None).as_str(), default.as_str());
        assert_eq!(
            read_mask::<EpochReadMask>(&Some(vec![])).as_str(),
            default.as_str()
        );
    }

    #[test]
    fn read_mask_joins_the_given_paths() {
        let mask = read_mask::<EpochReadMask>(&Some(vec![
            "epoch".to_owned(),
            "reference_gas_price".to_owned(),
        ]));
        assert_eq!(mask.as_str(), "epoch,reference_gas_price");
    }
}
