// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for gRPC client operations.
//!
//! The gRPC API lets callers control which fields the server returns via read
//! masks, given as a list of the typed fields of the endpoint (see
//! [`read_mask_fields`](crate::grpc::read_mask_fields)). Fields that were not
//! requested (or that the server did not populate) are `None` in the
//! corresponding record.
//!
//! Complex types (transactions, effects, events, objects, ...) are eagerly
//! deserialized from their BCS representation, so the read mask must include
//! the corresponding `bcs` sub-fields for those record fields to be
//! populated.

use crate::grpc::read_mask_fields::ReadMaskField;

pub mod execution;
pub mod ledger;
pub mod move_package;
pub mod state;

/// Convert an optional list of typed fields into an endpoint read mask.
///
/// The paths are normalized like the typed field lists of the Rust client
/// (duplicates and subsumed paths dropped). When no fields were given, or the
/// list is empty, the endpoint's default mask is used.
pub(crate) fn read_mask<M, F>(fields: Option<Vec<F>>) -> M
where
    M: Default + From<Vec<F::Field>>,
    F: ReadMaskField,
{
    match fields {
        Some(fields) if !fields.is_empty() => {
            M::from(fields.into_iter().map(F::Field::from).collect::<Vec<_>>())
        }
        _ => M::default(),
    }
}

/// Whether a read mask requests `field`, i.e. whether any of its paths is
/// `field` itself, an ancestor of it, one of its sub-paths, or `*`.
///
/// Repeated response fields arrive as an empty list both when they were not
/// requested and when there was nothing to return, so the mask is the only
/// way to tell those apart.
pub(crate) fn read_mask_requests(mask: impl AsRef<str>, field: impl AsRef<str>) -> bool {
    let field = field.as_ref();
    mask.as_ref().split(',').any(|path| {
        path == "*"
            || path == field
            || path
                .strip_prefix(field)
                .is_some_and(|rest| rest.starts_with('.'))
            || field
                .strip_prefix(path)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use iota_sdk::grpc_client::read_mask_fields::{
        EpochReadMask, ExecuteTransactionReadMask, TransactionReadMask,
    };

    use super::{read_mask, read_mask_requests};
    use crate::grpc::read_mask_fields::{EpochField, TransactionField};

    #[test]
    fn read_mask_requests_matches_the_field_its_ancestors_and_sub_paths() {
        assert!(read_mask_requests("*", "events.bcs"));
        assert!(read_mask_requests("events", "events.bcs"));
        assert!(read_mask_requests(
            "checkpoint.summary,events.bcs",
            "events.bcs"
        ));
        assert!(read_mask_requests(
            "transactions.effects.bcs",
            "transactions"
        ));
        assert!(!read_mask_requests("checkpoint.summary", "transactions"));
        assert!(!read_mask_requests("events.event_type", "events.bcs"));
        assert!(!read_mask_requests("eventsx", "events"));
        assert!(!read_mask_requests("events", "eventsx"));
    }

    #[test]
    fn read_mask_falls_back_to_the_default_without_fields() {
        let default = EpochReadMask::default();
        assert_eq!(
            read_mask::<EpochReadMask, EpochField>(None).as_str(),
            default.as_str()
        );
        assert_eq!(
            read_mask::<EpochReadMask, EpochField>(Some(vec![])).as_str(),
            default.as_str()
        );
    }

    #[test]
    fn read_mask_normalizes_the_given_fields() {
        let mask = read_mask::<EpochReadMask, _>(Some(vec![
            EpochField::ProtocolConfigFeatureFlags,
            EpochField::ProtocolConfig,
            EpochField::Epoch,
            EpochField::Epoch,
        ]));
        assert_eq!(mask.as_str(), "epoch,protocol_config");
    }

    #[test]
    fn read_mask_joins_the_given_fields() {
        let mask = read_mask::<EpochReadMask, _>(Some(vec![
            EpochField::Epoch,
            EpochField::ReferenceGasPrice,
        ]));
        assert_eq!(mask.as_str(), "epoch,reference_gas_price");
    }

    #[test]
    fn transaction_fields_build_the_mask_of_either_transaction_endpoint() {
        let fields = || {
            Some(vec![
                TransactionField::EffectsBcs,
                TransactionField::Checkpoint,
            ])
        };
        assert_eq!(
            read_mask::<TransactionReadMask, _>(fields()).as_str(),
            "checkpoint,effects.bcs"
        );
        assert_eq!(
            read_mask::<ExecuteTransactionReadMask, _>(fields()).as_str(),
            "checkpoint,effects.bcs"
        );
    }
}
