// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction and event filters for the checkpoint read/stream APIs.
//!
//! These mirror the gRPC `TransactionFilter`, `EventFilter`, and
//! `CommandFilter` oneofs. Each filter is built through variant constructors;
//! logical filters (`all`, `any`, `not`) compose other filters, so complex
//! predicates can be expressed as a tree.
//!
//! The types are prefixed with `Grpc` to avoid clashing with the similarly
//! named GraphQL filter types in the flat FFI type namespace.

use std::sync::Arc;

use iota_sdk::grpc_types::v1::{filter as proto, types as proto_types};

use crate::types::{address::Address, move_core::StructTag, object::ObjectId};

/// The kind of a transaction, used by [`GrpcTransactionFilter::kinds`].
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum GrpcTransactionKind {
    /// Matches all kinds of system transactions.
    System,
    Programmable,
    Genesis,
    ConsensusCommitPrologueV1,
    EndOfEpoch,
    RandomnessStateUpdate,
}

impl From<GrpcTransactionKind> for proto::TransactionKind {
    fn from(kind: GrpcTransactionKind) -> Self {
        match kind {
            GrpcTransactionKind::System => Self::System,
            GrpcTransactionKind::Programmable => Self::Programmable,
            GrpcTransactionKind::Genesis => Self::Genesis,
            GrpcTransactionKind::ConsensusCommitPrologueV1 => Self::ConsensusCommitPrologueV1,
            GrpcTransactionKind::EndOfEpoch => Self::EndOfEpoch,
            GrpcTransactionKind::RandomnessStateUpdate => Self::RandomnessStateUpdate,
        }
    }
}

/// A filter over events, used to narrow the events returned for a checkpoint.
#[derive(Clone, Debug, uniffi::Object)]
pub struct GrpcEventFilter(pub(crate) proto::EventFilter);

#[uniffi::export]
impl GrpcEventFilter {
    /// Matches events that satisfy every one of the given filters.
    #[uniffi::constructor]
    pub fn all(filters: Vec<Arc<GrpcEventFilter>>) -> Self {
        Self(
            proto::EventFilter::default().with_all(
                proto::AllEventFilter::default().with_filters(inner_event_filters(&filters)),
            ),
        )
    }

    /// Matches events that satisfy at least one of the given filters.
    #[uniffi::constructor]
    pub fn any(filters: Vec<Arc<GrpcEventFilter>>) -> Self {
        Self(
            proto::EventFilter::default().with_any(
                proto::AnyEventFilter::default().with_filters(inner_event_filters(&filters)),
            ),
        )
    }

    /// Matches events that do not satisfy the given filter.
    #[uniffi::constructor]
    pub fn not(filter: &GrpcEventFilter) -> Self {
        Self(
            proto::EventFilter::default()
                .with_negation(proto::NotEventFilter::default().with_filter(filter.0.clone())),
        )
    }

    /// Matches events emitted by transactions sent from the given address.
    #[uniffi::constructor]
    pub fn sender(sender: &Address) -> Self {
        Self(
            proto::EventFilter::default()
                .with_sender(proto::AddressFilter::default().with_address(sender.0)),
        )
    }

    /// Matches events emitted in the given Move package (and optional module).
    #[uniffi::constructor(default(module = None))]
    pub fn move_package_and_module(package_id: &ObjectId, module: Option<String>) -> Self {
        Self(
            proto::EventFilter::default()
                .with_move_package_and_module(move_package_and_module(package_id, module)),
        )
    }

    /// Matches events whose struct is defined in the given Move package (and
    /// optional module).
    #[uniffi::constructor(default(module = None))]
    pub fn move_event_package_and_module(package_id: &ObjectId, module: Option<String>) -> Self {
        Self(
            proto::EventFilter::default()
                .with_move_event_package_and_module(move_package_and_module(package_id, module)),
        )
    }

    /// Matches events with the given Move event struct tag, e.g.
    /// `0xabcd::my_module::Foo`.
    #[uniffi::constructor]
    pub fn move_event_type(struct_tag: &StructTag) -> Self {
        Self(proto::EventFilter::default().with_move_event_type(
            proto::MoveEventTypeFilter::default().with_struct_tag(struct_tag.0.to_string()),
        ))
    }
}

/// A filter over the commands of a programmable transaction.
#[derive(Clone, Debug, uniffi::Object)]
pub struct GrpcCommandFilter(pub(crate) proto::CommandFilter);

#[uniffi::export]
impl GrpcCommandFilter {
    /// Matches a `MoveCall` command targeting the given package (and optional
    /// module and function).
    #[uniffi::constructor(default(module = None, function = None))]
    pub fn move_call(
        package_id: &ObjectId,
        module: Option<String>,
        function: Option<String>,
    ) -> Self {
        let mut filter = proto::MoveCallCommandFilter::default().with_package_id(package_id.0);
        if let Some(module) = module {
            filter = filter.with_module(module);
        }
        if let Some(function) = function {
            filter = filter.with_function(function);
        }
        Self(proto::CommandFilter::default().with_move_call(filter))
    }

    /// Matches a `TransferObjects` command.
    #[uniffi::constructor]
    pub fn transfer_objects() -> Self {
        Self(
            proto::CommandFilter::default()
                .with_transfer_objects(proto::TransferObjectsCommandFilter::default()),
        )
    }

    /// Matches a `SplitCoins` command.
    #[uniffi::constructor]
    pub fn split_coins() -> Self {
        Self(
            proto::CommandFilter::default()
                .with_split_coins(proto::SplitCoinsCommandFilter::default()),
        )
    }

    /// Matches a `MergeCoins` command.
    #[uniffi::constructor]
    pub fn merge_coins() -> Self {
        Self(
            proto::CommandFilter::default()
                .with_merge_coins(proto::MergeCoinsCommandFilter::default()),
        )
    }

    /// Matches a `Publish` command.
    #[uniffi::constructor]
    pub fn publish() -> Self {
        Self(proto::CommandFilter::default().with_publish(proto::PublishCommandFilter::default()))
    }

    /// Matches a `MakeMoveVec` command.
    #[uniffi::constructor]
    pub fn make_move_vec() -> Self {
        Self(
            proto::CommandFilter::default()
                .with_make_move_vec(proto::MakeMoveVecCommandFilter::default()),
        )
    }

    /// Matches an `Upgrade` command, optionally restricted to the given
    /// package being upgraded.
    #[uniffi::constructor(default(package_id = None))]
    pub fn upgrade(package_id: Option<Arc<ObjectId>>) -> Self {
        let mut filter = proto::UpgradeCommandFilter::default();
        if let Some(package_id) = package_id {
            filter = filter.with_package_id(package_id.0);
        }
        Self(proto::CommandFilter::default().with_upgrade(filter))
    }
}

/// A filter over transactions, used to narrow the transactions returned for a
/// checkpoint.
#[derive(Clone, Debug, uniffi::Object)]
pub struct GrpcTransactionFilter(pub(crate) proto::TransactionFilter);

#[uniffi::export]
impl GrpcTransactionFilter {
    /// Matches transactions that satisfy every one of the given filters.
    #[uniffi::constructor]
    pub fn all(filters: Vec<Arc<GrpcTransactionFilter>>) -> Self {
        Self(
            proto::TransactionFilter::default().with_all(
                proto::AllTransactionFilter::default()
                    .with_filters(inner_transaction_filters(&filters)),
            ),
        )
    }

    /// Matches transactions that satisfy at least one of the given filters.
    #[uniffi::constructor]
    pub fn any(filters: Vec<Arc<GrpcTransactionFilter>>) -> Self {
        Self(
            proto::TransactionFilter::default().with_any(
                proto::AnyTransactionFilter::default()
                    .with_filters(inner_transaction_filters(&filters)),
            ),
        )
    }

    /// Matches transactions that do not satisfy the given filter.
    #[uniffi::constructor]
    pub fn not(filter: &GrpcTransactionFilter) -> Self {
        Self(
            proto::TransactionFilter::default().with_negation(
                proto::NotTransactionFilter::default().with_filter(filter.0.clone()),
            ),
        )
    }

    /// Matches transactions of any of the given kinds.
    #[uniffi::constructor]
    pub fn kinds(kinds: Vec<GrpcTransactionKind>) -> Self {
        let kinds = kinds
            .into_iter()
            .map(|kind| proto::TransactionKind::from(kind) as i32)
            .collect();
        Self(
            proto::TransactionFilter::default()
                .with_transaction_kinds(proto::TransactionKindsFilter::default().with_kinds(kinds)),
        )
    }

    /// Matches transactions by execution status: `true` for successful
    /// transactions, `false` for failed ones.
    #[uniffi::constructor]
    pub fn execution_status(success: bool) -> Self {
        Self(
            proto::TransactionFilter::default().with_execution_status(
                proto::ExecutionStatusFilter::default().with_success(success),
            ),
        )
    }

    /// Matches transactions sent from the given address.
    #[uniffi::constructor]
    pub fn sender(sender: &Address) -> Self {
        Self(
            proto::TransactionFilter::default()
                .with_sender(proto::AddressFilter::default().with_address(sender.0)),
        )
    }

    /// Matches transactions received by the given address (determined from the
    /// owners of mutated and unwrapped objects).
    #[uniffi::constructor]
    pub fn receiver(receiver: &Address) -> Self {
        Self(
            proto::TransactionFilter::default()
                .with_receiver(proto::AddressFilter::default().with_address(receiver.0)),
        )
    }

    /// Matches transactions that touch the given object.
    #[uniffi::constructor]
    pub fn affected_object(object_id: &ObjectId) -> Self {
        Self(proto::TransactionFilter::default().with_affected_object(
            proto::ObjectIdFilter::default().with_object_ref(
                proto_types::ObjectReference::default().with_object_id(object_id.0),
            ),
        ))
    }

    /// Matches transactions containing a command that satisfies the given
    /// command filter.
    #[uniffi::constructor]
    pub fn command(command: &GrpcCommandFilter) -> Self {
        Self(proto::TransactionFilter::default().with_command(command.0.clone()))
    }

    /// Matches transactions that emit an event satisfying the given event
    /// filter.
    #[uniffi::constructor]
    pub fn event(filter: &GrpcEventFilter) -> Self {
        Self(proto::TransactionFilter::default().with_event(filter.0.clone()))
    }
}

fn inner_event_filters(filters: &[Arc<GrpcEventFilter>]) -> Vec<proto::EventFilter> {
    filters.iter().map(|filter| filter.0.clone()).collect()
}

fn inner_transaction_filters(
    filters: &[Arc<GrpcTransactionFilter>],
) -> Vec<proto::TransactionFilter> {
    filters.iter().map(|filter| filter.0.clone()).collect()
}

fn move_package_and_module(
    package_id: &ObjectId,
    module: Option<String>,
) -> proto::MovePackageAndModuleFilter {
    let mut filter = proto::MovePackageAndModuleFilter::default().with_package_id(package_id.0);
    if let Some(module) = module {
        filter = filter.with_module(module);
    }
    filter
}
