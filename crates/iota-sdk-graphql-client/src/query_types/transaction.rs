// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;
use iota_types::{ObjectId, SenderSignedTransaction, SignedTransaction, TransactionEffects};

use crate::{
    error::{self, Error, Kind},
    query_types::{Address, Base64, PageInfo, checkpoint::Checkpoint, schema},
};

// ===========================================================================
// Transaction Block(s) Queries
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlockArgs"
)]
pub struct TransactionBlockQuery {
    #[arguments(digest: $digest)]
    pub transaction_block: Option<TransactionBlock>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlockArgs"
)]
pub struct TransactionBlockWithEffectsQuery {
    #[arguments(digest: $digest)]
    pub transaction_block: Option<TransactionBlockWithEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlockArgs"
)]
pub struct TransactionBlockEffectsQuery {
    #[arguments(digest: $digest)]
    pub transaction_block: Option<TxBlockEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlockArgs"
)]
pub struct TransactionBlockCheckpointQuery {
    #[arguments(digest: $digest)]
    pub transaction_block: Option<TxBlockCheckpoint>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlockArgs"
)]
pub struct TransactionBlockIndexedQuery {
    #[arguments(digest: $digest)]
    pub is_transaction_indexed_on_node: bool,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlocksQueryArgs"
)]
pub struct TransactionBlocksQuery {
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub transaction_blocks: TransactionBlockConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlocksQueryArgs"
)]
pub struct TransactionBlocksWithEffectsQuery {
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub transaction_blocks: TransactionBlockWithEffectsConnection,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionBlocksQueryArgs"
)]
pub struct TransactionBlocksEffectsQuery {
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub transaction_blocks: TransactionBlockEffectsConnection,
}
// ===========================================================================
// Transaction Block(s) Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionBlockArgs {
    pub digest: String,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionBlocksQueryArgs {
    pub first: Option<i32>,
    pub after: Option<String>,
    pub last: Option<i32>,
    pub before: Option<String>,
    pub filter: Option<TransactionBlockFilter>,
}

// ===========================================================================
// Transaction Block(s) Types
// ===========================================================================

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct TransactionBlock {
    pub bcs: Option<Base64>,
    pub effects: Option<TransactionBlockEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct TransactionBlockWithEffects {
    pub bcs: Option<Base64>,
    pub effects: Option<TransactionBlockEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct TxBlockEffects {
    pub effects: Option<TransactionBlockEffects>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct TxBlockCheckpoint {
    pub effects: Option<TransactionBlockCheckpoint>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockEffects")]
pub struct TransactionBlockEffects {
    pub bcs: Option<Base64>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockEffects")]
pub struct TransactionBlockCheckpoint {
    pub checkpoint: Option<Checkpoint>,
}

#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "TransactionBlockKindInput",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[non_exhaustive]
pub enum TransactionBlockKindInput {
    SystemTx,
    ProgrammableTx,
    Genesis,
    ConsensusCommitPrologueV1,
    RandomnessStateUpdate,
    EndOfEpochTx,
}

/// Selection criteria for querying transactions.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum TransactionsSelector {
    /// Select by package, module, or function name, e.g. `"0x03"`,
    /// `"0x03::iota_system"`, or `"0x03::iota_system::request_add_stake"`.
    Function(String),
    /// Select by transaction kind.
    Kind(TransactionBlockKindInput),
    /// Select transactions that sent an object to the given address.
    RecvAddress(Address),
    /// Select transactions that used the given object as an input.
    InputObject(ObjectId),
    /// Select transactions that output a version of the given object.
    ChangedObject(ObjectId),
    /// Select transactions that wrapped or deleted the given object.
    WrappedOrDeletedObject(ObjectId),
}

/// Filter for transaction queries.
///
/// Holds at most one [`TransactionsSelector`], so each of the setters that
/// picks one replaces whichever was set before; the sender, checkpoint and
/// digest filters can be combined with it and with each other freely.
#[derive(Clone, Debug, Default)]
pub struct TransactionsFilter {
    selector: Option<TransactionsSelector>,
    sent_address: Option<Address>,
    after_checkpoint: Option<u64>,
    at_checkpoint: Option<u64>,
    before_checkpoint: Option<u64>,
    transaction_ids: Option<Vec<String>>,
}

impl TransactionsFilter {
    /// Select on a function, kind, address or object, replacing the selector
    /// already set, if any.
    pub fn with_selector(mut self, selector: impl Into<Option<TransactionsSelector>>) -> Self {
        self.selector = selector.into();
        self
    }

    /// Select by package, module, or function name, e.g. `"0x03"`,
    /// `"0x03::iota_system"`, or `"0x03::iota_system::request_add_stake"`.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_function(self, function: impl Into<Option<String>>) -> Self {
        self.with_selector(function.into().map(TransactionsSelector::Function))
    }

    /// Select by transaction kind.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_kind(self, kind: impl Into<Option<TransactionBlockKindInput>>) -> Self {
        self.with_selector(kind.into().map(TransactionsSelector::Kind))
    }

    /// Select transactions that sent an object to the given address.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_recv_address(self, recv_address: impl Into<Option<Address>>) -> Self {
        self.with_selector(recv_address.into().map(TransactionsSelector::RecvAddress))
    }

    /// Select transactions that used the given object as an input.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_input_object(self, input_object: impl Into<Option<ObjectId>>) -> Self {
        self.with_selector(input_object.into().map(TransactionsSelector::InputObject))
    }

    /// Select transactions that output a version of the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_changed_object(self, changed_object: impl Into<Option<ObjectId>>) -> Self {
        self.with_selector(
            changed_object
                .into()
                .map(TransactionsSelector::ChangedObject),
        )
    }

    /// Select transactions that wrapped or deleted the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_wrapped_or_deleted_object(
        self,
        wrapped_or_deleted_object: impl Into<Option<ObjectId>>,
    ) -> Self {
        self.with_selector(
            wrapped_or_deleted_object
                .into()
                .map(TransactionsSelector::WrappedOrDeletedObject),
        )
    }

    /// Filter by sender address.
    pub fn with_sent_address(mut self, sent_address: impl Into<Option<Address>>) -> Self {
        self.sent_address = sent_address.into();
        self
    }

    /// Limit to transactions executed after the given checkpoint, exclusive.
    pub fn with_after_checkpoint(mut self, after_checkpoint: impl Into<Option<u64>>) -> Self {
        self.after_checkpoint = after_checkpoint.into();
        self
    }

    /// Limit to transactions executed in the given checkpoint.
    pub fn with_at_checkpoint(mut self, at_checkpoint: impl Into<Option<u64>>) -> Self {
        self.at_checkpoint = at_checkpoint.into();
        self
    }

    /// Limit to transactions executed before the given checkpoint, exclusive.
    pub fn with_before_checkpoint(mut self, before_checkpoint: impl Into<Option<u64>>) -> Self {
        self.before_checkpoint = before_checkpoint.into();
        self
    }

    /// Filter by transaction digests.
    pub fn with_transaction_ids(mut self, transaction_ids: impl Into<Option<Vec<String>>>) -> Self {
        self.transaction_ids = transaction_ids.into();
        self
    }

    /// The selector this filter selects on, if any.
    pub fn selector(&self) -> Option<&TransactionsSelector> {
        self.selector.as_ref()
    }

    /// The sender address this filter is limited to, if any.
    pub fn sent_address(&self) -> Option<Address> {
        self.sent_address
    }

    /// The exclusive lower checkpoint bound of this filter, if any.
    pub fn after_checkpoint(&self) -> Option<u64> {
        self.after_checkpoint
    }

    /// The checkpoint this filter is limited to, if any.
    pub fn at_checkpoint(&self) -> Option<u64> {
        self.at_checkpoint
    }

    /// The exclusive upper checkpoint bound of this filter, if any.
    pub fn before_checkpoint(&self) -> Option<u64> {
        self.before_checkpoint
    }

    /// The transaction digests this filter is limited to, if any.
    pub fn transaction_ids(&self) -> Option<&[String]> {
        self.transaction_ids.as_deref()
    }
}

/// The GraphQL input object, built from a [`TransactionsFilter`].
#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockFilter")]
pub struct TransactionBlockFilter {
    function: Option<String>,
    kind: Option<TransactionBlockKindInput>,
    after_checkpoint: Option<u64>,
    at_checkpoint: Option<u64>,
    before_checkpoint: Option<u64>,
    sent_address: Option<Address>,
    recv_address: Option<Address>,
    input_object: Option<ObjectId>,
    changed_object: Option<ObjectId>,
    wrapped_or_deleted_object: Option<ObjectId>,
    transaction_ids: Option<Vec<String>>,
}

impl From<TransactionsFilter> for TransactionBlockFilter {
    fn from(filter: TransactionsFilter) -> Self {
        let TransactionsFilter {
            selector,
            sent_address,
            after_checkpoint,
            at_checkpoint,
            before_checkpoint,
            transaction_ids,
        } = filter;

        let mut input = Self {
            sent_address,
            after_checkpoint,
            at_checkpoint,
            before_checkpoint,
            transaction_ids,
            ..Default::default()
        };

        if let Some(selector) = selector {
            match selector {
                TransactionsSelector::Function(function) => input.function = Some(function),
                TransactionsSelector::Kind(kind) => input.kind = Some(kind),
                TransactionsSelector::RecvAddress(address) => input.recv_address = Some(address),
                TransactionsSelector::InputObject(object_id) => {
                    input.input_object = Some(object_id)
                }
                TransactionsSelector::ChangedObject(object_id) => {
                    input.changed_object = Some(object_id)
                }
                TransactionsSelector::WrappedOrDeletedObject(object_id) => {
                    input.wrapped_or_deleted_object = Some(object_id)
                }
            }
        }

        input
    }
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockConnection")]
pub struct TransactionBlockConnection {
    pub nodes: Vec<TransactionBlock>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockConnection")]
pub struct TransactionBlockWithEffectsConnection {
    pub nodes: Vec<TransactionBlockWithEffects>,
    pub page_info: PageInfo,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockConnection")]
pub struct TransactionBlockEffectsConnection {
    pub nodes: Vec<TxBlockEffects>,
    pub page_info: PageInfo,
}

impl TryFrom<TransactionBlock> for SignedTransaction {
    type Error = error::Error;

    fn try_from(value: TransactionBlock) -> Result<Self, Self::Error> {
        let transaction = value
            .bcs
            .map(|tx| base64ct::Base64::decode_vec(tx.0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<SenderSignedTransaction>(&bcs))
            .transpose()?;

        if let Some(transaction) = transaction {
            Ok(transaction.into())
        } else {
            Err(Error::from_error(
                Kind::Other,
                "Expected a deserialized transaction but got None",
            ))
        }
    }
}

impl TryFrom<TxBlockEffects> for TransactionEffects {
    type Error = error::Error;

    fn try_from(value: TxBlockEffects) -> Result<Self, Self::Error> {
        let effects = value
            .effects
            .map(|fx| base64ct::Base64::decode_vec(fx.bcs.unwrap().0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<TransactionEffects>(&bcs))
            .transpose()?;
        effects.ok_or_else(|| {
            Error::from_error(
                Kind::Other,
                "Cannot convert GraphQL TxBlockEffects into TransactionEffects",
            )
        })
    }
}
