// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;
use iota_types::{
    ObjectId, SenderSignedTransaction, SignedTransaction, TransactionDigest, TransactionEffects,
};

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
#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "AddressTransactionsQueryArgs"
)]
pub struct AddressTransactionsQuery {
    #[arguments(address: $address)]
    pub address: Option<AddressTransactionBlocksQuery>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Address",
    variables = "AddressTransactionsQueryArgs"
)]
pub struct AddressTransactionBlocksQuery {
    #[arguments(first: $first, after: $after, last: $last, before: $before, relation: $relation, filter: $filter)]
    pub transaction_blocks: TransactionBlockConnection,
}

// ===========================================================================
// Transaction Block(s) Query Args
// ===========================================================================

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionBlockArgs {
    pub digest: String,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct AddressTransactionsQueryArgs {
    pub address: Address,
    pub first: Option<i32>,
    pub after: Option<String>,
    pub last: Option<i32>,
    pub before: Option<String>,
    pub relation: Option<AddressTransactionRelationship>,
    pub filter: Option<TransactionBlockFilter>,
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

/// The relationship between an address and a transaction.
#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "AddressTransactionBlockRelationship",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[non_exhaustive]
pub enum AddressTransactionRelationship {
    /// Transactions the address has sent.
    Sent,
    /// Transactions that sent objects to the address.
    Recv,
    /// Transactions that affected the address: it is the sender, a recipient,
    /// or the owner of the gas payment.
    Affected,
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
    /// Select transactions that affected the given address.
    AffectedAddress(Address),
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
    pub fn with_selector(mut self, selector: TransactionsSelector) -> Self {
        self.selector = Some(selector);
        self
    }

    /// Select by package, module, or function name, e.g. `"0x03"`,
    /// `"0x03::iota_system"`, or `"0x03::iota_system::request_add_stake"`.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_function(self, function: String) -> Self {
        self.with_selector(TransactionsSelector::Function(function))
    }

    /// Select by transaction kind.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_kind(self, kind: TransactionBlockKindInput) -> Self {
        self.with_selector(TransactionsSelector::Kind(kind))
    }

    /// Select transactions that sent an object to the given address.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_recv_address(self, recv_address: Address) -> Self {
        self.with_selector(TransactionsSelector::RecvAddress(recv_address))
    }

    /// Select transactions that affected the given address.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_affected_address(self, affected_address: Address) -> Self {
        self.with_selector(TransactionsSelector::AffectedAddress(affected_address))
    }

    /// Select transactions that used the given object as an input.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_input_object(self, input_object: ObjectId) -> Self {
        self.with_selector(TransactionsSelector::InputObject(input_object))
    }

    /// Select transactions that output a version of the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_changed_object(self, changed_object: ObjectId) -> Self {
        self.with_selector(TransactionsSelector::ChangedObject(changed_object))
    }

    /// Select transactions that wrapped or deleted the given object.
    ///
    /// Replaces the selector already set, if any.
    pub fn with_wrapped_or_deleted_object(self, wrapped_or_deleted_object: ObjectId) -> Self {
        self.with_selector(TransactionsSelector::WrappedOrDeletedObject(
            wrapped_or_deleted_object,
        ))
    }

    /// Filter by sender address.
    pub fn with_sent_address(mut self, sent_address: Address) -> Self {
        self.sent_address = Some(sent_address);
        self
    }

    /// Limit to transactions executed after the given checkpoint, exclusive.
    pub fn with_after_checkpoint(mut self, after_checkpoint: u64) -> Self {
        self.after_checkpoint = Some(after_checkpoint);
        self
    }

    /// Limit to transactions executed in the given checkpoint.
    pub fn with_at_checkpoint(mut self, at_checkpoint: u64) -> Self {
        self.at_checkpoint = Some(at_checkpoint);
        self
    }

    /// Limit to transactions executed before the given checkpoint, exclusive.
    pub fn with_before_checkpoint(mut self, before_checkpoint: u64) -> Self {
        self.before_checkpoint = Some(before_checkpoint);
        self
    }

    /// Select by transaction digests.
    pub fn with_transaction_ids(
        mut self,
        transaction_ids: impl IntoIterator<Item = TransactionDigest>,
    ) -> Self {
        self.transaction_ids = Some(
            transaction_ids
                .into_iter()
                .map(|id| id.to_string())
                .collect(),
        );
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
    affected_address: Option<Address>,
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
                TransactionsSelector::AffectedAddress(address) => {
                    input.affected_address = Some(address)
                }
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
