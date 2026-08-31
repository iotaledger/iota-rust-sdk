// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;
use iota_types::{ObjectId, SenderSignedTransaction, SignedTransaction, TransactionEffects};

use crate::{
    error::{self, GraphQLError},
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
    pub filter: Option<TransactionsFilter>,
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

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockFilter")]
#[non_exhaustive]
pub struct TransactionsFilter {
    pub function: Option<String>,
    pub kind: Option<TransactionBlockKindInput>,
    pub after_checkpoint: Option<u64>,
    pub at_checkpoint: Option<u64>,
    pub before_checkpoint: Option<u64>,
    pub sent_address: Option<Address>,
    pub recv_address: Option<Address>,
    pub input_object: Option<ObjectId>,
    pub changed_object: Option<ObjectId>,
    pub wrapped_or_deleted_object: Option<ObjectId>,
    pub transaction_ids: Option<Vec<String>>,
}

impl TransactionsFilter {
    /// Filter by package, module, or function name, e.g. `"0x03"`,
    /// `"0x03::iota_system"`, or `"0x03::iota_system::request_add_stake"`.
    pub fn with_function(mut self, function: impl Into<Option<String>>) -> Self {
        self.function = function.into();
        self
    }

    /// Filter by transaction kind.
    pub fn with_kind(mut self, kind: impl Into<Option<TransactionBlockKindInput>>) -> Self {
        self.kind = kind.into();
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

    /// Filter by sender address.
    pub fn with_sent_address(mut self, sent_address: impl Into<Option<Address>>) -> Self {
        self.sent_address = sent_address.into();
        self
    }

    /// Filter by the address receiving an object from the transaction.
    pub fn with_recv_address(mut self, recv_address: impl Into<Option<Address>>) -> Self {
        self.recv_address = recv_address.into();
        self
    }

    /// Filter by an object used as input to the transaction.
    pub fn with_input_object(mut self, input_object: impl Into<Option<ObjectId>>) -> Self {
        self.input_object = input_object.into();
        self
    }

    /// Filter by an object changed by the transaction.
    pub fn with_changed_object(mut self, changed_object: impl Into<Option<ObjectId>>) -> Self {
        self.changed_object = changed_object.into();
        self
    }

    /// Filter by an object wrapped or deleted by the transaction.
    pub fn with_wrapped_or_deleted_object(
        mut self,
        wrapped_or_deleted_object: impl Into<Option<ObjectId>>,
    ) -> Self {
        self.wrapped_or_deleted_object = wrapped_or_deleted_object.into();
        self
    }

    /// Filter by transaction digests.
    pub fn with_transaction_ids(mut self, transaction_ids: impl Into<Option<Vec<String>>>) -> Self {
        self.transaction_ids = transaction_ids.into();
        self
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
    type Error = error::GraphQLError;

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
            Err(GraphQLError::EmptyResponseField("transaction bcs"))
        }
    }
}

impl TryFrom<TxBlockEffects> for TransactionEffects {
    type Error = error::GraphQLError;

    fn try_from(value: TxBlockEffects) -> Result<Self, Self::Error> {
        let effects = value
            .effects
            .map(|fx| base64ct::Base64::decode_vec(fx.bcs.unwrap().0.as_str()))
            .transpose()?
            .map(|bcs| bcs::from_bytes::<TransactionEffects>(&bcs))
            .transpose()?;
        effects.ok_or(GraphQLError::EmptyResponseField("transaction effects bcs"))
    }
}
