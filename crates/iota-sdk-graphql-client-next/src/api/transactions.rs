// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use cynic::{Operation, QueryBuilder, QueryFragment};
use iota_types::{
    Address, ObjectId, SenderSignedTransaction, SignedTransaction, TransactionDigest,
    TransactionEffects,
};

use crate::{
    Error, FunctionFilter, GraphQLClient, Page, PageArgs, Paginated, Query, Request, Result,
    ServerVersion, TransactionKindFilter,
    repr::{Effects, Signed, WithEffects},
    wire::{self, EffectsBcs, PageInfo, schema},
};

/// A transaction together with its effects.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExecutedTransaction {
    /// The transaction and its signatures.
    pub transaction: SignedTransaction,
    /// What executing it did.
    pub effects: TransactionEffects,
}

/// Query for [`GraphQLClient::transaction`].
#[derive(Clone, Debug)]
pub struct GetTransaction<R = Signed> {
    digest: TransactionDigest,
    repr: PhantomData<fn() -> R>,
}

impl<R> GetTransaction<R> {
    fn with_repr<S>(self) -> GetTransaction<S> {
        GetTransaction {
            digest: self.digest,
            repr: PhantomData,
        }
    }
}

impl<R: TransactionRepr> Query for GetTransaction<R> {
    type Output = Option<R::Output>;
    type Data = TransactionQuery<R::Node>;
    type Variables = TransactionVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<Self::Data, TransactionVariables>> {
        Ok(TransactionQuery::build(TransactionVariables {
            digest: self.digest.to_string(),
        }))
    }

    fn decode(self, data: Self::Data) -> Result<Self::Output> {
        data.transaction_block.map(R::decode).transpose()
    }
}

impl<R> Request<GetTransaction<R>> {
    /// Return the transaction's effects instead of the transaction.
    pub fn effects(self) -> Request<GetTransaction<Effects>> {
        self.map(GetTransaction::with_repr)
    }

    /// Return the transaction together with its effects.
    pub fn with_effects(self) -> Request<GetTransaction<WithEffects>> {
        self.map(GetTransaction::with_repr)
    }
}

/// Query for [`GraphQLClient::transactions`].
#[derive(Debug)]
pub struct ListTransactions<R = Signed> {
    filter: TransactionFilter,
    page: PageArgs,
    repr: PhantomData<fn() -> R>,
}

impl<R> Clone for ListTransactions<R> {
    fn clone(&self) -> Self {
        Self {
            filter: self.filter.clone(),
            page: self.page.clone(),
            repr: PhantomData,
        }
    }
}

impl<R> ListTransactions<R> {
    fn with_repr<S>(self) -> ListTransactions<S> {
        ListTransactions {
            filter: self.filter,
            page: self.page,
            repr: PhantomData,
        }
    }
}

impl<R: TransactionRepr> Query for ListTransactions<R> {
    type Output = Page<R::Output>;
    type Data = TransactionsQuery<R::Node>;
    type Variables = TransactionsVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<Self::Data, TransactionsVariables>> {
        Ok(TransactionsQuery::build(TransactionsVariables {
            first: self.page.first(),
            after: self.page.after(),
            last: self.page.last(),
            before: self.page.before(),
            filter: Some(self.filter.input()),
        }))
    }

    fn decode(self, data: Self::Data) -> Result<Self::Output> {
        let TransactionConnection { page_info, nodes } = data.transaction_blocks;
        let items = nodes.into_iter().map(R::decode).collect::<Result<_>>()?;
        Ok(Page::from_wire(items, page_info))
    }
}

impl<R: TransactionRepr> Paginated for ListTransactions<R> {
    type Item = R::Output;

    fn page_args(&self) -> &PageArgs {
        &self.page
    }

    fn page_args_mut(&mut self) -> &mut PageArgs {
        &mut self.page
    }
}

/// The filters of [`ListTransactions`]. The server is removing support for
/// combining selectors (in 1.38), so at most one is kept, alongside the
/// sender, checkpoint and digest filters.
#[derive(Clone, Debug, Default)]
struct TransactionFilter {
    selector: Option<Selector>,
    sender: Option<Address>,
    after_checkpoint: Option<u64>,
    at_checkpoint: Option<u64>,
    before_checkpoint: Option<u64>,
    digests: Option<Vec<TransactionDigest>>,
}

#[derive(Clone, Debug)]
enum Selector {
    Function(FunctionFilter),
    Kind(TransactionKindFilter),
    Recipient(Address),
    AffectedAddress(Address),
    InputObject(ObjectId),
    ChangedObject(ObjectId),
    WrappedOrDeletedObject(ObjectId),
}

impl TransactionFilter {
    fn input(&self) -> TransactionFilterInput {
        let mut input = TransactionFilterInput {
            sent_address: self.sender,
            after_checkpoint: self.after_checkpoint,
            at_checkpoint: self.at_checkpoint,
            before_checkpoint: self.before_checkpoint,
            transaction_ids: self
                .digests
                .as_ref()
                .map(|digests| digests.iter().map(ToString::to_string).collect()),
            ..TransactionFilterInput::default()
        };
        match &self.selector {
            Some(Selector::Function(function)) => input.function = Some(function.to_string()),
            Some(Selector::Kind(kind)) => input.kind = Some((*kind).into()),
            Some(Selector::Recipient(address)) => input.recv_address = Some(*address),
            Some(Selector::AffectedAddress(address)) => input.affected_address = Some(*address),
            Some(Selector::InputObject(object)) => input.input_object = Some(*object),
            Some(Selector::ChangedObject(object)) => input.changed_object = Some(*object),
            Some(Selector::WrappedOrDeletedObject(object)) => {
                input.wrapped_or_deleted_object = Some(*object)
            }
            None => {}
        }
        input
    }
}

impl<R> Request<ListTransactions<R>> {
    fn filter(self, f: impl FnOnce(&mut TransactionFilter)) -> Self {
        self.map(|mut query| {
            f(&mut query.filter);
            query
        })
    }

    fn select(self, selector: Selector) -> Self {
        self.filter(|filter| filter.selector = Some(selector))
    }

    /// Only return transactions `sender` sent.
    pub fn sender(self, sender: Address) -> Self {
        self.filter(|filter| filter.sender = Some(sender))
    }

    /// Only return transactions in checkpoints after `checkpoint`.
    pub fn after_checkpoint(self, checkpoint: u64) -> Self {
        self.filter(|filter| filter.after_checkpoint = Some(checkpoint))
    }

    /// Only return transactions in `checkpoint`.
    pub fn at_checkpoint(self, checkpoint: u64) -> Self {
        self.filter(|filter| filter.at_checkpoint = Some(checkpoint))
    }

    /// Only return transactions in checkpoints before `checkpoint`.
    pub fn before_checkpoint(self, checkpoint: u64) -> Self {
        self.filter(|filter| filter.before_checkpoint = Some(checkpoint))
    }

    /// Only return the transactions with these digests.
    pub fn digests(self, digests: impl IntoIterator<Item = TransactionDigest>) -> Self {
        let digests = digests.into_iter().collect();
        self.filter(|filter| filter.digests = Some(digests))
    }

    /// Only return transactions that call a function matching `function`.
    /// Replaces any other selector: `kind`, `recipient`, `affected_address`,
    /// `input_object`, `changed_object` or `wrapped_or_deleted_object`.
    pub fn function(self, function: FunctionFilter) -> Self {
        self.select(Selector::Function(function))
    }

    /// Only return transactions of `kind`. Replaces any other selector.
    pub fn kind(self, kind: TransactionKindFilter) -> Self {
        self.select(Selector::Kind(kind))
    }

    /// Only return transactions that sent an object to `recipient`. Replaces
    /// any other selector.
    pub fn recipient(self, recipient: Address) -> Self {
        self.select(Selector::Recipient(recipient))
    }

    /// Only return transactions that affected `address`: it sent them,
    /// received objects from them, or paid their gas. Replaces any other
    /// selector.
    pub fn affected_address(self, address: Address) -> Self {
        self.select(Selector::AffectedAddress(address))
    }

    /// Only return transactions that took `object` as an input. Replaces any
    /// other selector.
    pub fn input_object(self, object: ObjectId) -> Self {
        self.select(Selector::InputObject(object))
    }

    /// Only return transactions that wrote a new version of `object`.
    /// Replaces any other selector.
    pub fn changed_object(self, object: ObjectId) -> Self {
        self.select(Selector::ChangedObject(object))
    }

    /// Only return transactions that wrapped or deleted `object`. Replaces
    /// any other selector.
    pub fn wrapped_or_deleted_object(self, object: ObjectId) -> Self {
        self.select(Selector::WrappedOrDeletedObject(object))
    }

    /// Return the transactions' effects instead of the transactions.
    pub fn effects(self) -> Request<ListTransactions<Effects>> {
        self.map(ListTransactions::with_repr)
    }

    /// Return the transactions together with their effects.
    pub fn with_effects(self) -> Request<ListTransactions<WithEffects>> {
        self.map(ListTransactions::with_repr)
    }
}

impl GraphQLClient {
    /// A transaction, by digest. Resolves to `None` if the server does not
    /// know it, or no longer does (e.g., after pruning).
    ///
    /// By default the transaction is returned as a [`SignedTransaction`];
    /// request its [`effects`](Request::<GetTransaction>::effects) instead, or
    /// [`with_effects`](Request::<GetTransaction>::with_effects).
    pub fn transaction(&self, digest: TransactionDigest) -> Request<GetTransaction> {
        Request::new(
            self,
            GetTransaction {
                digest,
                repr: PhantomData,
            },
        )
    }

    /// A page of transactions, optionally filtered.
    pub fn transactions(&self) -> Request<ListTransactions> {
        Request::new(
            self,
            ListTransactions {
                filter: TransactionFilter::default(),
                page: PageArgs::default(),
                repr: PhantomData,
            },
        )
    }
}

pub(crate) mod sealed {
    use cynic::QueryFragment;
    use serde::de::DeserializeOwned;

    use crate::{Result, transport::MaybeSend, wire::schema};

    /// A form transactions can be returned in: what to select, and how to
    /// decode it.
    pub trait TransactionRepr: MaybeSend + 'static {
        type Node: QueryFragment<SchemaType = schema::TransactionBlock, VariablesFields = ()>
            + DeserializeOwned
            + MaybeSend;
        type Output: MaybeSend;

        fn decode(node: Self::Node) -> Result<Self::Output>;
    }
}

use self::sealed::TransactionRepr;

fn decode_transaction(
    bcs: Option<wire::Bcs<SenderSignedTransaction>>,
) -> Result<SignedTransaction> {
    bcs.map(|wire::Bcs(transaction)| transaction.into())
        .ok_or_else(|| Error::malformed("a transaction has no BCS"))
}

fn decode_effects(effects: Option<EffectsBcs>) -> Result<TransactionEffects> {
    effects
        .and_then(|effects| effects.bcs)
        .map(|wire::Bcs(effects)| effects)
        .ok_or_else(|| Error::malformed("a transaction has no effects"))
}

impl TransactionRepr for Signed {
    type Node = SignedNode;
    type Output = SignedTransaction;

    fn decode(node: SignedNode) -> Result<SignedTransaction> {
        decode_transaction(node.bcs)
    }
}

impl TransactionRepr for Effects {
    type Node = EffectsNode;
    type Output = TransactionEffects;

    fn decode(node: EffectsNode) -> Result<TransactionEffects> {
        decode_effects(node.effects)
    }
}

impl TransactionRepr for WithEffects {
    type Node = WithEffectsNode;
    type Output = ExecutedTransaction;

    fn decode(node: WithEffectsNode) -> Result<ExecutedTransaction> {
        Ok(ExecutedTransaction {
            transaction: decode_transaction(node.bcs)?,
            effects: decode_effects(node.effects)?,
        })
    }
}

impl From<TransactionKindFilter> for TransactionKindInput {
    fn from(kind: TransactionKindFilter) -> Self {
        match kind {
            TransactionKindFilter::System => Self::SystemTx,
            TransactionKindFilter::Programmable => Self::ProgrammableTx,
            TransactionKindFilter::Genesis => Self::Genesis,
            TransactionKindFilter::ConsensusCommitPrologue => Self::ConsensusCommitPrologueV1,
            TransactionKindFilter::RandomnessStateUpdate => Self::RandomnessStateUpdate,
            TransactionKindFilter::EndOfEpoch => Self::EndOfEpochTx,
        }
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionVariables {
    pub(crate) digest: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionVariables"
)]
pub struct TransactionQuery<N>
where
    N: QueryFragment<SchemaType = schema::TransactionBlock, VariablesFields = ()>,
{
    #[arguments(digest: $digest)]
    pub(crate) transaction_block: Option<N>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct TransactionsVariables {
    pub(crate) first: Option<i32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<i32>,
    pub(crate) before: Option<String>,
    pub(crate) filter: Option<TransactionFilterInput>,
}

#[derive(Clone, cynic::InputObject, Debug, Default)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockFilter")]
pub struct TransactionFilterInput {
    pub(crate) function: Option<String>,
    pub(crate) kind: Option<TransactionKindInput>,
    pub(crate) after_checkpoint: Option<u64>,
    pub(crate) at_checkpoint: Option<u64>,
    pub(crate) before_checkpoint: Option<u64>,
    pub(crate) sent_address: Option<Address>,
    pub(crate) recv_address: Option<Address>,
    pub(crate) affected_address: Option<Address>,
    pub(crate) input_object: Option<ObjectId>,
    pub(crate) changed_object: Option<ObjectId>,
    pub(crate) wrapped_or_deleted_object: Option<ObjectId>,
    pub(crate) transaction_ids: Option<Vec<String>>,
}

#[derive(Clone, Copy, cynic::Enum, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "TransactionBlockKindInput",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum TransactionKindInput {
    SystemTx,
    ProgrammableTx,
    Genesis,
    ConsensusCommitPrologueV1,
    RandomnessStateUpdate,
    EndOfEpochTx,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Query",
    variables = "TransactionsVariables"
)]
pub struct TransactionsQuery<N>
where
    N: QueryFragment<SchemaType = schema::TransactionBlock, VariablesFields = ()>,
{
    #[arguments(first: $first, after: $after, last: $last, before: $before, filter: $filter)]
    pub(crate) transaction_blocks: TransactionConnection<N>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockConnection")]
pub(crate) struct TransactionConnection<N>
where
    N: QueryFragment<SchemaType = schema::TransactionBlock, VariablesFields = ()>,
{
    pub(crate) page_info: PageInfo,
    pub(crate) nodes: Vec<N>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct SignedNode {
    pub(crate) bcs: Option<wire::Bcs<SenderSignedTransaction>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct EffectsNode {
    pub(crate) effects: Option<EffectsBcs>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub struct WithEffectsNode {
    pub(crate) bcs: Option<wire::Bcs<SenderSignedTransaction>>,
    pub(crate) effects: Option<EffectsBcs>,
}
