// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{future::IntoFuture, str::FromStr, time::Duration};

use base64ct::Encoding;
use cynic::{MutationBuilder, Operation, OperationBuilder, QueryBuilder};
use iota_client_api::WaitForTransaction;
use iota_types::{
    Address, Argument, Transaction, TransactionDigest, TransactionEffects, TypeTag, UserSignature,
};

use crate::{
    Error, GraphQLClient, Query, Request, Result, ServerVersion, time,
    transport::BoxFuture,
    wire::{self, Bytes, EffectsBcs, MoveTypeRepr, Num, schema},
};

/// The fields selected only from servers since 1.33, which have them.
const SINCE_1_33: &str = "since-1.33";

/// How long [`TransactionWait`] waits by default.
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The result of a dry run.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct DryRunResult {
    /// What executing the transaction would do.
    pub effects: Option<TransactionEffects>,
    /// Why execution would fail, if it would.
    pub error: Option<String>,
    /// What each command returned and which arguments it mutated.
    pub results: Vec<CommandResult>,
    /// The transaction as the server simulated it. Reported by servers since
    /// 1.33.
    pub transaction: Option<Transaction>,
    /// The gas price to use: the reference gas price, or higher if an input
    /// object is congested. Reported by servers since 1.33.
    pub suggested_gas_price: Option<u64>,
}

/// What one command of a dry run returned and mutated.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CommandResult {
    /// The arguments the command borrowed mutably, with their new values.
    pub mutated_references: Vec<MutatedReference>,
    /// The values the command returned.
    pub return_values: Vec<ReturnValue>,
}

/// An argument a command borrowed mutably, with its new value.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MutatedReference {
    /// The argument.
    pub argument: Argument,
    /// The Move type of its value.
    pub type_tag: TypeTag,
    /// The BCS of its new value.
    pub bcs: Vec<u8>,
}

/// A value a command returned.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReturnValue {
    /// The Move type of the value.
    pub type_tag: TypeTag,
    /// The BCS of the value.
    pub bcs: Vec<u8>,
}

/// Query for [`GraphQLClient::dry_run`].
#[derive(Clone, Debug)]
pub struct DryRun {
    transaction: Transaction,
    skip_checks: bool,
}

impl DryRun {
    /// The full transaction when it names its gas objects. Otherwise its kind
    /// and gas settings, so that the server selects the gas objects.
    fn variables(&self) -> Result<DryRunVariables> {
        let Transaction::V1(transaction) = &self.transaction else {
            return Err(Error::invalid_input(
                "this client cannot dry run this transaction version",
            ));
        };
        if transaction.gas_payment.objects.is_empty() {
            Ok(DryRunVariables {
                tx_bytes: encode_bcs(&transaction.kind)?,
                tx_meta: Some(TransactionMetadataInput {
                    sender: Some(transaction.sender),
                    gas_price: Some(transaction.gas_payment.price),
                    gas_budget: Some(transaction.gas_payment.budget),
                    gas_sponsor: Some(transaction.gas_payment.owner),
                }),
                skip_checks: Some(self.skip_checks),
            })
        } else {
            Ok(DryRunVariables {
                tx_bytes: encode_bcs(&self.transaction)?,
                tx_meta: None,
                skip_checks: Some(self.skip_checks),
            })
        }
    }
}

/// The Base64 of the BCS of `value`.
fn encode_bcs<T: serde::Serialize>(value: &T) -> Result<String> {
    let bytes = bcs::to_bytes(value)
        .map_err(|error| Error::invalid_input(format!("cannot encode the transaction: {error}")))?;
    Ok(base64ct::Base64::encode_string(&bytes))
}

impl Query for DryRun {
    type Output = DryRunResult;
    type Data = DryRunQuery;
    type Variables = DryRunVariables;

    const NEEDS_SERVER_VERSION: bool = true;

    fn operation(
        &self,
        server_version: Option<&ServerVersion>,
    ) -> Result<Operation<DryRunQuery, DryRunVariables>> {
        let mut builder = OperationBuilder::query().with_variables(self.variables()?);
        if server_version.is_some_and(|version| version.is_at_least(1, 33, 0)) {
            builder.enable_feature(SINCE_1_33);
        }
        builder
            .build()
            .map_err(|error| Error::invalid_input(format!("cannot build the dry run: {error}")))
    }

    fn decode(self, data: DryRunQuery) -> Result<DryRunResult> {
        let result = data.dry_run_transaction_block;
        let (effects, transaction) = match result.transaction {
            Some(block) => (block.effects, block.bcs_unsigned),
            None => (None, None),
        };
        Ok(DryRunResult {
            effects: effects
                .and_then(|effects| effects.bcs)
                .map(|wire::Bcs(effects)| effects),
            error: result.error,
            results: result
                .results
                .unwrap_or_default()
                .into_iter()
                .map(CommandResult::decode)
                .collect::<Result<_>>()?,
            transaction: transaction.map(|wire::Bcs(transaction)| transaction),
            suggested_gas_price: result.suggested_gas_price.map(Num::into_inner),
        })
    }
}

impl CommandResult {
    fn decode(effect: DryRunEffectNode) -> Result<Self> {
        Ok(Self {
            mutated_references: effect
                .mutated_references
                .unwrap_or_default()
                .into_iter()
                .map(|mutation| {
                    Ok(MutatedReference {
                        argument: mutation.input.decode()?,
                        type_tag: parse_type(&mutation.type_)?,
                        bcs: mutation.bcs.0,
                    })
                })
                .collect::<Result<_>>()?,
            return_values: effect
                .return_values
                .unwrap_or_default()
                .into_iter()
                .map(|value| {
                    Ok(ReturnValue {
                        type_tag: parse_type(&value.type_)?,
                        bcs: value.bcs.0,
                    })
                })
                .collect::<Result<_>>()?,
        })
    }
}

fn parse_type(move_type: &MoveTypeRepr) -> Result<TypeTag> {
    TypeTag::from_str(&move_type.repr).map_err(|error| {
        Error::malformed_with(format!("invalid Move type `{}`", move_type.repr), error)
    })
}

impl ArgumentNode {
    fn decode(self) -> Result<Argument> {
        let index = |value: i32| {
            u16::try_from(value)
                .map_err(|error| Error::malformed_with(format!("invalid index {value}"), error))
        };
        Ok(match self {
            Self::GasCoin(gas_coin) => gas_coin.argument(),
            Self::Input(input) => Argument::Input(index(input.ix)?),
            Self::Result(result) => match result.ix {
                Some(ix) => Argument::NestedResult(index(result.cmd)?, index(ix)?),
                None => Argument::Result(index(result.cmd)?),
            },
            Self::Unknown => return Err(Error::malformed("unknown transaction argument")),
        })
    }
}

impl Request<DryRun> {
    /// Skip the checks that keep the transaction from accessing objects other
    /// addresses own, or calling non-public functions. Defaults to `false`.
    pub fn skip_checks(self, skip_checks: bool) -> Self {
        self.map(|query| DryRun {
            skip_checks,
            ..query
        })
    }
}

/// Query for [`GraphQLClient::execute`].
#[derive(Clone, Debug)]
pub struct ExecuteTransaction {
    transaction: Transaction,
    signatures: Vec<UserSignature>,
}

impl Query for ExecuteTransaction {
    type Output = TransactionEffects;
    type Data = ExecuteMutation;
    type Variables = ExecuteVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<ExecuteMutation, ExecuteVariables>> {
        Ok(ExecuteMutation::build(ExecuteVariables {
            tx_bytes: encode_bcs(&self.transaction)?,
            signatures: self
                .signatures
                .iter()
                .map(UserSignature::to_base64)
                .collect(),
        }))
    }

    fn decode(self, data: ExecuteMutation) -> Result<TransactionEffects> {
        data.execute_transaction_block
            .effects
            .bcs
            .map(|wire::Bcs(effects)| effects)
            .ok_or_else(|| Error::malformed("the executed transaction has no effects"))
    }
}

/// Waits until a transaction is indexed or finalized; returned by
/// [`GraphQLClient::wait_for_transaction`]. Resolves when awaited.
///
/// It polls the server with a growing interval, keeps polling through
/// [retryable](Error::is_retryable) failures, and fails with
/// [`Error::TimedOut`] at its deadline.
#[derive(Clone, Debug)]
#[must_use = "a wait only happens when awaited"]
pub struct TransactionWait {
    client: GraphQLClient,
    digest: TransactionDigest,
    until: WaitForTransaction,
    timeout: Duration,
}

impl TransactionWait {
    /// What to wait for. Defaults to [`WaitForTransaction::Finalized`].
    pub fn until(self, until: WaitForTransaction) -> Self {
        Self { until, ..self }
    }

    /// How long to wait. Defaults to 60 seconds.
    pub fn timeout(self, timeout: Duration) -> Self {
        Self { timeout, ..self }
    }

    async fn poll(&self) -> Result<()> {
        let mut interval = FIRST_POLL_INTERVAL;
        loop {
            let done = match self.until {
                WaitForTransaction::Finalized => self.client.send(IsFinalized(self.digest)).await,
                WaitForTransaction::IndexedOnNode => {
                    self.client.send(IsIndexedOnNode(self.digest)).await
                }
                _ => return Err(Error::invalid_input("unsupported wait condition")),
            };
            match done {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) if error.is_retryable() => {
                    tracing::debug!(%error, "transaction status unavailable, polling again");
                }
                Err(error) => return Err(error),
            }
            time::sleep(interval).await;
            interval = (interval * 2).min(MAX_POLL_INTERVAL);
        }
    }
}

impl IntoFuture for TransactionWait {
    type Output = Result<()>;
    type IntoFuture = BoxFuture<'static, Result<()>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            time::timeout(self.timeout, self.poll())
                .await
                .unwrap_or(Err(Error::TimedOut(self.timeout)))
        })
    }
}

/// Whether a transaction is included in a checkpoint.
struct IsFinalized(TransactionDigest);

impl Query for IsFinalized {
    type Output = bool;
    type Data = TransactionCheckpointQuery;
    type Variables = DigestVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<TransactionCheckpointQuery, DigestVariables>> {
        Ok(TransactionCheckpointQuery::build(DigestVariables {
            digest: self.0.to_string(),
        }))
    }

    fn decode(self, data: TransactionCheckpointQuery) -> Result<bool> {
        Ok(data
            .transaction_block
            .and_then(|block| block.effects)
            .and_then(|effects| effects.checkpoint)
            .map(|checkpoint| checkpoint.sequence_number)
            .is_some())
    }
}

/// Whether a transaction is indexed on the server's fullnode.
struct IsIndexedOnNode(TransactionDigest);

impl Query for IsIndexedOnNode {
    type Output = bool;
    type Data = IndexedOnNodeQuery;
    type Variables = DigestVariables;

    fn operation(
        &self,
        _: Option<&ServerVersion>,
    ) -> Result<Operation<IndexedOnNodeQuery, DigestVariables>> {
        Ok(IndexedOnNodeQuery::build(DigestVariables {
            digest: self.0.to_string(),
        }))
    }

    fn decode(self, data: IndexedOnNodeQuery) -> Result<bool> {
        Ok(data.is_transaction_indexed_on_node)
    }
}

impl GraphQLClient {
    /// Simulate `transaction` without committing it.
    ///
    /// If the transaction names no gas objects, the server picks them, using
    /// the transaction's gas price, budget and owner.
    pub fn dry_run(&self, transaction: &Transaction) -> Request<DryRun> {
        Request::new(
            self,
            DryRun {
                transaction: transaction.clone(),
                skip_checks: false,
            },
        )
    }

    /// Execute `transaction`, signed with `signatures`, and resolve to its
    /// effects once a validator quorum has executed it.
    ///
    /// The transaction may not be queryable yet when this resolves; follow up
    /// with [`wait_for_transaction`](Self::wait_for_transaction) to wait until
    /// it is.
    pub fn execute(
        &self,
        transaction: &Transaction,
        signatures: &[UserSignature],
    ) -> Request<ExecuteTransaction> {
        Request::new(
            self,
            ExecuteTransaction {
                transaction: transaction.clone(),
                signatures: signatures.to_vec(),
            },
        )
    }

    /// Wait until the transaction with `digest` is finalized, or what
    /// [`until`](TransactionWait::until) sets.
    pub fn wait_for_transaction(&self, digest: TransactionDigest) -> TransactionWait {
        TransactionWait {
            client: self.clone(),
            digest,
            until: WaitForTransaction::Finalized,
            timeout: DEFAULT_WAIT_TIMEOUT,
        }
    }
}

#[derive(cynic::QueryVariables, Debug)]
pub struct DryRunVariables {
    pub(crate) tx_bytes: String,
    pub(crate) tx_meta: Option<TransactionMetadataInput>,
    pub(crate) skip_checks: Option<bool>,
}

#[derive(Clone, cynic::InputObject, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionMetadata")]
pub struct TransactionMetadataInput {
    pub(crate) sender: Option<Address>,
    pub(crate) gas_price: Option<u64>,
    pub(crate) gas_budget: Option<u64>,
    pub(crate) gas_sponsor: Option<Address>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DryRunVariables")]
pub struct DryRunQuery {
    #[arguments(txBytes: $tx_bytes, txMeta: $tx_meta, skipChecks: $skip_checks)]
    pub(crate) dry_run_transaction_block: DryRunResultNode,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunResult")]
pub(crate) struct DryRunResultNode {
    pub(crate) error: Option<String>,
    pub(crate) results: Option<Vec<DryRunEffectNode>>,
    pub(crate) transaction: Option<DryRunTransactionNode>,
    #[cynic(feature = "since-1.33")]
    pub(crate) suggested_gas_price: Option<Num<u64>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub(crate) struct DryRunTransactionNode {
    #[cynic(feature = "since-1.33")]
    pub(crate) bcs_unsigned: Option<wire::Bcs<Transaction>>,
    pub(crate) effects: Option<EffectsBcs>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunEffect")]
pub(crate) struct DryRunEffectNode {
    pub(crate) mutated_references: Option<Vec<DryRunMutationNode>>,
    pub(crate) return_values: Option<Vec<DryRunReturnNode>>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunMutation")]
pub(crate) struct DryRunMutationNode {
    pub(crate) input: ArgumentNode,
    #[cynic(rename = "type")]
    pub(crate) type_: MoveTypeRepr,
    pub(crate) bcs: Bytes,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "DryRunReturn")]
pub(crate) struct DryRunReturnNode {
    #[cynic(rename = "type")]
    pub(crate) type_: MoveTypeRepr,
    pub(crate) bcs: Bytes,
}

#[derive(cynic::InlineFragments, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionArgument")]
pub(crate) enum ArgumentNode {
    GasCoin(GasCoinNode),
    Input(InputNode),
    Result(ResultNode),
    #[cynic(fallback)]
    Unknown,
}

/// The gas coin argument. GraphQL requires selecting a field, and `_` is its
/// only one.
#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "GasCoin")]
pub(crate) struct GasCoinNode {
    #[cynic(rename = "_")]
    pub(crate) _placeholder: Option<bool>,
}

impl GasCoinNode {
    fn argument(self) -> Argument {
        Argument::Gas
    }
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Input")]
pub(crate) struct InputNode {
    pub(crate) ix: i32,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Result")]
pub(crate) struct ResultNode {
    pub(crate) cmd: i32,
    pub(crate) ix: Option<i32>,
}

#[derive(cynic::QueryVariables, Debug)]
pub struct ExecuteVariables {
    pub(crate) tx_bytes: String,
    pub(crate) signatures: Vec<String>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(
    schema = "rpc",
    graphql_type = "Mutation",
    variables = "ExecuteVariables"
)]
pub struct ExecuteMutation {
    #[arguments(txBytes: $tx_bytes, signatures: $signatures)]
    pub(crate) execute_transaction_block: ExecutionResultNode,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "ExecutionResult")]
pub(crate) struct ExecutionResultNode {
    pub(crate) effects: EffectsBcs,
}

#[derive(cynic::QueryVariables, Debug)]
pub(crate) struct DigestVariables {
    pub(crate) digest: String,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DigestVariables")]
pub(crate) struct TransactionCheckpointQuery {
    #[arguments(digest: $digest)]
    pub(crate) transaction_block: Option<TransactionCheckpointNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlock")]
pub(crate) struct TransactionCheckpointNode {
    pub(crate) effects: Option<EffectsCheckpointNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "TransactionBlockEffects")]
pub(crate) struct EffectsCheckpointNode {
    pub(crate) checkpoint: Option<CheckpointNumberNode>,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Checkpoint")]
pub(crate) struct CheckpointNumberNode {
    pub(crate) sequence_number: u64,
}

#[derive(cynic::QueryFragment, Debug)]
#[cynic(schema = "rpc", graphql_type = "Query", variables = "DigestVariables")]
pub(crate) struct IndexedOnNodeQuery {
    #[arguments(digest: $digest)]
    pub(crate) is_transaction_indexed_on_node: bool,
}
