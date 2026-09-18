// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::{
    grpc_client::GrpcClient as SdkGrpcClient,
    grpc_types::v1 as proto,
    transaction_builder::{
        ObjectsPage, ProtocolConfig, TransactionBuilderClientBase,
        TransactionBuilderExecutionClient, TransactionBuilderLedgerClient,
        TransactionBuilderSimulationClient, WaitForTransaction,
    },
    types::{
        Address, Object, ObjectId, StructTag, Transaction, TransactionDigest, TransactionEffects,
        Version,
    },
};

use crate::{
    error::{Result as FfiResult, SdkFfiError},
    graphql::output_types::{
        DryRunEffect, DryRunMutation, DryRunResult, DryRunReturn, TransactionArgument,
    },
    grpc::client::GrpcClient,
};

impl TransactionBuilderClientBase for GrpcClient {
    type Error = <SdkGrpcClient as TransactionBuilderClientBase>::Error;
}

impl TransactionBuilderLedgerClient for GrpcClient {
    async fn object(
        &self,
        object_id: ObjectId,
        version: impl Into<Option<Version>>,
    ) -> Result<Option<Object>, Self::Error> {
        TransactionBuilderLedgerClient::object(&self.client(), object_id, version).await
    }

    async fn objects_by_id(
        &self,
        object_ids: &[(ObjectId, Option<Version>)],
    ) -> Result<Vec<Option<Object>>, Self::Error> {
        TransactionBuilderLedgerClient::objects_by_id(&self.client(), object_ids).await
    }

    async fn objects(
        &self,
        struct_tag: Option<StructTag>,
        owner: Address,
        cursor: Option<Vec<u8>>,
        limit: Option<usize>,
    ) -> Result<ObjectsPage, Self::Error> {
        TransactionBuilderLedgerClient::objects(&self.client(), struct_tag, owner, cursor, limit)
            .await
    }

    async fn protocol_config(&self) -> Result<ProtocolConfig, Self::Error> {
        TransactionBuilderLedgerClient::protocol_config(&self.client()).await
    }

    async fn reference_gas_price(
        &self,
        epoch: impl Into<Option<u64>>,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderLedgerClient::reference_gas_price(&self.client(), epoch).await
    }
}

impl TransactionBuilderSimulationClient for GrpcClient {
    type DryRunResult = <SdkGrpcClient as TransactionBuilderSimulationClient>::DryRunResult;

    async fn estimate_transaction_budget(
        &self,
        transaction: &Transaction,
    ) -> Result<Option<u64>, Self::Error> {
        TransactionBuilderSimulationClient::estimate_transaction_budget(&self.client(), transaction)
            .await
    }

    async fn dry_run_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
    ) -> Result<Self::DryRunResult, Self::Error> {
        TransactionBuilderSimulationClient::dry_run_transaction(
            &self.client(),
            transaction,
            skip_checks,
        )
        .await
    }
}

impl TransactionBuilderExecutionClient for GrpcClient {
    async fn execute_transaction(
        &self,
        signatures: &[iota_sdk::types::UserSignature],
        transaction: &Transaction,
        wait_for: impl Into<Option<WaitForTransaction>>,
    ) -> Result<TransactionEffects, Self::Error> {
        TransactionBuilderExecutionClient::execute_transaction(
            &self.client(),
            signatures,
            transaction,
            wait_for,
        )
        .await
    }

    async fn wait_for_transaction(
        &self,
        digest: TransactionDigest,
        wait_for: WaitForTransaction,
    ) -> Result<(), Self::Error> {
        TransactionBuilderExecutionClient::wait_for_transaction(&self.client(), digest, wait_for)
            .await
    }

    async fn transaction_effects(
        &self,
        digest: TransactionDigest,
    ) -> Result<Option<TransactionEffects>, Self::Error> {
        TransactionBuilderExecutionClient::transaction_effects(&self.client(), digest).await
    }
}

/// Convert a simulated transaction returned by the gRPC client into the
/// common [`DryRunResult`] shape used by the transaction builder.
pub(crate) fn dry_run_result_from_simulated(
    value: &proto::transaction_execution_service::SimulatedTransaction,
) -> FfiResult<DryRunResult> {
    let error = value.execution_error().map(|error| {
        error.source.clone().unwrap_or_else(|| {
            error
                .error_kind()
                .map(|kind| kind.to_string())
                .unwrap_or_else(|_| "execution error".to_string())
        })
    });
    let results = value
        .command_results()
        .map(|results| {
            results
                .results
                .iter()
                .map(dry_run_effect)
                .collect::<FfiResult<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let executed = value.executed_transaction.as_ref();
    let transaction = executed
        .and_then(|tx| tx.transaction.as_ref())
        .filter(|transaction| transaction.bcs.is_some())
        .map(|transaction| transaction.transaction().map_err(SdkFfiError::new))
        .transpose()?
        .map(|transaction| {
            let signatures = executed
                .and_then(|tx| tx.signatures.as_ref())
                .map(Vec::<iota_sdk::types::UserSignature>::try_from)
                .transpose()?
                .unwrap_or_default();
            Ok::<_, SdkFfiError>(
                iota_sdk::types::SignedTransaction {
                    transaction,
                    signatures,
                }
                .into(),
            )
        })
        .transpose()?;
    let effects = executed
        .and_then(|tx| tx.effects.as_ref())
        .filter(|effects| effects.bcs.is_some())
        .map(|effects| effects.effects().map_err(SdkFfiError::new))
        .transpose()?
        .map(Into::into)
        .map(Arc::new);

    Ok(DryRunResult {
        error,
        results,
        transaction,
        effects,
    })
}

fn dry_run_effect(value: &proto::command::CommandResult) -> FfiResult<DryRunEffect> {
    Ok(DryRunEffect {
        mutated_references: value
            .mutated_by_ref
            .as_ref()
            .map(|outputs| {
                outputs
                    .outputs
                    .iter()
                    .map(dry_run_mutation)
                    .collect::<FfiResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
        return_values: value
            .return_values
            .as_ref()
            .map(|outputs| {
                outputs
                    .outputs
                    .iter()
                    .map(dry_run_return)
                    .collect::<FfiResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default(),
    })
}

fn dry_run_mutation(value: &proto::command::CommandOutput) -> FfiResult<DryRunMutation> {
    Ok(DryRunMutation {
        input: transaction_argument(value.argument()?)?,
        type_tag: Arc::new(value.type_tag()?.into()),
        bcs: value.output_bcs()?.to_vec(),
    })
}

fn dry_run_return(value: &proto::command::CommandOutput) -> FfiResult<DryRunReturn> {
    Ok(DryRunReturn {
        type_tag: Arc::new(value.type_tag()?.into()),
        bcs: value.output_bcs()?.to_vec(),
    })
}

fn transaction_argument(value: iota_sdk::types::Argument) -> FfiResult<TransactionArgument> {
    Ok(match value {
        iota_sdk::types::Argument::Gas => TransactionArgument::GasCoin,
        iota_sdk::types::Argument::Input(index) => TransactionArgument::Input {
            index: index.into(),
        },
        iota_sdk::types::Argument::Result(cmd) => TransactionArgument::Result {
            cmd: cmd.into(),
            index: None,
        },
        iota_sdk::types::Argument::NestedResult(cmd, index) => TransactionArgument::Result {
            cmd: cmd.into(),
            index: Some(index.into()),
        },
        other => {
            return Err(SdkFfiError::custom(format!(
                "unsupported transaction argument in dry run result: {other:?}"
            )));
        }
    })
}
