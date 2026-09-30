// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transaction simulation API implementation.

use std::sync::Arc;

use iota_sdk::{grpc_client::read_mask_fields::SimulateReadMask, grpc_types::v1 as proto};

use crate::{
    error::{Result, SdkFfiError},
    grpc::{
        api::ledger::transactions::ExecutedTransaction, client::GrpcClient,
        read_mask_fields::SimulateField,
    },
    types::{
        execution_status::ExecutionError,
        move_core::TypeTag,
        transaction::{Argument, Transaction},
    },
};

/// An intermediate result/output from the execution of a single command.
#[derive(uniffi::Record)]
pub struct CommandOutput {
    /// The argument the output corresponds to.
    pub argument: Option<Arc<Argument>>,
    /// The Move type of the output.
    pub type_tag: Option<Arc<TypeTag>>,
    /// The BCS representation of the output.
    pub bcs: Option<Vec<u8>>,
    /// The JSON rendering of the output.
    pub json: Option<serde_json::Value>,
}

impl TryFrom<&proto::command::CommandOutput> for CommandOutput {
    type Error = SdkFfiError;

    fn try_from(value: &proto::command::CommandOutput) -> Result<Self> {
        Ok(Self {
            argument: value
                .argument
                .as_ref()
                .map(|argument| argument.argument().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            type_tag: value
                .type_tag
                .as_ref()
                .map(|type_tag| type_tag.type_tag().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            bcs: value.bcs.as_ref().map(Vec::from),
            json: value
                .json
                .is_some()
                .then(|| value.output_json().map_err(SdkFfiError::new))
                .transpose()?,
        })
    }
}

/// The intermediate results/outputs from the execution of a single command.
#[derive(uniffi::Record)]
pub struct CommandResult {
    /// The outputs of the arguments that were mutably borrowed by the command.
    pub mutated_by_ref: Vec<CommandOutput>,
    /// The return values of the command.
    pub return_values: Vec<CommandOutput>,
}

impl TryFrom<&proto::command::CommandResult> for CommandResult {
    type Error = SdkFfiError;

    fn try_from(value: &proto::command::CommandResult) -> Result<Self> {
        Ok(Self {
            mutated_by_ref: value
                .mutated_by_ref
                .as_ref()
                .map(|outputs| {
                    outputs
                        .outputs
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
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
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// An error that occurred during the simulated execution of a transaction.
#[derive(uniffi::Record)]
pub struct SimulatedExecutionError {
    /// The kind of execution error.
    pub error: Option<ExecutionError>,
    /// The error source as a string.
    pub source: Option<String>,
    /// The index of the command that failed.
    pub command_index: Option<u64>,
}

impl TryFrom<&proto::transaction_execution_service::ExecutionError> for SimulatedExecutionError {
    type Error = SdkFfiError;

    fn try_from(value: &proto::transaction_execution_service::ExecutionError) -> Result<Self> {
        Ok(Self {
            error: value
                .bcs_kind
                .is_some()
                .then(|| value.error_kind().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into),
            source: value.source.clone(),
            command_index: value.command_index,
        })
    }
}

/// The result of simulating a transaction.
#[derive(uniffi::Record)]
pub struct SimulatedTransaction {
    /// The simulated executed transaction.
    pub transaction: Option<ExecutedTransaction>,
    /// The suggested gas price (in NANOS).
    pub suggested_gas_price: Option<u64>,
    /// The intermediate results/outputs for each command of the transaction,
    /// if the simulation succeeded.
    pub command_results: Option<Vec<CommandResult>>,
    /// The execution error, if the simulation failed.
    pub execution_error: Option<SimulatedExecutionError>,
}

impl TryFrom<&proto::transaction_execution_service::SimulatedTransaction> for SimulatedTransaction {
    type Error = SdkFfiError;

    fn try_from(
        value: &proto::transaction_execution_service::SimulatedTransaction,
    ) -> Result<Self> {
        Ok(Self {
            transaction: value
                .executed_transaction
                .as_ref()
                .map(TryInto::try_into)
                .transpose()?,
            suggested_gas_price: value.suggested_gas_price,
            command_results: value
                .command_results()
                .map(|results| {
                    results
                        .results
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            execution_error: value.execution_error().map(TryInto::try_into).transpose()?,
        })
    }
}

/// The result of simulating a single transaction in a batch: either the
/// simulated transaction or an error.
#[derive(uniffi::Record)]
pub struct SimulatedTransactionResult {
    /// The simulated transaction, if the simulation succeeded.
    pub transaction: Option<SimulatedTransaction>,
    /// The error message, if the simulation failed.
    pub error: Option<String>,
}

/// A transaction to simulate with `simulate_transactions`.
#[derive(uniffi::Record)]
pub struct SimulateTransactionInput {
    /// The transaction to simulate.
    pub transaction: Arc<Transaction>,
    /// Whether to skip the VM checks during the simulation.
    #[uniffi(default = false)]
    pub skip_checks: bool,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Simulate a transaction.
    ///
    /// If `skip_checks` is `true`, the VM checks are skipped during the
    /// simulation.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(skip_checks = false, read_mask = None))]
    pub async fn simulate_transaction(
        &self,
        transaction: &Transaction,
        skip_checks: bool,
        read_mask: Option<Vec<SimulateField>>,
    ) -> Result<SimulatedTransaction> {
        (&self
            .client()
            .simulate_transaction(
                transaction.0.clone(),
                skip_checks,
                crate::grpc::api::read_mask::<SimulateReadMask, _>(read_mask),
            )
            .await?
            .into_inner())
            .try_into()
    }

    /// Simulate a batch of transactions.
    ///
    /// A per-transaction error does not abort the rest of the batch; each
    /// result carries either the simulated transaction or an error message.
    #[uniffi::method(default(read_mask = None))]
    pub async fn simulate_transactions(
        &self,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: Option<Vec<SimulateField>>,
    ) -> Result<Vec<SimulatedTransactionResult>> {
        self.client()
            .simulate_transactions(
                transactions
                    .into_iter()
                    .map(|input| {
                        iota_sdk::grpc_client::SimulateTransactionInput::new(
                            input.transaction.0.clone(),
                        )
                        .skip_checks(input.skip_checks)
                    })
                    .collect(),
                crate::grpc::api::read_mask::<SimulateReadMask, _>(read_mask),
            )
            .await?
            .into_inner()
            .into_iter()
            .map(|result| {
                Ok(match result {
                    Ok(transaction) => SimulatedTransactionResult {
                        transaction: Some((&transaction).try_into()?),
                        error: None,
                    },
                    Err(error) => SimulatedTransactionResult {
                        transaction: None,
                        error: Some(error.to_string()),
                    },
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use iota_sdk::grpc_types::{
        proto::json_to_prost_stringify_numbers,
        v1::{
            command::{CommandOutput as ProtoCommandOutput, CommandOutputs, CommandResults},
            transaction_execution_service::{
                ExecutionError as ProtoExecutionError,
                SimulatedTransaction as ProtoSimulatedTransaction,
                simulated_transaction::ExecutionResult,
            },
        },
    };

    use super::SimulatedTransaction;

    #[test]
    fn simulated_transaction_with_command_results() {
        let mut output = ProtoCommandOutput::default();
        output.json = Some(json_to_prost_stringify_numbers(&serde_json::json!(42)));
        let mut outputs = CommandOutputs::default();
        outputs.outputs = vec![output];
        let mut result = iota_sdk::grpc_types::v1::command::CommandResult::default();
        result.return_values = Some(outputs);
        let mut results = CommandResults::default();
        results.results = vec![result];
        let mut proto = ProtoSimulatedTransaction::default();
        proto.suggested_gas_price = Some(1000);
        proto.execution_result = Some(ExecutionResult::CommandResults(results));

        let converted = SimulatedTransaction::try_from(&proto).unwrap();

        assert_eq!(converted.suggested_gas_price, Some(1000));
        let command_results = converted.command_results.unwrap();
        assert_eq!(command_results.len(), 1);
        assert_eq!(
            command_results[0].return_values[0].json,
            Some(serde_json::json!("42"))
        );
        assert!(command_results[0].mutated_by_ref.is_empty());
        assert!(converted.execution_error.is_none());
    }

    #[test]
    fn simulated_transaction_with_execution_error() {
        let mut error = ProtoExecutionError::default();
        error.source = Some("insufficient gas".to_owned());
        error.command_index = Some(2);
        let mut proto = ProtoSimulatedTransaction::default();
        proto.execution_result = Some(ExecutionResult::ExecutionError(error));

        let converted = SimulatedTransaction::try_from(&proto).unwrap();

        assert!(converted.command_results.is_none());
        let execution_error = converted.execution_error.unwrap();
        assert_eq!(execution_error.source.as_deref(), Some("insufficient gas"));
        assert_eq!(execution_error.command_index, Some(2));
    }
}
