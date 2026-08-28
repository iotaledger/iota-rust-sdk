// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction simulation.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, SimulateReadMask},
    v1::transaction_execution_service::{
        SimulateTransactionItem, SimulateTransactionsRequest, SimulatedTransaction,
        simulate_transaction_item::TransactionCheckModes,
    },
};
use iota_types::Transaction;

use crate::{
    Client,
    api::{
        Error, MetadataEnvelope, ProtocolError, Result, build_proto_transaction, into_item_results,
    },
};

/// A single transaction with simulation options for use in batch simulation.
pub struct SimulateTransactionInput {
    /// The transaction to simulate.
    pub transaction: Transaction,
    /// Set to true for relaxed Move VM checks (useful for debugging and
    /// development).
    pub skip_checks: bool,
}

impl Client {
    /// Simulate a transaction without executing it.
    ///
    /// This allows you to preview the effects of a transaction before
    /// actually submitting it to the network.
    ///
    /// Uses the default field mask `SimulateReadMask::default()` which includes
    /// effects, events, and input/output objects. Use
    /// [`simulate_transaction_masked`](Self::simulate_transaction_masked) to
    /// specify a custom mask.
    ///
    /// # Parameters
    ///
    /// - `transaction`: The transaction to simulate
    /// - `skip_checks`: Set to true for relaxed Move VM checks (useful for
    ///   debugging and development)
    ///
    /// Returns [`SimulatedTransaction`] which contains:
    /// - `executed_transaction()` - Access to the simulated ExecutedTransaction
    /// - `command_results()` - Access to intermediate command execution results
    ///
    /// Use lazy conversion methods on the executed transaction to extract data:
    /// - `result.executed_transaction()?.effects()` - Get simulated effects
    /// - `result.executed_transaction()?.events()` - Get simulated events (if
    ///   available)
    /// - `result.executed_transaction()?.input_objects()` - Get input objects
    ///   (if requested)
    /// - `result.executed_transaction()?.output_objects()` - Get output objects
    ///   (if requested)
    /// - `result.executed_transaction()?.balance_changes()` - Get balance
    ///   changes (if requested)
    /// - `result.executed_transaction()?.object_changes()` - Get object changes
    ///   (if requested)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::SimulateReadMask;
    /// # use iota_types::Transaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// let tx: Transaction = todo!();
    /// let result = client.simulate_transaction(tx, false).await?;
    ///
    /// let executed_tx = result.body().executed_transaction()?;
    /// let effects = executed_tx.effects()?.effects()?;
    /// println!("Simulation status: {:?}", effects.as_v1().status);
    ///
    /// let output_objs = executed_tx.output_objects()?;
    /// println!("Would create {} objects", output_objs.objects.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn simulate_transaction(
        &self,
        transaction: Transaction,
        skip_checks: bool,
    ) -> Result<MetadataEnvelope<SimulatedTransaction>> {
        self.simulate_transactions_internal(
            vec![SimulateTransactionInput {
                transaction,
                skip_checks,
            }],
            Default::default(),
        )
        .await?
        .try_map(extract_single_simulation_result)
    }

    /// Simulate a transaction without executing it, with a custom read mask.
    ///
    /// See [`simulate_transaction`](Self::simulate_transaction) for behavior.
    /// Pass a
    /// [`SimulateField`](iota_grpc_types::read_mask_fields::SimulateField) or
    /// any slice/array/vec of fields — conversion is automatic.
    pub async fn simulate_transaction_masked(
        &self,
        transaction: Transaction,
        skip_checks: bool,
        read_mask: impl IntoReadMask<SimulateReadMask>,
    ) -> Result<MetadataEnvelope<SimulatedTransaction>> {
        self.simulate_transactions_internal(
            vec![SimulateTransactionInput {
                transaction,
                skip_checks,
            }],
            read_mask.into_read_mask(),
        )
        .await?
        .try_map(extract_single_simulation_result)
    }

    /// Simulate a batch of transactions without executing them.
    ///
    /// Transactions are simulated sequentially on the server. Each transaction
    /// is independent — failure of one does not abort the rest.
    ///
    /// Returns a `Vec<Result<SimulatedTransaction>>` in the same order as the
    /// input. Each element is either the successfully simulated transaction or
    /// the per-item error returned by the server.
    ///
    /// Uses the default field mask `SimulateReadMask::default()`. Use
    /// [`simulate_transactions_masked`](Self::simulate_transactions_masked) to
    /// specify a custom mask.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `transactions` is empty.
    /// Returns a transport-level [`Error::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub async fn simulate_transactions(
        &self,
        transactions: Vec<SimulateTransactionInput>,
    ) -> Result<MetadataEnvelope<Vec<Result<SimulatedTransaction>>>> {
        self.simulate_transactions_internal(transactions, Default::default())
            .await
    }

    /// Simulate a batch of transactions, with a custom read mask.
    ///
    /// See [`simulate_transactions`](Self::simulate_transactions) for
    /// behavior. Pass a
    /// [`SimulateField`](iota_grpc_types::read_mask_fields::SimulateField) or
    /// any slice/array/vec of fields — conversion is automatic.
    pub async fn simulate_transactions_masked(
        &self,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: impl IntoReadMask<SimulateReadMask>,
    ) -> Result<MetadataEnvelope<Vec<Result<SimulatedTransaction>>>> {
        self.simulate_transactions_internal(transactions, read_mask.into_read_mask())
            .await
    }

    async fn simulate_transactions_internal(
        &self,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: SimulateReadMask,
    ) -> Result<MetadataEnvelope<Vec<Result<SimulatedTransaction>>>> {
        if transactions.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let items = transactions
            .into_iter()
            .map(|input| build_simulate_item(input.transaction, input.skip_checks))
            .collect::<Result<Vec<_>>>()?;

        let request = SimulateTransactionsRequest::default()
            .with_transactions(items)
            .with_read_mask(read_mask);

        let response = self
            .execution_service_client()
            .simulate_transactions(request)
            .await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.transaction_results)))
    }
}

fn extract_single_simulation_result(
    results: Vec<Result<SimulatedTransaction>>,
) -> Result<SimulatedTransaction> {
    results
        .into_iter()
        .next()
        .ok_or_else(|| Error::Protocol(ProtocolError::EmptyResponseField("transaction_results")))?
}

/// Convert a transaction and options into a proto `SimulateTransactionItem`.
fn build_simulate_item(
    transaction: Transaction,
    skip_checks: bool,
) -> Result<SimulateTransactionItem> {
    let proto_transaction = build_proto_transaction(&transaction, transaction.digest())?;

    let tx_checks = if skip_checks {
        vec![TransactionCheckModes::DisableVmChecks as i32]
    } else {
        vec![]
    };

    Ok(SimulateTransactionItem::default()
        .with_transaction(proto_transaction)
        .with_tx_checks(tx_checks))
}
