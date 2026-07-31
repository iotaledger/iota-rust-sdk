// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction simulation.

use iota_grpc_types::v1::transaction_execution_service::{
    SimulateTransactionItem, SimulateTransactionsRequest, SimulatedTransaction,
    simulate_transaction_item::TransactionCheckModes,
};
use iota_types::Transaction;

use crate::{
    Client,
    api::{
        Error, MetadataEnvelope, ProtocolError, ReadMask, Result, SIMULATE_TRANSACTIONS_READ_MASK,
        build_proto_transaction, field_mask_with_default, into_item_results,
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
    /// # Parameters
    ///
    /// - `transaction`: The transaction to simulate
    /// - `skip_checks`: Set to true for relaxed Move VM checks (useful for
    ///   debugging and development)
    /// - `read_mask`: Optional field mask to control which fields are returned
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
    /// # Read Mask
    ///
    /// The optional `read_mask` parameter controls which fields the server
    /// returns. If `None`, uses [`SIMULATE_TRANSACTIONS_READ_MASK`] which
    /// includes effects, events, and input/output objects.
    ///
    /// Use [`SimulateField`](iota_grpc_types::read_mask_fields::SimulateField)
    /// constants with [`ReadMask::from`] for field selection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_types::Transaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000")?;
    ///
    /// let tx: Transaction = todo!();
    ///
    /// // Simulate transaction - returns proto type
    /// let result = client.simulate_transaction(tx, false, None).await?;
    ///
    /// // Lazy conversion - only deserialize what you need
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
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<SimulatedTransaction>> {
        self.simulate_transactions(
            vec![SimulateTransactionInput {
                transaction,
                skip_checks,
            }],
            read_mask,
        )
        .await?
        .try_map(|results| {
            results.into_iter().next().ok_or_else(|| {
                Error::Protocol(ProtocolError::EmptyResponseField("transaction_results"))
            })?
        })
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
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `transactions` is empty.
    /// Returns a transport-level [`Error::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub async fn simulate_transactions(
        &self,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: Option<ReadMask<'_>>,
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
            .with_read_mask(field_mask_with_default(
                read_mask,
                SIMULATE_TRANSACTIONS_READ_MASK,
            ));

        let response = self
            .execution_service_client()
            .simulate_transactions(request)
            .await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.transaction_results)))
    }
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
