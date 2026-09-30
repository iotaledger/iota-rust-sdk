// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction simulation.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, SimulateReadMask},
    v1::transaction_execution_service::{
        SimulateTransactionItem, SimulateTransactionsRequest, SimulatedTransaction,
        simulate_transaction_item::TransactionCheckModes,
        transaction_execution_service_client::TransactionExecutionServiceClient,
    },
};
use iota_types::Transaction;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, ProtocolError, build_proto_transaction,
        define_query, into_item_results,
    },
};

/// A single transaction with simulation options for use in batch simulation.
pub struct SimulateTransactionInput {
    pub(crate) transaction: Transaction,
    pub(crate) skip_checks: bool,
}

impl SimulateTransactionInput {
    /// Simulate `transaction` with the node's usual Move VM checks.
    pub fn new(transaction: Transaction) -> Self {
        Self {
            transaction,
            skip_checks: false,
        }
    }

    /// Ask for relaxed Move VM checks, which is useful for debugging and
    /// development.
    pub fn skip_checks(mut self, skip_checks: bool) -> Self {
        self.skip_checks = skip_checks;
        self
    }

    /// The transaction to simulate.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Whether the node is asked to relax its Move VM checks.
    pub fn is_skip_checks_enabled(&self) -> bool {
        self.skip_checks
    }
}

define_query! {
    /// Query for [`GrpcClient::simulate_transaction`]. Await it to send the
    /// request.
    pub struct SimulateTransactionQuery {
        service_client: TransactionExecutionServiceClient<InterceptedChannel>,
        input: SimulateTransactionInput,
        read_mask: SimulateReadMask,
    }
    output: GrpcResult<MetadataEnvelope<SimulatedTransaction>>;
}

impl SimulateTransactionQuery {
    /// Ask for relaxed Move VM checks, which is useful for debugging and
    /// development.
    pub fn skip_checks(mut self, skip_checks: bool) -> Self {
        self.input = self.input.skip_checks(skip_checks);
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<SimulateReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_batch(self) -> SimulateTransactionsQuery {
        SimulateTransactionsQuery {
            service_client: self.service_client,
            transactions: vec![self.input],
            read_mask: self.read_mask,
        }
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<SimulatedTransaction>> {
        self.into_batch()
            .send()
            .await?
            .try_map(extract_single_simulation_result)
    }
}

define_query! {
    /// Query for [`GrpcClient::simulate_transactions`]. Await it to send the
    /// request.
    pub struct SimulateTransactionsQuery {
        service_client: TransactionExecutionServiceClient<InterceptedChannel>,
        transactions: Vec<SimulateTransactionInput>,
        read_mask: SimulateReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<SimulatedTransaction>>>>;
}

impl SimulateTransactionsQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<SimulateReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(
        self,
    ) -> GrpcResult<(
        TransactionExecutionServiceClient<InterceptedChannel>,
        SimulateTransactionsRequest,
    )> {
        let items = self
            .transactions
            .into_iter()
            .map(|input| build_simulate_item(input.transaction, input.skip_checks))
            .collect::<GrpcResult<Vec<_>>>()?;

        let request = SimulateTransactionsRequest::default()
            .with_transactions(items)
            .with_read_mask(self.read_mask);

        Ok((self.service_client, request))
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<SimulatedTransaction>>>> {
        if self.transactions.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let (mut service_client, request) = self.into_request()?;
        let response = service_client.simulate_transactions(request).await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.transaction_results)))
    }
}

impl GrpcClient {
    /// Simulate a transaction without executing it.
    ///
    /// This allows you to preview the effects of a transaction before
    /// actually submitting it to the network.
    ///
    /// # Parameters
    ///
    /// - `transaction`: The transaction to simulate
    ///
    /// Set [`skip_checks`](SimulateTransactionQuery::skip_checks) for relaxed
    /// Move VM checks.
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
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::Transaction;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    ///
    /// let tx: Transaction = todo!();
    /// let result = client.simulate_transaction(tx).await?;
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
    ///
    /// Without [`read_mask`](SimulateTransactionQuery::read_mask), the default
    /// mask is used. Pass a
    /// [`SimulateField`](iota_grpc_types::read_mask_fields::SimulateField) or
    /// any slice/array/vec of fields to choose the returned fields.
    pub fn simulate_transaction(&self, transaction: Transaction) -> SimulateTransactionQuery {
        SimulateTransactionQuery {
            service_client: self.execution_service_client(),
            input: SimulateTransactionInput::new(transaction),
            read_mask: SimulateReadMask::default(),
        }
    }

    /// Simulate a batch of transactions without executing them.
    ///
    /// Transactions are simulated sequentially on the server. Each transaction
    /// is independent — failure of one does not abort the rest.
    ///
    /// Returns a `Vec<GrpcResult<SimulatedTransaction>>` in the same order as
    /// the input. Each element is either the successfully simulated
    /// transaction or the per-item error returned by the server.
    ///
    /// Without [`read_mask`](SimulateTransactionsQuery::read_mask), the
    /// default mask is used for each `SimulatedTransaction`. Pass a
    /// [`SimulateField`](iota_grpc_types::read_mask_fields::SimulateField) or
    /// any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `transactions` is empty.
    /// Returns a transport-level [`GrpcError::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub fn simulate_transactions(
        &self,
        transactions: Vec<SimulateTransactionInput>,
    ) -> SimulateTransactionsQuery {
        SimulateTransactionsQuery {
            service_client: self.execution_service_client(),
            transactions,
            read_mask: SimulateReadMask::default(),
        }
    }
}

fn extract_single_simulation_result(
    results: Vec<GrpcResult<SimulatedTransaction>>,
) -> GrpcResult<SimulatedTransaction> {
    results.into_iter().next().ok_or_else(|| {
        GrpcError::Protocol(ProtocolError::EmptyResponseField("transaction_results"))
    })?
}

/// Convert a transaction and options into a proto `SimulateTransactionItem`.
fn build_simulate_item(
    transaction: Transaction,
    skip_checks: bool,
) -> GrpcResult<SimulateTransactionItem> {
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

#[cfg(test)]
mod tests {
    use iota_grpc_types::{
        read_mask_fields::{SimulateField, SimulateReadMask},
        v1::transaction_execution_service::simulate_transaction_item::TransactionCheckModes,
    };
    use iota_types::{
        Address, GasPayment, ProgrammableTransaction, Transaction, TransactionExpiration,
        TransactionKind, TransactionV1,
    };

    use crate::{GrpcClient, GrpcError, SimulateTransactionInput};

    fn transaction() -> Transaction {
        Transaction::V1(TransactionV1 {
            kind: TransactionKind::Programmable(ProgrammableTransaction {
                inputs: Vec::new(),
                commands: Vec::new(),
            }),
            sender: Address::ZERO,
            gas_payment: GasPayment {
                objects: Vec::new(),
                owner: Address::ZERO,
                price: 1,
                budget: 1,
            },
            expiration: TransactionExpiration::None,
        })
    }

    #[tokio::test]
    async fn skip_checks_defaults_to_the_usual_checks() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.simulate_transaction(transaction());
        assert!(!query.input.is_skip_checks_enabled());
        assert_eq!(
            query.read_mask.as_str(),
            SimulateReadMask::default().as_str()
        );

        let query = query
            .skip_checks(true)
            .read_mask(SimulateField::EXECUTED_TRANSACTION_EFFECTS_BCS);
        assert!(query.input.is_skip_checks_enabled());
        assert_eq!(
            query.read_mask.as_str(),
            SimulateReadMask::from(SimulateField::EXECUTED_TRANSACTION_EFFECTS_BCS).as_str()
        );
    }

    #[tokio::test]
    async fn awaiting_no_transactions_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.simulate_transactions(Vec::new()).await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }

    #[tokio::test]
    async fn skip_checks_decides_the_request_checks() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let checks = |skip_checks| {
            let (_, request) = client
                .simulate_transaction(transaction())
                .skip_checks(skip_checks)
                .into_batch()
                .into_request()
                .unwrap();
            request.transactions[0].tx_checks.clone()
        };
        assert_eq!(checks(false), Vec::<i32>::new());
        assert_eq!(
            checks(true),
            vec![TransactionCheckModes::DisableVmChecks as i32]
        );
    }

    #[tokio::test]
    async fn the_request_carries_every_transaction_and_the_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let (_, request) = client
            .simulate_transactions(vec![
                SimulateTransactionInput::new(transaction()),
                SimulateTransactionInput::new(transaction()),
            ])
            .read_mask(SimulateField::EXECUTED_TRANSACTION_EFFECTS_BCS)
            .into_request()
            .unwrap();
        assert_eq!(request.transactions.len(), 2);
        assert_eq!(
            request.read_mask,
            Some(SimulateReadMask::from(SimulateField::EXECUTED_TRANSACTION_EFFECTS_BCS).into())
        );
    }
}
