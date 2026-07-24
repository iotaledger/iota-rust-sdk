// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for transaction simulation.

use iota_grpc_types::v1::{
    command::CommandOutputs,
    transaction_execution_service::{
        ViewFunctionCallArgument, ViewFunctionCallItem, ViewFunctionCallsRequest,
    },
};
use iota_types::TypeTag;

use crate::{
    Client,
    api::{
        Error, MetadataEnvelope, ProtocolError, ReadMask, Result, VIEW_FUNCTION_CALLS_READ_MASK,
        field_mask_with_default, into_item_results,
    },
};

impl Client {
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
    pub async fn view_function_call(
        &self,
        fq_function_name: &str,
        type_args: &[TypeTag],
        call_args: &[&str],
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<CommandOutputs>> {
        if fq_function_name.is_empty() {
            return Err(Error::EmptyRequest);
        }

        self.view_function_calls(
            vec![
                ViewFunctionCallItem::default()
                    .with_fq_function_name(fq_function_name)
                    .with_type_args(type_args.iter().map(|t| t.into()).collect())
                    .with_arguments(
                        call_args
                            .iter()
                            .map(|arg| {
                                ViewFunctionCallArgument::default().with_json((*arg).to_owned())
                            })
                            .collect(),
                    ),
            ],
            read_mask,
        )
        .await?
        .try_map(|results| {
            results.into_iter().next().ok_or_else(|| {
                Error::Protocol(ProtocolError::EmptyResponseField(
                    "view_function_call_results",
                ))
            })?
        })
    }

    pub async fn view_function_calls(
        &self,
        function_calls: Vec<ViewFunctionCallItem>,
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<Vec<Result<CommandOutputs>>>> {
        if function_calls.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let request = ViewFunctionCallsRequest::default()
            .with_function_calls(function_calls)
            .with_read_mask(field_mask_with_default(
                read_mask,
                VIEW_FUNCTION_CALLS_READ_MASK,
            ));

        let response = self
            .execution_service_client()
            .view_function_calls(request)
            .await?;

        Ok(MetadataEnvelope::from(response)
            .map(|r| into_item_results(r.view_function_call_results)))
    }
}
