// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for calling Move view functions.

use iota_grpc_types::{
    proto::json_to_prost,
    read_mask_fields::{IntoReadMask, ViewFunctionCallReadMask},
    v1::{
        command::InputArgument,
        transaction_execution_service::{
            ViewFunctionCallItem, ViewFunctionCallOutputs, ViewFunctionCallsRequest,
        },
    },
};
use iota_types::TypeTag;

use crate::{
    Client,
    api::{Error, MetadataEnvelope, ProtocolError, Result, into_item_results},
};

impl Client {
    /// Call a Move view function and read back what it returns, without
    /// submitting a transaction.
    ///
    /// Arguments are passed as JSON and encoded by the node against the
    /// parameter's Move type. Numbers go over the wire as strings. To
    /// pass BCS-encoded arguments instead, build the [`InputArgument`]s
    /// yourself and use [`view_function_calls`](Self::view_function_calls).
    ///
    /// # Parameters
    ///
    /// - `fq_function_name`: Fully qualified Move view function name
    /// - `type_args`: Type arguments
    /// - `call_args`: Value arguments
    ///
    /// Returns [`ViewFunctionCallOutputs`] which contains:
    /// - `return_values()` - View function return values in case of success
    /// - `execution_error()` - View function execution error in case of failure
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::ViewFunctionCallReadMask;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    ///
    /// // `discounted_price` has to be declared `#[view]` in the package.
    /// let outputs = client
    ///     .view_function_call(
    ///         "0x1234::shop::discounted_price",
    ///         &[],
    ///         &[serde_json::json!(100), serde_json::json!(25)],
    ///         ViewFunctionCallReadMask::default(),
    ///     )
    ///     .await?;
    ///
    /// // The call ran either way; `execution_error` says whether it aborted.
    /// match outputs.body().return_values() {
    ///     Some(values) => println!("returned {} value(s)", values.outputs.len()),
    ///     None => println!("aborted: {:?}", outputs.body().execution_error()),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The `read_mask` controls which fields the server returns; use
    /// `ViewFunctionCallReadMask::default()` for the default mask. Pass a
    /// [`ViewFunctionCallField`](iota_grpc_types::read_mask_fields::ViewFunctionCallField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `fq_function_name` is empty.
    /// Returns [`Error::Server`] if the node rejected the call (an unknown
    /// function, a wrong argument count, a non-view function). A call that ran
    /// and *aborted* is not an error here — it comes back as
    /// [`ViewFunctionCallOutputs::execution_error`].
    pub async fn view_function_call(
        &self,
        fq_function_name: &str,
        type_args: &[TypeTag],
        call_args: &[serde_json::Value],
        read_mask: impl IntoReadMask<ViewFunctionCallReadMask>,
    ) -> Result<MetadataEnvelope<ViewFunctionCallOutputs>> {
        if fq_function_name.is_empty() {
            return Err(Error::EmptyRequest);
        }

        self.view_function_calls(
            vec![
                ViewFunctionCallItem::default()
                    .with_fq_function_name(fq_function_name)
                    .with_type_args(type_args.iter().map(|t| t.into()).collect())
                    .with_inputs(
                        call_args
                            .iter()
                            .map(|arg| InputArgument::default().with_json(json_to_prost(arg)))
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

    /// Call a batch of Move view functions.
    ///
    /// Each call runs in its own transaction on the server, so one call being
    /// rejected leaves the rest untouched.
    ///
    /// Returns a `Vec<Result<ViewFunctionCallOutputs>>` in the same order as
    /// the input. Each element is either the outputs of that call or the
    /// per-item error the server returned for it. Note that a call which ran
    /// and aborted lands in the `Ok` slot — the abort is reported by
    /// [`ViewFunctionCallOutputs::execution_error`]; only a call the server
    /// refused to run yields `Err`.
    ///
    /// The `read_mask` controls which fields the server returns for each
    /// `ViewFunctionCallOutputs`; use `ViewFunctionCallReadMask::default()`
    /// for the default mask. Pass a
    /// [`ViewFunctionCallField`](iota_grpc_types::read_mask_fields::ViewFunctionCallField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `function_calls` is empty.
    /// Returns a transport-level [`Error::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    pub async fn view_function_calls(
        &self,
        function_calls: Vec<ViewFunctionCallItem>,
        read_mask: impl IntoReadMask<ViewFunctionCallReadMask>,
    ) -> Result<MetadataEnvelope<Vec<Result<ViewFunctionCallOutputs>>>> {
        if function_calls.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let read_mask = read_mask.into_read_mask();
        let request = ViewFunctionCallsRequest::default()
            .with_view_function_calls(function_calls)
            .with_read_mask(read_mask);

        let response = self
            .execution_service_client()
            .view_function_calls(request)
            .await?;

        Ok(MetadataEnvelope::from(response).map(|r| into_item_results(r.call_results)))
    }
}
