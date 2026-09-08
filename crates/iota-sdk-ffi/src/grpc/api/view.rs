// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Move view function calls API implementation.

use std::sync::Arc;

use iota_sdk::{
    grpc_client::read_mask_fields::ViewFunctionCallReadMask,
    grpc_types::{
        proto::json_to_prost_stringify_numbers,
        v1::{command::InputArgument, transaction_execution_service::ViewFunctionCallItem},
    },
};

use crate::{
    error::Result,
    graphql::api::move_view_call::MoveViewArg,
    grpc::{
        client::GrpcClient,
        output_types::{ViewFunctionCallInput, ViewFunctionCallOutputs, ViewFunctionCallResult},
    },
    types::move_core::TypeTag,
};

fn view_function_call_item(
    fq_function_name: &str,
    type_args: &[Arc<TypeTag>],
    call_args: &[Arc<MoveViewArg>],
) -> ViewFunctionCallItem {
    ViewFunctionCallItem::default()
        .with_fq_function_name(fq_function_name)
        .with_type_args(type_args.iter().map(|tag| (&tag.0).into()).collect())
        .with_inputs(
            call_args
                .iter()
                .map(|arg| {
                    InputArgument::default()
                        .with_json(json_to_prost_stringify_numbers(&arg.to_json()))
                })
                .collect(),
        )
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Call a Move view function and read back what it returns, without
    /// submitting a transaction.
    ///
    /// Only a function declared with the `#[view]` attribute can be called
    /// this way. `fq_function_name` is the fully qualified name
    /// `<package>::<module>::<function>`.
    ///
    /// A call that ran and aborted is not an error: the abort is reported in
    /// the `execution_error` field of the outputs. The call fails only if the
    /// node refused to run it (unknown function, wrong argument count, not a
    /// view function).
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(type_args = None, call_args = None, read_mask = None))]
    pub async fn view_function_call(
        &self,
        fq_function_name: String,
        type_args: Option<Vec<Arc<TypeTag>>>,
        call_args: Option<Vec<Arc<MoveViewArg>>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<ViewFunctionCallOutputs> {
        let item = view_function_call_item(
            &fq_function_name,
            &type_args.unwrap_or_default(),
            &call_args.unwrap_or_default(),
        );
        let mut results = self
            .0
            .read()
            .await
            .view_function_calls(
                vec![item],
                super::read_mask::<ViewFunctionCallReadMask>(&read_mask),
            )
            .await?
            .into_inner();
        (&results.remove(0)?).try_into()
    }

    /// Call a batch of Move view functions.
    ///
    /// Each call runs in its own transaction on the server, so one call being
    /// rejected leaves the rest untouched. Results are returned in the same
    /// order as the input; each result carries either the outputs of the call
    /// or the error the node returned for it. A call that ran and aborted
    /// lands in `outputs`, with the abort in its `execution_error` field.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    #[uniffi::method(default(read_mask = None))]
    pub async fn view_function_calls(
        &self,
        function_calls: Vec<ViewFunctionCallInput>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<ViewFunctionCallResult>> {
        let items = function_calls
            .iter()
            .map(|call| {
                view_function_call_item(&call.fq_function_name, &call.type_args, &call.call_args)
            })
            .collect();
        self.0
            .read()
            .await
            .view_function_calls(
                items,
                super::read_mask::<ViewFunctionCallReadMask>(&read_mask),
            )
            .await?
            .into_inner()
            .iter()
            .map(|result| {
                Ok(match result {
                    Ok(outputs) => ViewFunctionCallResult {
                        outputs: Some(outputs.try_into()?),
                        error: None,
                    },
                    Err(error) => ViewFunctionCallResult {
                        outputs: None,
                        error: Some(error.to_string()),
                    },
                })
            })
            .collect()
    }
}
