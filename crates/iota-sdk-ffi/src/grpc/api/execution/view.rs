// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Move view function calls API implementation.

use std::sync::Arc;

use iota_sdk::{
    grpc_client::read_mask_fields::ViewFunctionCallReadMask,
    grpc_types::{
        proto::json_to_prost_stringify_numbers,
        v1::{
            self as proto, command::InputArgument,
            transaction_execution_service::ViewFunctionCallItem,
        },
    },
};

use crate::{
    error::{Result, SdkFfiError},
    grpc::{
        api::execution::simulate::{CommandOutput, SimulatedExecutionError},
        client::GrpcClient,
        read_mask_fields::ViewFunctionCallField,
    },
    move_view_call::MoveViewArg,
    types::move_core::TypeTag,
};

/// The outputs of a Move view function call.
///
/// Exactly one of `return_values` and `execution_error` is populated when the
/// read mask includes `execution_result`: the first if the call returned, the
/// second if it aborted.
#[derive(uniffi::Record)]
pub struct ViewFunctionCallOutputs {
    /// The values the function returned.
    pub return_values: Option<Vec<CommandOutput>>,
    /// Why the call aborted.
    pub execution_error: Option<SimulatedExecutionError>,
}

impl TryFrom<&proto::transaction_execution_service::ViewFunctionCallOutputs>
    for ViewFunctionCallOutputs
{
    type Error = SdkFfiError;

    fn try_from(
        value: &proto::transaction_execution_service::ViewFunctionCallOutputs,
    ) -> Result<Self> {
        Ok(Self {
            return_values: value
                .return_values()
                .map(|outputs| {
                    outputs
                        .outputs
                        .iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            execution_error: value.execution_error().map(TryInto::try_into).transpose()?,
        })
    }
}

/// The result of a single call in a batch of Move view function calls: either
/// the outputs of the call or the error the node returned for it.
#[derive(uniffi::Record)]
pub struct ViewFunctionCallResult {
    /// The outputs of the call, if the node ran it. A call that ran and
    /// aborted still has outputs, with the abort in `execution_error`.
    pub outputs: Option<ViewFunctionCallOutputs>,
    /// The error message, if the node refused to run the call.
    pub error: Option<String>,
}

/// A Move view function to call with `view_function_calls`.
#[derive(uniffi::Record)]
pub struct ViewFunctionCallInput {
    /// The fully qualified function name, `<package>::<module>::<function>`.
    pub fq_function_name: String,
    /// The type arguments, in declaration order.
    #[uniffi(default = [])]
    pub type_args: Vec<Arc<TypeTag>>,
    /// The call arguments, in declaration order.
    #[uniffi(default = [])]
    pub call_args: Vec<Arc<MoveViewArg>>,
}

impl From<&ViewFunctionCallInput> for ViewFunctionCallItem {
    fn from(input: &ViewFunctionCallInput) -> Self {
        ViewFunctionCallItem::default()
            .with_fq_function_name(&input.fq_function_name)
            .with_type_args(input.type_args.iter().map(|tag| (&tag.0).into()).collect())
            .with_inputs(
                input
                    .call_args
                    .iter()
                    .map(|arg| {
                        InputArgument::default()
                            .with_json(json_to_prost_stringify_numbers(&arg.to_json()))
                    })
                    .collect(),
            )
    }
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
    #[uniffi::method(default(type_args = [], call_args = [], read_mask = None))]
    pub async fn view_function_call(
        &self,
        fq_function_name: String,
        type_args: Vec<Arc<TypeTag>>,
        call_args: Vec<Arc<MoveViewArg>>,
        read_mask: Option<Vec<ViewFunctionCallField>>,
    ) -> Result<ViewFunctionCallOutputs> {
        (&self
            .client()
            .view_function_call(
                &fq_function_name,
                &type_args
                    .iter()
                    .map(|tag| tag.0.clone())
                    .collect::<Vec<_>>(),
                &call_args
                    .iter()
                    .map(|arg| arg.to_json())
                    .collect::<Vec<_>>(),
                crate::grpc::api::read_mask::<ViewFunctionCallReadMask, _>(read_mask),
            )
            .await?
            .into_inner())
            .try_into()
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
        read_mask: Option<Vec<ViewFunctionCallField>>,
    ) -> Result<Vec<ViewFunctionCallResult>> {
        self.client()
            .view_function_calls(
                function_calls.iter().map(Into::into).collect(),
                crate::grpc::api::read_mask::<ViewFunctionCallReadMask, _>(read_mask),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iota_sdk::grpc_types::{
        proto::json_to_prost_stringify_numbers,
        v1::{
            command::{CommandOutput as ProtoCommandOutput, CommandOutputs, input_argument::Input},
            transaction_execution_service::{
                ExecutionError as ProtoExecutionError, ViewFunctionCallItem,
                ViewFunctionCallOutputs as ProtoViewFunctionCallOutputs,
                view_function_call_outputs::ExecutionResult,
            },
        },
    };

    use super::{ViewFunctionCallInput, ViewFunctionCallOutputs};
    use crate::move_view_call::MoveViewArg;

    #[test]
    fn view_function_call_outputs_returned() {
        let mut output = ProtoCommandOutput::default();
        output.json = Some(json_to_prost_stringify_numbers(&serde_json::json!(75)));
        let mut outputs = CommandOutputs::default();
        outputs.outputs = vec![output];
        let mut proto = ProtoViewFunctionCallOutputs::default();
        proto.execution_result = Some(ExecutionResult::ReturnValues(outputs));

        let converted = ViewFunctionCallOutputs::try_from(&proto).unwrap();

        let return_values = converted.return_values.unwrap();
        assert_eq!(return_values.len(), 1);
        assert_eq!(return_values[0].json, Some(serde_json::json!("75")));
        assert!(converted.execution_error.is_none());
    }

    #[test]
    fn view_function_call_outputs_aborted() {
        let mut error = ProtoExecutionError::default();
        error.source = Some("discount over 100%".to_owned());
        error.command_index = Some(0);
        let mut proto = ProtoViewFunctionCallOutputs::default();
        proto.execution_result = Some(ExecutionResult::ExecutionError(error));

        let converted = ViewFunctionCallOutputs::try_from(&proto).unwrap();

        assert!(converted.return_values.is_none());
        let execution_error = converted.execution_error.unwrap();
        assert_eq!(
            execution_error.source.as_deref(),
            Some("discount over 100%")
        );
        assert_eq!(execution_error.command_index, Some(0));
        assert!(execution_error.error.is_none());
    }

    #[test]
    fn view_function_call_outputs_masked_out() {
        let converted =
            ViewFunctionCallOutputs::try_from(&ProtoViewFunctionCallOutputs::default()).unwrap();

        assert!(converted.return_values.is_none());
        assert!(converted.execution_error.is_none());
    }

    #[test]
    fn view_function_call_input_passes_numbers_as_json_strings() {
        let input = ViewFunctionCallInput {
            fq_function_name: "0x2::shop::discounted_price".to_owned(),
            type_args: vec![],
            call_args: vec![
                Arc::new(MoveViewArg::u8(100)),
                Arc::new(MoveViewArg::u64(25)),
            ],
        };

        let item = ViewFunctionCallItem::from(&input);

        assert_eq!(item.fq_function_name, "0x2::shop::discounted_price");
        assert!(item.type_args.is_empty());
        let inputs: Vec<_> = item
            .inputs
            .iter()
            .map(|input| input.input.clone())
            .collect();
        assert_eq!(
            inputs,
            [
                Some(Input::Json(json_to_prost_stringify_numbers(
                    &serde_json::json!("100")
                ))),
                Some(Input::Json(json_to_prost_stringify_numbers(
                    &serde_json::json!("25")
                ))),
            ]
        );
    }
}
