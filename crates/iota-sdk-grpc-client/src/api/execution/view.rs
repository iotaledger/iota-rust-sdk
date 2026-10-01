// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for calling Move view functions.

use std::borrow::Borrow;

use iota_grpc_types::{
    proto::json_to_prost_stringify_numbers,
    read_mask_fields::{IntoReadMask, ViewFunctionCallReadMask},
    v1::{
        command::InputArgument,
        transaction_execution_service::{
            ViewFunctionCallItem, ViewFunctionCallOutputs, ViewFunctionCallsRequest,
            transaction_execution_service_client::TransactionExecutionServiceClient,
        },
    },
};
use iota_types::TypeTag;

use crate::{
    GrpcClient, InterceptedChannel,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, ProtocolError, check_result_count, define_query,
        into_item_results,
    },
};

define_query! {
    /// Query for [`GrpcClient::view_function_call`]. Await it to send the
    /// request.
    pub struct ViewFunctionCallQuery {
        service_client: TransactionExecutionServiceClient<InterceptedChannel>,
        function_call: ViewFunctionCallItem,
        read_mask: ViewFunctionCallReadMask,
    }
    output: GrpcResult<MetadataEnvelope<ViewFunctionCallOutputs>>;
}

impl ViewFunctionCallQuery {
    /// Set the type arguments.
    pub fn type_args(mut self, type_args: impl IntoIterator<Item = impl Borrow<TypeTag>>) -> Self {
        self.function_call.type_args = type_args.into_iter().map(|t| t.borrow().into()).collect();
        self
    }

    /// Set the value arguments, passed as JSON.
    pub fn call_args(
        mut self,
        call_args: impl IntoIterator<Item = impl Borrow<serde_json::Value>>,
    ) -> Self {
        self.function_call.inputs = call_args
            .into_iter()
            .map(|arg| {
                InputArgument::default().with_json(json_to_prost_stringify_numbers(arg.borrow()))
            })
            .collect();
        self
    }

    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ViewFunctionCallReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_batch(self) -> ViewFunctionCallsQuery {
        ViewFunctionCallsQuery {
            service_client: self.service_client,
            function_calls: vec![self.function_call],
            read_mask: self.read_mask,
        }
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<ViewFunctionCallOutputs>> {
        if self.function_call.fq_function_name.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        self.into_batch().send().await?.try_map(|results| {
            results.into_iter().next().ok_or_else(|| {
                GrpcError::Protocol(ProtocolError::EmptyResponseField("call_results"))
            })?
        })
    }
}

define_query! {
    /// Query for [`GrpcClient::view_function_calls`]. Await it to send the
    /// request.
    pub struct ViewFunctionCallsQuery {
        service_client: TransactionExecutionServiceClient<InterceptedChannel>,
        function_calls: Vec<ViewFunctionCallItem>,
        read_mask: ViewFunctionCallReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<ViewFunctionCallOutputs>>>>;
}

impl ViewFunctionCallsQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ViewFunctionCallReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn into_request(
        self,
    ) -> (
        TransactionExecutionServiceClient<InterceptedChannel>,
        ViewFunctionCallsRequest,
    ) {
        let request = ViewFunctionCallsRequest::default()
            .with_view_function_calls(self.function_calls)
            .with_read_mask(self.read_mask);
        (self.service_client, request)
    }

    async fn send(self) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<ViewFunctionCallOutputs>>>> {
        if self.function_calls.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let expected_results = self.function_calls.len();
        let (mut service_client, request) = self.into_request();
        let response = service_client.view_function_calls(request).await?;

        let response = MetadataEnvelope::from(response).map(|r| into_item_results(r.call_results));
        check_result_count(response.body(), expected_results)?;

        Ok(response)
    }
}

impl GrpcClient {
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
    ///
    /// Set [`type_args`](ViewFunctionCallQuery::type_args) and
    /// [`call_args`](ViewFunctionCallQuery::call_args) for a function that
    /// takes them.
    ///
    /// Returns [`ViewFunctionCallOutputs`] which contains:
    /// - `return_values()` - View function return values in case of success
    /// - `execution_error()` - View function execution error in case of failure
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    ///
    /// // `discounted_price` has to be declared `#[view]` in the package.
    /// let outputs = client
    ///     .view_function_call("0x1234::shop::discounted_price")
    ///     .call_args([serde_json::json!(100), serde_json::json!(25)])
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
    /// Without [`read_mask`](ViewFunctionCallQuery::read_mask), the default
    /// mask is used. Pass a
    /// [`ViewFunctionCallField`](iota_grpc_types::read_mask_fields::ViewFunctionCallField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `fq_function_name` is empty.
    /// Returns [`GrpcError::Server`] if the node rejected the call (an unknown
    /// function, a wrong argument count, a non-view function). A call that ran
    /// and *aborted* is not an error here — it comes back as
    /// [`ViewFunctionCallOutputs::execution_error`].
    pub fn view_function_call(&self, fq_function_name: impl Into<String>) -> ViewFunctionCallQuery {
        ViewFunctionCallQuery {
            service_client: self.execution_service_client(),
            function_call: ViewFunctionCallItem::default().with_fq_function_name(fq_function_name),
            read_mask: ViewFunctionCallReadMask::default(),
        }
    }

    /// Call a batch of Move view functions.
    ///
    /// Each call runs in its own transaction on the server, so one call being
    /// rejected leaves the rest untouched.
    ///
    /// Returns a `Vec<GrpcResult<ViewFunctionCallOutputs>>` in the same order
    /// as the input. Each element is either the outputs of that call or the
    /// per-item error the server returned for it. Note that a call which ran
    /// and aborted lands in the `Ok` slot — the abort is reported by
    /// [`ViewFunctionCallOutputs::execution_error`]; only a call the server
    /// refused to run yields `Err`.
    ///
    /// Without [`read_mask`](ViewFunctionCallsQuery::read_mask), the default
    /// mask is used for each `ViewFunctionCallOutputs`. Pass a
    /// [`ViewFunctionCallField`](iota_grpc_types::read_mask_fields::ViewFunctionCallField)
    /// or any slice/array/vec of fields to choose the returned fields.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `function_calls` is empty.
    /// Returns a transport-level [`GrpcError::Grpc`] if the entire RPC fails
    /// (e.g. batch size exceeded).
    /// Returns [`ProtocolError::UnexpectedResultCount`] if the server did not
    /// answer every call, since results are paired with calls by position.
    pub fn view_function_calls(
        &self,
        function_calls: Vec<ViewFunctionCallItem>,
    ) -> ViewFunctionCallsQuery {
        ViewFunctionCallsQuery {
            service_client: self.execution_service_client(),
            function_calls,
            read_mask: ViewFunctionCallReadMask::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::{
        proto::json_to_prost_stringify_numbers,
        read_mask_fields::{ViewFunctionCallField, ViewFunctionCallReadMask},
        v1::command::InputArgument,
    };
    use iota_types::TypeTag;
    use serde_json::json;

    use crate::{GrpcClient, GrpcError};

    #[tokio::test]
    async fn view_function_call_starts_without_arguments_and_with_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.view_function_call("0x2::coin::value");
        assert_eq!(query.function_call.fq_function_name, "0x2::coin::value");
        assert!(query.function_call.type_args.is_empty());
        assert!(query.function_call.inputs.is_empty());
        assert_eq!(
            query.read_mask.as_str(),
            ViewFunctionCallReadMask::default().as_str()
        );
    }

    #[tokio::test]
    async fn argument_setters_convert_borrowed_and_owned_values_alike() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let tags = vec![TypeTag::U64, TypeTag::Bool];
        let args = vec![json!(100), json!("a")];

        let borrowed = client
            .view_function_call("0x2::m::f")
            .type_args(&tags)
            .call_args(&args);
        let owned = client
            .view_function_call("0x2::m::f")
            .type_args(tags.clone())
            .call_args(args.clone());

        let expected_type_args: Vec<_> = tags.iter().map(Into::into).collect();
        let expected_inputs: Vec<_> = args
            .iter()
            .map(|arg| InputArgument::default().with_json(json_to_prost_stringify_numbers(arg)))
            .collect();
        for query in [borrowed, owned] {
            assert_eq!(query.function_call.type_args, expected_type_args);
            assert_eq!(query.function_call.inputs, expected_inputs);
        }
    }

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client
            .view_function_call("0x2::m::f")
            .read_mask(ViewFunctionCallField::EXECUTION_RESULT_RETURN_VALUES);
        assert_eq!(
            query.read_mask.as_str(),
            ViewFunctionCallReadMask::from(ViewFunctionCallField::EXECUTION_RESULT_RETURN_VALUES)
                .as_str()
        );
    }

    #[tokio::test]
    async fn awaiting_an_empty_function_name_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.view_function_call("").await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }

    #[tokio::test]
    async fn awaiting_no_function_calls_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.view_function_calls(Vec::new()).await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }

    #[tokio::test]
    async fn the_request_carries_the_call_and_the_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let args = [json!(100)];
        let (_, request) = client
            .view_function_call("0x2::m::f")
            .type_args([TypeTag::U64])
            .call_args(&args)
            .read_mask(ViewFunctionCallField::EXECUTION_RESULT_RETURN_VALUES)
            .into_batch()
            .into_request();
        assert_eq!(request.view_function_calls.len(), 1);
        let call = &request.view_function_calls[0];
        assert_eq!(call.fq_function_name, "0x2::m::f");
        assert_eq!(call.type_args, vec![(&TypeTag::U64).into()]);
        assert_eq!(
            call.inputs,
            vec![InputArgument::default().with_json(json_to_prost_stringify_numbers(&args[0]))]
        );
        assert_eq!(
            request.read_mask,
            Some(
                ViewFunctionCallReadMask::from(
                    ViewFunctionCallField::EXECUTION_RESULT_RETURN_VALUES
                )
                .into()
            )
        );
    }
}
