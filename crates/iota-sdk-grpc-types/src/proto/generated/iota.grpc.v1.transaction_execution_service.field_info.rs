// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _field_impls {
    #![allow(clippy::wrong_self_convention)]
    use super::*;
    use crate::field::MessageFields;
    use crate::field::MessageField;
    impl ExecuteTransactionItem {
        pub const TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "transaction",
            json_name: "transaction",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::transaction::Transaction::FIELDS),
        };
        pub const SIGNATURES_FIELD: &'static MessageField = &MessageField {
            name: "signatures",
            json_name: "signatures",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::signatures::UserSignature::FIELDS),
        };
    }
    impl MessageFields for ExecuteTransactionItem {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTION_FIELD,
            Self::SIGNATURES_FIELD,
        ];
    }
    impl ExecuteTransactionItem {
        pub fn path_builder() -> ExecuteTransactionItemFieldPathBuilder {
            ExecuteTransactionItemFieldPathBuilder::new()
        }
    }
    pub struct ExecuteTransactionItemFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecuteTransactionItemFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transaction(
            mut self,
        ) -> crate::v1::transaction::TransactionFieldPathBuilder {
            self.path.push(ExecuteTransactionItem::TRANSACTION_FIELD.name);
            crate::v1::transaction::TransactionFieldPathBuilder::new_with_base(self.path)
        }
        pub fn signatures(
            mut self,
        ) -> crate::v1::signatures::UserSignatureFieldPathBuilder {
            self.path.push(ExecuteTransactionItem::SIGNATURES_FIELD.name);
            crate::v1::signatures::UserSignatureFieldPathBuilder::new_with_base(
                self.path,
            )
        }
    }
    impl ExecuteTransactionsRequest {
        pub const TRANSACTIONS_FIELD: &'static MessageField = &MessageField {
            name: "transactions",
            json_name: "transactions",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ExecuteTransactionItem::FIELDS),
        };
        pub const READ_MASK_FIELD: &'static MessageField = &MessageField {
            name: "read_mask",
            json_name: "readMask",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const CHECKPOINT_INCLUSION_TIMEOUT_MS_FIELD: &'static MessageField = &MessageField {
            name: "checkpoint_inclusion_timeout_ms",
            json_name: "checkpointInclusionTimeoutMs",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ExecuteTransactionsRequest {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTIONS_FIELD,
            Self::READ_MASK_FIELD,
            Self::CHECKPOINT_INCLUSION_TIMEOUT_MS_FIELD,
        ];
    }
    impl ExecuteTransactionsRequest {
        pub fn path_builder() -> ExecuteTransactionsRequestFieldPathBuilder {
            ExecuteTransactionsRequestFieldPathBuilder::new()
        }
    }
    pub struct ExecuteTransactionsRequestFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecuteTransactionsRequestFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transactions(mut self) -> ExecuteTransactionItemFieldPathBuilder {
            self.path.push(ExecuteTransactionsRequest::TRANSACTIONS_FIELD.name);
            ExecuteTransactionItemFieldPathBuilder::new_with_base(self.path)
        }
        pub fn read_mask(mut self) -> String {
            self.path.push(ExecuteTransactionsRequest::READ_MASK_FIELD.name);
            self.finish()
        }
        pub fn checkpoint_inclusion_timeout_ms(mut self) -> String {
            self.path
                .push(
                    ExecuteTransactionsRequest::CHECKPOINT_INCLUSION_TIMEOUT_MS_FIELD
                        .name,
                );
            self.finish()
        }
    }
    impl ExecuteTransactionResult {
        pub const EXECUTED_TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "executed_transaction",
            json_name: "executedTransaction",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(crate::v1::transaction::ExecutedTransaction::FIELDS),
        };
        pub const ERROR_FIELD: &'static MessageField = &MessageField {
            name: "error",
            json_name: "error",
            number: 2i32,
            is_optional: false,
            is_map: false,
            message_fields: None,
        };
    }
    impl ExecuteTransactionResult {
        pub const RESULT_ONEOF: &'static str = "result";
    }
    impl MessageFields for ExecuteTransactionResult {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::EXECUTED_TRANSACTION_FIELD,
            Self::ERROR_FIELD,
        ];
        const ONEOFS: &'static [&'static str] = &["result"];
    }
    impl ExecuteTransactionResult {
        pub fn path_builder() -> ExecuteTransactionResultFieldPathBuilder {
            ExecuteTransactionResultFieldPathBuilder::new()
        }
    }
    pub struct ExecuteTransactionResultFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecuteTransactionResultFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn executed_transaction(
            mut self,
        ) -> crate::v1::transaction::ExecutedTransactionFieldPathBuilder {
            self.path.push(ExecuteTransactionResult::EXECUTED_TRANSACTION_FIELD.name);
            crate::v1::transaction::ExecutedTransactionFieldPathBuilder::new_with_base(
                self.path,
            )
        }
        pub fn error(mut self) -> String {
            self.path.push(ExecuteTransactionResult::ERROR_FIELD.name);
            self.finish()
        }
    }
    impl ExecuteTransactionsResponse {
        pub const TRANSACTION_RESULTS_FIELD: &'static MessageField = &MessageField {
            name: "transaction_results",
            json_name: "transactionResults",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ExecuteTransactionResult::FIELDS),
        };
    }
    impl MessageFields for ExecuteTransactionsResponse {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTION_RESULTS_FIELD,
        ];
    }
    impl ExecuteTransactionsResponse {
        pub fn path_builder() -> ExecuteTransactionsResponseFieldPathBuilder {
            ExecuteTransactionsResponseFieldPathBuilder::new()
        }
    }
    pub struct ExecuteTransactionsResponseFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecuteTransactionsResponseFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transaction_results(
            mut self,
        ) -> ExecuteTransactionResultFieldPathBuilder {
            self.path.push(ExecuteTransactionsResponse::TRANSACTION_RESULTS_FIELD.name);
            ExecuteTransactionResultFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl SimulateTransactionItem {
        pub const TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "transaction",
            json_name: "transaction",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::transaction::Transaction::FIELDS),
        };
        pub const TX_CHECKS_FIELD: &'static MessageField = &MessageField {
            name: "tx_checks",
            json_name: "txChecks",
            number: 2i32,
            is_optional: false,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for SimulateTransactionItem {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTION_FIELD,
            Self::TX_CHECKS_FIELD,
        ];
    }
    impl SimulateTransactionItem {
        pub fn path_builder() -> SimulateTransactionItemFieldPathBuilder {
            SimulateTransactionItemFieldPathBuilder::new()
        }
    }
    pub struct SimulateTransactionItemFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl SimulateTransactionItemFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transaction(
            mut self,
        ) -> crate::v1::transaction::TransactionFieldPathBuilder {
            self.path.push(SimulateTransactionItem::TRANSACTION_FIELD.name);
            crate::v1::transaction::TransactionFieldPathBuilder::new_with_base(self.path)
        }
        pub fn tx_checks(mut self) -> String {
            self.path.push(SimulateTransactionItem::TX_CHECKS_FIELD.name);
            self.finish()
        }
    }
    impl SimulateTransactionsRequest {
        pub const TRANSACTIONS_FIELD: &'static MessageField = &MessageField {
            name: "transactions",
            json_name: "transactions",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(SimulateTransactionItem::FIELDS),
        };
        pub const READ_MASK_FIELD: &'static MessageField = &MessageField {
            name: "read_mask",
            json_name: "readMask",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for SimulateTransactionsRequest {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTIONS_FIELD,
            Self::READ_MASK_FIELD,
        ];
    }
    impl SimulateTransactionsRequest {
        pub fn path_builder() -> SimulateTransactionsRequestFieldPathBuilder {
            SimulateTransactionsRequestFieldPathBuilder::new()
        }
    }
    pub struct SimulateTransactionsRequestFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl SimulateTransactionsRequestFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transactions(mut self) -> SimulateTransactionItemFieldPathBuilder {
            self.path.push(SimulateTransactionsRequest::TRANSACTIONS_FIELD.name);
            SimulateTransactionItemFieldPathBuilder::new_with_base(self.path)
        }
        pub fn read_mask(mut self) -> String {
            self.path.push(SimulateTransactionsRequest::READ_MASK_FIELD.name);
            self.finish()
        }
    }
    impl ExecutionError {
        pub const BCS_KIND_FIELD: &'static MessageField = &MessageField {
            name: "bcs_kind",
            json_name: "bcsKind",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::bcs::BcsData::FIELDS),
        };
        pub const SOURCE_FIELD: &'static MessageField = &MessageField {
            name: "source",
            json_name: "source",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const COMMAND_INDEX_FIELD: &'static MessageField = &MessageField {
            name: "command_index",
            json_name: "commandIndex",
            number: 3i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ExecutionError {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::BCS_KIND_FIELD,
            Self::SOURCE_FIELD,
            Self::COMMAND_INDEX_FIELD,
        ];
    }
    impl ExecutionError {
        pub fn path_builder() -> ExecutionErrorFieldPathBuilder {
            ExecutionErrorFieldPathBuilder::new()
        }
    }
    pub struct ExecutionErrorFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ExecutionErrorFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn bcs_kind(mut self) -> crate::v1::bcs::BcsDataFieldPathBuilder {
            self.path.push(ExecutionError::BCS_KIND_FIELD.name);
            crate::v1::bcs::BcsDataFieldPathBuilder::new_with_base(self.path)
        }
        pub fn source(mut self) -> String {
            self.path.push(ExecutionError::SOURCE_FIELD.name);
            self.finish()
        }
        pub fn command_index(mut self) -> String {
            self.path.push(ExecutionError::COMMAND_INDEX_FIELD.name);
            self.finish()
        }
    }
    impl SimulatedTransaction {
        pub const EXECUTED_TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "executed_transaction",
            json_name: "executedTransaction",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::transaction::ExecutedTransaction::FIELDS),
        };
        pub const SUGGESTED_GAS_PRICE_FIELD: &'static MessageField = &MessageField {
            name: "suggested_gas_price",
            json_name: "suggestedGasPrice",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
        pub const COMMAND_RESULTS_FIELD: &'static MessageField = &MessageField {
            name: "command_results",
            json_name: "commandResults",
            number: 3i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(crate::v1::command::CommandResult::FIELDS),
        };
        pub const EXECUTION_ERROR_FIELD: &'static MessageField = &MessageField {
            name: "execution_error",
            json_name: "executionError",
            number: 4i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ExecutionError::FIELDS),
        };
    }
    impl SimulatedTransaction {
        pub const EXECUTION_RESULT_ONEOF: &'static str = "execution_result";
    }
    impl MessageFields for SimulatedTransaction {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::EXECUTED_TRANSACTION_FIELD,
            Self::SUGGESTED_GAS_PRICE_FIELD,
            Self::COMMAND_RESULTS_FIELD,
            Self::EXECUTION_ERROR_FIELD,
        ];
        const ONEOFS: &'static [&'static str] = &["execution_result"];
    }
    impl SimulatedTransaction {
        pub fn path_builder() -> SimulatedTransactionFieldPathBuilder {
            SimulatedTransactionFieldPathBuilder::new()
        }
    }
    pub struct SimulatedTransactionFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl SimulatedTransactionFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn executed_transaction(
            mut self,
        ) -> crate::v1::transaction::ExecutedTransactionFieldPathBuilder {
            self.path.push(SimulatedTransaction::EXECUTED_TRANSACTION_FIELD.name);
            crate::v1::transaction::ExecutedTransactionFieldPathBuilder::new_with_base(
                self.path,
            )
        }
        pub fn suggested_gas_price(mut self) -> String {
            self.path.push(SimulatedTransaction::SUGGESTED_GAS_PRICE_FIELD.name);
            self.finish()
        }
        pub fn command_results(
            mut self,
        ) -> crate::v1::command::CommandResultFieldPathBuilder {
            self.path.push(SimulatedTransaction::COMMAND_RESULTS_FIELD.name);
            crate::v1::command::CommandResultFieldPathBuilder::new_with_base(self.path)
        }
        pub fn execution_error(mut self) -> ExecutionErrorFieldPathBuilder {
            self.path.push(SimulatedTransaction::EXECUTION_ERROR_FIELD.name);
            ExecutionErrorFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl SimulateTransactionResult {
        pub const SIMULATED_TRANSACTION_FIELD: &'static MessageField = &MessageField {
            name: "simulated_transaction",
            json_name: "simulatedTransaction",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(SimulatedTransaction::FIELDS),
        };
        pub const ERROR_FIELD: &'static MessageField = &MessageField {
            name: "error",
            json_name: "error",
            number: 2i32,
            is_optional: false,
            is_map: false,
            message_fields: None,
        };
    }
    impl SimulateTransactionResult {
        pub const RESULT_ONEOF: &'static str = "result";
    }
    impl MessageFields for SimulateTransactionResult {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::SIMULATED_TRANSACTION_FIELD,
            Self::ERROR_FIELD,
        ];
        const ONEOFS: &'static [&'static str] = &["result"];
    }
    impl SimulateTransactionResult {
        pub fn path_builder() -> SimulateTransactionResultFieldPathBuilder {
            SimulateTransactionResultFieldPathBuilder::new()
        }
    }
    pub struct SimulateTransactionResultFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl SimulateTransactionResultFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn simulated_transaction(mut self) -> SimulatedTransactionFieldPathBuilder {
            self.path.push(SimulateTransactionResult::SIMULATED_TRANSACTION_FIELD.name);
            SimulatedTransactionFieldPathBuilder::new_with_base(self.path)
        }
        pub fn error(mut self) -> String {
            self.path.push(SimulateTransactionResult::ERROR_FIELD.name);
            self.finish()
        }
    }
    impl SimulateTransactionsResponse {
        pub const TRANSACTION_RESULTS_FIELD: &'static MessageField = &MessageField {
            name: "transaction_results",
            json_name: "transactionResults",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(SimulateTransactionResult::FIELDS),
        };
    }
    impl MessageFields for SimulateTransactionsResponse {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::TRANSACTION_RESULTS_FIELD,
        ];
    }
    impl SimulateTransactionsResponse {
        pub fn path_builder() -> SimulateTransactionsResponseFieldPathBuilder {
            SimulateTransactionsResponseFieldPathBuilder::new()
        }
    }
    pub struct SimulateTransactionsResponseFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl SimulateTransactionsResponseFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn transaction_results(
            mut self,
        ) -> SimulateTransactionResultFieldPathBuilder {
            self.path.push(SimulateTransactionsResponse::TRANSACTION_RESULTS_FIELD.name);
            SimulateTransactionResultFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ViewFunctionCallArgument {
        pub const BCS_FIELD: &'static MessageField = &MessageField {
            name: "bcs",
            json_name: "bcs",
            number: 1i32,
            is_optional: true,
            is_map: false,
            message_fields: Some(crate::v1::bcs::BcsData::FIELDS),
        };
        pub const JSON_FIELD: &'static MessageField = &MessageField {
            name: "json",
            json_name: "json",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ViewFunctionCallArgument {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::BCS_FIELD,
            Self::JSON_FIELD,
        ];
    }
    impl ViewFunctionCallArgument {
        pub fn path_builder() -> ViewFunctionCallArgumentFieldPathBuilder {
            ViewFunctionCallArgumentFieldPathBuilder::new()
        }
    }
    pub struct ViewFunctionCallArgumentFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ViewFunctionCallArgumentFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn bcs(mut self) -> crate::v1::bcs::BcsDataFieldPathBuilder {
            self.path.push(ViewFunctionCallArgument::BCS_FIELD.name);
            crate::v1::bcs::BcsDataFieldPathBuilder::new_with_base(self.path)
        }
        pub fn json(mut self) -> String {
            self.path.push(ViewFunctionCallArgument::JSON_FIELD.name);
            self.finish()
        }
    }
    impl ViewFunctionCallItem {
        pub const FQ_FUNCTION_NAME_FIELD: &'static MessageField = &MessageField {
            name: "fq_function_name",
            json_name: "fqFunctionName",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: None,
        };
        pub const TYPE_ARGS_FIELD: &'static MessageField = &MessageField {
            name: "type_args",
            json_name: "typeArgs",
            number: 2i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(crate::v1::types::TypeTag::FIELDS),
        };
        pub const ARGUMENTS_FIELD: &'static MessageField = &MessageField {
            name: "arguments",
            json_name: "arguments",
            number: 3i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ViewFunctionCallArgument::FIELDS),
        };
    }
    impl MessageFields for ViewFunctionCallItem {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::FQ_FUNCTION_NAME_FIELD,
            Self::TYPE_ARGS_FIELD,
            Self::ARGUMENTS_FIELD,
        ];
    }
    impl ViewFunctionCallItem {
        pub fn path_builder() -> ViewFunctionCallItemFieldPathBuilder {
            ViewFunctionCallItemFieldPathBuilder::new()
        }
    }
    pub struct ViewFunctionCallItemFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ViewFunctionCallItemFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn fq_function_name(mut self) -> String {
            self.path.push(ViewFunctionCallItem::FQ_FUNCTION_NAME_FIELD.name);
            self.finish()
        }
        pub fn type_args(mut self) -> crate::v1::types::TypeTagFieldPathBuilder {
            self.path.push(ViewFunctionCallItem::TYPE_ARGS_FIELD.name);
            crate::v1::types::TypeTagFieldPathBuilder::new_with_base(self.path)
        }
        pub fn arguments(mut self) -> ViewFunctionCallArgumentFieldPathBuilder {
            self.path.push(ViewFunctionCallItem::ARGUMENTS_FIELD.name);
            ViewFunctionCallArgumentFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ViewFunctionCallsRequest {
        pub const FUNCTION_CALLS_FIELD: &'static MessageField = &MessageField {
            name: "function_calls",
            json_name: "functionCalls",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ViewFunctionCallItem::FIELDS),
        };
        pub const READ_MASK_FIELD: &'static MessageField = &MessageField {
            name: "read_mask",
            json_name: "readMask",
            number: 2i32,
            is_optional: true,
            is_map: false,
            message_fields: None,
        };
    }
    impl MessageFields for ViewFunctionCallsRequest {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::FUNCTION_CALLS_FIELD,
            Self::READ_MASK_FIELD,
        ];
    }
    impl ViewFunctionCallsRequest {
        pub fn path_builder() -> ViewFunctionCallsRequestFieldPathBuilder {
            ViewFunctionCallsRequestFieldPathBuilder::new()
        }
    }
    pub struct ViewFunctionCallsRequestFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ViewFunctionCallsRequestFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn function_calls(mut self) -> ViewFunctionCallItemFieldPathBuilder {
            self.path.push(ViewFunctionCallsRequest::FUNCTION_CALLS_FIELD.name);
            ViewFunctionCallItemFieldPathBuilder::new_with_base(self.path)
        }
        pub fn read_mask(mut self) -> String {
            self.path.push(ViewFunctionCallsRequest::READ_MASK_FIELD.name);
            self.finish()
        }
    }
    impl ViewFunctionCallResult {
        pub const VIEW_FUNCTION_CALL_RESULT_FIELD: &'static MessageField = &MessageField {
            name: "view_function_call_result",
            json_name: "viewFunctionCallResult",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(crate::v1::command::CommandOutput::FIELDS),
        };
    }
    impl MessageFields for ViewFunctionCallResult {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::VIEW_FUNCTION_CALL_RESULT_FIELD,
        ];
    }
    impl ViewFunctionCallResult {
        pub fn path_builder() -> ViewFunctionCallResultFieldPathBuilder {
            ViewFunctionCallResultFieldPathBuilder::new()
        }
    }
    pub struct ViewFunctionCallResultFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ViewFunctionCallResultFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn view_function_call_result(
            mut self,
        ) -> crate::v1::command::CommandOutputFieldPathBuilder {
            self.path.push(ViewFunctionCallResult::VIEW_FUNCTION_CALL_RESULT_FIELD.name);
            crate::v1::command::CommandOutputFieldPathBuilder::new_with_base(self.path)
        }
    }
    impl ViewFunctionCallsResponse {
        pub const VIEW_FUNCTION_CALL_RESULTS_FIELD: &'static MessageField = &MessageField {
            name: "view_function_call_results",
            json_name: "viewFunctionCallResults",
            number: 1i32,
            is_optional: false,
            is_map: false,
            message_fields: Some(ViewFunctionCallResult::FIELDS),
        };
    }
    impl MessageFields for ViewFunctionCallsResponse {
        const FIELDS: &'static [&'static MessageField] = &[
            Self::VIEW_FUNCTION_CALL_RESULTS_FIELD,
        ];
    }
    impl ViewFunctionCallsResponse {
        pub fn path_builder() -> ViewFunctionCallsResponseFieldPathBuilder {
            ViewFunctionCallsResponseFieldPathBuilder::new()
        }
    }
    pub struct ViewFunctionCallsResponseFieldPathBuilder {
        path: Vec<&'static str>,
    }
    impl ViewFunctionCallsResponseFieldPathBuilder {
        #[allow(clippy::new_without_default)]
        pub fn new() -> Self {
            Self { path: Default::default() }
        }
        #[doc(hidden)]
        pub fn new_with_base(base: Vec<&'static str>) -> Self {
            Self { path: base }
        }
        pub fn finish(self) -> String {
            self.path.join(".")
        }
        pub fn view_function_call_results(
            mut self,
        ) -> ViewFunctionCallResultFieldPathBuilder {
            self.path
                .push(ViewFunctionCallsResponse::VIEW_FUNCTION_CALL_RESULTS_FIELD.name);
            ViewFunctionCallResultFieldPathBuilder::new_with_base(self.path)
        }
    }
}
pub use _field_impls::*;
