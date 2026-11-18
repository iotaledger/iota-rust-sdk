// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _accessor_impls {
    #![allow(clippy::useless_conversion)]
    impl super::DisplayFieldResult {
        /// Sets `value` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_value<T: Into<String>>(mut self, field: T) -> Self {
            self.result = Some(super::display_field_result::Result::Value(field.into()));
            self
        }
        /// Sets `error` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_error<
            T: Into<super::super::super::super::super::google::rpc::Status>,
        >(mut self, field: T) -> Self {
            self.result = Some(super::display_field_result::Result::Error(field.into()));
            self
        }
    }
}
