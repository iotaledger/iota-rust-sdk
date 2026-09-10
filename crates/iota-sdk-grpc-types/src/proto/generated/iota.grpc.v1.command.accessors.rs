// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod _accessor_impls {
    #![allow(clippy::useless_conversion)]
    impl super::InputArgument {
        /// Sets `bcs` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_bcs<T: Into<super::super::bcs::BcsData>>(
            mut self,
            field: T,
        ) -> Self {
            self.input = Some(super::input_argument::Input::Bcs(field.into()));
            self
        }
        /// Sets `json` with the provided value.
        /// If any other oneof field in the same oneof is set, it will be cleared.
        pub fn with_json<T: Into<::prost_types::Value>>(mut self, field: T) -> Self {
            self.input = Some(super::input_argument::Input::Json(field.into()));
            self
        }
    }
}
