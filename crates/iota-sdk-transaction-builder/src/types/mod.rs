// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for use with the transaction builder.

use iota_types::{Address, U256};

mod move_arg;

pub use iota_move_types::{MoveType, MoveTypes};
pub use move_arg::{MoveArg, MoveArgCollection, PureBytes};

macro_rules! impl_simple_move_arg {
    ($rust_ty:ident) => {
        impl MoveArg for &$rust_ty {
            fn pure_bytes(self) -> PureBytes {
                PureBytes(bcs::to_bytes(self).expect("bcs serialization failed"))
            }
        }

        impl MoveArg for $rust_ty {
            fn pure_bytes(self) -> PureBytes {
                PureBytes(bcs::to_bytes(&self).expect("bcs serialization failed"))
            }
        }
    };
}
impl_simple_move_arg!(bool);
impl_simple_move_arg!(u8);
impl_simple_move_arg!(u16);
impl_simple_move_arg!(u32);
impl_simple_move_arg!(u64);
impl_simple_move_arg!(u128);
impl_simple_move_arg!(U256);
impl_simple_move_arg!(Address);

#[cfg(test)]
mod tests {
    use iota_types::{Input, TransactionKind};

    use super::*;
    use crate::TransactionBuilder;

    fn u256_values() -> [U256; 5] {
        // 2^112 as a hex string is 32 bytes long too, so only the content
        // tells it apart from the 32 little-endian bytes.
        let mut two_pow_112 = [0; U256::LENGTH];
        two_pow_112[14] = 1;
        [
            U256::ZERO,
            U256::ONE,
            U256::from(1_000_000_000_000_000_000u64),
            U256::from_le_bytes(two_pow_112),
            U256::MAX,
        ]
    }

    /// The pure inputs of a transaction built from `builder`.
    fn pure_inputs(mut builder: TransactionBuilder) -> Vec<Input> {
        builder.gas_price(1000).gas_budget(1_000_000);
        let transaction = builder.finish().unwrap();
        let TransactionKind::Programmable(ptb) = &transaction.as_v1().kind else {
            panic!("expected a programmable transaction");
        };
        ptb.inputs.clone()
    }

    /// Move reads a `u256` as 32 little-endian bytes.
    #[test]
    fn u256_pure_bytes_are_32_little_endian_bytes() {
        for value in u256_values() {
            let expected = value.to_le_bytes().to_vec();
            assert_eq!(value.pure_bytes().0, expected, "u256 {value}");
            assert_eq!((&value).pure_bytes().0, expected, "&u256 {value}");
        }
    }

    /// A `vector<u256>` is a ULEB128 length followed by 32 bytes per element.
    #[test]
    fn u256_vector_pure_bytes() {
        let values = u256_values();
        let mut expected = vec![values.len() as u8];
        for value in values {
            expected.extend_from_slice(&value.to_le_bytes());
        }
        assert_eq!(values.to_vec().pure_bytes().0, expected);
    }

    /// The pure input of a built transaction carries the same 32 bytes.
    #[test]
    fn u256_move_call_argument() {
        for value in u256_values() {
            let mut builder = TransactionBuilder::new(Address::ZERO);
            builder
                .move_call(Address::STD, "u256", "sqrt")
                .arguments([value]);
            assert_eq!(
                pure_inputs(builder),
                [Input::Pure(value.to_le_bytes().to_vec())],
                "u256 {value}"
            );
        }
    }

    /// `pure` and serde structs encode a `U256` like a Move argument.
    #[test]
    fn u256_through_serde() {
        #[derive(serde::Serialize)]
        struct Wrapper {
            value: U256,
        }

        for value in u256_values() {
            let mut builder = TransactionBuilder::new(Address::ZERO);
            builder.pure(value);
            assert_eq!(
                pure_inputs(builder),
                [Input::Pure(value.to_le_bytes().to_vec())],
                "u256 {value}"
            );
            assert_eq!(
                bcs::to_bytes(&Wrapper { value }).unwrap(),
                value.to_le_bytes(),
                "u256 {value}"
            );
        }
    }
}
