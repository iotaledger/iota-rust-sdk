// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for use with the transaction builder.

use iota_types::Address;

mod move_arg;

pub use iota_move_types::{MoveType, MoveTypes};
pub use move_arg::{MoveArg, MoveArgCollection, PureBytes};
use primitive_types::U256;

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
impl_simple_move_arg!(Address);

// Move reads a `u256` as 32 little-endian bytes, while the serde form of
// `primitive_types::U256` is a hex string.
impl MoveArg for &U256 {
    fn pure_bytes(self) -> PureBytes {
        PureBytes(self.to_little_endian().to_vec())
    }
}

impl MoveArg for U256 {
    fn pure_bytes(self) -> PureBytes {
        (&self).pure_bytes()
    }
}

#[cfg(test)]
mod tests {
    use iota_types::{Input, TransactionKind};

    use super::*;
    use crate::TransactionBuilder;

    fn u256_values() -> [U256; 5] {
        [
            U256::zero(),
            U256::one(),
            U256::from(1_000_000_000_000_000_000u64),
            // Encodes to 32 bytes as a string too, so only the content tells
            // the two encodings apart.
            U256::one() << 112,
            U256::MAX,
        ]
    }

    /// Move reads a `u256` as 32 little-endian bytes.
    #[test]
    fn u256_pure_bytes_are_32_little_endian_bytes() {
        for value in u256_values() {
            let expected = value.to_little_endian().to_vec();
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
            expected.extend_from_slice(&value.to_little_endian());
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
            builder.gas_price(1000).gas_budget(1_000_000);
            let transaction = builder.finish().unwrap();

            let TransactionKind::Programmable(ptb) = &transaction.as_v1().kind else {
                panic!("expected a programmable transaction");
            };
            assert_eq!(
                ptb.inputs,
                [Input::Pure(value.to_little_endian().to_vec())],
                "u256 {value}"
            );
        }
    }
}
