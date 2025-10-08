// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for use with the transaction builder.

use iota_types::{Address, TypeTag};

mod move_arg;
mod move_type;

pub use move_arg::{MoveArg, MoveArgCollection, PureBytes};
pub use move_type::{MoveType, MoveTypes};
use primitive_types::U256;

macro_rules! impl_simple_move_type {
    ($rust_ty:ident, $move_ty:ident) => {
        impl MoveType for $rust_ty {
            fn type_tag() -> TypeTag {
                TypeTag::$move_ty
            }
        }

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
impl_simple_move_type!(bool, Bool);
impl_simple_move_type!(u8, U8);
impl_simple_move_type!(u16, U16);
impl_simple_move_type!(u32, U32);
impl_simple_move_type!(u64, U64);
impl_simple_move_type!(u128, U128);
impl_simple_move_type!(U256, U256);
impl_simple_move_type!(Address, Address);
