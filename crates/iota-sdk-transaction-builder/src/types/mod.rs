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
impl_simple_move_arg!(U256);
impl_simple_move_arg!(Address);
