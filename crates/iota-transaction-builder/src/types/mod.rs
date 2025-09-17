// Copyright 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for use with these tools.

use iota_types::{Address, ObjectId, TypeTag};

mod custom;
mod move_param;
mod move_type;

pub use custom::CustomMoveType;
pub use move_param::MoveParam;
pub use move_type::{MoveType, MoveTypes};
use primitive_types::U256;

/// A parameter type.
#[derive(Clone, Debug)]
pub enum ParamType {
    /// An object, referenced by ID.
    Object(ObjectId),
    /// A bcs serialized value.
    Pure(Vec<u8>),
}

/// A Move `vector` type for specifying that type and not a rust `Vec`, which is
/// used for passing multiple params.
#[derive(Clone, Debug)]
pub struct Vector<T>(pub Vec<T>);

impl<T> From<Vec<T>> for Vector<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}

macro_rules! impl_simple_move_type {
    ($rust_ty:ident, $move_ty:ident) => {
        impl MoveType for $rust_ty {
            fn type_tag() -> TypeTag {
                TypeTag::$move_ty
            }
        }

        impl MoveParam for $rust_ty {
            fn param(&self) -> ParamType {
                ParamType::Pure(bcs::to_bytes(self).expect("bcs serialization failed"))
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
