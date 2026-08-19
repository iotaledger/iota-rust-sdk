// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Argument types for Move view calls.

use iota_types::{Address, ObjectId, ObjectReference};

/// A trait which defines a single argument for a Move View Function call.
#[diagnostic::on_unimplemented(message = "Provided value is not a valid Move view argument.")]
pub trait MoveViewArg {
    /// Convert this argument to a JSON value.
    fn to_json(self) -> serde_json::Value;
}

// Macro for types that convert to JSON Number
macro_rules! impl_move_view_arg_number {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MoveViewArg for $ty {
                fn to_json(self) -> serde_json::Value {
                    serde_json::Value::Number(self.into())
                }
            }

            impl MoveViewArg for &$ty {
                fn to_json(self) -> serde_json::Value {
                    (*self).to_json()
                }
            }
        )*
    };
}

// Macro for types that convert to JSON String via to_string()
macro_rules! impl_move_view_arg_string {
    ($($ty:ty),* $(,)?) => {
        $(
            impl MoveViewArg for $ty {
                fn to_json(self) -> serde_json::Value {
                    serde_json::Value::String(self.to_string())
                }
            }

            impl MoveViewArg for &$ty {
                fn to_json(self) -> serde_json::Value {
                    (*self).to_json()
                }
            }
        )*
    };
}

impl MoveViewArg for bool {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Bool(self)
    }
}

impl MoveViewArg for &bool {
    fn to_json(self) -> serde_json::Value {
        (*self).to_json()
    }
}

impl_move_view_arg_number!(u8, u16, u32);

// u64 and u128 must be represented as strings in JSON to avoid precision loss
impl_move_view_arg_string!(u64, u128, ObjectId, Address);

impl MoveViewArg for &str {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String((*self).to_owned())
    }
}

impl MoveViewArg for String {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self)
    }
}

impl MoveViewArg for &String {
    fn to_json(self) -> serde_json::Value {
        self.as_str().to_json()
    }
}

impl MoveViewArg for ObjectReference {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self.object_id.to_string())
    }
}

impl MoveViewArg for &ObjectReference {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::String(self.object_id.to_string())
    }
}

// Collection implementations
impl<T: MoveViewArg> MoveViewArg for Vec<T> {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.into_iter().map(|v| v.to_json()).collect())
    }
}

impl<T> MoveViewArg for &[T]
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.iter().map(|v| v.to_json()).collect())
    }
}

impl<const N: usize, T: MoveViewArg> MoveViewArg for [T; N] {
    fn to_json(self) -> serde_json::Value {
        serde_json::Value::Array(self.into_iter().map(|v| v.to_json()).collect())
    }
}

impl<T: MoveViewArg> MoveViewArg for Option<T> {
    fn to_json(self) -> serde_json::Value {
        match self {
            Some(v) => v.to_json(),
            None => serde_json::Value::Null,
        }
    }
}

// Smart pointer implementations
impl<T> MoveViewArg for std::sync::Arc<T>
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        self.as_ref().to_json()
    }
}

impl<T> MoveViewArg for Box<T>
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json(self) -> serde_json::Value {
        self.as_ref().to_json()
    }
}

// Allow passing raw JSON values
impl MoveViewArg for serde_json::Value {
    fn to_json(self) -> serde_json::Value {
        self
    }
}

/// A trait which defines a list of arguments for a Move View Function call.
#[diagnostic::on_unimplemented(
    message = "Provided value is not a valid list of Move view arguments.",
    note = "Expected a tuple, vector, array, or slice of types that implement `MoveViewArg`."
)]
pub trait MoveViewArgList {
    /// Convert the arguments to a vector of JSON values.
    fn to_json_vec(self) -> Vec<serde_json::Value>;
}

// Single element tuple implementation
impl<T: MoveViewArg> MoveViewArgList for (T,) {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        vec![self.0.to_json()]
    }
}

impl<T: MoveViewArg> MoveViewArgList for Vec<T> {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.into_iter().map(|v| v.to_json()).collect()
    }
}

impl<const N: usize, T: MoveViewArg> MoveViewArgList for [T; N] {
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.into_iter().map(|v| v.to_json()).collect()
    }
}

impl<T> MoveViewArgList for &[T]
where
    for<'a> &'a T: MoveViewArg,
{
    fn to_json_vec(self) -> Vec<serde_json::Value> {
        self.iter().map(|v| v.to_json()).collect()
    }
}

// Tuple implementations using a macro
macro_rules! impl_move_view_args_tuple {
    ($(($n:tt, $T:ident)),*) => {
        impl<$($T),+> MoveViewArgList for ($($T),+)
        where $($T: MoveViewArg),+
        {
            fn to_json_vec(self) -> Vec<serde_json::Value> {
                vec![
                    $(
                        self.$n.to_json()
                    ),+
                ]
            }
        }
    };
}

variadics_please::all_tuples_enumerated!(impl_move_view_args_tuple, 2, 15, T);
