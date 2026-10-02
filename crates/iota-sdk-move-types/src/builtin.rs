// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! [`MoveType`] and [`MoveTypes`] impls for Rust built-in types.

use iota_types::{Address, TypeTag};

use crate::{MoveType, MoveTypes};

macro_rules! impl_primitive_move_type {
    ($($rust_ty:ty => $move_ty:ident),+ $(,)?) => {
        $(
            impl MoveType for $rust_ty {
                fn type_tag() -> TypeTag {
                    TypeTag::$move_ty
                }
            }
        )+
    };
}

impl_primitive_move_type!(
    bool => Bool,
    u8 => U8,
    u16 => U16,
    u32 => U32,
    u64 => U64,
    u128 => U128,
    Address => Address,
);

#[cfg(feature = "u256")]
impl_primitive_move_type!(primitive_types::U256 => U256);

impl MoveType for String {
    fn type_tag() -> TypeTag {
        TypeTag::Vector(Box::new(TypeTag::U8))
    }
}

impl<T: MoveType> MoveType for Vec<T> {
    fn type_tag() -> TypeTag {
        TypeTag::Vector(Box::new(T::type_tag()))
    }
}

macro_rules! impl_move_types_tuple {
    ($($tup:ident.$idx:tt),+$(,)?) => {
        impl<$($tup),+> MoveTypes for ($($tup),+)
        where $($tup: MoveTypes),+
        {
            fn push_type_tags(tags: &mut Vec<TypeTag>) {
                $(
                    $tup::push_type_tags(tags);
                )+
            }
        }
    };
}
impl_move_types_tuple!(T1.0, T2.1);
impl_move_types_tuple!(T1.0, T2.1, T3.2);
impl_move_types_tuple!(T1.0, T2.1, T3.2, T4.3);
impl_move_types_tuple!(T1.0, T2.1, T3.2, T4.3, T5.4);

impl MoveTypes for () {
    fn push_type_tags(_: &mut Vec<TypeTag>) {}
}

impl<T: MoveType> MoveTypes for T {
    fn push_type_tags(tags: &mut Vec<TypeTag>) {
        tags.push(Self::type_tag())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iota_framework::{balance::Balance, iota::IOTA, vec_map::VecMap};

    #[test]
    fn vectors_nest_their_element_tag() {
        assert_eq!(Vec::<u64>::type_tag().to_string(), "vector<u64>");
        assert_eq!(String::type_tag().to_string(), "vector<u8>");
        assert_eq!(
            Vec::<Balance<IOTA>>::type_tag().to_string(),
            "vector<0x2::balance::Balance<0x2::iota::IOTA>>"
        );
    }

    #[test]
    fn multi_parameter_mirrors_list_their_type_parameters() {
        assert_eq!(
            VecMap::<Address, Balance<IOTA>>::type_tag().to_string(),
            "0x2::vec_map::VecMap<address, 0x2::balance::Balance<0x2::iota::IOTA>>"
        );
    }
}
