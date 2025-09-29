// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::TypeTag;

/// A trait which defines the tag of the type.
pub trait MoveType {
    /// Return the type tag.
    fn type_tag() -> TypeTag;
}

impl MoveType for String {
    fn type_tag() -> TypeTag {
        TypeTag::Vector(Box::new(TypeTag::U8))
    }
}

/// A trait which defines multiple types for use with tuples.
pub trait MoveTypes {
    /// Get the type tags.
    fn type_tags() -> Vec<TypeTag> {
        let mut tags = Vec::new();
        Self::push_type_tags(&mut tags);
        tags
    }

    /// Push the type tags onto the list.
    fn push_type_tags(tags: &mut Vec<TypeTag>);
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

impl<T: MoveType> MoveType for Vec<T> {
    fn type_tag() -> TypeTag {
        TypeTag::Vector(Box::new(T::type_tag()))
    }
}
