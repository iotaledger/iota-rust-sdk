// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Address, TypeTag};
use primitive_types::U256;

use crate::types::{ParamType, move_param::MoveParam};

/// A trait which defines the tag of the type.
pub trait MoveTypeTag {
    /// Return the type tag.
    fn type_tag(&self) -> TypeTag;
}

/// A trait which defines multiple types for use with tuples.
pub trait MoveTypeTags {
    /// Get the type tags.
    fn type_tags(&self) -> Vec<TypeTag> {
        let mut tags = Vec::new();
        self.push_type_tags(&mut tags);
        tags
    }

    /// Push the type tags onto the list.
    fn push_type_tags(&self, tags: &mut Vec<TypeTag>);
}

impl<T: MoveTypeTag> MoveTypeTags for T {
    fn push_type_tags(&self, tags: &mut Vec<TypeTag>) {
        tags.push(Self::type_tag())
    }
}

impl<T: MoveTypeTag> MoveTypeTag for Vec<T> {
    fn type_tag(&self) -> TypeTag {
        TypeTag::Vector(Box::new(T::type_tag()))
    }
}
