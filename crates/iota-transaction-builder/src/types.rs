// Copyright 2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types for use with these tools.

use base64ct::Encoding;
use iota_types::{Address, Digest, IdentifierRef, ObjectId, StructTag, TypeTag};
use primitive_types::U256;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value as JsonValue;

/// A trait for defining a custom move struct in rust code.
/// NOTE: Ideally this type is derived.
pub trait CustomMoveType {
    /// The generic types of this custom type. The empty expression () indicates
    /// that there are no generics.
    type Generics: MoveTypes;
    /// The package address.
    const PACKAGE: Address;
    /// The name of the module in the move package in which this type is
    /// defined.
    const MODULE: &'static IdentifierRef;
    /// The name of this type in the move package.
    const TYPE_NAME: &'static IdentifierRef;

    /// Get the type tag from this custom move type.
    fn type_tag() -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: Self::PACKAGE,
            module: Self::MODULE.into(),
            name: Self::TYPE_NAME.into(),
            type_params: Self::Generics::type_tags(),
        }))
    }
}

/// A parameter type.
#[derive(Clone)]
pub enum ParamType {
    /// An object, referenced by ID.
    Object(ObjectId),
    /// A bcs serialized value.
    Pure(Vec<u8>),
}

/// A trait which defines how types are serialized for move calls.
pub trait MoveParam {
    /// Get the serialized argument.
    fn iota_arg(&self) -> anyhow::Result<JsonValue>;

    /// Get the param type.
    fn param(&self) -> anyhow::Result<ParamType>;
}

/// A trait which defines the iota tag of the type.
pub trait MoveType {
    /// Return the type tag.
    fn type_tag() -> TypeTag;
}

/// A trait which defines multiple params for use with tuples.
pub trait MoveParams {
    /// Get the aui args.
    fn iota_args(&self) -> anyhow::Result<Vec<JsonValue>> {
        let mut values = Vec::new();
        self.push_iota_args(&mut values)?;
        Ok(values)
    }

    /// Push the iota args onto the list.
    fn push_iota_args(&self, values: &mut Vec<JsonValue>) -> anyhow::Result<()>;
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

        impl<$($tup),+> MoveParams for ($($tup),+)
        where $($tup: MoveParams),+
        {
            fn push_iota_args(&self, values: &mut Vec<JsonValue>) -> anyhow::Result<()> {
                $(
                    self.$idx.push_iota_args(values)?;
                )+
                Ok(())
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

impl<T: MoveParam> MoveParams for T {
    fn push_iota_args(&self, values: &mut Vec<JsonValue>) -> anyhow::Result<()> {
        values.push(self.iota_arg()?);
        Ok(())
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
            fn iota_arg(&self) -> anyhow::Result<JsonValue> {
                Ok(serde_json::Value::String(self.to_string()))
            }

            fn param(&self) -> anyhow::Result<ParamType> {
                Ok(ParamType::Pure(bcs::to_bytes(self)?))
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

impl<T: MoveType> MoveType for Vec<T> {
    fn type_tag() -> TypeTag {
        TypeTag::Vector(Box::new(T::type_tag()))
    }
}

impl<T: CustomMoveType> MoveType for T {
    fn type_tag() -> TypeTag {
        <T as CustomMoveType>::type_tag()
    }
}

impl MoveParam for ObjectId {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(JsonValue::String(self.to_string()))
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Object(*self))
    }
}

impl MoveParam for Digest {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(JsonValue::String(base64ct::Base64::encode_string(
            self.as_bytes(),
        )))
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(bcs::to_bytes(self)?))
    }
}

impl MoveParam for ParamType {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        match self {
            ParamType::Object(object_id) => object_id.iota_arg(),
            ParamType::Pure(items) => Ok(JsonValue::String(base64ct::Base64::encode_string(items))),
        }
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(self.clone())
    }
}

impl MoveParam for () {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(JsonValue::Null)
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(Vec::new()))
    }
}

impl<T: Serialize> MoveParam for Vec<T> {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(serde_json::to_value(self)?)
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(bcs::to_bytes(self)?))
    }
}

impl<T: Serialize> MoveParam for Box<T> {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(serde_json::to_value(self)?)
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(bcs::to_bytes(self)?))
    }
}

impl<T: MoveParam + Serialize + DeserializeOwned> MoveParam for Option<T> {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        match self {
            Some(value) => value.iota_arg(),
            None => Ok(JsonValue::Null),
        }
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        match self {
            Some(value) => match value.param()? {
                ParamType::Object(object_id) => {
                    Ok(ParamType::Pure(bcs::to_bytes(&Some(object_id))?))
                }
                ParamType::Pure(items) => Ok(ParamType::Pure(bcs::to_bytes(&Some(
                    bcs::from_bytes::<T>(&items)?,
                ))?)),
            },
            None => Ok(ParamType::Pure(vec![0; core::mem::size_of::<T>() + 1])),
        }
    }
}

impl MoveParam for [u8] {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(JsonValue::String(base64ct::Base64::encode_string(self)))
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(self.to_vec()))
    }
}

impl<const N: usize> MoveParam for [u8; N] {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        Ok(JsonValue::String(base64ct::Base64::encode_string(self)))
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        Ok(ParamType::Pure(self.to_vec()))
    }
}

impl<T: MoveParam> MoveParam for &T {
    fn iota_arg(&self) -> anyhow::Result<JsonValue> {
        (*self).iota_arg()
    }

    fn param(&self) -> anyhow::Result<ParamType> {
        (*self).param()
    }
}

impl<T: MoveTypes> CustomMoveType for Option<T> {
    type Generics = T;

    const PACKAGE: Address = Address::ONE;
    const MODULE: &'static IdentifierRef = IdentifierRef::const_new("option");
    const TYPE_NAME: &'static IdentifierRef = IdentifierRef::const_new("Option");
}

/// Helper macro for wrapping possible type trees into Options.
#[macro_export]
macro_rules! opt {
    ($Some:tt) => {
        Some($Some)
    };
    () => {
        None
    };
}

/// Defines a custom move type.
#[macro_export]
macro_rules! move_type {
    (@impl $(($Package:tt))? $Module:tt $Name:ident $(($($Generics:tt)*) ($($Bounds:tt)*))?) => {
        impl $(<$($Bounds)*>)? CustomMoveType for $Name $(<$($Generics)*>)? {
            type Generics = ($($($Generics)*)?);

            const PACKAGE: Option<move_core_types::account_address::AccountAddress> = $crate::opt!($($Package)?);
            const MODULE: &'static move_core_types::identifier::IdentStr = move_core_types::ident_str!(core::stringify!($Module));
            const TYPE_NAME: &'static move_core_types::identifier::IdentStr = move_core_types::ident_str!(core::stringify!($Name));
        }
    };
    (@split $(($Package:tt))? $Module:tt $Name:ident <$($Generic:tt $(: $Bound1:tt $(+ $Bounds:tt)*)?),+>) => {
        move_type!(@impl $(($Package))? $Module $Name ($($Generic),+) ($($Generic $(: $Bound1 $(+ $Bounds)*)?),+));
    };
    (@generics $(($Package:tt))? $Module:tt $Name:ident <$($Generic:tt $(: $Bound1:tt $(+ $Bounds:tt)*)?),+> $($Rest:tt)*) => {
        move_type!(@split $(($Package))? $Module $Name <$($Generic $(: $Bound1 $(+ $Bounds)*)?),+>);
    };
    (@generics $(($Package:tt))? $Module:tt $Name:ident $($Rest:tt)*) => {
        move_type!(@impl $(($Package))? $Module $Name);
    };
    ($(#[$Meta:meta])* $Vis:vis struct $Package:tt :: $Module:tt :: $Name:ident $($Rest:tt)*) => {
        $(#[$Meta])*
        $Vis struct $Name $($Rest)*

        move_type!(@generics ($Package:tt) $Module $Name $($Rest)*);
    };
    ($(#[$Meta:meta])* $Vis:vis struct $Module:tt :: $Name:ident $($Rest:tt)*) => {
        $(#[$Meta])*
        $Vis struct $Name $($Rest)*

        move_type!(@generics $Module $Name $($Rest)*);
    };
}
