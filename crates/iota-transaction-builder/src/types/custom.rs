// Copyright 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{Address, IdentifierRef, StructTag, TypeTag};

use crate::types::move_type::{MoveType, MoveTypes};

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

impl<T: MoveTypes> CustomMoveType for Option<T> {
    type Generics = T;

    const PACKAGE: Address = Address::ONE;
    const MODULE: &'static IdentifierRef = IdentifierRef::const_new("option");
    const TYPE_NAME: &'static IdentifierRef = IdentifierRef::const_new("Option");
}

impl<T: CustomMoveType> MoveType for T {
    fn type_tag() -> TypeTag {
        <T as CustomMoveType>::type_tag()
    }
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
