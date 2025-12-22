// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod parse;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization;

use super::Address;

/// Type of a move value
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-tag = type-tag-u8 \
///            type-tag-u16 \
///            type-tag-u32 \
///            type-tag-u64 \
///            type-tag-u128 \
///            type-tag-u256 \
///            type-tag-bool \
///            type-tag-address \
///            type-tag-signer \
///            type-tag-vector \
///            type-tag-struct
///
/// type-tag-u8 = %x01
/// type-tag-u16 = %x08
/// type-tag-u32 = %x09
/// type-tag-u64 = %x02
/// type-tag-u128 = %x03
/// type-tag-u256 = %x0a
/// type-tag-bool = %x00
/// type-tag-address = %x04
/// type-tag-signer = %x05
/// type-tag-vector = %x06 type-tag
/// type-tag-struct = %x07 struct-tag
/// ```
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Clone, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub enum TypeTag {
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Bool,
    Address,
    Signer,
    #[cfg_attr(feature = "proptest", weight(0))]
    Vector(Box<TypeTag>),
    Struct(Box<StructTag>),
}

impl TypeTag {
    crate::def_is!(U8, U16, U32, U64, U128, U256, Bool, Address, Signer);

    pub fn is_vector(&self) -> bool {
        matches!(self, Self::Vector(_))
    }

    pub fn as_vector_type_tag_opt(&self) -> Option<&TypeTag> {
        if let Self::Vector(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn as_vector_type_tag(&self) -> &TypeTag {
        self.as_vector_type_tag_opt().expect("not a Vector")
    }

    pub fn into_vector_type_tag_opt(self) -> Option<TypeTag> {
        if let Self::Vector(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    pub fn into_vector_type_tag(self) -> TypeTag {
        self.into_vector_type_tag_opt().expect("not a Vector")
    }

    pub fn is_struct(&self) -> bool {
        matches!(self, Self::Struct(_))
    }

    pub fn as_struct_tag_opt(&self) -> Option<&StructTag> {
        if let Self::Struct(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn as_struct_tag(&self) -> &StructTag {
        self.as_struct_tag_opt().expect("not a Struct")
    }

    pub fn into_struct_tag_opt(self) -> Option<StructTag> {
        if let Self::Struct(inner) = self {
            Some(*inner)
        } else {
            None
        }
    }

    pub fn into_struct_tag(self) -> StructTag {
        self.into_struct_tag_opt().expect("not a Struct")
    }

    pub fn u8() -> Self {
        Self::U8
    }

    pub fn u16() -> Self {
        Self::U16
    }

    pub fn u32() -> Self {
        Self::U32
    }

    pub fn u64() -> Self {
        Self::U64
    }

    pub fn u128() -> Self {
        Self::U128
    }

    pub fn u256() -> Self {
        Self::U256
    }

    pub fn bool() -> Self {
        Self::Bool
    }

    pub fn address() -> Self {
        Self::Address
    }

    pub fn signer() -> Self {
        Self::Signer
    }

    /// Returns the string representation of this type tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        match self {
            TypeTag::U8 => "u8".to_owned(),
            TypeTag::U16 => "u16".to_owned(),
            TypeTag::U32 => "u32".to_owned(),
            TypeTag::U64 => "u64".to_owned(),
            TypeTag::U128 => "u128".to_owned(),
            TypeTag::U256 => "u256".to_owned(),
            TypeTag::Bool => "bool".to_owned(),
            TypeTag::Address => "address".to_owned(),
            TypeTag::Signer => "signer".to_owned(),
            TypeTag::Vector(t) => {
                format!("vector<{}>", t.to_canonical_string(with_prefix))
            }
            TypeTag::Struct(s) => s.to_canonical_string(with_prefix),
        }
    }
}

impl std::fmt::Display for TypeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string(true).fmt(f)
    }
}

impl std::str::FromStr for TypeTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_type_tag(s).map_err(|_| TypeParseError { source: s.into() })
    }
}

impl From<StructTag> for TypeTag {
    fn from(value: StructTag) -> Self {
        Self::Struct(Box::new(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeParseError {
    pub source: String,
}

impl std::fmt::Display for TypeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for TypeParseError {}

/// A move identifier
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// identifier = %x01-80    ; length of the identifier
///              (ALPHA *127(ALPHA / DIGIT / UNDERSCORE)) /
///              (UNDERSCORE 1*127(ALPHA / DIGIT / UNDERSCORE))
///
/// UNDERSCORE = %x95
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Identifier(
    #[cfg_attr(
        feature = "proptest",
        strategy(proptest::strategy::Strategy::prop_map(
            "[a-zA-Z][a-zA-Z0-9_]{0,127}",
            Into::into
        ))
    )]
    Box<str>,
);

impl Identifier {
    pub fn new(identifier: impl AsRef<str>) -> Result<Self, TypeParseError> {
        parse::parse_identifier(identifier.as_ref())
            .map(|ident| Self(ident.into()))
            .map_err(|_| TypeParseError {
                source: identifier.as_ref().into(),
            })
    }

    pub fn into_inner(self) -> Box<str> {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn is_valid(s: &str) -> bool {
        /// Returns `true` if all bytes in `b` after the offset `start_offset`
        /// are valid ASCII identifier characters.
        const fn all_bytes_valid(b: &[u8], start_offset: usize) -> bool {
            let mut i = start_offset;
            while i < b.len() {
                if !Identifier::is_valid_char(b[i] as char) {
                    return false;
                }
                i += 1;
            }
            true
        }
        // Rust const fn's don't currently support slicing or indexing &str's, so we
        // have to operate on the underlying byte slice. This is not a problem as
        // valid identifiers are (currently) ASCII-only.
        let b = s.as_bytes();
        match b {
            b"<SELF>" => true,
            [b'a'..=b'z', ..] | [b'A'..=b'Z', ..] => all_bytes_valid(b, 1),
            [b'_', ..] if b.len() > 1 => all_bytes_valid(b, 1),
            _ => false,
        }
    }

    /// Return true if this character can appear in a Move identifier.
    ///
    /// Note: there are stricter restrictions on whether a character can begin a
    /// Move identifier--only alphabetic characters are allowed here.
    #[inline]
    pub const fn is_valid_char(c: char) -> bool {
        matches!(c, '_' | 'a'..='z' | 'A'..='Z' | '0'..='9')
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Identifier {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_identifier(s)
            .map(|ident| Self(ident.into()))
            .map_err(|_| TypeParseError { source: s.into() })
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref() == other
    }
}

impl std::ops::Deref for Identifier {
    type Target = IdentifierRef;

    fn deref(&self) -> &IdentifierRef {
        unsafe { std::mem::transmute::<&str, &IdentifierRef>(self.0.as_ref()) }
    }
}

impl AsRef<IdentifierRef> for Identifier {
    fn as_ref(&self) -> &IdentifierRef {
        self
    }
}

impl std::borrow::Borrow<IdentifierRef> for Identifier {
    fn borrow(&self) -> &IdentifierRef {
        self
    }
}

impl PartialEq<IdentifierRef> for Identifier {
    fn eq(&self, other: &IdentifierRef) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Identifier> for IdentifierRef {
    fn eq(&self, other: &Identifier) -> bool {
        self == other.as_ref()
    }
}

#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct IdentifierRef(str);

impl IdentifierRef {
    pub const fn const_new(s: &'static str) -> &'static Self {
        if !Identifier::is_valid(s) {
            panic!("String is not a valid Move identifier");
        }

        // SAFETY: the following transmute is safe because
        // (1) it's equivalent to the unsafe-reborrow inside IdentStr::ref_cast()
        //     (which we can't use b/c it's not const).
        // (2) we've just asserted that IdentStr impls RefCast<From = str>, which
        //     already guarantees the transmute is safe (RefCast checks that
        //     IdentStr(str) is #[repr(transparent)]).
        // (3) both in and out lifetimes are 'static, so we're not widening the
        //     lifetime.
        // (4) we've just asserted that the IdentStr passes the
        //     is_valid check.
        unsafe { std::mem::transmute::<&'static str, &'static Self>(s) }
    }

    /// Returns true if this string is a valid identifier.
    pub fn is_valid(s: &str) -> bool {
        Identifier::is_valid(s)
    }

    /// Returns the length of `self` in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if `self` has a length of zero bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts `self` to a `&str`.
    ///
    /// This is not implemented as a `From` trait to discourage automatic
    /// conversions -- these conversions should not typically happen.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Converts `self` to a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<&IdentifierRef> for Identifier {
    fn from(value: &IdentifierRef) -> Self {
        value.to_owned()
    }
}

impl ToOwned for IdentifierRef {
    type Owned = Identifier;

    fn to_owned(&self) -> Identifier {
        Identifier(self.0.into())
    }
}

macro_rules! add_struct_tag_ctor {
    ($address:ident, $module:literal, $name:literal) => {
        paste::paste! {
            pub fn [< new_ $name:snake >]() -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![],
                }
            }
        }
    };
    ($address:ident, $module:literal, $name:literal, "with-module") => {
        paste::paste! {
            pub fn [< new_ $module:snake _ $name:snake >]() -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![],
                }
            }
        }
    };
}

macro_rules! add_struct_tag_ctor_from_struct_tag {
    ($address:ident, $module:literal, $name:literal) => {
        paste::paste! {
            pub fn [< new_ $name:snake >](struct_tag: impl Into<StructTag>) -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![TypeTag::Struct(Box::new(struct_tag.into()))],
                }
            }
        }
    };
    ($address:ident, $module:literal, $name:literal, "with-module") => {
        paste::paste! {
            pub fn [< new_ $module:snake _ $name:snake >](struct_tag: impl Into<StructTag>) -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![TypeTag::Struct(Box::new(struct_tag.into()))],
                }
            }
        }
    };
}

macro_rules! add_struct_tag_ctor_from_type_tag {
    ($address:ident, $module:literal, $name:literal) => {
        paste::paste! {
            pub fn [< new_ $name:snake >](type_tag: impl Into<TypeTag>) -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![type_tag.into()],
                }
            }
        }
    };
    ($address:ident, $module:literal, $name:literal, "with-module") => {
        paste::paste! {
            pub fn [< new_ $module:snake _ $name:snake >](type_tag: impl Into<TypeTag>) -> Self {
                Self {
                    address: Address::$address,
                    module: IdentifierRef::const_new($module).into(),
                    name: IdentifierRef::const_new($name).into(),
                    type_params: vec![type_tag.into()],
                }
            }
        }
    };
}

/// Type information for a move struct
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// struct-tag = address            ; address of the package
///              identifier         ; name of the module
///              identifier         ; name of the type
///              (vector type-tag)  ; type parameters
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct StructTag {
    pub address: Address,
    pub module: Identifier,
    pub name: Identifier,
    #[cfg_attr(feature = "proptest", strategy(proptest::strategy::Just(Vec::new())))]
    pub type_params: Vec<TypeTag>,
}

impl StructTag {
    pub fn new_iota_coin_type() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: IdentifierRef::const_new("iota").into(),
            name: IdentifierRef::const_new("IOTA").into(),
            type_params: vec![],
        }
    }

    pub fn new_gas_coin() -> Self {
        Self::new_coin(Self::new_iota_coin_type())
    }

    pub fn new_id() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: IdentifierRef::const_new("object").into(),
            name: IdentifierRef::const_new("ID").into(),
            type_params: vec![],
        }
    }

    pub fn new_uid() -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: IdentifierRef::const_new("object").into(),
            name: IdentifierRef::const_new("UID").into(),
            type_params: vec![],
        }
    }

    pub fn new_name(address: Address) -> Self {
        Self {
            address,
            module: IdentifierRef::const_new("name").into(),
            name: IdentifierRef::const_new("Name").into(),
            type_params: vec![],
        }
    }

    pub fn new_field(key: impl Into<TypeTag>, value: impl Into<TypeTag>) -> Self {
        Self {
            address: Address::FRAMEWORK,
            module: IdentifierRef::const_new("dynamic_field").into(),
            name: IdentifierRef::const_new("Field").into(),
            type_params: vec![key.into(), value.into()],
        }
    }

    add_struct_tag_ctor!(FRAMEWORK, "clock", "Clock");
    add_struct_tag_ctor!(FRAMEWORK, "config", "Config");
    add_struct_tag_ctor!(FRAMEWORK, "deny_list", "ConfigKey", "with-module");
    add_struct_tag_ctor!(FRAMEWORK, "deny_list", "AddressKey", "with-module");
    add_struct_tag_ctor!(FRAMEWORK, "deny_list", "GlobalPauseKey", "with-module");
    add_struct_tag_ctor!(FRAMEWORK, "iota", "IotaTreasuryCap");
    add_struct_tag_ctor!(FRAMEWORK, "package", "UpgradeCap");
    add_struct_tag_ctor!(FRAMEWORK, "package", "UpgradeTicket");
    add_struct_tag_ctor!(FRAMEWORK, "package", "UpgradeReceipt");
    add_struct_tag_ctor!(FRAMEWORK, "system_admin_cap", "IotaSystemAdminCap");
    add_struct_tag_ctor!(FRAMEWORK, "transfer", "Receiving", "with-module");
    add_struct_tag_ctor!(SYSTEM, "iota_system", "IotaSystemState");
    add_struct_tag_ctor!(SYSTEM, "staking_pool", "StakedIota");
    add_struct_tag_ctor!(SYSTEM, "timelocked_staking", "TimelockedStakedIota");
    add_struct_tag_ctor!(SYSTEM, "iota_system_state_inner", "SystemEpochInfoEvent");
    add_struct_tag_ctor!(STD_LIB, "ascii", "String", "with-module");
    add_struct_tag_ctor!(STD_LIB, "string", "String");
    add_struct_tag_ctor_from_struct_tag!(FRAMEWORK, "coin", "CoinMetadata");
    add_struct_tag_ctor_from_struct_tag!(FRAMEWORK, "coin", "TreasuryCap");
    add_struct_tag_ctor_from_struct_tag!(FRAMEWORK, "coin_manager", "CoinManager");
    add_struct_tag_ctor_from_struct_tag!(FRAMEWORK, "display", "VersionUpdated");
    add_struct_tag_ctor_from_struct_tag!(FRAMEWORK, "display", "DisplayCreated");
    add_struct_tag_ctor_from_type_tag!(FRAMEWORK, "coin", "Coin");
    add_struct_tag_ctor_from_type_tag!(FRAMEWORK, "balance", "Balance");
    add_struct_tag_ctor_from_type_tag!(FRAMEWORK, "timelock", "TimeLock");
    add_struct_tag_ctor_from_type_tag!(FRAMEWORK, "config", "Setting", "with-module");
    add_struct_tag_ctor_from_type_tag!(FRAMEWORK, "dynamic_object_field", "Wrapper", "with-module");

    /// Checks if this is a Coin type
    pub fn coin_type_opt(&self) -> Option<&crate::TypeTag> {
        let Self {
            address,
            module,
            name,
            type_params,
        } = self;

        if address == &Address::FRAMEWORK
            && module == "coin"
            && name == "Coin"
            && type_params.len() == 1
        {
            type_params.first()
        } else {
            None
        }
    }

    /// Checks if this is a Coin type
    pub fn coin_type(&self) -> &TypeTag {
        self.coin_type_opt().expect("not a coin")
    }

    /// Returns the address part of a `StructTag`
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the module part of a `StructTag`
    pub fn module(&self) -> &Identifier {
        &self.module
    }

    /// Returns the name part of a `StructTag`
    pub fn name(&self) -> &Identifier {
        &self.name
    }

    /// Returns the type params part of a `StructTag`
    pub fn type_params(&self) -> &[TypeTag] {
        &self.type_params
    }

    /// Returns the string representation of this struct tag using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        let mut tag = format!(
            "{}::{}::{}",
            self.address.to_canonical_string(with_prefix),
            self.module,
            self.name
        );
        if let Some(first_type) = self.type_params.first() {
            tag.push_str(&format!("<{first_type}"));
            for ty in self.type_params.iter().skip(1) {
                tag.push_str(&format!(", {ty}"));
            }
            tag.push('>');
        }
        tag
    }
}

impl std::fmt::Display for StructTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_canonical_string(true).fmt(f)
    }
}

impl std::str::FromStr for StructTag {
    type Err = TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse::parse_struct_tag(s).map_err(|_| TypeParseError { source: s.into() })
    }
}
