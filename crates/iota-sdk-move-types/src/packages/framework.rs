// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA framework (system package `0x2`).

/// Types from `0x2::object`.
pub mod object {
    use core::fmt;

    use iota_types::ObjectId;

    /// Rust version of the Move `iota::object::ID` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ID {
        pub bytes: ObjectId,
    }

    impl ID {
        pub fn new(object_id: ObjectId) -> Self {
            Self { bytes: object_id }
        }
    }

    impl From<ObjectId> for ID {
        fn from(object_id: ObjectId) -> Self {
            Self::new(object_id)
        }
    }

    impl From<ID> for ObjectId {
        fn from(id: ID) -> Self {
            id.bytes
        }
    }

    impl fmt::Display for ID {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.bytes.fmt(f)
        }
    }

    /// Rust version of the Move `iota::object::UID` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UID {
        pub id: ID,
    }

    impl UID {
        pub fn new(object_id: ObjectId) -> Self {
            Self {
                id: ID::new(object_id),
            }
        }

        pub fn object_id(&self) -> &ObjectId {
            &self.id.bytes
        }
    }

    impl From<ObjectId> for UID {
        fn from(object_id: ObjectId) -> Self {
            Self::new(object_id)
        }
    }

    impl fmt::Display for UID {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.id.fmt(f)
        }
    }
}

/// Types from `0x2::iota`.
pub mod iota {
    use super::coin::TreasuryCap;

    /// Rust version of the Move `iota::iota::IOTA` type.
    ///
    /// Name of the coin. The Move struct is empty; Move bytecode requires at
    /// least one field, so this carries a `dummy_field` to preserve the BCS
    /// wire format (1 byte, always `false`).
    // MoveShape derive enables `Balance<IOTA>` references in mirrors like
    // `Kiosk` to resolve `<IOTA as MoveShape>::NAME` at macro time. IOTA
    // itself is NOT registered with the comparator — the Move bytecode
    // defines it as a true empty struct (`{}`), while the Rust mirror
    // carries a `dummy_field: bool` to preserve the BCS wire format. The
    // comparator would flag that as a 0-vs-1 field-count mismatch.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct IOTA {
        dummy_field: bool,
    }

    #[cfg(feature = "serde")]
    impl crate::MoveType for IOTA {
        /// `0x2::iota::IOTA`.
        fn type_tag() -> iota_types::TypeTag {
            iota_types::TypeTag::Struct(Box::new(iota_types::StructTag::new_gas()))
        }
    }

    /// Rust version of the Move `iota::iota::IotaTreasuryCap` type.
    ///
    /// The non-generic IOTA treasury cap, wrapping a [`TreasuryCap<IOTA>`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct IotaTreasuryCap {
        pub inner: TreasuryCap<IOTA>,
    }

    impl IotaTreasuryCap {
        pub const fn new(inner: TreasuryCap<IOTA>) -> Self {
            Self { inner }
        }
    }
}

/// Types from `0x2::system_admin_cap`.
pub mod system_admin_cap {
    /// Rust version of the Move `iota::system_admin_cap::IotaSystemAdminCap`
    /// type.
    ///
    /// Capability allowing the bearer to perform privileged IOTA system
    /// operations. The Move struct is empty; the Rust mirror carries a
    /// `dummy_field` to preserve the BCS wire format.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct IotaSystemAdminCap {
        dummy_field: bool,
    }
}

/// Types from `0x2::balance`.
pub mod balance {
    use core::marker::PhantomData;

    /// Rust version of the Move `iota::balance::Supply<T>` type.
    ///
    /// A `Supply` of `T`; used for minting and burning. Wrapped into a
    /// `TreasuryCap` in the `coin` module.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Supply<T> {
        pub value: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Supply<T> {
        pub const fn new(value: u64) -> Self {
            Self {
                value,
                _marker: PhantomData,
            }
        }

        pub fn value(&self) -> u64 {
            self.value
        }
    }

    /// Rust version of the Move `iota::balance::Balance<T>` type.
    ///
    /// A storable balance — the inner struct of a `Coin` type. Can be used
    /// to store coins which don't need the `key` ability.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Balance<T> {
        pub value: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Balance<T> {
        pub const fn new(value: u64) -> Self {
            Self {
                value,
                _marker: PhantomData,
            }
        }

        pub fn value(&self) -> u64 {
            self.value
        }
    }

    /// Compositional tag: `Balance<T>` is itself a valid type argument
    /// (e.g. `TimeLock<Balance<IOTA>>`), so its tag is derived from `T`'s.
    #[cfg(feature = "serde")]
    impl<T: crate::MoveType> crate::MoveType for Balance<T> {
        /// `0x2::balance::Balance<T>`.
        fn type_tag() -> iota_types::TypeTag {
            iota_types::TypeTag::Struct(Box::new(iota_types::StructTag::new_balance(T::type_tag())))
        }
    }
}

/// Types from `0x2::bag`.
pub mod bag {
    use super::object::UID;

    /// Rust version of the Move `iota::bag::Bag` type.
    ///
    /// A heterogeneous map-like collection. Keys and values are stored as
    /// dynamic fields off the bag's UID; the struct itself just carries the
    /// handle and an entry count.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Bag {
        /// The ID of this bag.
        pub id: UID,
        /// The number of key-value pairs in the bag.
        pub size: u64,
    }

    impl Bag {
        pub const fn new(id: UID, size: u64) -> Self {
            Self { id, size }
        }
    }
}

/// Types from `0x2::coin`.
pub mod coin {
    use core::marker::PhantomData;

    use super::{
        balance::{Balance, Supply},
        object::{ID, UID},
        url::Url,
    };
    use crate::std::{ascii, string};

    /// Rust version of the Move `iota::coin::Coin<T>` type.
    ///
    /// A coin of type `T` worth `balance`. Transferable and storable.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Coin<T> {
        pub id: UID,
        pub balance: Balance<T>,
    }

    impl<T> Coin<T> {
        pub const fn new(id: UID, balance: Balance<T>) -> Self {
            Self { id, balance }
        }
    }

    #[cfg(feature = "serde")]
    impl<T> Coin<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode a [`Coin<T>`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`Coin<T>`] from an on-chain object, validating that
        /// the object's type tag matches `0x2::coin::Coin<coin_type>`.
        ///
        /// Escape hatch for coin types only known at runtime; nothing ties
        /// `coin_type` to `T`. When the coin type is known at compile time,
        /// prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            coin_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_coin() || tag.type_params() != core::slice::from_ref(coin_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> Coin<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode a [`Coin<T>`] from an on-chain object, validating that
        /// the object's type tag matches `0x2::coin::Coin<T>`, including
        /// the coin marker `T`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
        }
    }

    /// Rust version of the Move `iota::coin::CoinMetadata<T>` type.
    ///
    /// Each `Coin<T>` created through `create_currency` has a unique
    /// `CoinMetadata<T>` storing display metadata for the coin type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct CoinMetadata<T> {
        pub id: UID,
        /// Number of decimal places the coin uses.
        pub decimals: u8,
        /// Name for the token.
        pub name: string::String,
        /// Symbol for the token.
        pub symbol: ascii::String,
        /// Description of the token.
        pub description: string::String,
        /// URL for the token logo.
        pub icon_url: Option<Url>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> CoinMetadata<T> {
        pub const fn new(
            id: UID,
            decimals: u8,
            name: string::String,
            symbol: ascii::String,
            description: string::String,
            icon_url: Option<Url>,
        ) -> Self {
            Self {
                id,
                decimals,
                name,
                symbol,
                description,
                icon_url,
                _marker: PhantomData,
            }
        }
    }

    #[cfg(feature = "serde")]
    impl<T> CoinMetadata<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode a [`CoinMetadata<T>`] from BCS bytes without verifying
        /// the on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`CoinMetadata<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x2::coin::CoinMetadata<coin_type>`.
        ///
        /// Escape hatch for coin types only known at runtime; nothing ties
        /// `coin_type` to `T`. When the coin type is known at compile time,
        /// prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            coin_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_coin_metadata() || tag.type_params() != core::slice::from_ref(coin_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> CoinMetadata<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode a [`CoinMetadata<T>`] from an on-chain object, validating
        /// that the object's type tag matches `0x2::coin::CoinMetadata<T>`,
        /// including the coin marker `T`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
        }
    }

    /// Rust version of the Move `iota::coin::RegulatedCoinMetadata<T>` type.
    ///
    /// Similar to [`CoinMetadata`], but created only for regulated coins
    /// that use the DenyList. Always immutable.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct RegulatedCoinMetadata<T> {
        pub id: UID,
        /// The ID of the coin's `CoinMetadata` object.
        pub coin_metadata_object: ID,
        /// The ID of the coin's `DenyCap` object.
        pub deny_cap_object: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> RegulatedCoinMetadata<T> {
        pub const fn new(id: UID, coin_metadata_object: ID, deny_cap_object: ID) -> Self {
            Self {
                id,
                coin_metadata_object,
                deny_cap_object,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::coin::TreasuryCap<T>` type.
    ///
    /// Capability allowing the bearer to mint and burn coins of type `T`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TreasuryCap<T> {
        pub id: UID,
        pub total_supply: Supply<T>,
    }

    impl<T> TreasuryCap<T> {
        pub const fn new(id: UID, total_supply: Supply<T>) -> Self {
            Self { id, total_supply }
        }
    }

    /// Rust version of the Move `iota::coin::DenyCapV1<T>` type.
    ///
    /// Capability allowing the bearer to deny addresses from using the
    /// currency's coins. If `allow_global_pause` is `true`, the bearer can
    /// also enable a global pause.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct DenyCapV1<T> {
        pub id: UID,
        pub allow_global_pause: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> DenyCapV1<T> {
        pub const fn new(id: UID, allow_global_pause: bool) -> Self {
            Self {
                id,
                allow_global_pause,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::table`.
pub mod table {
    use core::marker::PhantomData;

    use super::object::UID;

    /// Rust version of the Move `iota::table::Table<K, V>` type.
    ///
    /// A map-like collection. Keys and values are stored as dynamic fields
    /// off the table's `UID`, not inside the struct itself.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Table<K, V> {
        /// The ID of this table.
        pub id: UID,
        /// The number of key-value pairs in the table.
        pub size: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _k: PhantomData<K>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _v: PhantomData<V>,
    }

    impl<K, V> Table<K, V> {
        pub const fn new(id: UID, size: u64) -> Self {
            Self {
                id,
                size,
                _k: PhantomData,
                _v: PhantomData,
            }
        }
    }
}

/// Types from `0x2::url`.
pub mod url {
    use crate::std::ascii;

    /// Rust version of the Move `iota::url::Url` type.
    ///
    /// A standard URL string. The Move type stores ASCII bytes only; this
    /// Rust mirror does **not** enforce that invariant on construction. Use
    /// [`Url::try_from_ascii`] for a validating constructor.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Url {
        pub url: ascii::String,
    }

    impl Url {
        pub const fn new(url: ascii::String) -> Self {
            Self { url }
        }

        /// Construct a [`Url`] from a Rust string, validating that it is
        /// ASCII.
        pub fn try_from_ascii(s: impl Into<String>) -> Result<Self, NonAsciiUrl> {
            let s = s.into();
            if !s.is_ascii() {
                return Err(NonAsciiUrl);
            }
            Ok(Self {
                url: ascii::String::new(s.into_bytes()),
            })
        }
    }

    /// Returned by [`Url::try_from_ascii`] when the input contains non-ASCII
    /// bytes.
    ///
    /// This is a Rust-side error type, not a mirror of a Move struct, so it
    /// has no Move counterpart and no `MoveShape` derive.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct NonAsciiUrl;

    impl core::fmt::Display for NonAsciiUrl {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("url is not valid ASCII")
        }
    }

    impl core::error::Error for NonAsciiUrl {}

    #[cfg(test)]
    mod tests {
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::*;

        #[test]
        fn url_rejects_non_ascii() {
            assert!(Url::try_from_ascii("héllo").is_err());
        }
    }
}

/// Types from `0x2::vec_map`.
pub mod vec_map {
    /// Rust version of the Move `iota::vec_map::Entry<K, V>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Entry<K, V> {
        pub key: K,
        pub value: V,
    }

    impl<K, V> Entry<K, V> {
        pub const fn new(key: K, value: V) -> Self {
            Self { key, value }
        }
    }

    /// Rust version of the Move `iota::vec_map::VecMap<K, V>` type.
    ///
    /// A map backed by a vector; guaranteed to contain no duplicate keys.
    /// Entries are *not* sorted; they are stored in insertion order. All
    /// operations are O(N).
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VecMap<K, V> {
        pub contents: Vec<Entry<K, V>>,
    }

    impl<K, V> VecMap<K, V> {
        pub const fn new(contents: Vec<Entry<K, V>>) -> Self {
            Self { contents }
        }
    }

    impl<K, V> Default for VecMap<K, V> {
        fn default() -> Self {
            Self {
                contents: Vec::new(),
            }
        }
    }
}

/// Types from `0x2::vec_set`.
pub mod vec_set {
    /// Rust version of the Move `iota::vec_set::VecSet<K>` type.
    ///
    /// A set backed by a vector; guaranteed to contain no duplicate keys.
    /// All operations are O(N).
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VecSet<K> {
        pub contents: Vec<K>,
    }

    impl<K> VecSet<K> {
        pub const fn new(contents: Vec<K>) -> Self {
            Self { contents }
        }
    }

    impl<K> Default for VecSet<K> {
        fn default() -> Self {
            Self {
                contents: Vec::new(),
            }
        }
    }
}

/// Types from `0x2::table_vec`.
pub mod table_vec {
    use super::table::Table;

    /// Rust version of the Move `iota::table_vec::TableVec<Element>` type.
    ///
    /// A vector-like collection whose elements are stored as dynamic fields
    /// off an inner [`Table<u64, Element>`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TableVec<Element> {
        /// The contents of the table vector.
        pub contents: Table<u64, Element>,
    }

    impl<Element> TableVec<Element> {
        pub const fn new(contents: Table<u64, Element>) -> Self {
            Self { contents }
        }
    }
}

/// Types from `0x2::versioned`.
pub mod versioned {
    use super::object::{ID, UID};

    /// Rust version of the Move `iota::versioned::Versioned` type.
    ///
    /// A wrapper that supports versioning of an inner type stored as a
    /// dynamic field keyed by `version`. Consumers load the inner object
    /// using the type corresponding to the current `version`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Versioned {
        pub id: UID,
        pub version: u64,
    }

    impl Versioned {
        pub const fn new(id: UID, version: u64) -> Self {
            Self { id, version }
        }
    }

    /// Rust version of the Move `iota::versioned::VersionChangeCap` type.
    ///
    /// A hot-potato object generated when the inner dynamic field is taken
    /// out, ensuring a new value is always put back.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VersionChangeCap {
        pub versioned_id: ID,
        pub old_version: u64,
    }

    impl VersionChangeCap {
        pub const fn new(versioned_id: ID, old_version: u64) -> Self {
            Self {
                versioned_id,
                old_version,
            }
        }
    }
}

/// Types from `0x2::bcs`.
pub mod bcs {
    /// Rust version of the Move `iota::bcs::BCS` type.
    ///
    /// A helper struct used by the Move-side BCS deserializer; stores
    /// reversed bytes so `vector::pop_back` can be used efficiently.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct BCS {
        pub bytes: Vec<u8>,
    }

    impl BCS {
        pub const fn new(bytes: Vec<u8>) -> Self {
            Self { bytes }
        }
    }
}

/// Types from `0x2::clock`.
pub mod clock {
    use super::object::UID;

    /// Rust version of the Move `iota::clock::Clock` type.
    ///
    /// Singleton shared object at `0x6` that exposes the current time to
    /// Move calls. Entry functions can only accept it by immutable
    /// reference.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Clock {
        pub id: UID,
        /// The clock's timestamp. Set automatically by a system transaction
        /// every time consensus commits a schedule.
        pub timestamp_ms: u64,
    }

    impl Clock {
        pub const fn new(id: UID, timestamp_ms: u64) -> Self {
            Self { id, timestamp_ms }
        }
    }

    #[cfg(feature = "serde")]
    impl Clock {
        /// Decode a [`Clock`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`Clock`] from an on-chain object, validating that the
        /// object's type tag matches `0x2::clock::Clock`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_clock() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }
}

/// Types from `0x2::tx_context`.
pub mod tx_context {
    use iota_types::Address;

    /// Rust version of the Move `iota::tx_context::TxContext` type.
    ///
    /// Information about the transaction currently being executed. Not
    /// constructible from user code — created by the VM and passed to the
    /// transaction entrypoint as `&mut TxContext`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TxContext {
        /// Address of the user that signed the current transaction.
        pub sender: Address,
        /// Hash of the current transaction.
        pub tx_hash: Vec<u8>,
        /// The current epoch number.
        pub epoch: u64,
        /// Timestamp at which the epoch started.
        pub epoch_timestamp_ms: u64,
        /// Counter recording the number of fresh IDs created while
        /// executing this transaction. Always 0 at the start.
        pub ids_created: u64,
    }
}

/// Types from `0x2::intent`.
pub mod intent {
    /// Rust version of the Move `iota::intent::Intent` type.
    ///
    /// Compact 3-byte struct prepended to a message before signing as a
    /// domain separator.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Intent {
        pub scope: u8,
        pub version: u8,
        pub app_id: u8,
    }

    impl Intent {
        pub const fn new(scope: u8, version: u8, app_id: u8) -> Self {
            Self {
                scope,
                version,
                app_id,
            }
        }
    }
}

/// Types from `0x2::ecdsa_k1`.
pub mod ecdsa_k1 {
    /// Rust version of the Move `iota::ecdsa_k1::KeyPair` type.
    // The Move-side `KeyPair` struct is `#[test_only]`, so it's absent
    // from the compiled package and cannot participate in the
    // `move_shape_compare` cross-check. No `MoveShape` derive here.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct KeyPair {
        pub private_key: Vec<u8>,
        pub public_key: Vec<u8>,
    }
}

/// Types from `0x2::zklogin_verified_id`.
pub mod zklogin_verified_id {
    use iota_types::Address;

    use super::object::UID;
    use crate::std::string;

    /// Rust version of the Move `iota::zklogin_verified_id::VerifiedID`
    /// type.
    ///
    /// Possession proves that the user's address was created using zkLogin
    /// with the given parameters.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VerifiedID {
        pub id: UID,
        /// The address this `VerifiedID` is associated with.
        pub owner: Address,
        /// The name of the key claim.
        pub key_claim_name: string::String,
        /// The value of the key claim.
        pub key_claim_value: string::String,
        /// The issuer.
        pub issuer: string::String,
        /// The audience (wallet).
        pub audience: string::String,
    }
}

/// Types from `0x2::zklogin_verified_issuer`.
pub mod zklogin_verified_issuer {
    use iota_types::Address;

    use super::object::UID;
    use crate::std::string;

    /// Rust version of the Move
    /// `iota::zklogin_verified_issuer::VerifiedIssuer` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VerifiedIssuer {
        pub id: UID,
        pub owner: Address,
        pub issuer: string::String,
    }
}

/// Types from `0x2::transfer`.
pub mod transfer {
    use core::marker::PhantomData;

    use super::object::ID;

    /// Rust version of the Move `iota::transfer::Receiving<T>` type.
    ///
    /// Represents the ability to `receive` an object of type `T`.
    /// Ephemeral per-transaction; cannot be stored on-chain.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Receiving<T> {
        pub id: ID,
        pub version: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Receiving<T> {
        pub const fn new(id: ID, version: u64) -> Self {
            Self {
                id,
                version,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::timelock`.
pub mod timelock {
    use super::object::UID;
    use crate::std::string;

    /// Rust version of the Move `iota::timelock::TimeLock<T>` type.
    ///
    /// A `TimeLock` that holds a locked object until `expiration_timestamp_ms`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TimeLock<T> {
        pub id: UID,
        /// The locked object.
        pub locked: T,
        /// Epoch timestamp (ms) of when the lock expires.
        pub expiration_timestamp_ms: u64,
        /// Optional timelock-related label.
        pub label: Option<string::String>,
    }

    impl<T> TimeLock<T> {
        pub const fn new(
            id: UID,
            locked: T,
            expiration_timestamp_ms: u64,
            label: Option<string::String>,
        ) -> Self {
            Self {
                id,
                locked,
                expiration_timestamp_ms,
                label,
            }
        }
    }

    #[cfg(feature = "serde")]
    impl<T> TimeLock<T>
    where
        T: serde::de::DeserializeOwned,
    {
        /// Decode a [`TimeLock<T>`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`TimeLock<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x2::timelock::TimeLock<locked_type>`.
        ///
        /// Escape hatch for locked types only known at runtime; nothing
        /// ties `locked_type` to `T`. When the locked type is known at
        /// compile time, prefer [`Self::try_from_object`].
        pub fn try_from_object_with_type(
            object: &iota_types::Object,
            locked_type: &iota_types::TypeTag,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            let tag = move_struct.struct_tag();
            if !tag.is_time_lock() || tag.type_params() != core::slice::from_ref(locked_type) {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    #[cfg(feature = "serde")]
    impl<T> TimeLock<T>
    where
        T: serde::de::DeserializeOwned + crate::MoveType,
    {
        /// Decode a [`TimeLock<T>`] from an on-chain object, validating
        /// that the object's type tag matches
        /// `0x2::timelock::TimeLock<T>`, including the locked type `T`
        /// (e.g. `Balance<IOTA>` for vested-reward timelocks).
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            Self::try_from_object_with_type(object, &T::type_tag())
        }
    }
}

/// Types from `0x2::borrow`.
pub mod borrow {
    use iota_types::Address;

    use super::object::{ID, UID};

    /// Rust version of the Move `iota::borrow::Referent<T>` type.
    ///
    /// An object wrapping a `T` and providing the borrow API.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Referent<T> {
        pub id: Address,
        pub value: Option<T>,
    }

    impl<T> Referent<T> {
        pub const fn new(id: Address, value: Option<T>) -> Self {
            Self { id, value }
        }
    }

    /// Rust version of the Move `iota::borrow::Borrow` type.
    ///
    /// A hot potato making sure the object is put back once borrowed. The
    /// Move field name `ref` is a Rust keyword, so it is stored on the
    /// raw identifier `r#ref`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Borrow {
        pub r#ref: Address,
        pub obj: ID,
    }

    /// Rust version of the Move `iota::borrow::Test` type.
    ///
    /// The Move-side `Test` struct is `#[test_only]`, so it doesn't ship
    /// in the compiled package and can't participate in the
    /// `move_shape_compare` cross-check. No `MoveShape` derive here.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Test {
        pub id: UID,
    }
}

/// Types from `0x2::dynamic_field`.
pub mod dynamic_field {
    use super::object::UID;

    /// Rust version of the Move `iota::dynamic_field::Field<Name, Value>`
    /// type.
    ///
    /// Internal object used for storing the field and value. The object's
    /// ID is determined by `hash(parent.id || name || Name)`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Field<Name, Value> {
        pub id: UID,
        /// The value for the name of this field.
        pub name: Name,
        /// The value bound to this field.
        pub value: Value,
    }

    impl<Name, Value> Field<Name, Value> {
        pub const fn new(id: UID, name: Name, value: Value) -> Self {
            Self { id, name, value }
        }
    }
}

/// Types from `0x2::dynamic_object_field`.
pub mod dynamic_object_field {
    /// Rust version of the Move
    /// `iota::dynamic_object_field::Wrapper<Name>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Wrapper<Name> {
        pub name: Name,
    }

    impl<Name> Wrapper<Name> {
        pub const fn new(name: Name) -> Self {
            Self { name }
        }
    }
}

/// Types from `0x2::labeler`.
pub mod labeler {
    use core::marker::PhantomData;

    use super::object::UID;

    /// Rust version of the Move `iota::labeler::LabelerCap<L>` type.
    ///
    /// Allows creating labels of the specific type `L`. Can be publicly
    /// transferred like any other object.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct LabelerCap<L> {
        pub id: UID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<L>,
    }

    impl<L> LabelerCap<L> {
        pub const fn new(id: UID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::linked_table`.
pub mod linked_table {
    use core::marker::PhantomData;

    use super::object::UID;

    /// Rust version of the Move `iota::linked_table::LinkedTable<K, V>`
    /// type.
    ///
    /// A map-like collection with ordered insertion and removal. Like a
    /// `Table`, keys and values are stored as dynamic fields off the
    /// table's UID, not inside the struct.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct LinkedTable<K, V> {
        pub id: UID,
        /// The number of key-value pairs in the table.
        pub size: u64,
        /// The front of the table — the key of the first entry.
        pub head: Option<K>,
        /// The back of the table — the key of the last entry.
        pub tail: Option<K>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _v: PhantomData<V>,
    }

    impl<K, V> LinkedTable<K, V> {
        pub const fn new(id: UID, size: u64, head: Option<K>, tail: Option<K>) -> Self {
            Self {
                id,
                size,
                head,
                tail,
                _v: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::linked_table::Node<K, V>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Node<K, V> {
        pub prev: Option<K>,
        pub next: Option<K>,
        pub value: V,
    }

    impl<K, V> Node<K, V> {
        pub const fn new(prev: Option<K>, next: Option<K>, value: V) -> Self {
            Self { prev, next, value }
        }
    }
}

/// Types from `0x2::object_table`.
pub mod object_table {
    use core::marker::PhantomData;

    use super::object::UID;

    /// Rust version of the Move `iota::object_table::ObjectTable<K, V>`
    /// type.
    ///
    /// Similar to `Table`, but the values bound as dynamic fields *must*
    /// be objects themselves.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ObjectTable<K, V> {
        pub id: UID,
        pub size: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _k: PhantomData<K>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _v: PhantomData<V>,
    }

    impl<K, V> ObjectTable<K, V> {
        pub const fn new(id: UID, size: u64) -> Self {
            Self {
                id,
                size,
                _k: PhantomData,
                _v: PhantomData,
            }
        }
    }
}

/// Types from `0x2::object_bag`.
pub mod object_bag {
    use super::object::UID;

    /// Rust version of the Move `iota::object_bag::ObjectBag` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ObjectBag {
        pub id: UID,
        pub size: u64,
    }
}

/// Types from `0x2::priority_queue`.
pub mod priority_queue {
    /// Rust version of the Move `iota::priority_queue::Entry<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Entry<T> {
        pub priority: u64,
        pub value: T,
    }

    impl<T> Entry<T> {
        pub const fn new(priority: u64, value: T) -> Self {
            Self { priority, value }
        }
    }

    /// Rust version of the Move `iota::priority_queue::PriorityQueue<T>`
    /// type.
    ///
    /// A priority queue implemented as a max-heap. `entries[0]` is the
    /// root; children of `entries[i]` are at `i * 2 + 1` and `i * 2 + 2`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PriorityQueue<T> {
        pub entries: Vec<Entry<T>>,
    }

    impl<T> PriorityQueue<T> {
        pub const fn new(entries: Vec<Entry<T>>) -> Self {
            Self { entries }
        }
    }
}

/// Types from `0x2::derived_object`.
pub mod derived_object {
    /// Rust version of the Move `iota::derived_object::DerivedObjectKey<K>`
    /// type.
    ///
    /// An internal key to protect from generating the same UID twice.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct DerivedObjectKey<K>(pub K);

    impl<K> DerivedObjectKey<K> {
        pub const fn new(inner: K) -> Self {
            Self(inner)
        }
    }
}

/// Types from `0x2::authenticator_state`.
pub mod authenticator_state {
    use super::object::UID;
    use crate::std::string;

    /// Rust version of the Move
    /// `iota::authenticator_state::AuthenticatorState` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorState {
        pub id: UID,
        pub version: u64,
    }

    /// Rust version of the Move
    /// `iota::authenticator_state::AuthenticatorStateInner` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorStateInner {
        pub version: u64,
        /// List of currently active JWKs.
        pub active_jwks: Vec<ActiveJwk>,
    }

    /// Rust version of the Move `iota::authenticator_state::JWK` type.
    ///
    /// Must match the `JWK` struct in fastcrypto-zkp.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct JWK {
        pub kty: string::String,
        pub e: string::String,
        pub n: string::String,
        pub alg: string::String,
    }

    /// Rust version of the Move `iota::authenticator_state::JwkId` type.
    ///
    /// Must match the `JwkId` struct in fastcrypto-zkp.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct JwkId {
        pub iss: string::String,
        pub kid: string::String,
    }

    /// Rust version of the Move `iota::authenticator_state::ActiveJwk`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ActiveJwk {
        pub jwk_id: JwkId,
        pub jwk: JWK,
        pub epoch: u64,
    }
}

/// Types from `0x2::display`.
pub mod display {
    use core::marker::PhantomData;

    use super::{
        object::{ID, UID},
        vec_map::VecMap,
    };
    use crate::std::string;

    /// Rust version of the Move `iota::display::Display<T>` type.
    ///
    /// Defines the way a `T` instance should be displayed. Uses `String`
    /// types throughout because display rules are external-facing and the
    /// property names take priority over their types.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Display<T> {
        pub id: UID,
        /// Fields for display. Currently supported field names are `name`,
        /// `link`, `image`, `description`.
        pub fields: VecMap<string::String, string::String>,
        /// Version that can only be updated manually by the publisher.
        pub version: u16,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Display<T> {
        pub const fn new(
            id: UID,
            fields: VecMap<string::String, string::String>,
            version: u16,
        ) -> Self {
            Self {
                id,
                fields,
                version,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::display::DisplayCreated<T>` event
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct DisplayCreated<T> {
        pub id: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> DisplayCreated<T> {
        pub const fn new(id: ID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::display::VersionUpdated<T>` event
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct VersionUpdated<T> {
        pub id: ID,
        pub version: u16,
        pub fields: VecMap<string::String, string::String>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> VersionUpdated<T> {
        pub const fn new(
            id: ID,
            version: u16,
            fields: VecMap<string::String, string::String>,
        ) -> Self {
            Self {
                id,
                version,
                fields,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::package`.
pub mod package {
    use super::object::{ID, UID};
    use crate::std::ascii;

    /// Rust version of the Move `iota::package::Publisher` type.
    ///
    /// Can only be created in the transaction that creates a module, by
    /// consuming its one-time witness, so it can be used to identify the
    /// publishing address.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Publisher {
        pub id: UID,
        pub package: ascii::String,
        pub module_name: ascii::String,
    }

    #[cfg(feature = "serde")]
    impl Publisher {
        /// Decode a [`Publisher`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`Publisher`] from an on-chain object, validating that
        /// the object's type tag matches `0x2::package::Publisher`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_publisher() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    /// Rust version of the Move `iota::package::UpgradeCap` type.
    ///
    /// Capability controlling the ability to upgrade a package.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UpgradeCap {
        pub id: UID,
        /// (Mutable) ID of the package that can be upgraded.
        pub package: ID,
        /// (Mutable) Number of upgrades that have been applied to the
        /// original package. Initially 0.
        pub version: u64,
        /// What kind of upgrades are allowed.
        pub policy: u8,
    }

    #[cfg(feature = "serde")]
    impl UpgradeCap {
        /// Decode an [`UpgradeCap`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode an [`UpgradeCap`] from an on-chain object, validating
        /// that the object's type tag matches `0x2::package::UpgradeCap`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_upgrade_cap() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    /// Rust version of the Move `iota::package::UpgradeTicket` type.
    ///
    /// Permission to perform a particular upgrade. An `UpgradeCap` can
    /// only issue one ticket at a time — the ticket is a hot potato.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UpgradeTicket {
        pub cap: ID,
        pub package: ID,
        pub policy: u8,
        /// SHA-256 digest of the bytecode and transitive dependencies that
        /// will be used in the upgrade.
        pub digest: Vec<u8>,
    }

    /// Rust version of the Move `iota::package::UpgradeReceipt` type.
    ///
    /// Issued as a result of a successful upgrade, containing info to be
    /// used to update the `UpgradeCap`. A hot potato to ensure that the
    /// upgrade is recorded before the transaction ends.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UpgradeReceipt {
        pub cap: ID,
        pub package: ID,
    }
}

/// Types from `0x2::bls12381`.
///
/// Each of the marker structs is empty in Move; the Rust mirrors carry a
/// `dummy_field` to preserve the BCS wire format (1 byte).
pub mod bls12381 {
    /// Rust version of the Move `iota::bls12381::Scalar` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Scalar {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::G1` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct G1 {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::G2` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct G2 {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::GT` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct GT {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::UncompressedG1` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UncompressedG1 {
        dummy_field: bool,
    }
}

/// Types from `0x2::groth16`.
pub mod groth16 {
    /// Rust version of the Move `iota::groth16::Curve` type.
    ///
    /// Represents an elliptic-curve construction to be used in the
    /// verifier. Currently BLS12-381 and BN254 are supported.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Curve {
        pub id: u8,
    }

    /// Rust version of the Move `iota::groth16::PreparedVerifyingKey` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PreparedVerifyingKey {
        pub vk_gamma_abc_g1_bytes: Vec<u8>,
        pub alpha_g1_beta_g2_bytes: Vec<u8>,
        pub gamma_g2_neg_pc_bytes: Vec<u8>,
        pub delta_g2_neg_pc_bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::groth16::PublicProofInputs` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PublicProofInputs {
        pub bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::groth16::ProofPoints` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ProofPoints {
        pub bytes: Vec<u8>,
    }
}

/// Types from `0x2::group_ops`.
pub mod group_ops {
    use core::marker::PhantomData;

    /// Rust version of the Move `iota::group_ops::Element<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Element<T> {
        pub bytes: Vec<u8>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Element<T> {
        pub const fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::authenticator_function`.
pub mod authenticator_function {
    use core::marker::PhantomData;

    use super::object::ID;
    use crate::std::ascii;

    /// Rust version of the Move
    /// `iota::authenticator_function::AuthenticatorFunctionRefV1<Account>`
    /// type.
    ///
    /// Represents a validated authenticate function.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorFunctionRefV1<Account> {
        pub package: ID,
        pub module_name: ascii::String,
        pub function_name: ascii::String,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<Account>,
    }

    impl<Account> AuthenticatorFunctionRefV1<Account> {
        pub const fn new(
            package: ID,
            module_name: ascii::String,
            function_name: ascii::String,
        ) -> Self {
            Self {
                package,
                module_name,
                function_name,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::account`.
pub mod account {
    use super::{authenticator_function::AuthenticatorFunctionRefV1, object::ID};

    /// Rust version of the Move `iota::account::ImmutableAccountCreated`
    /// event type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ImmutableAccountCreated<Account> {
        pub account_id: ID,
        pub authenticator: AuthenticatorFunctionRefV1<Account>,
    }

    /// Rust version of the Move `iota::account::MutableAccountCreated`
    /// event type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct MutableAccountCreated<Account> {
        pub account_id: ID,
        pub authenticator: AuthenticatorFunctionRefV1<Account>,
    }

    /// Rust version of the Move
    /// `iota::account::AuthenticatorFunctionRefV1Rotated` event type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorFunctionRefV1Rotated<Account> {
        pub account_id: ID,
        pub from: AuthenticatorFunctionRefV1<Account>,
        pub to: AuthenticatorFunctionRefV1<Account>,
    }

    /// Rust version of the Move
    /// `iota::account::AuthenticatorFunctionRefV1Key` type.
    ///
    /// Dynamic-field key used to locate a potential authenticate function.
    /// The Move struct is empty; the Rust mirror carries a `dummy_field`
    /// to preserve the BCS wire format.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorFunctionRefV1Key {
        dummy_field: bool,
    }
}

/// Types from `0x2::coin_manager`.
pub mod coin_manager {
    use core::marker::PhantomData;

    use super::{
        coin::{CoinMetadata, TreasuryCap},
        object::UID,
        url::Url,
    };
    use crate::std::{ascii, string};

    /// Rust version of the Move `iota::coin_manager::CoinManager<T>` type.
    ///
    /// Holds all the related objects to the coin of type `T` in a single
    /// shared object.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct CoinManager<T> {
        pub id: UID,
        /// The original `TreasuryCap` object as returned by
        /// `create_currency`.
        pub treasury_cap: TreasuryCap<T>,
        /// Metadata object, original one from the `coin` module, if
        /// available.
        pub metadata: Option<CoinMetadata<T>>,
        /// Immutable metadata object, only to be used as a last resort if
        /// the original metadata is frozen.
        pub immutable_metadata: Option<ImmutableCoinMetadata<T>>,
        /// Optional maximum supply.
        pub maximum_supply: Option<u64>,
        /// Flag indicating if the supply is considered immutable.
        pub supply_immutable: bool,
        /// Flag indicating if the metadata is considered immutable.
        pub metadata_immutable: bool,
    }

    /// Rust version of the Move
    /// `iota::coin_manager::CoinManagerTreasuryCap<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct CoinManagerTreasuryCap<T> {
        pub id: UID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> CoinManagerTreasuryCap<T> {
        pub const fn new(id: UID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move
    /// `iota::coin_manager::CoinManagerMetadataCap<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct CoinManagerMetadataCap<T> {
        pub id: UID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> CoinManagerMetadataCap<T> {
        pub const fn new(id: UID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move
    /// `iota::coin_manager::ImmutableCoinMetadata<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ImmutableCoinMetadata<T> {
        pub decimals: u8,
        pub name: string::String,
        pub symbol: ascii::String,
        pub description: string::String,
        pub icon_url: Option<Url>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> ImmutableCoinMetadata<T> {
        pub const fn new(
            decimals: u8,
            name: string::String,
            symbol: ascii::String,
            description: string::String,
            icon_url: Option<Url>,
        ) -> Self {
            Self {
                decimals,
                name,
                symbol,
                description,
                icon_url,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::coin_manager::CoinManaged` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct CoinManaged {
        pub coin_name: ascii::String,
    }

    /// Rust version of the Move
    /// `iota::coin_manager::TreasuryOwnershipRenounced` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TreasuryOwnershipRenounced {
        pub coin_name: ascii::String,
    }

    /// Rust version of the Move
    /// `iota::coin_manager::MetadataOwnershipRenounced` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct MetadataOwnershipRenounced {
        pub coin_name: ascii::String,
    }
}

/// Types from `0x2::token`.
pub mod token {
    use core::marker::PhantomData;

    use iota_types::Address;

    use super::{
        balance::Balance,
        object::{ID, UID},
        vec_map::VecMap,
        vec_set::VecSet,
    };
    use crate::std::{string, type_name::TypeName};

    /// Rust version of the Move `iota::token::Token<T>` type.
    ///
    /// A single `Token` with a `Balance` inside. Can only be owned by an
    /// address; actions on it must be confirmed in a matching `TokenPolicy`.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Token<T> {
        pub id: UID,
        pub balance: Balance<T>,
    }

    impl<T> Token<T> {
        pub const fn new(id: UID, balance: Balance<T>) -> Self {
            Self { id, balance }
        }
    }

    /// Rust version of the Move `iota::token::TokenPolicyCap<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TokenPolicyCap<T> {
        pub id: UID,
        pub r#for: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TokenPolicyCap<T> {
        pub const fn new(id: UID, r#for: ID) -> Self {
            Self {
                id,
                r#for,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::token::TokenPolicy<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TokenPolicy<T> {
        pub id: UID,
        /// Balance effectively spent on the `spend` action. Cannot be
        /// accessed by anyone but the `TreasuryCap` owner.
        pub spent_balance: Balance<T>,
        /// Rules that define what actions can be performed on the token,
        /// keyed by action name.
        pub rules: VecMap<string::String, VecSet<TypeName>>,
    }

    impl<T> TokenPolicy<T> {
        pub const fn new(
            id: UID,
            spent_balance: Balance<T>,
            rules: VecMap<string::String, VecSet<TypeName>>,
        ) -> Self {
            Self {
                id,
                spent_balance,
                rules,
            }
        }
    }

    /// Rust version of the Move `iota::token::ActionRequest<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ActionRequest<T> {
        /// Name of the action — one of `transfer`, `spend`, `to_coin`,
        /// `from_coin`, or a custom action.
        pub name: string::String,
        pub amount: u64,
        pub sender: Address,
        /// Only present for the `transfer` action.
        pub recipient: Option<Address>,
        /// Balance to be spent in the `TokenPolicy`. Only present for the
        /// `spend` action.
        pub spent_balance: Option<Balance<T>>,
        /// Collected approvals from completed rules.
        pub approvals: VecSet<TypeName>,
    }

    /// Rust version of the Move `iota::token::RuleKey<T>` type.
    ///
    /// Dynamic-field key for storing a `Config` for a specific action rule.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct RuleKey<T> {
        pub is_protected: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> RuleKey<T> {
        pub const fn new(is_protected: bool) -> Self {
            Self {
                is_protected,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::token::TokenPolicyCreated<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TokenPolicyCreated<T> {
        pub id: ID,
        pub is_mutable: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TokenPolicyCreated<T> {
        pub const fn new(id: ID, is_mutable: bool) -> Self {
            Self {
                id,
                is_mutable,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::test_scenario`.
///
/// The Move-side `test_scenario` module is annotated `#[test_only]`, so
/// none of its structs ship in the compiled package — they're omitted
/// from the `move_shape_compare` cross-check and therefore don't carry the
/// `MoveShape` derive.
pub mod test_scenario {
    use iota_types::Address;

    use super::{object::ID, tx_context::TxContext, vec_map::VecMap};

    /// Rust version of the Move `iota::test_scenario::Scenario` type.
    ///
    /// Mocks a multi-transaction IOTA execution in a single Move test
    /// procedure.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Scenario {
        pub txn_number: u64,
        pub ctx: TxContext,
    }

    /// Rust version of the Move `iota::test_scenario::TxContextBuilder` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TxContextBuilder {
        pub sender: Address,
        pub epoch: u64,
        pub epoch_timestamp_ms: u64,
        pub ids_created: u64,
        pub rgp: Option<u64>,
        pub gas_price: u64,
        pub gas_budget: u64,
        pub sponsor: Option<Address>,
    }

    /// Rust version of the Move `iota::test_scenario::TransactionEffects` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    pub struct TransactionEffects {
        pub created: Vec<ID>,
        pub written: Vec<ID>,
        pub deleted: Vec<ID>,
        pub transferred_to_account: VecMap<ID, Address>,
        pub transferred_to_object: VecMap<ID, ID>,
        pub shared: Vec<ID>,
        pub frozen: Vec<ID>,
        pub num_user_events: u64,
    }
}

/// Types from `0x2::package_metadata`.
pub mod package_metadata {
    use super::{
        object::{ID, UID},
        vec_map::VecMap,
    };
    use crate::std::{ascii, type_name::TypeName};

    /// Rust version of the Move
    /// `iota::package_metadata::PackageMetadataKey` type.
    ///
    /// Key type for deriving the package metadata object address. Empty in
    /// Move; the Rust mirror carries a `dummy_field` for BCS shape.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PackageMetadataKey {
        dummy_field: bool,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::PackageMetadataV1` type.
    ///
    /// Represents the metadata of a Move package, including storage ID,
    /// runtime ID, version, and per-module metadata.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PackageMetadataV1 {
        pub id: UID,
        /// Storage ID of the package represented by this metadata.
        pub storage_id: ID,
        /// Runtime ID of the package — the storage ID of the first version.
        pub runtime_id: ID,
        pub package_version: u64,
        pub modules_metadata: VecMap<ascii::String, ModuleMetadataV1>,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::ModuleMetadataV1` type.
    ///
    /// V1 includes only the authenticator function information.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ModuleMetadataV1 {
        pub authenticator_metadata: Vec<AuthenticatorMetadataV1>,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::AuthenticatorMetadataV1` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorMetadataV1 {
        pub function_name: ascii::String,
        pub account_type: TypeName,
    }
}

/// Types from `0x2::deny_list`.
pub mod deny_list {
    use iota_types::Address;

    use super::{
        bag::Bag,
        object::{ID, UID},
    };

    /// Rust version of the Move `iota::deny_list::DenyList` type.
    ///
    /// Shared object storing addresses blocked for a given core type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct DenyList {
        pub id: UID,
        /// The individual deny lists.
        pub lists: Bag,
    }

    /// Rust version of the Move `iota::deny_list::ConfigWriteCap` type.
    ///
    /// Move's source declares `ConfigWriteCap()` (positional empty) but
    /// the compiler injects a `dummy_field: bool` into the bytecode, so
    /// the Rust mirror carries the same named field to preserve the BCS
    /// wire format.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ConfigWriteCap {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::deny_list::ConfigKey` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ConfigKey {
        pub per_type_index: u64,
        pub per_type_key: Vec<u8>,
    }

    /// Rust version of the Move `iota::deny_list::AddressKey` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AddressKey(pub Address);

    /// Rust version of the Move `iota::deny_list::GlobalPauseKey` type.
    ///
    /// Move's source declares `GlobalPauseKey()` (positional empty) but
    /// the compiler injects a `dummy_field: bool` into the bytecode.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct GlobalPauseKey {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::deny_list::PerTypeConfigCreated`
    /// event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PerTypeConfigCreated {
        pub key: ConfigKey,
        pub config_id: ID,
    }
}

/// Types from `0x2::random`.
pub mod random {
    use super::{object::UID, versioned::Versioned};

    /// Rust version of the Move `iota::random::Random` type.
    ///
    /// Singleton shared object storing the global randomness state. The
    /// actual state lives in a versioned inner field.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Random {
        pub id: UID,
        pub inner: Versioned,
    }

    /// Rust version of the Move `iota::random::RandomInner` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct RandomInner {
        pub version: u64,
        pub epoch: u64,
        pub randomness_round: u64,
        pub random_bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::random::RandomGenerator` type.
    ///
    /// Unique randomness generator derived from the global randomness.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct RandomGenerator {
        pub seed: Vec<u8>,
        pub counter: u16,
        pub buffer: Vec<u8>,
    }
}

/// Types from `0x2::config`.
pub mod config {
    use core::marker::PhantomData;

    use super::object::UID;

    /// Rust version of the Move `iota::config::Config<WriteCap>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Config<WriteCap> {
        pub id: UID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<WriteCap>,
    }

    impl<WriteCap> Config<WriteCap> {
        pub const fn new(id: UID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::config::Setting<Value>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Setting<Value> {
        pub data: Option<SettingData<Value>>,
    }

    impl<Value> Setting<Value> {
        pub const fn new(data: Option<SettingData<Value>>) -> Self {
            Self { data }
        }
    }

    /// Rust version of the Move `iota::config::SettingData<Value>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct SettingData<Value> {
        pub newer_value_epoch: u64,
        pub newer_value: Option<Value>,
        pub older_value_opt: Option<Value>,
    }
}

/// Types from `0x2::ptb_command`.
pub mod ptb_command {
    use super::object::ID;
    use crate::std::{ascii, type_name::TypeName};

    /// Rust version of the Move `iota::ptb_command::Argument` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub enum Argument {
        GasCoin,
        Input(u16),
        Result(u16),
        NestedResult(u16, u16),
    }

    /// Rust version of the Move
    /// `iota::ptb_command::ProgrammableMoveCall` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ProgrammableMoveCall {
        pub package: ID,
        pub module_name: ascii::String,
        pub function: ascii::String,
        pub type_arguments: Vec<TypeName>,
        pub arguments: Vec<Argument>,
    }

    /// Rust version of the Move
    /// `iota::ptb_command::TransferObjectsData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferObjectsData {
        pub objects: Vec<Argument>,
        pub recipient: Argument,
    }

    /// Rust version of the Move `iota::ptb_command::SplitCoinsData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct SplitCoinsData {
        pub coin: Argument,
        pub amounts: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::MergeCoinsData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct MergeCoinsData {
        pub target_coin: Argument,
        pub source_coins: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::PublishData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PublishData {
        pub modules: Vec<Vec<u8>>,
        pub dependencies: Vec<ID>,
    }

    /// Rust version of the Move `iota::ptb_command::MakeMoveVecData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct MakeMoveVecData {
        pub type_arg: Option<TypeName>,
        pub elements: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::UpgradeData` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct UpgradeData {
        pub modules: Vec<Vec<u8>>,
        pub dependencies: Vec<ID>,
        pub package: ID,
        pub upgrade_ticket: Argument,
    }

    /// Rust version of the Move `iota::ptb_command::Command` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub enum Command {
        MoveCall(ProgrammableMoveCall),
        TransferObjects(TransferObjectsData),
        SplitCoins(SplitCoinsData),
        MergeCoins(MergeCoinsData),
        Publish(PublishData),
        MakeMoveVec(MakeMoveVecData),
        Upgrade(UpgradeData),
    }
}

/// Types from `0x2::ptb_call_arg`.
pub mod ptb_call_arg {
    use super::object::ID;

    /// Rust version of the Move `iota::ptb_call_arg::ObjectRef` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ObjectRef {
        pub object_id: ID,
        pub sequence_number: u64,
        pub object_digest: Vec<u8>,
    }

    /// Rust version of the Move `iota::ptb_call_arg::ObjectArg` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub enum ObjectArg {
        ImmOrOwnedObject(ObjectRef),
        SharedObject {
            id: ID,
            initial_shared_version: u64,
            mutable: bool,
        },
        ReceivingObject(ObjectRef),
    }

    /// Rust version of the Move `iota::ptb_call_arg::CallArg` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub enum CallArg {
        PureData(Vec<u8>),
        ObjectData(ObjectArg),
    }
}

/// Types from `0x2::ptb`.
pub mod ptb {
    use super::{ptb_call_arg::CallArg, ptb_command::Command};

    /// Rust version of the Move `iota::ptb::ProgrammableTransaction` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ProgrammableTransaction {
        pub inputs: Vec<CallArg>,
        pub commands: Vec<Command>,
    }
}

/// Types from `0x2::auth_context`.
pub mod auth_context {
    use super::{object::ID, ptb_call_arg::CallArg, ptb_command::Command};
    use crate::std::ascii;

    /// Rust version of the Move `iota::auth_context::AuthContext` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthContext {
        /// Digest of the `MoveAuthenticator`.
        pub auth_digest: Vec<u8>,
        /// Transaction input objects or primitive values.
        pub tx_inputs: Vec<CallArg>,
        /// Transaction commands to be executed sequentially.
        pub tx_commands: Vec<Command>,
    }

    /// Rust version of the Move
    /// `iota::auth_context::AuthenticatorFunctionInfoV1` type.
    ///
    /// Identifies the `authenticate` function used by a `MoveAuthenticator`
    /// signature, without binding to a specific account type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct AuthenticatorFunctionInfoV1 {
        pub package: ID,
        pub module_name: ascii::String,
        pub function_name: ascii::String,
    }
}

/// Types from `0x2::kiosk`.
pub mod kiosk {
    use core::marker::PhantomData;

    use iota_types::Address;

    use super::{
        balance::Balance,
        iota::IOTA,
        object::{ID, UID},
    };

    /// Rust version of the Move `iota::kiosk::Kiosk` type.
    ///
    /// An object which allows selling collectibles within the kiosk
    /// ecosystem.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Kiosk {
        pub id: UID,
        /// Balance of the Kiosk — all profits from sales go here.
        pub profits: Balance<IOTA>,
        /// Always points to the `sender` of the transaction; can be
        /// changed by calling `set_owner` with the owner cap.
        pub owner: Address,
        /// Number of items stored in the Kiosk.
        pub item_count: u32,
    }

    #[cfg(feature = "serde")]
    impl Kiosk {
        /// Decode a [`Kiosk`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`Kiosk`] from an on-chain object, validating that the
        /// object's type tag matches `0x2::kiosk::Kiosk`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_kiosk() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    /// Rust version of the Move `iota::kiosk::KioskOwnerCap` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct KioskOwnerCap {
        pub id: UID,
        pub r#for: ID,
    }

    #[cfg(feature = "serde")]
    impl KioskOwnerCap {
        /// Decode a [`KioskOwnerCap`] from BCS bytes without verifying the
        /// on-chain type tag.
        pub fn try_from_bcs(bytes: &[u8]) -> Result<Self, bcs::Error> {
            bcs::from_bytes(bytes)
        }

        /// Decode a [`KioskOwnerCap`] from an on-chain object, validating
        /// that the object's type tag matches `0x2::kiosk::KioskOwnerCap`.
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.object_type().is_kiosk_owner_cap() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(move_struct.contents()).map_err(crate::FromObjectError::Bcs)
        }
    }

    /// Rust version of the Move `iota::kiosk::PurchaseCap<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct PurchaseCap<T> {
        pub id: UID,
        pub kiosk_id: ID,
        pub item_id: ID,
        pub min_price: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> PurchaseCap<T> {
        pub const fn new(id: UID, kiosk_id: ID, item_id: ID, min_price: u64) -> Self {
            Self {
                id,
                kiosk_id,
                item_id,
                min_price,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::kiosk::Borrow` type.
    ///
    /// Hot potato ensuring an item was returned after being taken with
    /// `borrow_val`. Schema named `kiosk-borrow` to disambiguate from
    /// [`super::borrow::Borrow`].
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "kiosk-borrow")
    )]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Borrow {
        pub kiosk_id: ID,
        pub item_id: ID,
    }

    /// Rust version of the Move `iota::kiosk::Item` type.
    ///
    /// Dynamic-field key for an item placed into the kiosk.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Item {
        pub id: ID,
    }

    /// Rust version of the Move `iota::kiosk::Listing` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Listing {
        pub id: ID,
        pub is_exclusive: bool,
    }

    /// Rust version of the Move `iota::kiosk::Lock` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Lock {
        pub id: ID,
    }

    /// Rust version of the Move `iota::kiosk::ItemListed<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ItemListed<T> {
        pub kiosk: ID,
        pub id: ID,
        pub price: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> ItemListed<T> {
        pub const fn new(kiosk: ID, id: ID, price: u64) -> Self {
            Self {
                kiosk,
                id,
                price,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::kiosk::ItemPurchased<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ItemPurchased<T> {
        pub kiosk: ID,
        pub id: ID,
        pub price: u64,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> ItemPurchased<T> {
        pub const fn new(kiosk: ID, id: ID, price: u64) -> Self {
            Self {
                kiosk,
                id,
                price,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::kiosk::ItemDelisted<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ItemDelisted<T> {
        pub kiosk: ID,
        pub id: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> ItemDelisted<T> {
        pub const fn new(kiosk: ID, id: ID) -> Self {
            Self {
                kiosk,
                id,
                _marker: PhantomData,
            }
        }
    }
}

/// Types from `0x2::kiosk_extension`.
pub mod kiosk_extension {
    use core::marker::PhantomData;

    use super::bag::Bag;

    /// Rust version of the Move `iota::kiosk_extension::Extension` type.
    ///
    /// Configuration and storage for a kiosk extension; stored under the
    /// [`ExtensionKey`] dynamic field.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct Extension {
        pub storage: Bag,
        /// Bitmap of permissions. Bit 0 = `place`, bit 1 = `lock` (and
        /// `place`).
        pub permissions: u128,
        /// Whether the extension can call protected actions.
        pub is_enabled: bool,
    }

    /// Rust version of the Move
    /// `iota::kiosk_extension::ExtensionKey<Ext>` type.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct ExtensionKey<Ext> {
        dummy_field: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<Ext>,
    }
}

/// Types from `0x2::transfer_policy`.
pub mod transfer_policy {
    use core::marker::PhantomData;

    use super::{
        balance::Balance,
        iota::IOTA,
        object::{ID, UID},
        vec_set::VecSet,
    };
    use crate::std::type_name::TypeName;

    /// Rust version of the Move
    /// `iota::transfer_policy::TransferRequest<T>` type.
    ///
    /// A hot potato forcing the buyer to get a transfer permission from
    /// the item type's owner on purchase.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferRequest<T> {
        pub item: ID,
        /// Amount of IOTA paid for the item.
        pub paid: u64,
        /// ID of the kiosk / safe the object is being sold from.
        pub from: ID,
        /// Collected receipts. Used to verify that all rules were
        /// followed.
        pub receipts: VecSet<TypeName>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TransferRequest<T> {
        pub const fn new(item: ID, paid: u64, from: ID, receipts: VecSet<TypeName>) -> Self {
            Self {
                item,
                paid,
                from,
                receipts,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::transfer_policy::TransferPolicy<T>`
    /// type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferPolicy<T> {
        pub id: UID,
        /// The Balance of the `TransferPolicy` (collected in IOTA).
        pub balance: Balance<IOTA>,
        /// Set of types of attached rules.
        pub rules: VecSet<TypeName>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TransferPolicy<T> {
        pub const fn new(id: UID, balance: Balance<IOTA>, rules: VecSet<TypeName>) -> Self {
            Self {
                id,
                balance,
                rules,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move
    /// `iota::transfer_policy::TransferPolicyCap<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferPolicyCap<T> {
        pub id: UID,
        pub policy_id: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TransferPolicyCap<T> {
        pub const fn new(id: UID, policy_id: ID) -> Self {
            Self {
                id,
                policy_id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move
    /// `iota::transfer_policy::TransferPolicyCreated<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferPolicyCreated<T> {
        pub id: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TransferPolicyCreated<T> {
        pub const fn new(id: ID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move
    /// `iota::transfer_policy::TransferPolicyDestroyed<T>` event.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct TransferPolicyDestroyed<T> {
        pub id: ID,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> TransferPolicyDestroyed<T> {
        pub const fn new(id: ID) -> Self {
            Self {
                id,
                _marker: PhantomData,
            }
        }
    }

    /// Rust version of the Move `iota::transfer_policy::RuleKey<T>` type.
    #[derive(Clone, Debug, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    #[cfg_attr(test, derive(iota_bcs_schema::MoveShape))]
    pub struct RuleKey<T> {
        dummy_field: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> RuleKey<T> {
        pub const fn new() -> Self {
            Self {
                dummy_field: false,
                _marker: PhantomData,
            }
        }
    }

    impl<T> Default for RuleKey<T> {
        fn default() -> Self {
            Self::new()
        }
    }
}
