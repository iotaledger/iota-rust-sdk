// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA framework (system package `0x2`).

/// Types from `0x2::object`.
pub mod object {
    use core::fmt;

    use iota_types::ObjectId;

    /// Rust version of the Move `iota::object::ID` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        fn sample_object_id() -> ObjectId {
            ObjectId::new([0xab; ObjectId::LENGTH])
        }

        #[test]
        fn id_bcs_roundtrip() {
            let id = ID::new(sample_object_id());
            let bytes = bcs::to_bytes(&id).unwrap();
            // `#[serde(transparent)]`: an ID encodes exactly as its inner ObjectId.
            assert_eq!(bytes, bcs::to_bytes(&sample_object_id()).unwrap());
            let decoded: ID = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(id, decoded);
        }

        #[test]
        fn uid_bcs_roundtrip() {
            let uid = UID::new(sample_object_id());
            let bytes = bcs::to_bytes(&uid).unwrap();
            // UID wraps an ID, which is transparent over ObjectId, so the
            // wire format is exactly an ObjectId.
            assert_eq!(bytes, bcs::to_bytes(&sample_object_id()).unwrap());
            let decoded: UID = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(uid, decoded);
        }

        // moverox-parity --------------------------------------------------

        use crate::parity_check::assert_parity;

        #[test]
        fn id_moverox_parity() {
            let sample = ID::new(sample_object_id());
            assert_parity::<_, crate::generated::framework::object::ID>(&sample);
        }

        #[test]
        fn uid_moverox_parity() {
            let sample = UID::new(sample_object_id());
            assert_parity::<_, crate::generated::framework::object::UID>(&sample);
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct IOTA {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::iota::IotaTreasuryCap` type.
    ///
    /// The non-generic IOTA treasury cap, wrapping a [`TreasuryCap<IOTA>`].
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct IotaTreasuryCap {
        pub inner: TreasuryCap<IOTA>,
    }

    impl IotaTreasuryCap {
        pub const fn new(inner: TreasuryCap<IOTA>) -> Self {
            Self { inner }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::balance::Supply;
        use crate::framework::object::UID;
        use iota_types::ObjectId;

        #[test]
        fn iota_bcs_roundtrip() {
            let i = IOTA::default();
            let bytes = bcs::to_bytes(&i).unwrap();
            assert_eq!(bytes, [0u8]);
            let decoded: IOTA = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(i, decoded);
        }

        #[test]
        fn iota_treasury_cap_bcs_roundtrip() {
            let cap = IotaTreasuryCap::new(TreasuryCap::new(
                UID::new(ObjectId::ZERO),
                Supply::new(1_000_000),
            ));
            let bytes = bcs::to_bytes(&cap).unwrap();
            let decoded: IotaTreasuryCap = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(cap, decoded);
        }

        // moverox-parity --------------------------------------------------

        use crate::parity_check::assert_parity;

        #[test]
        fn iota_marker_moverox_parity() {
            assert_parity::<_, crate::generated::framework::iota::IOTA>(&IOTA::default());
        }

        #[test]
        fn iota_treasury_cap_moverox_parity() {
            let sample = IotaTreasuryCap::new(TreasuryCap::new(
                UID::new(ObjectId::ZERO),
                Supply::new(1_000_000),
            ));
            assert_parity::<_, crate::generated::framework::iota::IotaTreasuryCap>(&sample);
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct IotaSystemAdminCap {
        dummy_field: bool,
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn iota_system_admin_cap_bcs_roundtrip() {
            let cap = IotaSystemAdminCap::default();
            let bytes = bcs::to_bytes(&cap).unwrap();
            assert_eq!(bytes, [0u8]);
            let decoded: IotaSystemAdminCap = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(cap, decoded);
        }

        #[test]
        fn iota_system_admin_cap_moverox_parity() {
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::system_admin_cap::IotaSystemAdminCap,
            >(&IotaSystemAdminCap::default());
        }
    }
}

/// Types from `0x2::balance`.
pub mod balance {
    use core::marker::PhantomData;

    /// Rust version of the Move `iota::balance::Supply<T>` type.
    ///
    /// A `Supply` of `T`; used for minting and burning. Wrapped into a
    /// `TreasuryCap` in the `coin` module.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[derive(Debug, Clone, Eq, PartialEq)]
        struct TestCoin;

        #[test]
        fn balance_bcs_roundtrip() {
            let b: Balance<TestCoin> = Balance::new(1_000_000_000);
            let bytes = bcs::to_bytes(&b).unwrap();
            // BCS shape: just a u64
            assert_eq!(bytes.len(), 8);
            let decoded: Balance<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(b, decoded);
        }

        #[test]
        fn supply_bcs_roundtrip() {
            let s: Supply<TestCoin> = Supply::new(42);
            let bytes = bcs::to_bytes(&s).unwrap();
            assert_eq!(bytes.len(), 8);
            let decoded: Supply<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }

        #[test]
        fn balance_moverox_parity() {
            let sample: Balance<u64> = Balance::new(1_000);
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::balance::Balance<u64>,
            >(&sample);
        }

        #[test]
        fn supply_moverox_parity() {
            let sample: Supply<u64> = Supply::new(7);
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::balance::Supply<u64>,
            >(&sample);
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn bag_bcs_roundtrip() {
            let b = Bag::new(UID::new(ObjectId::ZERO), 5);
            let bytes = bcs::to_bytes(&b).unwrap();
            let decoded: Bag = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(b, decoded);
        }

        #[test]
        fn bag_moverox_parity() {
            let sample = Bag::new(UID::new(ObjectId::new([0x02; ObjectId::LENGTH])), 5);
            crate::parity_check::assert_parity::<_, crate::generated::framework::bag::Bag>(&sample);
        }
    }
}

/// Types from `0x2::coin`.
pub mod coin {
    use core::marker::PhantomData;

    use super::balance::{Balance, Supply};
    use super::object::{ID, UID};
    use super::url::Url;
    use crate::std::ascii;
    use crate::std::string;

    /// Rust version of the Move `iota::coin::Coin<T>` type.
    ///
    /// A coin of type `T` worth `balance`. Transferable and storable.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Coin<T> {
        pub id: UID,
        pub balance: Balance<T>,
    }

    impl<T> Coin<T> {
        pub const fn new(id: UID, balance: Balance<T>) -> Self {
            Self { id, balance }
        }
    }

    /// Rust version of the Move `iota::coin::CoinMetadata<T>` type.
    ///
    /// Each `Coin<T>` created through `create_currency` has a unique
    /// `CoinMetadata<T>` storing display metadata for the coin type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        /// `0x2::coin::CoinMetadata<T>` for *some* `T` (the inner coin
        /// marker is not checked against `T`).
        pub fn try_from_object(
            object: &iota_types::Object,
        ) -> Result<Self, crate::FromObjectError> {
            let move_struct = object
                .as_struct_opt()
                .ok_or(crate::FromObjectError::NotAMoveStruct)?;
            if !move_struct.type_.is_coin_metadata() {
                return Err(crate::FromObjectError::WrongType);
            }
            bcs::from_bytes(&move_struct.contents).map_err(crate::FromObjectError::Bcs)
        }
    }

    /// Rust version of the Move `iota::coin::RegulatedCoinMetadata<T>` type.
    ///
    /// Similar to [`CoinMetadata`], but created only for regulated coins
    /// that use the DenyList. Always immutable.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        // Phantom markers in field positions (e.g. `balance: Balance<T>`) make
        // serde's auto-derive require `T: Serialize + Deserialize<'de>` even
        // though `T` is only carried via `PhantomData`. Real coin markers
        // satisfy this trivially (e.g. `IOTA` derives both).
        #[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        struct TestCoin;

        fn sample_object_id() -> ObjectId {
            ObjectId::new([0xab; ObjectId::LENGTH])
        }

        #[test]
        fn coin_bcs_roundtrip() {
            let c: Coin<TestCoin> = Coin::new(UID::new(sample_object_id()), Balance::new(1_000));
            let bytes = bcs::to_bytes(&c).unwrap();
            let decoded: Coin<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(c, decoded);
        }

        #[test]
        fn treasury_cap_bcs_roundtrip() {
            let t: TreasuryCap<TestCoin> =
                TreasuryCap::new(UID::new(sample_object_id()), Supply::new(7));
            let bytes = bcs::to_bytes(&t).unwrap();
            let decoded: TreasuryCap<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(t, decoded);
        }

        #[test]
        fn coin_metadata_bcs_roundtrip() {
            let m: CoinMetadata<TestCoin> = CoinMetadata::new(
                UID::new(sample_object_id()),
                9,
                string::String::new(b"Test Coin".to_vec()),
                ascii::String::new(b"TST".to_vec()),
                string::String::new(b"a test coin".to_vec()),
                Some(Url::new(ascii::String::new(b"https://iota.org/logo.png".to_vec()))),
            );
            let bytes = bcs::to_bytes(&m).unwrap();
            let decoded: CoinMetadata<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(m, decoded);
        }

        #[test]
        fn regulated_coin_metadata_bcs_roundtrip() {
            let r: RegulatedCoinMetadata<TestCoin> = RegulatedCoinMetadata::new(
                UID::new(sample_object_id()),
                ID::new(sample_object_id()),
                ID::new(sample_object_id()),
            );
            let bytes = bcs::to_bytes(&r).unwrap();
            let decoded: RegulatedCoinMetadata<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(r, decoded);
        }

        #[test]
        fn deny_cap_v1_bcs_roundtrip() {
            let d: DenyCapV1<TestCoin> = DenyCapV1::new(UID::new(sample_object_id()), true);
            let bytes = bcs::to_bytes(&d).unwrap();
            let decoded: DenyCapV1<TestCoin> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(d, decoded);
        }

        // moverox-parity --------------------------------------------------

        use crate::framework::iota::IOTA;
        use crate::parity_check::assert_parity;

        #[test]
        fn coin_moverox_parity() {
            let sample: Coin<u64> = Coin::new(UID::new(sample_object_id()), Balance::new(42));
            assert_parity::<_, crate::generated::framework::coin::Coin<u64>>(&sample);
        }

        #[test]
        fn treasury_cap_moverox_parity() {
            let sample: TreasuryCap<u64> =
                TreasuryCap::new(UID::new(sample_object_id()), Supply::new(7));
            assert_parity::<_, crate::generated::framework::coin::TreasuryCap<u64>>(&sample);
        }

        #[test]
        fn coin_metadata_iota_moverox_parity() {
            let sample = CoinMetadata::<IOTA>::new(
                UID::new(sample_object_id()),
                9,
                string::String::new(b"IOTA".to_vec()),
                ascii::String::new(b"IOTA".to_vec()),
                string::String::new(b"Native IOTA coin".to_vec()),
                Some(Url::new(ascii::String::new(b"https://iota.org/logo.png".to_vec()))),
            );
            // moverox's CoinMetadata<T> is phantom in T; instantiate with u64
            // on that side — the wire shape is identical regardless of T.
            assert_parity::<_, crate::generated::framework::coin::CoinMetadata<u64>>(&sample);
        }

        #[test]
        fn coin_metadata_no_icon_moverox_parity() {
            let sample = CoinMetadata::<IOTA>::new(
                UID::new(sample_object_id()),
                0,
                string::String::new(b"X".to_vec()),
                ascii::String::new(b"X".to_vec()),
                string::String::new(b"".to_vec()),
                None,
            );
            assert_parity::<_, crate::generated::framework::coin::CoinMetadata<u64>>(&sample);
        }

        #[test]
        fn regulated_coin_metadata_moverox_parity() {
            let sample: RegulatedCoinMetadata<u64> = RegulatedCoinMetadata::new(
                UID::new(sample_object_id()),
                ID::new(sample_object_id()),
                ID::new(sample_object_id()),
            );
            assert_parity::<_, crate::generated::framework::coin::RegulatedCoinMetadata<u64>>(
                &sample,
            );
        }

        #[test]
        fn deny_cap_v1_moverox_parity() {
            let sample: DenyCapV1<u64> = DenyCapV1::new(UID::new(sample_object_id()), true);
            assert_parity::<_, crate::generated::framework::coin::DenyCapV1<u64>>(&sample);
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn table_bcs_roundtrip() {
            let t: Table<u64, u64> = Table::new(UID::new(ObjectId::ZERO), 3);
            let bytes = bcs::to_bytes(&t).unwrap();
            let decoded: Table<u64, u64> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(t, decoded);
        }

        #[test]
        fn table_moverox_parity() {
            let sample: Table<u64, u64> = Table::new(UID::new(ObjectId::ZERO), 3);
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::table::Table<u64, u64>,
            >(&sample);
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct NonAsciiUrl;

    impl core::fmt::Display for NonAsciiUrl {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("url is not valid ASCII")
        }
    }

    impl core::error::Error for NonAsciiUrl {}

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn url_bcs_roundtrip() {
            let u = Url::try_from_ascii("https://iota.org/").unwrap();
            let bytes = bcs::to_bytes(&u).unwrap();
            // Wire format: length-prefixed bytes (the inner ascii::String).
            assert_eq!(
                bytes,
                bcs::to_bytes(&b"https://iota.org/".to_vec()).unwrap()
            );
            let decoded: Url = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(u, decoded);
        }

        #[test]
        fn url_moverox_parity() {
            let sample = Url::try_from_ascii("https://iota.org/").unwrap();
            crate::parity_check::assert_parity::<_, crate::generated::framework::url::Url>(
                &sample,
            );
        }

        #[test]
        fn url_rejects_non_ascii() {
            assert!(Url::try_from_ascii("héllo").is_err());
        }
    }
}

/// Types from `0x2::vec_map`.
pub mod vec_map {
    /// Rust version of the Move `iota::vec_map::Entry<K, V>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn vec_map_bcs_roundtrip() {
            let m: VecMap<u64, u64> = VecMap::new(vec![Entry::new(1, 10), Entry::new(2, 20)]);
            let bytes = bcs::to_bytes(&m).unwrap();
            let decoded: VecMap<u64, u64> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(m, decoded);
        }

        #[test]
        fn vec_map_moverox_parity() {
            let sample: VecMap<u64, u64> =
                VecMap::new(vec![Entry::new(1, 10), Entry::new(2, 20)]);
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::vec_map::VecMap<u64, u64>,
            >(&sample);
        }
    }
}

/// Types from `0x2::vec_set`.
pub mod vec_set {
    /// Rust version of the Move `iota::vec_set::VecSet<K>` type.
    ///
    /// A set backed by a vector; guaranteed to contain no duplicate keys.
    /// All operations are O(N).
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;

        #[test]
        fn vec_set_bcs_roundtrip() {
            let s: VecSet<u64> = VecSet::new(vec![1, 2, 3]);
            let bytes = bcs::to_bytes(&s).unwrap();
            let decoded: VecSet<u64> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(s, decoded);
        }

        #[test]
        fn vec_set_moverox_parity() {
            let sample: VecSet<u64> = VecSet::new(vec![1, 2, 3]);
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::vec_set::VecSet<u64>,
            >(&sample);
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct TableVec<Element> {
        /// The contents of the table vector.
        pub contents: Table<u64, Element>,
    }

    impl<Element> TableVec<Element> {
        pub const fn new(contents: Table<u64, Element>) -> Self {
            Self { contents }
        }
    }

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use crate::framework::object::UID;
        use iota_types::ObjectId;

        #[test]
        fn table_vec_bcs_roundtrip() {
            let tv: TableVec<u64> = TableVec::new(Table::new(UID::new(ObjectId::ZERO), 3));
            let bytes = bcs::to_bytes(&tv).unwrap();
            let decoded: TableVec<u64> = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(tv, decoded);
        }

        #[test]
        fn table_vec_moverox_parity() {
            let sample: TableVec<u64> = TableVec::new(Table::new(UID::new(ObjectId::ZERO), 3));
            crate::parity_check::assert_parity::<
                _,
                crate::generated::framework::table_vec::TableVec<u64>,
            >(&sample);
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    #[cfg(all(test, feature = "serde"))]
    mod tests {
        use super::*;
        use iota_types::ObjectId;

        #[test]
        fn versioned_bcs_roundtrip() {
            let v = Versioned::new(UID::new(ObjectId::ZERO), 7);
            let bytes = bcs::to_bytes(&v).unwrap();
            let decoded: Versioned = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(v, decoded);
        }

        #[test]
        fn version_change_cap_bcs_roundtrip() {
            let c = VersionChangeCap::new(ID::new(ObjectId::ZERO), 3);
            let bytes = bcs::to_bytes(&c).unwrap();
            let decoded: VersionChangeCap = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(c, decoded);
        }

        // moverox-parity --------------------------------------------------

        use crate::parity_check::assert_parity;

        #[test]
        fn versioned_moverox_parity() {
            let sample = Versioned::new(UID::new(ObjectId::ZERO), 7);
            assert_parity::<_, crate::generated::framework::versioned::Versioned>(&sample);
        }

        #[test]
        fn version_change_cap_moverox_parity() {
            let sample = VersionChangeCap::new(ID::new(ObjectId::ZERO), 3);
            assert_parity::<_, crate::generated::framework::versioned::VersionChangeCap>(
                &sample,
            );
        }
    }
}

/// Types from `0x2::bcs`.
pub mod bcs {
    /// Rust version of the Move `iota::bcs::BCS` type.
    ///
    /// A helper struct used by the Move-side BCS deserializer; stores
    /// reversed bytes so `vector::pop_back` can be used efficiently.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
}

/// Types from `0x2::tx_context`.
pub mod tx_context {
    use iota_types::Address;

    /// Rust version of the Move `iota::tx_context::TxContext` type.
    ///
    /// Information about the transaction currently being executed. Not
    /// constructible from user code — created by the VM and passed to the
    /// transaction entrypoint as `&mut TxContext`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use crate::std::string::String as MoveString;

    /// Rust version of the Move `iota::zklogin_verified_id::VerifiedID`
    /// type.
    ///
    /// Possession proves that the user's address was created using zkLogin
    /// with the given parameters.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct VerifiedID {
        pub id: UID,
        /// The address this `VerifiedID` is associated with.
        pub owner: Address,
        /// The name of the key claim.
        pub key_claim_name: MoveString,
        /// The value of the key claim.
        pub key_claim_value: MoveString,
        /// The issuer.
        pub issuer: MoveString,
        /// The audience (wallet).
        pub audience: MoveString,
    }
}

/// Types from `0x2::zklogin_verified_issuer`.
pub mod zklogin_verified_issuer {
    use iota_types::Address;

    use super::object::UID;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move
    /// `iota::zklogin_verified_issuer::VerifiedIssuer` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct VerifiedIssuer {
        pub id: UID,
        pub owner: Address,
        pub issuer: MoveString,
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use crate::std::string::String as MoveString;

    /// Rust version of the Move `iota::timelock::TimeLock<T>` type.
    ///
    /// A `TimeLock` that holds a locked object until `expiration_timestamp_ms`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct TimeLock<T> {
        pub id: UID,
        /// The locked object.
        pub locked: T,
        /// Epoch timestamp (ms) of when the lock expires.
        pub expiration_timestamp_ms: u64,
        /// Optional timelock-related label.
        pub label: Option<MoveString>,
    }

    impl<T> TimeLock<T> {
        pub const fn new(
            id: UID,
            locked: T,
            expiration_timestamp_ms: u64,
            label: Option<MoveString>,
        ) -> Self {
            Self {
                id,
                locked,
                expiration_timestamp_ms,
                label,
            }
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Borrow {
        pub r#ref: Address,
        pub obj: ID,
    }

    /// Rust version of the Move `iota::borrow::Test` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ObjectBag {
        pub id: UID,
        pub size: u64,
    }
}

/// Types from `0x2::priority_queue`.
pub mod priority_queue {
    /// Rust version of the Move `iota::priority_queue::Entry<T>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use crate::std::string::String as MoveString;

    /// Rust version of the Move
    /// `iota::authenticator_state::AuthenticatorState` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct AuthenticatorState {
        pub id: UID,
        pub version: u64,
    }

    /// Rust version of the Move
    /// `iota::authenticator_state::AuthenticatorStateInner` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct AuthenticatorStateInner {
        pub version: u64,
        /// List of currently active JWKs.
        pub active_jwks: Vec<ActiveJwk>,
    }

    /// Rust version of the Move `iota::authenticator_state::JWK` type.
    ///
    /// Must match the `JWK` struct in fastcrypto-zkp.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct JWK {
        pub kty: MoveString,
        pub e: MoveString,
        pub n: MoveString,
        pub alg: MoveString,
    }

    /// Rust version of the Move `iota::authenticator_state::JwkId` type.
    ///
    /// Must match the `JwkId` struct in fastcrypto-zkp.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct JwkId {
        pub iss: MoveString,
        pub kid: MoveString,
    }

    /// Rust version of the Move `iota::authenticator_state::ActiveJwk`
    /// type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ActiveJwk {
        pub jwk_id: JwkId,
        pub jwk: JWK,
        pub epoch: u64,
    }
}

/// Types from `0x2::display`.
pub mod display {
    use core::marker::PhantomData;

    use super::object::{ID, UID};
    use super::vec_map::VecMap;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move `iota::display::Display<T>` type.
    ///
    /// Defines the way a `T` instance should be displayed. Uses `String`
    /// types throughout because display rules are external-facing and the
    /// property names take priority over their types.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Display<T> {
        pub id: UID,
        /// Fields for display. Currently supported field names are `name`,
        /// `link`, `image`, `description`.
        pub fields: VecMap<MoveString, MoveString>,
        /// Version that can only be updated manually by the publisher.
        pub version: u16,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> Display<T> {
        pub const fn new(
            id: UID,
            fields: VecMap<MoveString, MoveString>,
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct VersionUpdated<T> {
        pub id: ID,
        pub version: u16,
        pub fields: VecMap<MoveString, MoveString>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> VersionUpdated<T> {
        pub const fn new(
            id: ID,
            version: u16,
            fields: VecMap<MoveString, MoveString>,
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
    use crate::std::ascii::String as AsciiString;

    /// Rust version of the Move `iota::package::Publisher` type.
    ///
    /// Can only be created in the transaction that creates a module, by
    /// consuming its one-time witness, so it can be used to identify the
    /// publishing address.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Publisher {
        pub id: UID,
        pub package: AsciiString,
        pub module_name: AsciiString,
    }

    /// Rust version of the Move `iota::package::UpgradeCap` type.
    ///
    /// Capability controlling the ability to upgrade a package.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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

    /// Rust version of the Move `iota::package::UpgradeTicket` type.
    ///
    /// Permission to perform a particular upgrade. An `UpgradeCap` can
    /// only issue one ticket at a time — the ticket is a hot potato.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Scalar {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::G1` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct G1 {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::G2` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct G2 {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::GT` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct GT {
        dummy_field: bool,
    }

    /// Rust version of the Move `iota::bls12381::UncompressedG1` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Curve {
        pub id: u8,
    }

    /// Rust version of the Move `iota::groth16::PreparedVerifyingKey` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct PreparedVerifyingKey {
        pub vk_gamma_abc_g1_bytes: Vec<u8>,
        pub alpha_g1_beta_g2_bytes: Vec<u8>,
        pub gamma_g2_neg_pc_bytes: Vec<u8>,
        pub delta_g2_neg_pc_bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::groth16::PublicProofInputs` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct PublicProofInputs {
        pub bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::groth16::ProofPoints` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ProofPoints {
        pub bytes: Vec<u8>,
    }
}

/// Types from `0x2::group_ops`.
pub mod group_ops {
    use core::marker::PhantomData;

    /// Rust version of the Move `iota::group_ops::Element<T>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use crate::std::ascii::String as AsciiString;

    /// Rust version of the Move
    /// `iota::authenticator_function::AuthenticatorFunctionRefV1<Account>`
    /// type.
    ///
    /// Represents a validated authenticate function.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AuthenticatorFunctionRefV1<Account> {
        pub package: ID,
        pub module_name: AsciiString,
        pub function_name: AsciiString,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<Account>,
    }

    impl<Account> AuthenticatorFunctionRefV1<Account> {
        pub const fn new(package: ID, module_name: AsciiString, function_name: AsciiString) -> Self {
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
    use super::authenticator_function::AuthenticatorFunctionRefV1;
    use super::object::ID;

    /// Rust version of the Move `iota::account::ImmutableAccountCreated`
    /// event type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ImmutableAccountCreated<Account> {
        pub account_id: ID,
        pub authenticator: AuthenticatorFunctionRefV1<Account>,
    }

    /// Rust version of the Move `iota::account::MutableAccountCreated`
    /// event type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct MutableAccountCreated<Account> {
        pub account_id: ID,
        pub authenticator: AuthenticatorFunctionRefV1<Account>,
    }

    /// Rust version of the Move
    /// `iota::account::AuthenticatorFunctionRefV1Rotated` event type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct AuthenticatorFunctionRefV1Key {
        dummy_field: bool,
    }
}

/// Types from `0x2::coin_manager`.
pub mod coin_manager {
    use core::marker::PhantomData;

    use super::coin::{CoinMetadata, TreasuryCap};
    use super::object::UID;
    use super::url::Url;
    use crate::std::ascii::String as AsciiString;
    use crate::std::string::String as MoveString;

    /// Rust version of the Move `iota::coin_manager::CoinManager<T>` type.
    ///
    /// Holds all the related objects to the coin of type `T` in a single
    /// shared object.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ImmutableCoinMetadata<T> {
        pub decimals: u8,
        pub name: MoveString,
        pub symbol: AsciiString,
        pub description: MoveString,
        pub icon_url: Option<Url>,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<T>,
    }

    impl<T> ImmutableCoinMetadata<T> {
        pub const fn new(
            decimals: u8,
            name: MoveString,
            symbol: AsciiString,
            description: MoveString,
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct CoinManaged {
        pub coin_name: AsciiString,
    }

    /// Rust version of the Move
    /// `iota::coin_manager::TreasuryOwnershipRenounced` event.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct TreasuryOwnershipRenounced {
        pub coin_name: AsciiString,
    }

    /// Rust version of the Move
    /// `iota::coin_manager::MetadataOwnershipRenounced` event.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct MetadataOwnershipRenounced {
        pub coin_name: AsciiString,
    }
}

#[cfg(all(test, feature = "serde"))]
mod round4_tests {
    //! Sanity round-trip tests for the round-4 modules added above. One
    //! representative test per module — exhaustive shape testing on every
    //! field is left to consumers who care.

    use iota_types::{Address, ObjectId};

    use super::*;
    use crate::std::ascii;
    use crate::std::string::String as MoveString;

    fn oid() -> ObjectId {
        ObjectId::new([0xab; ObjectId::LENGTH])
    }

    fn uid() -> object::UID {
        object::UID::new(oid())
    }

    #[test]
    fn bcs_bcs_roundtrip() {
        let b = bcs::BCS::new(vec![1, 2, 3]);
        let bytes = ::bcs::to_bytes(&b).unwrap();
        let decoded: bcs::BCS = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(b, decoded);
    }

    #[test]
    fn clock_bcs_roundtrip() {
        let c = clock::Clock::new(uid(), 1_700_000_000_000);
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: clock::Clock = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn tx_context_bcs_roundtrip() {
        let t = tx_context::TxContext {
            sender: Address::new([0xab; 32]),
            tx_hash: vec![0; 32],
            epoch: 1,
            epoch_timestamp_ms: 1_700_000_000_000,
            ids_created: 0,
        };
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: tx_context::TxContext = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn intent_bcs_roundtrip() {
        let i = intent::Intent::new(1, 2, 3);
        let bytes = ::bcs::to_bytes(&i).unwrap();
        let decoded: intent::Intent = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(i, decoded);
    }

    #[test]
    fn ecdsa_k1_keypair_bcs_roundtrip() {
        let k = ecdsa_k1::KeyPair {
            private_key: vec![1; 32],
            public_key: vec![2; 33],
        };
        let bytes = ::bcs::to_bytes(&k).unwrap();
        let decoded: ecdsa_k1::KeyPair = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn zklogin_verified_id_bcs_roundtrip() {
        let v = zklogin_verified_id::VerifiedID {
            id: uid(),
            owner: Address::new([0; 32]),
            key_claim_name: MoveString::new(b"sub".to_vec()),
            key_claim_value: MoveString::new(b"123".to_vec()),
            issuer: MoveString::new(b"https://accounts.google.com".to_vec()),
            audience: MoveString::new(b"wallet".to_vec()),
        };
        let bytes = ::bcs::to_bytes(&v).unwrap();
        let decoded: zklogin_verified_id::VerifiedID = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn zklogin_verified_issuer_bcs_roundtrip() {
        let v = zklogin_verified_issuer::VerifiedIssuer {
            id: uid(),
            owner: Address::new([0; 32]),
            issuer: MoveString::new(b"https://accounts.google.com".to_vec()),
        };
        let bytes = ::bcs::to_bytes(&v).unwrap();
        let decoded: zklogin_verified_issuer::VerifiedIssuer = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn receiving_bcs_roundtrip() {
        let r: transfer::Receiving<u64> = transfer::Receiving::new(object::ID::new(oid()), 7);
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: transfer::Receiving<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn timelock_bcs_roundtrip() {
        let t: timelock::TimeLock<u64> =
            timelock::TimeLock::new(uid(), 42, 1_700_000_000_000, None);
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: timelock::TimeLock<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn borrow_referent_bcs_roundtrip() {
        let r: borrow::Referent<u64> = borrow::Referent::new(Address::new([0; 32]), Some(42));
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: borrow::Referent<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn borrow_borrow_bcs_roundtrip() {
        let b = borrow::Borrow {
            r#ref: Address::new([0; 32]),
            obj: object::ID::new(oid()),
        };
        let bytes = ::bcs::to_bytes(&b).unwrap();
        let decoded: borrow::Borrow = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(b, decoded);
    }

    #[test]
    fn borrow_test_bcs_roundtrip() {
        let t = borrow::Test { id: uid() };
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: borrow::Test = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn dynamic_field_field_bcs_roundtrip() {
        let f: dynamic_field::Field<u64, u64> = dynamic_field::Field::new(uid(), 1, 2);
        let bytes = ::bcs::to_bytes(&f).unwrap();
        let decoded: dynamic_field::Field<u64, u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(f, decoded);
    }

    #[test]
    fn dynamic_object_field_wrapper_bcs_roundtrip() {
        let w: dynamic_object_field::Wrapper<u64> = dynamic_object_field::Wrapper::new(7);
        let bytes = ::bcs::to_bytes(&w).unwrap();
        let decoded: dynamic_object_field::Wrapper<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(w, decoded);
    }

    #[test]
    fn labeler_cap_bcs_roundtrip() {
        let c: labeler::LabelerCap<u64> = labeler::LabelerCap::new(uid());
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: labeler::LabelerCap<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn linked_table_bcs_roundtrip() {
        let t: linked_table::LinkedTable<u64, u64> =
            linked_table::LinkedTable::new(uid(), 2, Some(1), Some(2));
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: linked_table::LinkedTable<u64, u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn linked_table_node_bcs_roundtrip() {
        let n: linked_table::Node<u64, u64> = linked_table::Node::new(None, Some(2), 1);
        let bytes = ::bcs::to_bytes(&n).unwrap();
        let decoded: linked_table::Node<u64, u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn object_table_bcs_roundtrip() {
        let t: object_table::ObjectTable<u64, u64> = object_table::ObjectTable::new(uid(), 3);
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: object_table::ObjectTable<u64, u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn object_bag_bcs_roundtrip() {
        let b = object_bag::ObjectBag { id: uid(), size: 5 };
        let bytes = ::bcs::to_bytes(&b).unwrap();
        let decoded: object_bag::ObjectBag = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(b, decoded);
    }

    #[test]
    fn priority_queue_bcs_roundtrip() {
        let q: priority_queue::PriorityQueue<u64> = priority_queue::PriorityQueue::new(vec![
            priority_queue::Entry::new(10, 100),
            priority_queue::Entry::new(5, 50),
        ]);
        let bytes = ::bcs::to_bytes(&q).unwrap();
        let decoded: priority_queue::PriorityQueue<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(q, decoded);
    }

    #[test]
    fn derived_object_key_bcs_roundtrip() {
        let k: derived_object::DerivedObjectKey<u64> = derived_object::DerivedObjectKey::new(42);
        let bytes = ::bcs::to_bytes(&k).unwrap();
        let decoded: derived_object::DerivedObjectKey<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn authenticator_state_bcs_roundtrip() {
        let s = authenticator_state::AuthenticatorState {
            id: uid(),
            version: 1,
        };
        let bytes = ::bcs::to_bytes(&s).unwrap();
        let decoded: authenticator_state::AuthenticatorState = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn authenticator_state_inner_bcs_roundtrip() {
        let inner = authenticator_state::AuthenticatorStateInner {
            version: 1,
            active_jwks: vec![authenticator_state::ActiveJwk {
                jwk_id: authenticator_state::JwkId {
                    iss: MoveString::new(b"google".to_vec()),
                    kid: MoveString::new(b"kid".to_vec()),
                },
                jwk: authenticator_state::JWK {
                    kty: MoveString::new(b"RSA".to_vec()),
                    e: MoveString::new(b"AQAB".to_vec()),
                    n: MoveString::new(b"...".to_vec()),
                    alg: MoveString::new(b"RS256".to_vec()),
                },
                epoch: 1,
            }],
        };
        let bytes = ::bcs::to_bytes(&inner).unwrap();
        let decoded: authenticator_state::AuthenticatorStateInner =
            ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(inner, decoded);
    }

    #[test]
    fn display_bcs_roundtrip() {
        let d: display::Display<u64> =
            display::Display::new(uid(), vec_map::VecMap::default(), 1);
        let bytes = ::bcs::to_bytes(&d).unwrap();
        let decoded: display::Display<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(d, decoded);
    }

    #[test]
    fn package_publisher_bcs_roundtrip() {
        let p = package::Publisher {
            id: uid(),
            package: ascii::String::new(b"0x2".to_vec()),
            module_name: ascii::String::new(b"package".to_vec()),
        };
        let bytes = ::bcs::to_bytes(&p).unwrap();
        let decoded: package::Publisher = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn package_upgrade_cap_bcs_roundtrip() {
        let u = package::UpgradeCap {
            id: uid(),
            package: object::ID::new(oid()),
            version: 1,
            policy: 0,
        };
        let bytes = ::bcs::to_bytes(&u).unwrap();
        let decoded: package::UpgradeCap = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(u, decoded);
    }

    #[test]
    fn bls12381_scalar_bcs_roundtrip() {
        let s = bls12381::Scalar::default();
        let bytes = ::bcs::to_bytes(&s).unwrap();
        assert_eq!(bytes, [0u8]);
        let decoded: bls12381::Scalar = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn groth16_prepared_verifying_key_bcs_roundtrip() {
        let k = groth16::PreparedVerifyingKey {
            vk_gamma_abc_g1_bytes: vec![1],
            alpha_g1_beta_g2_bytes: vec![2],
            gamma_g2_neg_pc_bytes: vec![3],
            delta_g2_neg_pc_bytes: vec![4],
        };
        let bytes = ::bcs::to_bytes(&k).unwrap();
        let decoded: groth16::PreparedVerifyingKey = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn group_ops_element_bcs_roundtrip() {
        let e: group_ops::Element<u64> = group_ops::Element::new(vec![1, 2, 3]);
        let bytes = ::bcs::to_bytes(&e).unwrap();
        let decoded: group_ops::Element<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }

    #[test]
    fn authenticator_function_ref_v1_bcs_roundtrip() {
        let r: authenticator_function::AuthenticatorFunctionRefV1<u64> =
            authenticator_function::AuthenticatorFunctionRefV1::new(
                object::ID::new(oid()),
                ascii::String::new(b"m".to_vec()),
                ascii::String::new(b"f".to_vec()),
            );
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: authenticator_function::AuthenticatorFunctionRefV1<u64> =
            ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn account_authenticator_function_ref_v1_key_bcs_roundtrip() {
        let k = account::AuthenticatorFunctionRefV1Key::default();
        let bytes = ::bcs::to_bytes(&k).unwrap();
        assert_eq!(bytes, [0u8]);
        let decoded: account::AuthenticatorFunctionRefV1Key = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn coin_manager_event_bcs_roundtrip() {
        let e = coin_manager::CoinManaged {
            coin_name: ascii::String::new(b"0x2::iota::IOTA".to_vec()),
        };
        let bytes = ::bcs::to_bytes(&e).unwrap();
        let decoded: coin_manager::CoinManaged = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }

    // -------------------------------------------------------------
    // moverox-parity for round-4 modules (one test per type)
    // -------------------------------------------------------------

    use crate::generated as mx;
    use crate::parity_check::assert_parity;

    #[test]
    fn bcs_moverox_parity() {
        let sample = bcs::BCS::new(vec![1, 2, 3]);
        assert_parity::<_, mx::framework::bcs::BCS>(&sample);
    }

    #[test]
    fn clock_moverox_parity() {
        let sample = clock::Clock::new(uid(), 1_700_000_000_000);
        assert_parity::<_, mx::framework::clock::Clock>(&sample);
    }

    #[test]
    fn tx_context_moverox_parity() {
        let sample = tx_context::TxContext {
            sender: Address::new([0xab; 32]),
            tx_hash: vec![0; 32],
            epoch: 1,
            epoch_timestamp_ms: 1_700_000_000_000,
            ids_created: 0,
        };
        assert_parity::<_, mx::framework::tx_context::TxContext>(&sample);
    }

    #[test]
    fn intent_moverox_parity() {
        assert_parity::<_, mx::framework::intent::Intent>(&intent::Intent::new(1, 2, 3));
    }

    #[test]
    fn ecdsa_k1_keypair_moverox_parity() {
        let sample = ecdsa_k1::KeyPair {
            private_key: vec![1; 32],
            public_key: vec![2; 33],
        };
        assert_parity::<_, mx::framework::ecdsa_k1::KeyPair>(&sample);
    }

    #[test]
    fn zklogin_verified_id_moverox_parity() {
        let sample = zklogin_verified_id::VerifiedID {
            id: uid(),
            owner: Address::new([0; 32]),
            key_claim_name: MoveString::new(b"sub".to_vec()),
            key_claim_value: MoveString::new(b"123".to_vec()),
            issuer: MoveString::new(b"https://accounts.google.com".to_vec()),
            audience: MoveString::new(b"wallet".to_vec()),
        };
        assert_parity::<_, mx::framework::zklogin_verified_id::VerifiedID>(&sample);
    }

    #[test]
    fn zklogin_verified_issuer_moverox_parity() {
        let sample = zklogin_verified_issuer::VerifiedIssuer {
            id: uid(),
            owner: Address::new([0; 32]),
            issuer: MoveString::new(b"https://accounts.google.com".to_vec()),
        };
        assert_parity::<_, mx::framework::zklogin_verified_issuer::VerifiedIssuer>(&sample);
    }

    #[test]
    fn receiving_moverox_parity() {
        let sample: transfer::Receiving<u64> = transfer::Receiving::new(object::ID::new(oid()), 7);
        assert_parity::<_, mx::framework::transfer::Receiving<u64>>(&sample);
    }

    #[test]
    fn timelock_moverox_parity() {
        let sample: timelock::TimeLock<u64> =
            timelock::TimeLock::new(uid(), 42, 1_700_000_000_000, None);
        assert_parity::<_, mx::framework::timelock::TimeLock<u64>>(&sample);
    }

    #[test]
    fn borrow_referent_moverox_parity() {
        let sample: borrow::Referent<u64> = borrow::Referent::new(Address::new([0; 32]), Some(42));
        assert_parity::<_, mx::framework::borrow::Referent<u64>>(&sample);
    }

    #[test]
    fn borrow_borrow_moverox_parity() {
        let sample = borrow::Borrow {
            r#ref: Address::new([0; 32]),
            obj: object::ID::new(oid()),
        };
        assert_parity::<_, mx::framework::borrow::Borrow>(&sample);
    }

    #[test]
    fn borrow_test_moverox_parity() {
        let sample = borrow::Test { id: uid() };
        assert_parity::<_, mx::framework::borrow::Test>(&sample);
    }

    #[test]
    fn dynamic_field_field_moverox_parity() {
        let sample: dynamic_field::Field<u64, u64> = dynamic_field::Field::new(uid(), 1, 2);
        assert_parity::<_, mx::framework::dynamic_field::Field<u64, u64>>(&sample);
    }

    #[test]
    fn dynamic_object_field_wrapper_moverox_parity() {
        let sample: dynamic_object_field::Wrapper<u64> = dynamic_object_field::Wrapper::new(7);
        assert_parity::<_, mx::framework::dynamic_object_field::Wrapper<u64>>(&sample);
    }

    #[test]
    fn labeler_cap_moverox_parity() {
        let sample: labeler::LabelerCap<u64> = labeler::LabelerCap::new(uid());
        assert_parity::<_, mx::framework::labeler::LabelerCap<u64>>(&sample);
    }

    #[test]
    fn linked_table_moverox_parity() {
        let sample: linked_table::LinkedTable<u64, u64> =
            linked_table::LinkedTable::new(uid(), 2, Some(1), Some(2));
        assert_parity::<_, mx::framework::linked_table::LinkedTable<u64, u64>>(&sample);
    }

    #[test]
    fn linked_table_node_moverox_parity() {
        let sample: linked_table::Node<u64, u64> = linked_table::Node::new(None, Some(2), 1);
        assert_parity::<_, mx::framework::linked_table::Node<u64, u64>>(&sample);
    }

    #[test]
    fn object_table_moverox_parity() {
        let sample: object_table::ObjectTable<u64, u64> =
            object_table::ObjectTable::new(uid(), 3);
        assert_parity::<_, mx::framework::object_table::ObjectTable<u64, u64>>(&sample);
    }

    #[test]
    fn object_bag_moverox_parity() {
        let sample = object_bag::ObjectBag { id: uid(), size: 5 };
        assert_parity::<_, mx::framework::object_bag::ObjectBag>(&sample);
    }

    #[test]
    fn priority_queue_moverox_parity() {
        let sample: priority_queue::PriorityQueue<u64> = priority_queue::PriorityQueue::new(vec![
            priority_queue::Entry::new(10, 100),
            priority_queue::Entry::new(5, 50),
        ]);
        assert_parity::<_, mx::framework::priority_queue::PriorityQueue<u64>>(&sample);
    }

    #[test]
    fn derived_object_key_moverox_parity() {
        let sample: derived_object::DerivedObjectKey<u64> =
            derived_object::DerivedObjectKey::new(42);
        assert_parity::<_, mx::framework::derived_object::DerivedObjectKey<u64>>(&sample);
    }

    #[test]
    fn authenticator_state_moverox_parity() {
        let sample = authenticator_state::AuthenticatorState {
            id: uid(),
            version: 1,
        };
        assert_parity::<_, mx::framework::authenticator_state::AuthenticatorState>(&sample);
    }

    #[test]
    fn authenticator_state_inner_moverox_parity() {
        let sample = authenticator_state::AuthenticatorStateInner {
            version: 1,
            active_jwks: vec![authenticator_state::ActiveJwk {
                jwk_id: authenticator_state::JwkId {
                    iss: MoveString::new(b"google".to_vec()),
                    kid: MoveString::new(b"kid".to_vec()),
                },
                jwk: authenticator_state::JWK {
                    kty: MoveString::new(b"RSA".to_vec()),
                    e: MoveString::new(b"AQAB".to_vec()),
                    n: MoveString::new(b"...".to_vec()),
                    alg: MoveString::new(b"RS256".to_vec()),
                },
                epoch: 1,
            }],
        };
        assert_parity::<_, mx::framework::authenticator_state::AuthenticatorStateInner>(&sample);
    }

    #[test]
    fn display_moverox_parity() {
        let sample: display::Display<u64> =
            display::Display::new(uid(), vec_map::VecMap::default(), 1);
        assert_parity::<_, mx::framework::display::Display<u64>>(&sample);
    }

    #[test]
    fn package_publisher_moverox_parity() {
        let sample = package::Publisher {
            id: uid(),
            package: ascii::String::new(b"0x2".to_vec()),
            module_name: ascii::String::new(b"package".to_vec()),
        };
        assert_parity::<_, mx::framework::package::Publisher>(&sample);
    }

    #[test]
    fn package_upgrade_cap_moverox_parity() {
        let sample = package::UpgradeCap {
            id: uid(),
            package: object::ID::new(oid()),
            version: 1,
            policy: 0,
        };
        assert_parity::<_, mx::framework::package::UpgradeCap>(&sample);
    }

    #[test]
    fn package_upgrade_ticket_moverox_parity() {
        let sample = package::UpgradeTicket {
            cap: object::ID::new(oid()),
            package: object::ID::new(oid()),
            policy: 0,
            digest: vec![0xab; 32],
        };
        assert_parity::<_, mx::framework::package::UpgradeTicket>(&sample);
    }

    #[test]
    fn package_upgrade_receipt_moverox_parity() {
        let sample = package::UpgradeReceipt {
            cap: object::ID::new(oid()),
            package: object::ID::new(oid()),
        };
        assert_parity::<_, mx::framework::package::UpgradeReceipt>(&sample);
    }

    #[test]
    fn bls12381_markers_moverox_parity() {
        assert_parity::<_, mx::framework::bls12381::Scalar>(&bls12381::Scalar::default());
        assert_parity::<_, mx::framework::bls12381::G1>(&bls12381::G1::default());
        assert_parity::<_, mx::framework::bls12381::G2>(&bls12381::G2::default());
        assert_parity::<_, mx::framework::bls12381::GT>(&bls12381::GT::default());
        assert_parity::<_, mx::framework::bls12381::UncompressedG1>(
            &bls12381::UncompressedG1::default(),
        );
    }

    #[test]
    fn groth16_moverox_parity() {
        assert_parity::<_, mx::framework::groth16::Curve>(&groth16::Curve { id: 1 });
        assert_parity::<_, mx::framework::groth16::PreparedVerifyingKey>(
            &groth16::PreparedVerifyingKey {
                vk_gamma_abc_g1_bytes: vec![1],
                alpha_g1_beta_g2_bytes: vec![2],
                gamma_g2_neg_pc_bytes: vec![3],
                delta_g2_neg_pc_bytes: vec![4],
            },
        );
        assert_parity::<_, mx::framework::groth16::PublicProofInputs>(
            &groth16::PublicProofInputs { bytes: vec![1, 2, 3] },
        );
        assert_parity::<_, mx::framework::groth16::ProofPoints>(&groth16::ProofPoints {
            bytes: vec![4, 5, 6],
        });
    }

    #[test]
    fn group_ops_element_moverox_parity() {
        let sample: group_ops::Element<u64> = group_ops::Element::new(vec![1, 2, 3]);
        assert_parity::<_, mx::framework::group_ops::Element<u64>>(&sample);
    }

    #[test]
    fn authenticator_function_ref_v1_moverox_parity() {
        let sample: authenticator_function::AuthenticatorFunctionRefV1<u64> =
            authenticator_function::AuthenticatorFunctionRefV1::new(
                object::ID::new(oid()),
                ascii::String::new(b"m".to_vec()),
                ascii::String::new(b"f".to_vec()),
            );
        assert_parity::<
            _,
            mx::framework::authenticator_function::AuthenticatorFunctionRefV1<u64>,
        >(&sample);
    }

    #[test]
    fn account_authenticator_function_ref_v1_key_moverox_parity() {
        assert_parity::<_, mx::framework::account::AuthenticatorFunctionRefV1Key>(
            &account::AuthenticatorFunctionRefV1Key::default(),
        );
    }

    #[test]
    fn account_immutable_account_created_moverox_parity() {
        let sample = account::ImmutableAccountCreated::<u64> {
            account_id: object::ID::new(oid()),
            authenticator: authenticator_function::AuthenticatorFunctionRefV1::<u64>::new(
                object::ID::new(oid()),
                ascii::String::new(b"m".to_vec()),
                ascii::String::new(b"f".to_vec()),
            ),
        };
        assert_parity::<_, mx::framework::account::ImmutableAccountCreated<u64>>(&sample);
    }

    #[test]
    fn coin_manager_events_moverox_parity() {
        let coin_name = ascii::String::new(b"0x2::iota::IOTA".to_vec());
        assert_parity::<_, mx::framework::coin_manager::CoinManaged>(
            &coin_manager::CoinManaged {
                coin_name: coin_name.clone(),
            },
        );
        assert_parity::<_, mx::framework::coin_manager::TreasuryOwnershipRenounced>(
            &coin_manager::TreasuryOwnershipRenounced {
                coin_name: coin_name.clone(),
            },
        );
        assert_parity::<_, mx::framework::coin_manager::MetadataOwnershipRenounced>(
            &coin_manager::MetadataOwnershipRenounced { coin_name },
        );
    }

    #[test]
    fn coin_manager_moverox_parity() {
        let sample = coin_manager::CoinManager::<u64> {
            id: uid(),
            treasury_cap: coin::TreasuryCap::<u64>::new(uid(), balance::Supply::<u64>::new(0)),
            metadata: None,
            immutable_metadata: None,
            maximum_supply: Some(1_000_000),
            supply_immutable: false,
            metadata_immutable: false,
        };
        assert_parity::<_, mx::framework::coin_manager::CoinManager<u64>>(&sample);
    }

    #[test]
    fn coin_manager_caps_moverox_parity() {
        assert_parity::<_, mx::framework::coin_manager::CoinManagerTreasuryCap<u64>>(
            &coin_manager::CoinManagerTreasuryCap::<u64>::new(uid()),
        );
        assert_parity::<_, mx::framework::coin_manager::CoinManagerMetadataCap<u64>>(
            &coin_manager::CoinManagerMetadataCap::<u64>::new(uid()),
        );
    }

    #[test]
    fn coin_manager_immutable_coin_metadata_moverox_parity() {
        let sample = coin_manager::ImmutableCoinMetadata::<u64>::new(
            9,
            MoveString::new(b"X".to_vec()),
            ascii::String::new(b"X".to_vec()),
            MoveString::new(b"".to_vec()),
            Some(url::Url::new(ascii::String::new(b"https://x".to_vec()))),
        );
        assert_parity::<_, mx::framework::coin_manager::ImmutableCoinMetadata<u64>>(&sample);
    }
}

/// Types from `0x2::token`.
pub mod token {
    use core::marker::PhantomData;

    use iota_types::Address;

    use super::balance::Balance;
    use super::object::{ID, UID};
    use super::vec_map::VecMap;
    use super::vec_set::VecSet;
    use crate::std::string::String as MoveString;
    use crate::std::type_name::TypeName;

    /// Rust version of the Move `iota::token::Token<T>` type.
    ///
    /// A single `Token` with a `Balance` inside. Can only be owned by an
    /// address; actions on it must be confirmed in a matching `TokenPolicy`.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct TokenPolicy<T> {
        pub id: UID,
        /// Balance effectively spent on the `spend` action. Cannot be
        /// accessed by anyone but the `TreasuryCap` owner.
        pub spent_balance: Balance<T>,
        /// Rules that define what actions can be performed on the token,
        /// keyed by action name.
        pub rules: VecMap<MoveString, VecSet<TypeName>>,
    }

    impl<T> TokenPolicy<T> {
        pub const fn new(
            id: UID,
            spent_balance: Balance<T>,
            rules: VecMap<MoveString, VecSet<TypeName>>,
        ) -> Self {
            Self {
                id,
                spent_balance,
                rules,
            }
        }
    }

    /// Rust version of the Move `iota::token::ActionRequest<T>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ActionRequest<T> {
        /// Name of the action — one of `transfer`, `spend`, `to_coin`,
        /// `from_coin`, or a custom action.
        pub name: MoveString,
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
pub mod test_scenario {
    use iota_types::Address;

    use super::object::ID;
    use super::tx_context::TxContext;
    use super::vec_map::VecMap;

    /// Rust version of the Move `iota::test_scenario::Scenario` type.
    ///
    /// Mocks a multi-transaction IOTA execution in a single Move test
    /// procedure.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Scenario {
        pub txn_number: u64,
        pub ctx: TxContext,
    }

    /// Rust version of the Move `iota::test_scenario::TxContextBuilder` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    use super::object::{ID, UID};
    use super::vec_map::VecMap;
    use crate::std::ascii::String as AsciiString;
    use crate::std::type_name::TypeName;

    /// Rust version of the Move
    /// `iota::package_metadata::PackageMetadataKey` type.
    ///
    /// Key type for deriving the package metadata object address. Empty in
    /// Move; the Rust mirror carries a `dummy_field` for BCS shape.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct PackageMetadataKey {
        dummy_field: bool,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::PackageMetadataV1` type.
    ///
    /// Represents the metadata of a Move package, including storage ID,
    /// runtime ID, version, and per-module metadata.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PackageMetadataV1 {
        pub id: UID,
        /// Storage ID of the package represented by this metadata.
        pub storage_id: ID,
        /// Runtime ID of the package — the storage ID of the first version.
        pub runtime_id: ID,
        pub package_version: u64,
        pub modules_metadata: VecMap<AsciiString, ModuleMetadataV1>,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::ModuleMetadataV1` type.
    ///
    /// V1 includes only the authenticator function information.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ModuleMetadataV1 {
        pub authenticator_metadata: Vec<AuthenticatorMetadataV1>,
    }

    /// Rust version of the Move
    /// `iota::package_metadata::AuthenticatorMetadataV1` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct AuthenticatorMetadataV1 {
        pub function_name: AsciiString,
        pub account_type: TypeName,
    }
}

/// Types from `0x2::deny_list`.
pub mod deny_list {
    use iota_types::Address;

    use super::bag::Bag;
    use super::object::{ID, UID};

    /// Rust version of the Move `iota::deny_list::DenyList` type.
    ///
    /// Shared object storing addresses blocked for a given core type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct DenyList {
        pub id: UID,
        /// The individual deny lists.
        pub lists: Bag,
    }

    /// Rust version of the Move `iota::deny_list::ConfigWriteCap` type.
    ///
    /// Tuple newtype `(bool)` — preserves the BCS wire format.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ConfigWriteCap(bool);

    /// Rust version of the Move `iota::deny_list::ConfigKey` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct ConfigKey {
        pub per_type_index: u64,
        pub per_type_key: Vec<u8>,
    }

    /// Rust version of the Move `iota::deny_list::AddressKey` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct AddressKey(pub Address);

    /// Rust version of the Move `iota::deny_list::GlobalPauseKey` type.
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct GlobalPauseKey(bool);

    /// Rust version of the Move `iota::deny_list::PerTypeConfigCreated`
    /// event.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct PerTypeConfigCreated {
        pub key: ConfigKey,
        pub config_id: ID,
    }
}

/// Types from `0x2::random`.
pub mod random {
    use super::object::UID;
    use super::versioned::Versioned;

    /// Rust version of the Move `iota::random::Random` type.
    ///
    /// Singleton shared object storing the global randomness state. The
    /// actual state lives in a versioned inner field.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Random {
        pub id: UID,
        pub inner: Versioned,
    }

    /// Rust version of the Move `iota::random::RandomInner` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct RandomInner {
        pub version: u64,
        pub epoch: u64,
        pub randomness_round: u64,
        pub random_bytes: Vec<u8>,
    }

    /// Rust version of the Move `iota::random::RandomGenerator` type.
    ///
    /// Unique randomness generator derived from the global randomness.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Setting<Value> {
        pub data: Option<SettingData<Value>>,
    }

    impl<Value> Setting<Value> {
        pub const fn new(data: Option<SettingData<Value>>) -> Self {
            Self { data }
        }
    }

    /// Rust version of the Move `iota::config::SettingData<Value>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SettingData<Value> {
        pub newer_value_epoch: u64,
        pub newer_value: Option<Value>,
        pub older_value_opt: Option<Value>,
    }
}

/// Types from `0x2::ptb_command`.
pub mod ptb_command {
    use super::object::ID;
    use crate::std::ascii::String as AsciiString;
    use crate::std::type_name::TypeName;

    /// Rust version of the Move `iota::ptb_command::Argument` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum Argument {
        GasCoin,
        Input(u16),
        Result(u16),
        NestedResult(u16, u16),
    }

    /// Rust version of the Move
    /// `iota::ptb_command::ProgrammableMoveCall` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ProgrammableMoveCall {
        pub package: ID,
        pub module_name: AsciiString,
        pub function: AsciiString,
        pub type_arguments: Vec<TypeName>,
        pub arguments: Vec<Argument>,
    }

    /// Rust version of the Move
    /// `iota::ptb_command::TransferObjectsData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct TransferObjectsData {
        pub objects: Vec<Argument>,
        pub recipient: Argument,
    }

    /// Rust version of the Move `iota::ptb_command::SplitCoinsData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SplitCoinsData {
        pub coin: Argument,
        pub amounts: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::MergeCoinsData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct MergeCoinsData {
        pub target_coin: Argument,
        pub source_coins: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::PublishData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublishData {
        pub modules: Vec<Vec<u8>>,
        pub dependencies: Vec<ID>,
    }

    /// Rust version of the Move `iota::ptb_command::MakeMoveVecData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct MakeMoveVecData {
        pub type_arg: Option<TypeName>,
        pub elements: Vec<Argument>,
    }

    /// Rust version of the Move `iota::ptb_command::UpgradeData` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct UpgradeData {
        pub modules: Vec<Vec<u8>>,
        pub dependencies: Vec<ID>,
        pub package: ID,
        pub upgrade_ticket: Argument,
    }

    /// Rust version of the Move `iota::ptb_command::Command` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ObjectRef {
        pub object_id: ID,
        pub sequence_number: u64,
        pub object_digest: Vec<u8>,
    }

    /// Rust version of the Move `iota::ptb_call_arg::ObjectArg` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub enum CallArg {
        PureData(Vec<u8>),
        ObjectData(ObjectArg),
    }
}

/// Types from `0x2::ptb`.
pub mod ptb {
    use super::ptb_call_arg::CallArg;
    use super::ptb_command::Command;

    /// Rust version of the Move `iota::ptb::ProgrammableTransaction` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ProgrammableTransaction {
        pub inputs: Vec<CallArg>,
        pub commands: Vec<Command>,
    }
}

/// Types from `0x2::auth_context`.
pub mod auth_context {
    use super::ptb_call_arg::CallArg;
    use super::ptb_command::Command;

    /// Rust version of the Move `iota::auth_context::AuthContext` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct AuthContext {
        /// Digest of the `MoveAuthenticator`.
        pub auth_digest: Vec<u8>,
        /// Transaction input objects or primitive values.
        pub tx_inputs: Vec<CallArg>,
        /// Transaction commands to be executed sequentially.
        pub tx_commands: Vec<Command>,
    }
}

/// Types from `0x2::kiosk`.
pub mod kiosk {
    use core::marker::PhantomData;

    use iota_types::Address;

    use super::balance::Balance;
    use super::iota::IOTA;
    use super::object::{ID, UID};

    /// Rust version of the Move `iota::kiosk::Kiosk` type.
    ///
    /// An object which allows selling collectibles within the kiosk
    /// ecosystem.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Rust version of the Move `iota::kiosk::KioskOwnerCap` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct KioskOwnerCap {
        pub id: UID,
        pub r#for: ID,
    }

    /// Rust version of the Move `iota::kiosk::PurchaseCap<T>` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "kiosk-borrow")
    )]
    pub struct Borrow {
        pub kiosk_id: ID,
        pub item_id: ID,
    }

    /// Rust version of the Move `iota::kiosk::Item` type.
    ///
    /// Dynamic-field key for an item placed into the kiosk.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Item {
        pub id: ID,
    }

    /// Rust version of the Move `iota::kiosk::Listing` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Listing {
        pub id: ID,
        pub is_exclusive: bool,
    }

    /// Rust version of the Move `iota::kiosk::Lock` type.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
    pub struct Lock {
        pub id: ID,
    }

    /// Rust version of the Move `iota::kiosk::ItemListed<T>` event.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
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
    #[derive(Debug, Default, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct ExtensionKey<Ext> {
        dummy_field: bool,
        #[cfg_attr(feature = "serde", serde(skip))]
        _marker: PhantomData<Ext>,
    }
}

/// Types from `0x2::transfer_policy`.
pub mod transfer_policy {
    use core::marker::PhantomData;

    use super::balance::Balance;
    use super::iota::IOTA;
    use super::object::{ID, UID};
    use super::vec_set::VecSet;
    use crate::std::type_name::TypeName;

    /// Rust version of the Move
    /// `iota::transfer_policy::TransferRequest<T>` type.
    ///
    /// A hot potato forcing the buyer to get a transfer permission from
    /// the item type's owner on purchase.
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    #[derive(Debug, Clone, Eq, PartialEq)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

#[cfg(all(test, feature = "serde"))]
mod round5_tests {
    use iota_types::{Address, ObjectId};

    use super::*;
    use crate::std::ascii;
    use crate::std::string::String as MoveString;
    use crate::std::type_name::TypeName;

    fn oid() -> ObjectId {
        ObjectId::new([0xab; ObjectId::LENGTH])
    }

    fn uid() -> object::UID {
        object::UID::new(oid())
    }

    fn iid() -> object::ID {
        object::ID::new(oid())
    }

    #[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
    struct TestT;

    #[test]
    fn token_bcs_roundtrip() {
        let t: token::Token<TestT> =
            token::Token::new(uid(), balance::Balance::new(1_000));
        let bytes = ::bcs::to_bytes(&t).unwrap();
        let decoded: token::Token<TestT> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn token_policy_cap_bcs_roundtrip() {
        let c: token::TokenPolicyCap<TestT> = token::TokenPolicyCap::new(uid(), iid());
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: token::TokenPolicyCap<TestT> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn test_scenario_scenario_bcs_roundtrip() {
        let s = test_scenario::Scenario {
            txn_number: 0,
            ctx: tx_context::TxContext {
                sender: Address::new([0; 32]),
                tx_hash: vec![0; 32],
                epoch: 0,
                epoch_timestamp_ms: 0,
                ids_created: 0,
            },
        };
        let bytes = ::bcs::to_bytes(&s).unwrap();
        let decoded: test_scenario::Scenario = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn test_scenario_transaction_effects_bcs_roundtrip() {
        let e = test_scenario::TransactionEffects {
            created: vec![iid()],
            written: vec![],
            deleted: vec![],
            transferred_to_account: vec_map::VecMap::default(),
            transferred_to_object: vec_map::VecMap::default(),
            shared: vec![],
            frozen: vec![],
            num_user_events: 0,
        };
        let bytes = ::bcs::to_bytes(&e).unwrap();
        let decoded: test_scenario::TransactionEffects = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }

    #[test]
    fn package_metadata_authenticator_metadata_v1_bcs_roundtrip() {
        let m = package_metadata::AuthenticatorMetadataV1 {
            function_name: ascii::String::new(b"authenticate".to_vec()),
            account_type: TypeName::new(ascii::String::new(b"0x2::account::Account".to_vec())),
        };
        let bytes = ::bcs::to_bytes(&m).unwrap();
        let decoded: package_metadata::AuthenticatorMetadataV1 =
            ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn deny_list_bcs_roundtrip() {
        let d = deny_list::DenyList {
            id: uid(),
            lists: bag::Bag::new(uid(), 0),
        };
        let bytes = ::bcs::to_bytes(&d).unwrap();
        let decoded: deny_list::DenyList = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(d, decoded);
    }

    #[test]
    fn deny_list_address_key_bcs_roundtrip() {
        let k = deny_list::AddressKey(Address::new([0xab; 32]));
        let bytes = ::bcs::to_bytes(&k).unwrap();
        let decoded: deny_list::AddressKey = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn random_bcs_roundtrip() {
        let r = random::Random {
            id: uid(),
            inner: versioned::Versioned::new(uid(), 1),
        };
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: random::Random = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn random_inner_bcs_roundtrip() {
        let r = random::RandomInner {
            version: 1,
            epoch: 1,
            randomness_round: 1,
            random_bytes: vec![0; 32],
        };
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: random::RandomInner = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn config_bcs_roundtrip() {
        let c: config::Config<TestT> = config::Config::new(uid());
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: config::Config<TestT> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn setting_data_bcs_roundtrip() {
        let s: config::SettingData<u64> = config::SettingData {
            newer_value_epoch: 0,
            newer_value: Some(42),
            older_value_opt: None,
        };
        let bytes = ::bcs::to_bytes(&s).unwrap();
        let decoded: config::SettingData<u64> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn ptb_command_argument_bcs_roundtrip() {
        for a in [
            ptb_command::Argument::GasCoin,
            ptb_command::Argument::Input(7),
            ptb_command::Argument::Result(3),
            ptb_command::Argument::NestedResult(1, 2),
        ] {
            let bytes = ::bcs::to_bytes(&a).unwrap();
            let decoded: ptb_command::Argument = ::bcs::from_bytes(&bytes).unwrap();
            assert_eq!(a, decoded);
        }
    }

    #[test]
    fn ptb_command_command_bcs_roundtrip() {
        let c = ptb_command::Command::TransferObjects(ptb_command::TransferObjectsData {
            objects: vec![ptb_command::Argument::Input(0)],
            recipient: ptb_command::Argument::Input(1),
        });
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: ptb_command::Command = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn ptb_call_arg_object_arg_bcs_roundtrip() {
        let o = ptb_call_arg::ObjectArg::SharedObject {
            id: iid(),
            initial_shared_version: 1,
            mutable: true,
        };
        let bytes = ::bcs::to_bytes(&o).unwrap();
        let decoded: ptb_call_arg::ObjectArg = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(o, decoded);
    }

    #[test]
    fn ptb_programmable_transaction_bcs_roundtrip() {
        let p = ptb::ProgrammableTransaction {
            inputs: vec![ptb_call_arg::CallArg::PureData(vec![1, 2, 3])],
            commands: vec![ptb_command::Command::SplitCoins(
                ptb_command::SplitCoinsData {
                    coin: ptb_command::Argument::GasCoin,
                    amounts: vec![ptb_command::Argument::Input(0)],
                },
            )],
        };
        let bytes = ::bcs::to_bytes(&p).unwrap();
        let decoded: ptb::ProgrammableTransaction = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn auth_context_bcs_roundtrip() {
        let a = auth_context::AuthContext {
            auth_digest: vec![0; 32],
            tx_inputs: vec![],
            tx_commands: vec![],
        };
        let bytes = ::bcs::to_bytes(&a).unwrap();
        let decoded: auth_context::AuthContext = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn kiosk_bcs_roundtrip() {
        let k = kiosk::Kiosk {
            id: uid(),
            profits: balance::Balance::new(1_000),
            owner: Address::new([0; 32]),
            item_count: 5,
        };
        let bytes = ::bcs::to_bytes(&k).unwrap();
        let decoded: kiosk::Kiosk = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn kiosk_owner_cap_bcs_roundtrip() {
        let c = kiosk::KioskOwnerCap {
            id: uid(),
            r#for: iid(),
        };
        let bytes = ::bcs::to_bytes(&c).unwrap();
        let decoded: kiosk::KioskOwnerCap = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn kiosk_borrow_bcs_roundtrip() {
        let b = kiosk::Borrow {
            kiosk_id: iid(),
            item_id: iid(),
        };
        let bytes = ::bcs::to_bytes(&b).unwrap();
        let decoded: kiosk::Borrow = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(b, decoded);
    }

    #[test]
    fn kiosk_extension_bcs_roundtrip() {
        let e = kiosk_extension::Extension {
            storage: bag::Bag::new(uid(), 0),
            permissions: 0b11,
            is_enabled: true,
        };
        let bytes = ::bcs::to_bytes(&e).unwrap();
        let decoded: kiosk_extension::Extension = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(e, decoded);
    }

    #[test]
    fn transfer_policy_bcs_roundtrip() {
        let p: transfer_policy::TransferPolicy<TestT> = transfer_policy::TransferPolicy::new(
            uid(),
            balance::Balance::new(0),
            vec_set::VecSet::default(),
        );
        let bytes = ::bcs::to_bytes(&p).unwrap();
        let decoded: transfer_policy::TransferPolicy<TestT> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(p, decoded);
    }

    #[test]
    fn transfer_request_bcs_roundtrip() {
        let r: transfer_policy::TransferRequest<TestT> = transfer_policy::TransferRequest::new(
            iid(),
            1_000,
            iid(),
            vec_set::VecSet::new(vec![TypeName::new(ascii::String::new(b"X".to_vec()))]),
        );
        let _ = MoveString::new(b"unused".to_vec());
        let bytes = ::bcs::to_bytes(&r).unwrap();
        let decoded: transfer_policy::TransferRequest<TestT> = ::bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }

    // -------------------------------------------------------------
    // moverox-parity for round-5 modules (one test per type)
    // -------------------------------------------------------------

    use crate::generated as mx;
    use crate::parity_check::assert_parity;

    #[test]
    fn token_moverox_parity() {
        let sample: token::Token<u64> =
            token::Token::new(uid(), balance::Balance::<u64>::new(1_000));
        assert_parity::<_, mx::framework::token::Token<u64>>(&sample);
    }

    #[test]
    fn token_policy_cap_moverox_parity() {
        let sample: token::TokenPolicyCap<u64> = token::TokenPolicyCap::new(uid(), iid());
        assert_parity::<_, mx::framework::token::TokenPolicyCap<u64>>(&sample);
    }

    #[test]
    fn token_policy_moverox_parity() {
        let sample: token::TokenPolicy<u64> = token::TokenPolicy::new(
            uid(),
            balance::Balance::<u64>::new(0),
            vec_map::VecMap::default(),
        );
        assert_parity::<_, mx::framework::token::TokenPolicy<u64>>(&sample);
    }

    #[test]
    fn token_action_request_moverox_parity() {
        let sample = token::ActionRequest::<u64> {
            name: MoveString::new(b"transfer".to_vec()),
            amount: 1_000,
            sender: Address::new([0; 32]),
            recipient: Some(Address::new([1; 32])),
            spent_balance: None,
            approvals: vec_set::VecSet::default(),
        };
        assert_parity::<_, mx::framework::token::ActionRequest<u64>>(&sample);
    }

    #[test]
    fn token_rule_key_moverox_parity() {
        assert_parity::<_, mx::framework::token::RuleKey<u64>>(&token::RuleKey::<u64>::new(true));
    }

    #[test]
    fn token_policy_created_moverox_parity() {
        let sample = token::TokenPolicyCreated::<u64>::new(iid(), true);
        assert_parity::<_, mx::framework::token::TokenPolicyCreated<u64>>(&sample);
    }

    #[test]
    fn test_scenario_scenario_moverox_parity() {
        let sample = test_scenario::Scenario {
            txn_number: 0,
            ctx: tx_context::TxContext {
                sender: Address::new([0; 32]),
                tx_hash: vec![0; 32],
                epoch: 0,
                epoch_timestamp_ms: 0,
                ids_created: 0,
            },
        };
        assert_parity::<_, mx::framework::test_scenario::Scenario>(&sample);
    }

    #[test]
    fn test_scenario_transaction_effects_moverox_parity() {
        let sample = test_scenario::TransactionEffects {
            created: vec![iid()],
            written: vec![],
            deleted: vec![],
            transferred_to_account: vec_map::VecMap::default(),
            transferred_to_object: vec_map::VecMap::default(),
            shared: vec![],
            frozen: vec![],
            num_user_events: 0,
        };
        assert_parity::<_, mx::framework::test_scenario::TransactionEffects>(&sample);
    }

    #[test]
    fn package_metadata_authenticator_metadata_v1_moverox_parity() {
        let sample = package_metadata::AuthenticatorMetadataV1 {
            function_name: ascii::String::new(b"authenticate".to_vec()),
            account_type: TypeName::new(ascii::String::new(b"0x2::account::Account".to_vec())),
        };
        assert_parity::<_, mx::framework::package_metadata::AuthenticatorMetadataV1>(&sample);
    }

    #[test]
    fn package_metadata_v1_moverox_parity() {
        let sample = package_metadata::PackageMetadataV1 {
            id: uid(),
            storage_id: iid(),
            runtime_id: iid(),
            package_version: 1,
            modules_metadata: vec_map::VecMap::new(vec![vec_map::Entry::new(
                ascii::String::new(b"m".to_vec()),
                package_metadata::ModuleMetadataV1 {
                    authenticator_metadata: vec![package_metadata::AuthenticatorMetadataV1 {
                        function_name: ascii::String::new(b"authenticate".to_vec()),
                        account_type: TypeName::new(ascii::String::new(b"0x2::a::A".to_vec())),
                    }],
                },
            )]),
        };
        assert_parity::<_, mx::framework::package_metadata::PackageMetadataV1>(&sample);
    }

    #[test]
    fn deny_list_moverox_parity() {
        let sample = deny_list::DenyList {
            id: uid(),
            lists: bag::Bag::new(uid(), 0),
        };
        assert_parity::<_, mx::framework::deny_list::DenyList>(&sample);
    }

    #[test]
    fn deny_list_keys_moverox_parity() {
        assert_parity::<_, mx::framework::deny_list::ConfigWriteCap>(
            &deny_list::ConfigWriteCap::default(),
        );
        assert_parity::<_, mx::framework::deny_list::ConfigKey>(&deny_list::ConfigKey {
            per_type_index: 1,
            per_type_key: vec![1, 2, 3],
        });
        assert_parity::<_, mx::framework::deny_list::AddressKey>(&deny_list::AddressKey(
            Address::new([0xab; 32]),
        ));
        assert_parity::<_, mx::framework::deny_list::GlobalPauseKey>(
            &deny_list::GlobalPauseKey::default(),
        );
        assert_parity::<_, mx::framework::deny_list::PerTypeConfigCreated>(
            &deny_list::PerTypeConfigCreated {
                key: deny_list::ConfigKey {
                    per_type_index: 1,
                    per_type_key: vec![],
                },
                config_id: iid(),
            },
        );
    }

    #[test]
    fn random_moverox_parity() {
        let sample = random::Random {
            id: uid(),
            inner: versioned::Versioned::new(uid(), 1),
        };
        assert_parity::<_, mx::framework::random::Random>(&sample);
    }

    #[test]
    fn random_inner_moverox_parity() {
        let sample = random::RandomInner {
            version: 1,
            epoch: 1,
            randomness_round: 1,
            random_bytes: vec![0; 32],
        };
        assert_parity::<_, mx::framework::random::RandomInner>(&sample);
    }

    #[test]
    fn random_generator_moverox_parity() {
        let sample = random::RandomGenerator {
            seed: vec![0; 32],
            counter: 0,
            buffer: vec![],
        };
        assert_parity::<_, mx::framework::random::RandomGenerator>(&sample);
    }

    #[test]
    fn config_moverox_parity() {
        let sample: config::Config<u64> = config::Config::new(uid());
        assert_parity::<_, mx::framework::config::Config<u64>>(&sample);
    }

    #[test]
    fn setting_data_moverox_parity() {
        let sample: config::SettingData<u64> = config::SettingData {
            newer_value_epoch: 0,
            newer_value: Some(42),
            older_value_opt: None,
        };
        assert_parity::<_, mx::framework::config::SettingData<u64>>(&sample);
    }

    #[test]
    fn ptb_command_argument_moverox_parity() {
        use ptb_command::Argument as A;
        for sample in [A::GasCoin, A::Input(7), A::Result(3), A::NestedResult(1, 2)] {
            assert_parity::<_, mx::framework::ptb_command::Argument>(&sample);
        }
    }

    #[test]
    fn ptb_command_command_moverox_parity() {
        let cases: Vec<ptb_command::Command> = vec![
            ptb_command::Command::TransferObjects(ptb_command::TransferObjectsData {
                objects: vec![ptb_command::Argument::Input(0)],
                recipient: ptb_command::Argument::Input(1),
            }),
            ptb_command::Command::SplitCoins(ptb_command::SplitCoinsData {
                coin: ptb_command::Argument::GasCoin,
                amounts: vec![ptb_command::Argument::Input(0)],
            }),
            ptb_command::Command::MergeCoins(ptb_command::MergeCoinsData {
                target_coin: ptb_command::Argument::GasCoin,
                source_coins: vec![ptb_command::Argument::Input(0)],
            }),
            ptb_command::Command::Publish(ptb_command::PublishData {
                modules: vec![vec![1, 2, 3]],
                dependencies: vec![iid()],
            }),
            ptb_command::Command::MakeMoveVec(ptb_command::MakeMoveVecData {
                type_arg: None,
                elements: vec![],
            }),
            ptb_command::Command::Upgrade(ptb_command::UpgradeData {
                modules: vec![vec![1]],
                dependencies: vec![],
                package: iid(),
                upgrade_ticket: ptb_command::Argument::Input(0),
            }),
        ];
        for c in cases {
            assert_parity::<_, mx::framework::ptb_command::Command>(&c);
        }
    }

    #[test]
    fn ptb_call_arg_variants_moverox_parity() {
        let cases: Vec<ptb_call_arg::CallArg> = vec![
            ptb_call_arg::CallArg::PureData(vec![1, 2, 3]),
            ptb_call_arg::CallArg::ObjectData(ptb_call_arg::ObjectArg::ImmOrOwnedObject(
                ptb_call_arg::ObjectRef {
                    object_id: iid(),
                    sequence_number: 1,
                    object_digest: vec![0; 32],
                },
            )),
            ptb_call_arg::CallArg::ObjectData(ptb_call_arg::ObjectArg::SharedObject {
                id: iid(),
                initial_shared_version: 7,
                mutable: true,
            }),
            ptb_call_arg::CallArg::ObjectData(ptb_call_arg::ObjectArg::ReceivingObject(
                ptb_call_arg::ObjectRef {
                    object_id: iid(),
                    sequence_number: 2,
                    object_digest: vec![1; 32],
                },
            )),
        ];
        for c in cases {
            assert_parity::<_, mx::framework::ptb_call_arg::CallArg>(&c);
        }
    }

    #[test]
    fn ptb_programmable_transaction_moverox_parity() {
        let sample = ptb::ProgrammableTransaction {
            inputs: vec![ptb_call_arg::CallArg::PureData(vec![1])],
            commands: vec![ptb_command::Command::SplitCoins(
                ptb_command::SplitCoinsData {
                    coin: ptb_command::Argument::GasCoin,
                    amounts: vec![ptb_command::Argument::Input(0)],
                },
            )],
        };
        assert_parity::<_, mx::framework::ptb::ProgrammableTransaction>(&sample);
    }

    #[test]
    fn auth_context_moverox_parity() {
        let sample = auth_context::AuthContext {
            auth_digest: vec![0; 32],
            tx_inputs: vec![],
            tx_commands: vec![],
        };
        assert_parity::<_, mx::framework::auth_context::AuthContext>(&sample);
    }

    #[test]
    fn kiosk_moverox_parity() {
        let sample = kiosk::Kiosk {
            id: uid(),
            profits: balance::Balance::new(1_000),
            owner: Address::new([0; 32]),
            item_count: 5,
        };
        assert_parity::<_, mx::framework::kiosk::Kiosk>(&sample);
    }

    #[test]
    fn kiosk_owner_cap_moverox_parity() {
        let sample = kiosk::KioskOwnerCap {
            id: uid(),
            r#for: iid(),
        };
        assert_parity::<_, mx::framework::kiosk::KioskOwnerCap>(&sample);
    }

    #[test]
    fn kiosk_purchase_cap_moverox_parity() {
        let sample = kiosk::PurchaseCap::<u64>::new(uid(), iid(), iid(), 100);
        assert_parity::<_, mx::framework::kiosk::PurchaseCap<u64>>(&sample);
    }

    #[test]
    fn kiosk_records_moverox_parity() {
        assert_parity::<_, mx::framework::kiosk::Borrow>(&kiosk::Borrow {
            kiosk_id: iid(),
            item_id: iid(),
        });
        assert_parity::<_, mx::framework::kiosk::Item>(&kiosk::Item { id: iid() });
        assert_parity::<_, mx::framework::kiosk::Listing>(&kiosk::Listing {
            id: iid(),
            is_exclusive: false,
        });
        assert_parity::<_, mx::framework::kiosk::Lock>(&kiosk::Lock { id: iid() });
    }

    #[test]
    fn kiosk_item_events_moverox_parity() {
        assert_parity::<_, mx::framework::kiosk::ItemListed<u64>>(
            &kiosk::ItemListed::<u64>::new(iid(), iid(), 1_000),
        );
        assert_parity::<_, mx::framework::kiosk::ItemPurchased<u64>>(
            &kiosk::ItemPurchased::<u64>::new(iid(), iid(), 1_000),
        );
        assert_parity::<_, mx::framework::kiosk::ItemDelisted<u64>>(
            &kiosk::ItemDelisted::<u64>::new(iid(), iid()),
        );
    }

    #[test]
    fn kiosk_extension_moverox_parity() {
        let sample = kiosk_extension::Extension {
            storage: bag::Bag::new(uid(), 0),
            permissions: 0b11,
            is_enabled: true,
        };
        assert_parity::<_, mx::framework::kiosk_extension::Extension>(&sample);
    }

    #[test]
    fn kiosk_extension_key_moverox_parity() {
        assert_parity::<_, mx::framework::kiosk_extension::ExtensionKey<u64>>(
            &kiosk_extension::ExtensionKey::<u64>::default(),
        );
    }

    #[test]
    fn transfer_policy_moverox_parity() {
        let sample = transfer_policy::TransferPolicy::<u64>::new(
            uid(),
            balance::Balance::<iota::IOTA>::new(0),
            vec_set::VecSet::default(),
        );
        assert_parity::<_, mx::framework::transfer_policy::TransferPolicy<u64>>(&sample);
    }

    #[test]
    fn transfer_request_moverox_parity() {
        let sample = transfer_policy::TransferRequest::<u64>::new(
            iid(),
            1_000,
            iid(),
            vec_set::VecSet::default(),
        );
        assert_parity::<_, mx::framework::transfer_policy::TransferRequest<u64>>(&sample);
    }

    #[test]
    fn transfer_policy_cap_moverox_parity() {
        let sample = transfer_policy::TransferPolicyCap::<u64>::new(uid(), iid());
        assert_parity::<_, mx::framework::transfer_policy::TransferPolicyCap<u64>>(&sample);
    }

    #[test]
    fn transfer_policy_events_moverox_parity() {
        assert_parity::<_, mx::framework::transfer_policy::TransferPolicyCreated<u64>>(
            &transfer_policy::TransferPolicyCreated::<u64>::new(iid()),
        );
        assert_parity::<_, mx::framework::transfer_policy::TransferPolicyDestroyed<u64>>(
            &transfer_policy::TransferPolicyDestroyed::<u64>::new(iid()),
        );
        assert_parity::<_, mx::framework::transfer_policy::RuleKey<u64>>(
            &transfer_policy::RuleKey::<u64>::new(),
        );
    }
}
