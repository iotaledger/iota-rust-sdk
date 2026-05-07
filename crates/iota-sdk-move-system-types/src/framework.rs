// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Types from the IOTA framework (system package `0x2`).

use core::fmt;

use iota_types::ObjectId;

// ------------------------------------------------------------------
// iota::bag
// ------------------------------------------------------------------

/// Rust version of the Move iota::bag::Bag type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Bag {
    pub id: UID,
    pub size: u64,
}

impl Default for Bag {
    fn default() -> Self {
        Self {
            id: UID::new(ObjectId::ZERO),
            size: 0,
        }
    }
}

// ------------------------------------------------------------------
// iota::balance
// ------------------------------------------------------------------

/// Rust version of the Move `iota::balance::Balance<T>` type.
///
/// The Move type is generic over the coin marker `T`; on the wire it is a
/// single `u64`, so this Rust type does not carry the type parameter.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Balance {
    value: u64,
}

impl Balance {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

/// Rust version of the Move `iota::balance::Supply<T>` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Supply {
    pub value: u64,
}

#[cfg(all(test, feature = "serde"))]
mod iota_balance_tests {
    use super::*;

    #[test]
    fn balance_bcs_roundtrip() {
        let balance = Balance::new(0xdead_beef_u64);
        let bytes = bcs::to_bytes(&balance).unwrap();
        // Single u64 field — wire format is a little-endian u64.
        assert_eq!(bytes, 0xdead_beef_u64.to_le_bytes());
        let decoded: Balance = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(balance, decoded);
    }

    #[test]
    fn supply_bcs_roundtrip() {
        let supply = Supply { value: 1_000_000 };
        let bytes = bcs::to_bytes(&supply).unwrap();
        let decoded: Supply = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(supply, decoded);
    }
}

// ------------------------------------------------------------------
// iota::coin
// ------------------------------------------------------------------

/// Rust version of the Move `iota::coin::Coin<T>` type.
///
/// The Move type is generic over the coin marker `T`; on the wire only the
/// `id` and `balance` fields are encoded, so the Rust mirror is non-generic.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Coin {
    pub id: UID,
    pub balance: Balance,
}

impl Coin {
    pub fn new(id: ObjectId, value: u64) -> Self {
        Self {
            id: UID::new(id),
            balance: Balance::new(value),
        }
    }

    pub fn id(&self) -> &ObjectId {
        self.id.object_id()
    }

    pub fn value(&self) -> u64 {
        self.balance.value()
    }
}

/// Rust version of the Move `iota::coin::TreasuryCap<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TreasuryCap {
    pub id: UID,
    pub total_supply: Supply,
}

/// Rust version of the Move `iota::coin::CoinMetadata<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CoinMetadata {
    pub id: UID,
    /// Number of decimal places the coin uses.
    pub decimals: u8,
    /// Name for the token.
    pub name: String,
    /// Symbol for the token.
    pub symbol: String,
    /// Description of the token.
    pub description: String,
    /// URL for the token logo.
    pub icon_url: Option<String>,
}

#[cfg(all(test, feature = "serde"))]
mod iota_coin_tests {
    use super::*;

    fn sample_object_id() -> ObjectId {
        ObjectId::new([0xab; ObjectId::LENGTH])
    }

    #[test]
    fn coin_bcs_roundtrip() {
        let coin = Coin::new(sample_object_id(), 1_000_000);
        let bytes = bcs::to_bytes(&coin).unwrap();
        let decoded: Coin = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(coin, decoded);
    }

    #[test]
    fn treasury_cap_bcs_roundtrip() {
        let cap = TreasuryCap {
            id: UID::new(sample_object_id()),
            total_supply: Supply { value: 1_000 },
        };
        let bytes = bcs::to_bytes(&cap).unwrap();
        let decoded: TreasuryCap = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cap, decoded);
    }

    #[test]
    fn coin_metadata_bcs_roundtrip() {
        let meta = CoinMetadata {
            id: UID::new(sample_object_id()),
            decimals: 9,
            name: "IOTA".to_owned(),
            symbol: "IOTA".to_owned(),
            description: "test".to_owned(),
            icon_url: Some("https://iota.org/logo.png".to_owned()),
        };
        let bytes = bcs::to_bytes(&meta).unwrap();
        let decoded: CoinMetadata = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(meta, decoded);
    }
}

// ------------------------------------------------------------------
// iota::display
// ------------------------------------------------------------------

/// Rust version of the Move `iota::display::Display<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Display {
    pub id: UID,
    pub fields: VecMap<String, String>,
    pub version: u16,
}

#[cfg(all(test, feature = "serde"))]
mod iota_display_tests {
    use super::*;

    #[test]
    fn display_bcs_roundtrip() {
        let display = Display {
            id: UID::new(ObjectId::ZERO),
            fields: VecMap {
                contents: vec![Entry {
                    key: "name".to_owned(),
                    value: "IOTA".to_owned(),
                }],
            },
            version: 1,
        };
        let bytes = bcs::to_bytes(&display).unwrap();
        let decoded: Display = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(display, decoded);
    }
}

// ------------------------------------------------------------------
// iota::dynamic_field
// ------------------------------------------------------------------

/// Rust version of the Move `iota::dynamic_field::Field<N, V>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Field<N, V> {
    pub id: UID,
    pub name: N,
    pub value: V,
}

#[cfg(all(test, feature = "serde"))]
mod iota_dynamic_field_tests {
    use super::*;

    #[test]
    fn field_bcs_roundtrip() {
        let field: Field<u64, String> = Field {
            id: UID::new(ObjectId::ZERO),
            name: 42,
            value: "hi".to_owned(),
        };
        let bytes = bcs::to_bytes(&field).unwrap();
        let decoded: Field<u64, String> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(field, decoded);
    }
}

// ------------------------------------------------------------------
// iota::dynamic_object_field
// ------------------------------------------------------------------

/// Rust version of the Move `iota::dynamic_object_field::Wrapper<N>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Wrapper<N> {
    pub name: N,
}

#[cfg(all(test, feature = "serde"))]
mod iota_dynamic_object_field_tests {
    use super::*;

    #[test]
    fn wrapper_bcs_roundtrip() {
        let wrapper: Wrapper<u64> = Wrapper { name: 7 };
        let bytes = bcs::to_bytes(&wrapper).unwrap();
        // Single-field struct: wire format is just the field.
        assert_eq!(bytes, bcs::to_bytes(&7u64).unwrap());
        let decoded: Wrapper<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(wrapper, decoded);
    }
}

// ------------------------------------------------------------------
// iota::iota
// ------------------------------------------------------------------

/// Rust version of the Move `iota::iota::IotaTreasuryCap` type.
///
/// The non-generic IOTA treasury cap. It wraps a [`TreasuryCap`] for the
/// canonical IOTA coin marker `T = 0x2::iota::IOTA`.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IotaTreasuryCap {
    pub inner: TreasuryCap,
}

#[cfg(all(test, feature = "serde"))]
mod iota_iota_tests {
    use super::*;

    #[test]
    fn iota_treasury_cap_bcs_roundtrip() {
        let cap = IotaTreasuryCap {
            inner: TreasuryCap {
                id: UID::new(ObjectId::ZERO),
                total_supply: Supply { value: 0 },
            },
        };
        let bytes = bcs::to_bytes(&cap).unwrap();
        let decoded: IotaTreasuryCap = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cap, decoded);
    }
}

// ------------------------------------------------------------------
// iota::linked_table
// ------------------------------------------------------------------

/// Rust version of the Move `iota::linked_table::LinkedTable<K>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LinkedTable<K> {
    pub id: UID,
    pub size: u64,
    pub head: Option<K>,
    pub tail: Option<K>,
}

impl<K> Default for LinkedTable<K> {
    fn default() -> Self {
        Self {
            id: UID::new(ObjectId::ZERO),
            size: 0,
            head: None,
            tail: None,
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

#[cfg(all(test, feature = "serde"))]
mod iota_linked_table_tests {
    use super::*;

    #[test]
    fn linked_table_bcs_roundtrip() {
        let table: LinkedTable<u64> = LinkedTable::default();
        let bytes = bcs::to_bytes(&table).unwrap();
        let decoded: LinkedTable<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(table, decoded);
    }

    #[test]
    fn node_bcs_roundtrip() {
        let node: Node<u64, String> = Node {
            prev: Some(1),
            next: Some(3),
            value: "two".to_owned(),
        };
        let bytes = bcs::to_bytes(&node).unwrap();
        let decoded: Node<u64, String> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(node, decoded);
    }
}

// ------------------------------------------------------------------
// iota::object
// ------------------------------------------------------------------

/// Rust version of the Move `iota::object::UID` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

/// Rust version of the Move `iota::object::ID` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
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

#[cfg(all(test, feature = "serde"))]
mod iota_object_tests {
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
        // UID is a single-field struct wrapping an ID, which is transparent
        // over ObjectId, so the wire format is exactly an ObjectId.
        assert_eq!(bytes, bcs::to_bytes(&sample_object_id()).unwrap());
        let decoded: UID = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(uid, decoded);
    }
}

// ------------------------------------------------------------------
// iota::system_admin_cap
// ------------------------------------------------------------------

/// Rust version of the Move `iota::system_admin_cap::IotaSystemAdminCap` type.
///
/// The Move type is empty; Move bytecode requires at least one field, so the
/// struct contains a 1-byte dummy bool that is always `false`.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IotaSystemAdminCap {
    dummy_field: bool,
}

#[cfg(all(test, feature = "serde"))]
mod iota_system_admin_cap_tests {
    use super::*;

    #[test]
    fn iota_system_admin_cap_bcs_roundtrip() {
        let cap = IotaSystemAdminCap::default();
        let bytes = bcs::to_bytes(&cap).unwrap();
        // Single bool field: 1 byte on the wire.
        assert_eq!(bytes, [0u8]);
        let decoded: IotaSystemAdminCap = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(cap, decoded);
    }
}

// ------------------------------------------------------------------
// iota::table
// ------------------------------------------------------------------

/// Rust version of the Move `iota::table::Table<K, V>` type.
///
/// The Move type carries phantom `K, V` parameters; only `id` and `size`
/// are encoded on the wire, so this Rust type drops them.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Table {
    pub id: UID,
    pub size: u64,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            id: UID::new(ObjectId::ZERO),
            size: 0,
        }
    }
}

/// Rust version of the Move `iota::table_vec::TableVec<T>` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TableVec {
    pub contents: Table,
}

#[cfg(all(test, feature = "serde"))]
mod iota_table_tests {
    use super::*;

    #[test]
    fn table_bcs_roundtrip() {
        let table = Table::default();
        let bytes = bcs::to_bytes(&table).unwrap();
        let decoded: Table = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(table, decoded);
    }

    #[test]
    fn table_vec_bcs_roundtrip() {
        let tvec = TableVec::default();
        let bytes = bcs::to_bytes(&tvec).unwrap();
        let decoded: TableVec = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tvec, decoded);
    }
}

// ------------------------------------------------------------------
// iota::timelock
// ------------------------------------------------------------------

/// Rust version of the Move `iota::timelock::TimeLock<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TimeLock<T> {
    pub id: UID,
    /// The locked object.
    pub locked: T,
    /// Epoch timestamp (ms) of when the lock expires.
    pub expiration_timestamp_ms: u64,
    /// Optional timelock-related label.
    pub label: Option<String>,
}

impl<T> TimeLock<T> {
    pub fn new(
        id: ObjectId,
        locked: T,
        expiration_timestamp_ms: u64,
        label: Option<String>,
    ) -> Self {
        Self {
            id: UID::new(id),
            locked,
            expiration_timestamp_ms,
            label,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod iota_timelock_tests {
    use super::*;

    #[test]
    fn timelock_bcs_roundtrip() {
        let tl: TimeLock<Balance> = TimeLock::new(
            ObjectId::ZERO,
            Balance::new(1_000_000),
            1_700_000_000_000,
            Some("vested".to_owned()),
        );
        let bytes = bcs::to_bytes(&tl).unwrap();
        let decoded: TimeLock<Balance> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tl, decoded);
    }

    #[test]
    fn timelock_no_label_bcs_roundtrip() {
        let tl: TimeLock<u64> = TimeLock::new(ObjectId::ZERO, 42, 0, None);
        let bytes = bcs::to_bytes(&tl).unwrap();
        let decoded: TimeLock<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tl, decoded);
    }
}

// ------------------------------------------------------------------
// iota::transfer
// ------------------------------------------------------------------

/// Rust version of the Move `iota::transfer::Receiving<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receiving {
    pub id: ID,
    pub version: u64,
}

impl Receiving {
    pub fn new(id: ObjectId, version: u64) -> Self {
        Self {
            id: ID::new(id),
            version,
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod iota_transfer_tests {
    use super::*;

    #[test]
    fn receiving_bcs_roundtrip() {
        let r = Receiving::new(ObjectId::new([0xcd; ObjectId::LENGTH]), 7);
        let bytes = bcs::to_bytes(&r).unwrap();
        let decoded: Receiving = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(r, decoded);
    }
}

// ------------------------------------------------------------------
// iota::url
// ------------------------------------------------------------------

/// Rust version of the Move `iota::url::Url` type.
///
/// # SAFETY
///
/// The Move `Url` is ASCII-encoded. This Rust type stores the URL as a
/// `String` (UTF-8) but the constructors enforce that the contents are valid
/// ASCII so the on-the-wire BCS bytes match.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Url {
    url: String,
}

impl Url {
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TryFrom<String> for Url {
    type Error = NonAsciiUrl;

    fn try_from(url: String) -> Result<Self, Self::Error> {
        if !url.is_ascii() {
            return Err(NonAsciiUrl);
        }
        Ok(Self { url })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonAsciiUrl;

impl fmt::Display for NonAsciiUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("url is not valid ASCII")
    }
}

impl core::error::Error for NonAsciiUrl {}

#[cfg(all(test, feature = "serde"))]
mod iota_url_tests {
    use super::*;

    #[test]
    fn url_bcs_roundtrip() {
        let url = Url::try_from("https://iota.org/".to_owned()).unwrap();
        let bytes = bcs::to_bytes(&url).unwrap();
        // Wire format: BCS-encoded `String` (a length-prefixed byte sequence).
        assert_eq!(
            bytes,
            bcs::to_bytes(&"https://iota.org/".to_owned()).unwrap()
        );
        let decoded: Url = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(url, decoded);
    }

    #[test]
    fn url_rejects_non_ascii() {
        assert!(Url::try_from("héllo".to_owned()).is_err());
    }
}

// ------------------------------------------------------------------
// iota::vec_map
// ------------------------------------------------------------------

/// Rust version of the Move `iota::vec_map::VecMap<K, V>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VecMap<K, V> {
    pub contents: Vec<Entry<K, V>>,
}

impl<K, V> Default for VecMap<K, V> {
    fn default() -> Self {
        Self {
            contents: Vec::new(),
        }
    }
}

/// Rust version of the Move `iota::vec_map::Entry<K, V>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Entry<K, V> {
    pub key: K,
    pub value: V,
}

#[cfg(all(test, feature = "serde"))]
mod iota_vec_map_tests {
    use super::*;

    #[test]
    fn vec_map_bcs_roundtrip() {
        let m: VecMap<String, u64> = VecMap {
            contents: vec![
                Entry {
                    key: "a".to_owned(),
                    value: 1,
                },
                Entry {
                    key: "b".to_owned(),
                    value: 2,
                },
            ],
        };
        let bytes = bcs::to_bytes(&m).unwrap();
        let decoded: VecMap<String, u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(m, decoded);
    }
}

// ------------------------------------------------------------------
// iota::vec_set
// ------------------------------------------------------------------

/// Rust version of the Move `iota::vec_set::VecSet<T>` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VecSet<T> {
    pub contents: Vec<T>,
}

impl<T> Default for VecSet<T> {
    fn default() -> Self {
        Self {
            contents: Vec::new(),
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod iota_vec_set_tests {
    use super::*;

    #[test]
    fn vec_set_bcs_roundtrip() {
        let s: VecSet<u64> = VecSet {
            contents: vec![1, 2, 3],
        };
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: VecSet<u64> = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }
}

// ------------------------------------------------------------------
// iota::versioned
// ------------------------------------------------------------------

/// Rust version of the Move `iota::versioned::Versioned` type.
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Versioned {
    pub id: UID,
    pub version: u64,
}

#[cfg(all(test, feature = "serde"))]
mod iota_versioned_tests {
    use super::*;

    #[test]
    fn versioned_bcs_roundtrip() {
        let v = Versioned {
            id: UID::new(ObjectId::ZERO),
            version: 7,
        };
        let bytes = bcs::to_bytes(&v).unwrap();
        let decoded: Versioned = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }
}
