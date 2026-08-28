// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use crate::{
    error::Result,
    types::{
        address::Address,
        digest::{ObjectDigest, TransactionDigest},
        move_core::{Identifier, StructTag, TypeTag},
        version::Version,
    },
};

/// An `ObjectId` is a 32-byte identifier used to uniquely identify an object on
/// the IOTA blockchain.
///
/// ## Relationship to Address
///
/// `Address`es and `ObjectId`s share the same 32-byte addressable space but
/// are derived leveraging different domain-separator values to ensure,
/// cryptographically, that there won't be any overlap, e.g. there can't be a
/// valid `Object` whose `ObjectId` is equal to that of the `Address` of a user
/// account.
///
/// # BCS
///
/// An `ObjectId`'s BCS serialized form is defined by the following:
///
/// ```text
/// object-id = address
/// ```
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    PartialEq,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct ObjectId(pub iota_sdk::types::ObjectId);

#[uniffi::export]
impl ObjectId {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from(
            iota_sdk::types::Address::from_bytes(bytes)?,
        )))
    }

    /// Parses an ObjectId from a full-length hex string (64 hex characters),
    /// with or without a `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from_hex(hex)?))
    }

    /// Parses an ObjectId from a full-length hex string (64 hex characters),
    /// with a mandatory `0x` prefix. Will return an error if the string is not
    /// exactly 64 hex characters long (excluding the `0x` prefix).
    #[uniffi::constructor]
    pub fn from_prefixed_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from_prefixed_hex(hex)?))
    }

    /// Parses an ObjectId from a hex string, with or without a `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    #[uniffi::constructor]
    pub fn from_short_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from_short_hex(hex)?))
    }

    /// Parses an ObjectId from a hex string with a mandatory `0x` prefix.
    /// The string can be of variable length; if it's shorter than 64 hex
    /// characters, it will be left-padded with `0`s.
    #[uniffi::constructor]
    pub fn from_prefixed_short_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from_prefixed_short_hex(
            hex,
        )?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    /// Create an ObjectId from a transaction digest and the number of objects
    /// that have been created during a transactions.
    #[uniffi::constructor]
    pub fn derive_id(digest: &TransactionDigest, count: u64) -> Self {
        Self(iota_sdk::types::ObjectId::derive_id(**digest, count))
    }

    /// Derive an ObjectId for a Dynamic Child Object.
    ///
    /// hash(parent || len(key) || key || key_type_tag)
    pub fn derive_dynamic_child_id(&self, key_type_tag: &TypeTag, key_bytes: &[u8]) -> Self {
        self.0
            .derive_dynamic_child_id(&key_type_tag.0, key_bytes)
            .into()
    }

    /// Derive the ObjectId of a derived object (`0x2::derived_object`).
    ///
    /// hash(parent || len(key) || key || DerivedObjectKey(key_type_tag))
    pub fn derive_object_id(&self, key_type_tag: &TypeTag, key_bytes: &[u8]) -> Self {
        self.0.derive_object_id(&key_type_tag.0, key_bytes).into()
    }

    /// Returns the string representation of this object ID using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }

    /// Returns the string representation of this object id in hex format with
    /// `0x` prefix.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Returns the string representation of this object id in hex format
    /// without `0x` prefix.
    pub fn to_raw_hex(&self) -> String {
        self.0.to_raw_hex()
    }

    /// Returns the shortest possible string representation of the object ID
    /// (i.e. with leading zeroes trimmed).
    pub fn to_short_hex(&self) -> String {
        self.0.to_short_hex()
    }

    /// Returns the shortest possible string representation of the object id
    /// (i.e. with leading zeroes trimmed), without `0x` prefix.
    pub fn to_raw_short_hex(&self) -> String {
        self.0.to_raw_short_hex()
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        Self(self.0.next_lexicographical())
    }

    /// Returns the next digest in byte-increasing order, or `None` if the
    /// result would overflow.
    pub fn next_lexicographical_opt(&self) -> Option<Arc<Self>> {
        self.0.next_lexicographical_opt().map(Self).map(Arc::new)
    }
}

macro_rules! named_object_id {
    ($($constant:ident),+ $(,)?) => {
        paste::paste! {
            #[uniffi::export]
            impl ObjectId {$(
                #[uniffi::constructor]
                pub const fn [< $constant:lower >]() -> Self {
                    Self(iota_sdk::types::ObjectId::$constant)
                }
            )+}
        }
    }
}

named_object_id!(
    ZERO,
    MAX,
    STD,
    FRAMEWORK,
    SYSTEM,
    GENESIS_BRIDGE,
    STARDUST,
    SYSTEM_STATE,
    CLOCK,
    AUTHENTICATOR_STATE,
    RANDOMNESS_STATE,
    GENESIS_IOTA_BRIDGE,
    DENY_LIST,
    TRANSACTION_DENY_RULES
);

/// Reference to an object
///
/// Contains sufficient information to uniquely identify a specific object.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-reference = object-id u64 digest
/// ```
#[derive(Clone, uniffi::Record)]
pub struct ObjectReference {
    object_id: Arc<ObjectId>,
    version: Arc<Version>,
    digest: Arc<ObjectDigest>,
}

impl From<iota_sdk::types::ObjectReference> for ObjectReference {
    fn from(value: iota_sdk::types::ObjectReference) -> Self {
        Self {
            object_id: Arc::new((*value.object_id()).into()),
            version: Arc::new(value.version().into()),
            digest: Arc::new((*value.digest()).into()),
        }
    }
}

impl From<ObjectReference> for iota_sdk::types::ObjectReference {
    fn from(value: ObjectReference) -> Self {
        Self::new(**value.object_id, **value.version, **value.digest)
    }
}

/// An object on the IOTA blockchain
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object = object-data owner digest u64
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct Object(pub iota_sdk::types::Object);

#[uniffi::export]
impl Object {
    #[uniffi::constructor]
    pub fn new(
        data: &ObjectData,
        owner: &Owner,
        previous_transaction: &TransactionDigest,
        storage_rebate: u64,
    ) -> Self {
        Self(iota_sdk::types::Object::new(
            data.0.clone(),
            **owner,
            **previous_transaction,
            storage_rebate,
        ))
    }

    /// Return this object's id
    pub fn id(&self) -> ObjectId {
        self.0.id().into()
    }

    /// Return this object's reference
    pub fn object_ref(&self) -> ObjectReference {
        self.0.object_ref().into()
    }

    /// Return this object's version
    pub fn version(&self) -> Version {
        self.0.version().into()
    }

    /// Return this object's type
    pub fn object_type(&self) -> ObjectType {
        self.0.object_type().into()
    }

    /// Try to interpret this object as a move struct
    pub fn as_opt_struct(&self) -> Option<MoveStruct> {
        self.0.as_opt_struct().cloned().map(Into::into)
    }

    /// Interpret this object as a move struct
    pub fn as_struct(&self) -> MoveStruct {
        self.0.as_struct().clone().into()
    }

    /// Try to interpret this object as a move package
    pub fn as_opt_package(&self) -> Option<Arc<MovePackage>> {
        self.0
            .as_opt_package()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Interpret this object as a move package
    pub fn as_package(&self) -> MovePackage {
        self.0.as_package().clone().into()
    }

    /// Return this object's owner
    pub fn owner(&self) -> Owner {
        (*self.0.owner()).into()
    }

    /// Return this object's data
    pub fn data(&self) -> ObjectData {
        self.0.data().clone().into()
    }

    /// Return the digest of the transaction that last modified this object
    pub fn previous_transaction(&self) -> TransactionDigest {
        self.0.previous_transaction.into()
    }

    /// Return the storage rebate locked in this object
    ///
    /// Storage rebates are credited to the gas coin used in a transaction that
    /// deletes this object.
    pub fn storage_rebate(&self) -> u64 {
        self.0.storage_rebate
    }

    /// Calculate the digest of this `Object`
    ///
    /// This is done by hashing the BCS bytes of this `Object` prefixed
    pub fn digest(&self) -> ObjectDigest {
        self.0.digest().into()
    }
}

/// Object data, either a package or struct
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-data = object-data-struct / object-data-package
///
/// object-data-struct  = %d00 object-move-struct
/// object-data-package = %d01 object-move-package
/// ```
#[derive(Debug, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq, Hash)]
pub struct ObjectData(pub iota_sdk::types::ObjectData);

#[uniffi::export]
impl ObjectData {
    /// Create an `ObjectData` from a `MoveStruct`
    #[uniffi::constructor]
    pub fn new_move_struct(move_struct: MoveStruct) -> Self {
        Self(iota_sdk::types::ObjectData::Struct(move_struct.into()))
    }

    /// Create an `ObjectData` from  `MovePackage`
    #[uniffi::constructor]
    pub fn new_move_package(move_package: &MovePackage) -> Self {
        Self(iota_sdk::types::ObjectData::Package(move_package.0.clone()))
    }

    /// Return whether this object is a `MoveStruct`
    pub fn is_struct(&self) -> bool {
        self.0.is_struct()
    }

    /// Return whether this object is a `MovePackage`
    pub fn is_package(&self) -> bool {
        self.0.is_package()
    }

    /// Try to interpret this object as a `MoveStruct`
    pub fn as_opt_struct(&self) -> Option<MoveStruct> {
        self.0.as_opt_struct().cloned().map(Into::into)
    }

    /// Try to interpret this object as a `MovePackage`
    pub fn as_opt_package(&self) -> Option<Arc<MovePackage>> {
        self.0
            .as_opt_package()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }
}

/// Stores the origin of a data type where it first appeared in the version
/// chain. A data type is identified by the name of the module and the name of
/// the struct/enum in combination.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-origin = identifier identifier object-id
/// ```
#[derive(Clone, uniffi::Record)]
pub struct TypeOrigin {
    /// The name of the module the data type resides in.
    pub module_name: Arc<Identifier>,
    /// The name of the data type. Either refers to an enum or a struct
    /// identifier.
    pub datatype_name: Arc<Identifier>,
    /// ID of the package, where the given type first appeared.
    pub package: Arc<ObjectId>,
}

impl From<iota_sdk::types::TypeOrigin> for TypeOrigin {
    fn from(value: iota_sdk::types::TypeOrigin) -> Self {
        Self {
            module_name: Arc::new(value.module_name.into()),
            datatype_name: Arc::new(value.datatype_name.into()),
            package: Arc::new(value.package.into()),
        }
    }
}

impl From<TypeOrigin> for iota_sdk::types::TypeOrigin {
    fn from(value: TypeOrigin) -> Self {
        Self {
            module_name: value.module_name.0.clone(),
            datatype_name: value.datatype_name.0.clone(),
            package: **value.package,
        }
    }
}

/// Upgraded package info for the linkage table
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// upgrade-info = object-id u64
/// ```
#[derive(Clone, uniffi::Record)]
pub struct UpgradeInfo {
    /// ID of the upgraded package
    pub upgraded_id: Arc<ObjectId>,
    /// Version of the upgraded package
    pub upgraded_version: Arc<Version>,
}

impl From<iota_sdk::types::UpgradeInfo> for UpgradeInfo {
    fn from(value: iota_sdk::types::UpgradeInfo) -> Self {
        Self {
            upgraded_id: Arc::new(value.upgraded_id.into()),
            upgraded_version: Arc::new(value.upgraded_version.into()),
        }
    }
}

impl From<UpgradeInfo> for iota_sdk::types::UpgradeInfo {
    fn from(value: UpgradeInfo) -> Self {
        Self {
            upgraded_id: **value.upgraded_id,
            upgraded_version: **value.upgraded_version,
        }
    }
}

/// A move package
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// move-package = object-id                          ; id
///                u64                                ; version
///                (vector (identifier bytes))        ; modules
///                (vector type-origin)               ; type-origin-table
///                (vector (object-id upgrade-info))  ; linkage-table
/// ```
#[derive(Debug, derive_more::From, Eq, Hash, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq, Hash)]
pub struct MovePackage(pub iota_sdk::types::MovePackage);

#[uniffi::export]
impl MovePackage {
    #[uniffi::constructor]
    pub fn new(
        id: &ObjectId,
        version: &Version,
        modules: HashMap<Arc<Identifier>, Vec<u8>>,
        type_origin_table: Vec<TypeOrigin>,
        linkage_table: HashMap<Arc<ObjectId>, UpgradeInfo>,
    ) -> Result<Self> {
        Ok(Self(iota_sdk::types::MovePackage {
            id: **id,
            version: **version,
            modules: modules.into_iter().map(|(k, v)| (k.0.clone(), v)).collect(),
            type_origin_table: type_origin_table
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            linkage_table: linkage_table
                .into_iter()
                .map(|(k, v)| (**k, v.into()))
                .collect(),
        }))
    }

    pub fn id(&self) -> ObjectId {
        self.0.id.into()
    }

    pub fn version(&self) -> Version {
        self.0.version.into()
    }

    pub fn modules(&self) -> HashMap<Arc<Identifier>, Vec<u8>> {
        self.0
            .modules
            .iter()
            .map(|(k, v)| (Arc::new(k.clone().into()), v.clone()))
            .collect()
    }

    pub fn type_origin_table(&self) -> Vec<TypeOrigin> {
        self.0
            .type_origin_table
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    pub fn linkage_table(&self) -> HashMap<Arc<ObjectId>, UpgradeInfo> {
        self.0
            .linkage_table
            .iter()
            .map(|(k, v)| (Arc::new((*k).into()), v.clone().into()))
            .collect()
    }
}

/// A move struct
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// move-struct = compressed-struct-tag u64 bytes
///
/// compressed-struct-tag = other-struct-type / gas-coin-type / staked-iota-type / coin-type
/// other-struct-type     = %d00 struct-tag
/// gas-coin-type         = %d01
/// staked-iota-type      = %d02
/// coin-type             = %d03 type-tag
///
/// ; The first 32 bytes of the `bytes` contents are the object's object-id.
/// ```
#[derive(Clone, uniffi::Record)]
pub struct MoveStruct {
    /// The type of this object
    pub struct_type: Arc<StructTag>,
    /// Number that increases each time a tx takes this object as a mutable
    /// input This is a lamport timestamp, not a sequentially increasing
    /// version
    pub version: Arc<Version>,
    /// BCS bytes of a Move struct value
    pub contents: Vec<u8>,
}

impl From<iota_sdk::types::MoveStruct> for MoveStruct {
    fn from(value: iota_sdk::types::MoveStruct) -> Self {
        let (object_type, version, contents) = value.into_parts();
        let struct_tag: iota_sdk::types::StructTag = object_type.into();
        Self {
            struct_type: Arc::new(struct_tag.into()),
            version: Arc::new(version.into()),
            contents,
        }
    }
}

impl From<MoveStruct> for iota_sdk::types::MoveStruct {
    fn from(value: MoveStruct) -> Self {
        iota_sdk::types::MoveStruct::new(
            value.struct_type.0.clone().into(),
            **value.version,
            value.contents,
        )
        .expect("FFI MoveStruct should always have valid contents")
    }
}

/// Enum of different types of ownership for an object.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// owner = owner-address / owner-object / owner-shared / owner-immutable
///
/// owner-address   = %d00 address
/// owner-object    = %d01 object-id
/// owner-shared    = %d02 u64
/// owner-immutable = %d03
/// ```
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Eq, Hash)]
pub struct Owner(pub iota_sdk::types::Owner);

#[uniffi::export]
impl Owner {
    #[uniffi::constructor]
    pub fn new_address(address: &Address) -> Self {
        Self(iota_sdk::types::Owner::Address(address.0))
    }

    #[uniffi::constructor]
    pub fn new_object(id: &ObjectId) -> Self {
        Self(iota_sdk::types::Owner::Object(id.0))
    }

    #[uniffi::constructor]
    pub fn new_shared(version: &Version) -> Self {
        Self(iota_sdk::types::Owner::Shared(**version))
    }

    #[uniffi::constructor]
    pub fn new_immutable() -> Self {
        Self(iota_sdk::types::Owner::Immutable)
    }

    /// Check if this is an address owner
    pub fn is_address(&self) -> bool {
        self.0.is_address()
    }

    /// Check if this is an object owner
    pub fn is_object(&self) -> bool {
        self.0.is_object()
    }

    /// Check if this is a shared owner
    pub fn is_shared(&self) -> bool {
        self.0.is_shared()
    }

    /// Check if this is an immutable owner
    pub fn is_immutable(&self) -> bool {
        self.0.is_immutable()
    }

    /// Convert this owner into an address owner if it is one, or panic
    /// otherwise
    pub fn as_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    /// Convert this owner into an address owner if it is one, or return `None`
    /// otherwise
    pub fn as_opt_address(&self) -> Option<Arc<Address>> {
        self.0
            .as_opt_address()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this owner into an object owner if it is one, or panic otherwise
    pub fn as_object(&self) -> ObjectId {
        (*self.0.as_object()).into()
    }

    /// Convert this owner into an object owner if it is one, or return `None`
    /// otherwise
    pub fn as_opt_object(&self) -> Option<Arc<ObjectId>> {
        self.0
            .as_opt_object()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Convert this owner into a shared owner if it is one, or panic otherwise
    pub fn as_shared(&self) -> Version {
        (*self.0.as_shared()).into()
    }

    /// Convert this owner into a shared owner if it is one, or return `None`
    /// otherwise
    pub fn as_opt_shared(&self) -> Option<Arc<Version>> {
        self.0
            .as_opt_shared()
            .copied()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Returns an `Address` if this object is owned by an address or
    /// object, and None if it is shared or immutable.
    pub fn address_or_object(&self) -> Option<Arc<Address>> {
        self.0
            .address_or_object()
            .copied()
            .map(Into::into)
            .map(Arc::new)
    }
}

/// Type of an IOTA object
#[derive(
    Debug, derive_more::Display, derive_more::From, Eq, Ord, PartialEq, PartialOrd, uniffi::Object,
)]
#[uniffi::export(Debug, Display, Eq)]
pub struct ObjectType(pub iota_sdk::types::ObjectType);

#[uniffi::export]
impl ObjectType {
    #[uniffi::constructor]
    pub fn new_package() -> Self {
        Self(iota_sdk::types::ObjectType::Package)
    }

    #[uniffi::constructor]
    pub fn new_struct(struct_tag: &StructTag) -> Self {
        Self(iota_sdk::types::ObjectType::Struct(struct_tag.0.clone()))
    }

    pub fn is_package(&self) -> bool {
        self.0.is_package()
    }

    pub fn is_struct(&self) -> bool {
        self.0.is_struct()
    }

    pub fn as_struct(&self) -> StructTag {
        self.0.as_struct().clone().into()
    }

    pub fn as_opt_struct(&self) -> Option<Arc<StructTag>> {
        self.0
            .as_opt_struct()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }
}

/// An object part of the initial chain state
///
/// `GenesisObject`'s are included as a part of genesis, the initial
/// checkpoint/transaction, that initializes the state of the blockchain.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// genesis-object = %d00 object-data owner   ; RawObject
/// ```
#[derive(Debug, derive_more::From, Eq, PartialEq, uniffi::Object)]
#[uniffi::export(Debug, Eq)]
pub struct GenesisObject(pub iota_sdk::types::GenesisObject);

#[uniffi::export]
impl GenesisObject {
    #[uniffi::constructor]
    pub fn new(data: &ObjectData, owner: &Owner) -> Self {
        Self(iota_sdk::types::GenesisObject::new(data.0.clone(), owner.0))
    }

    pub fn object_id(&self) -> ObjectId {
        self.0.object_id().into()
    }

    pub fn version(&self) -> Version {
        self.0.version().into()
    }

    pub fn object_type(&self) -> ObjectType {
        self.0.object_type().into()
    }

    pub fn owner(&self) -> Owner {
        (*self.0.owner()).into()
    }

    pub fn data(&self) -> ObjectData {
        self.0.data().clone().into()
    }
}

crate::export_iota_types_bcs_conversion!(ObjectReference, TypeOrigin, UpgradeInfo, MoveStruct);
crate::export_iota_types_objects_bcs_conversion!(
    ObjectId,
    Object,
    ObjectData,
    MovePackage,
    Owner,
    GenesisObject
);
crate::export_iota_types_json_conversion!(ObjectReference, TypeOrigin, UpgradeInfo, MoveStruct);
crate::export_iota_types_objects_json_conversion!(
    ObjectId,
    Object,
    ObjectData,
    MovePackage,
    Owner,
    GenesisObject
);
