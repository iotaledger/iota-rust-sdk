// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

pub type Version = iota_sdk::types::Version;

use crate::{
    error::Result,
    types::{
        address::Address,
        digest::Digest,
        struct_tag::{Identifier, StructTag},
        type_tag::TypeTag,
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
/// object-id = 32*OCTET
/// ```
#[derive(PartialEq, Eq, Hash, derive_more::From, derive_more::Deref, uniffi::Object)]
#[uniffi::export(Hash)]
pub struct ObjectId(pub iota_sdk::types::ObjectId);

#[uniffi::export]
impl ObjectId {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from(
            iota_sdk::types::Address::from_bytes(bytes)?,
        )))
    }

    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::ObjectId::from_hex(hex)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Create an ObjectId from a transaction digest and the number of objects
    /// that have been created during a transactions.
    #[uniffi::constructor]
    pub fn derive_id(digest: &Digest, count: u64) -> Self {
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

    /// Returns the string representation of this object ID using the
    /// canonical display, with or without a `0x` prefix.
    pub fn to_canonical_string(&self, with_prefix: bool) -> String {
        self.0.to_canonical_string(with_prefix)
    }

    /// Returns the shortest possible string representation of the object ID
    /// (i.e. with leading zeroes trimmed).
    pub fn to_short_string(&self, with_prefix: bool) -> String {
        self.0.to_short_string(with_prefix)
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

named_object_id!(ZERO, SYSTEM, CLOCK);

/// Reference to an object
///
/// Contains sufficient information to uniquely identify a specific object.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// object-ref = object-id u64 digest
/// ```
#[derive(uniffi::Record)]
pub struct ObjectReference {
    object_id: Arc<ObjectId>,
    version: u64,
    digest: Arc<Digest>,
}

impl From<iota_sdk::types::ObjectReference> for ObjectReference {
    fn from(value: iota_sdk::types::ObjectReference) -> Self {
        Self {
            object_id: Arc::new((*value.object_id()).into()),
            version: value.version(),
            digest: Arc::new((*value.digest()).into()),
        }
    }
}

impl From<ObjectReference> for iota_sdk::types::ObjectReference {
    fn from(value: ObjectReference) -> Self {
        Self::new(**value.object_id, value.version, **value.digest)
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
#[derive(derive_more::From, uniffi::Object)]
pub struct Object(pub iota_sdk::types::Object);

#[uniffi::export]
impl Object {
    #[uniffi::constructor]
    pub fn new(
        data: &ObjectData,
        owner: &Owner,
        previous_transaction: &Digest,
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
    pub fn object_id(&self) -> ObjectId {
        self.0.object_id().into()
    }

    /// Return this object's reference
    pub fn object_ref(&self) -> ObjectReference {
        self.0.object_ref().into()
    }

    /// Return this object's version
    pub fn version(&self) -> Version {
        self.0.version()
    }

    /// Return this object's type
    pub fn object_type(&self) -> ObjectType {
        self.0.object_type().into()
    }

    /// Try to interpret this object as a move struct
    pub fn as_struct_opt(&self) -> Option<MoveStruct> {
        self.0.as_struct_opt().cloned().map(Into::into)
    }

    /// Interpret this object as a move struct
    pub fn as_struct(&self) -> MoveStruct {
        self.0.as_struct().clone().into()
    }

    /// Try to interpret this object as a move package
    pub fn as_package_opt(&self) -> Option<Arc<MovePackage>> {
        self.0
            .as_package_opt()
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
    pub fn previous_transaction(&self) -> Digest {
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
    pub fn digest(&self) -> Digest {
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
/// object-data-struct  = %x00 object-move-struct
/// object-data-package = %x01 object-move-package
/// ```
#[derive(derive_more::From, uniffi::Object)]
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
    pub fn as_struct_opt(&self) -> Option<MoveStruct> {
        self.0.as_struct_opt().cloned().map(Into::into)
    }

    /// Try to interpret this object as a `MovePackage`
    pub fn as_package_opt(&self) -> Option<Arc<MovePackage>> {
        self.0
            .as_package_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }
}

/// Identifies a struct and the module it was defined in
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// type-origin = identifier identifier object-id
/// ```
#[derive(uniffi::Record)]
pub struct TypeOrigin {
    pub module_name: Arc<Identifier>,
    pub struct_name: Arc<Identifier>,
    pub package: Arc<ObjectId>,
}

impl From<iota_sdk::types::TypeOrigin> for TypeOrigin {
    fn from(value: iota_sdk::types::TypeOrigin) -> Self {
        Self {
            module_name: Arc::new(value.module_name.into()),
            struct_name: Arc::new(value.struct_name.into()),
            package: Arc::new(value.package.into()),
        }
    }
}

impl From<TypeOrigin> for iota_sdk::types::TypeOrigin {
    fn from(value: TypeOrigin) -> Self {
        Self {
            module_name: value.module_name.0.clone(),
            struct_name: value.struct_name.0.clone(),
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
#[derive(uniffi::Record)]
pub struct UpgradeInfo {
    /// Id of the upgraded packages
    pub upgraded_id: Arc<ObjectId>,
    /// Version of the upgraded package
    pub upgraded_version: Version,
}

impl From<iota_sdk::types::UpgradeInfo> for UpgradeInfo {
    fn from(value: iota_sdk::types::UpgradeInfo) -> Self {
        Self {
            upgraded_id: Arc::new(value.upgraded_id.into()),
            upgraded_version: value.upgraded_version,
        }
    }
}

impl From<UpgradeInfo> for iota_sdk::types::UpgradeInfo {
    fn from(value: UpgradeInfo) -> Self {
        Self {
            upgraded_id: **value.upgraded_id,
            upgraded_version: value.upgraded_version,
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
/// object-move-package = object-id u64 move-modules type-origin-table linkage-table
///
/// move-modules = map (identifier bytes)
/// type-origin-table = vector type-origin
/// linkage-table = map (object-id upgrade-info)
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct MovePackage(pub iota_sdk::types::MovePackage);

#[uniffi::export]
impl MovePackage {
    #[uniffi::constructor]
    pub fn new(
        id: &ObjectId,
        version: Version,
        modules: HashMap<Arc<Identifier>, Vec<u8>>,
        type_origin_table: Vec<TypeOrigin>,
        linkage_table: HashMap<Arc<ObjectId>, UpgradeInfo>,
    ) -> Result<Self> {
        Ok(Self(iota_sdk::types::MovePackage {
            id: **id,
            version,
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
        self.0.version
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
/// object-move-struct = compressed-struct-tag bool u64 object-contents
///
/// compressed-struct-tag = other-struct-type / gas-coin-type / staked-iota-type / coin-type
/// other-struct-type     = %x00 struct-tag
/// gas-coin-type         = %x01
/// staked-iota-type      = %x02
/// coin-type             = %x03 type-tag
///
/// ; first 32 bytes of the contents are the object's object-id
/// object-contents = uleb128 (object-id *OCTET) ; length followed by contents
/// ```
#[derive(uniffi::Record)]
pub struct MoveStruct {
    /// The type of this object
    pub struct_type: Arc<StructTag>,
    /// Number that increases each time a tx takes this object as a mutable
    /// input This is a lamport timestamp, not a sequentially increasing
    /// version
    pub version: Version,
    /// BCS bytes of a Move struct value
    pub contents: Vec<u8>,
}

impl From<iota_sdk::types::MoveStruct> for MoveStruct {
    fn from(value: iota_sdk::types::MoveStruct) -> Self {
        Self {
            struct_type: Arc::new(value.type_.into()),
            version: value.version,
            contents: value.contents,
        }
    }
}

impl From<MoveStruct> for iota_sdk::types::MoveStruct {
    fn from(value: MoveStruct) -> Self {
        Self {
            type_: value.struct_type.0.clone(),
            version: value.version,
            contents: value.contents,
        }
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
/// owner-address   = %x00 address
/// owner-object    = %x01 object-id
/// owner-shared    = %x02 u64
/// owner-immutable = %x03
/// ```
#[derive(derive_more::From, derive_more::Deref, derive_more::Display, uniffi::Object)]
#[uniffi::export(Display)]
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
    pub fn new_shared(version: Version) -> Self {
        Self(iota_sdk::types::Owner::Shared(version))
    }

    #[uniffi::constructor]
    pub fn new_immutable() -> Self {
        Self(iota_sdk::types::Owner::Immutable)
    }

    pub fn is_address(&self) -> bool {
        self.0.is_address()
    }

    pub fn is_object(&self) -> bool {
        self.0.is_object()
    }

    pub fn is_shared(&self) -> bool {
        self.0.is_shared()
    }

    pub fn is_immutable(&self) -> bool {
        self.0.is_immutable()
    }

    pub fn as_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    pub fn as_address_opt(&self) -> Option<Arc<Address>> {
        self.0
            .as_address_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_object(&self) -> ObjectId {
        (*self.0.as_object()).into()
    }

    pub fn as_object_opt(&self) -> Option<Arc<ObjectId>> {
        self.0
            .as_object_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn as_shared(&self) -> Version {
        *self.0.as_shared()
    }

    pub fn as_shared_opt(&self) -> Option<Version> {
        self.0.as_shared_opt().copied()
    }
}

/// Type of an IOTA object
#[derive(derive_more::From, derive_more::Display, uniffi::Object)]
#[uniffi::export(Display)]
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

    pub fn as_struct_opt(&self) -> Option<Arc<StructTag>> {
        self.0
            .as_struct_opt()
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
/// genesis-object = object-data owner
/// ```
#[derive(derive_more::From, uniffi::Object)]
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
        self.0.version()
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
