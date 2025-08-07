// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{str::FromStr, sync::Arc};

use iota_types::Version;

use crate::{
    error::Result,
    types::{
        address::Address,
        digest::{ObjectDigest, TransactionDigest},
        tag::StructTag,
    },
};

/// An `ObjectId` is a 32-byte identifier used to uniquely identify an object on
/// the IOTA blockchain.
///
/// ## Relationship to Address
///
/// [`Address`]es and [`ObjectId`]s share the same 32-byte addressable space but
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
#[derive(Clone, Debug, derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct ObjectId(pub iota_types::ObjectId);

#[uniffi::export]
impl ObjectId {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_types::ObjectId::from(
            iota_types::Address::from_bytes(bytes)?,
        )))
    }

    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_types::ObjectId::from_str(hex)?))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_address(&self) -> Address {
        (*self.0.as_address()).into()
    }

    pub fn to_hex(&self) -> String {
        self.0.as_address().to_hex()
    }
}

impl From<&iota_types::ObjectId> for ObjectId {
    fn from(value: &iota_types::ObjectId) -> Self {
        Self(*value)
    }
}

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
#[derive(Clone, Debug, uniffi::Record)]
pub struct ObjectReference {
    object_id: Arc<ObjectId>,
    version: u64,
    digest: Arc<ObjectDigest>,
}

impl From<iota_types::ObjectReference> for ObjectReference {
    fn from(value: iota_types::ObjectReference) -> Self {
        Self {
            object_id: Arc::new(value.object_id().into()),
            version: value.version(),
            digest: Arc::new(value.digest().into()),
        }
    }
}

impl From<ObjectReference> for iota_types::ObjectReference {
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
#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct Object(pub iota_types::Object);

#[uniffi::export]
impl Object {
    #[uniffi::constructor]
    pub fn new(
        data: &ObjectData,
        owner: &Owner,
        previous_transaction: &TransactionDigest,
        storage_rebate: u64,
    ) -> Self {
        Self(iota_types::Object::new(
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

    /// Return this object's version
    pub fn version(&self) -> Version {
        self.0.version()
    }

    /// Return this object's type
    pub fn object_type(&self) -> ObjectType {
        self.0.object_type().into()
    }

    /// Try to interpret this object as a move struct
    pub fn as_struct(&self) -> Option<Arc<MoveStruct>> {
        self.0.as_struct().cloned().map(Into::into).map(Arc::new)
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
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectData(pub iota_types::ObjectData);

#[uniffi::export]
impl ObjectData {
    /// Create an `ObjectData` from a `MoveStruct`
    #[uniffi::constructor]
    pub fn from_move_struct(move_struct: &MoveStruct) -> Self {
        Self(iota_types::ObjectData::Struct(move_struct.0.clone()))
    }

    /// Create an `ObjectData` from  `MovePackage`
    #[uniffi::constructor]
    pub fn from_move_package(move_package: &MovePackage) -> Self {
        Self(iota_types::ObjectData::Package(move_package.0.clone()))
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
    pub fn try_as_struct(&self) -> Option<Arc<MoveStruct>> {
        self.0
            .as_struct_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    /// Try to interpret this object as a `MovePackage`
    pub fn try_as_package(&self) -> Option<Arc<MovePackage>> {
        self.0
            .as_package_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MovePackage(pub iota_types::MovePackage);

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct MoveStruct(pub iota_types::MoveStruct);

#[derive(Copy, Clone, Debug, derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct Owner(pub iota_types::Owner);

#[uniffi::export]
impl Owner {
    #[uniffi::constructor]
    pub fn new_address(address: &Address) -> Self {
        Self(iota_types::Owner::Address(address.0))
    }

    #[uniffi::constructor]
    pub fn new_object(id: &ObjectId) -> Self {
        Self(iota_types::Owner::Object(id.0))
    }

    #[uniffi::constructor]
    pub fn new_shared(version: Version) -> Self {
        Self(iota_types::Owner::Shared(version))
    }

    #[uniffi::constructor]
    pub fn new_immutable() -> Self {
        Self(iota_types::Owner::Immutable)
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

    pub fn try_as_address(&self) -> Option<Arc<Address>> {
        self.0
            .as_address_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn try_as_object(&self) -> Option<Arc<ObjectId>> {
        self.0
            .as_object_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }

    pub fn try_as_shared(&self) -> Option<Version> {
        self.0.as_shared_opt().copied()
    }
}

#[derive(Clone, Debug, derive_more::From, uniffi::Object)]
pub struct ObjectType(pub iota_types::ObjectType);

#[uniffi::export]
impl ObjectType {
    #[uniffi::constructor]
    pub fn new_package() -> Self {
        Self(iota_types::ObjectType::Package)
    }

    #[uniffi::constructor]
    pub fn new_struct(struct_tag: &StructTag) -> Self {
        Self(iota_types::ObjectType::Struct(struct_tag.0.clone()))
    }

    pub fn is_package(&self) -> bool {
        self.0.is_package()
    }

    pub fn is_struct(&self) -> bool {
        self.0.is_struct()
    }

    pub fn try_as_struct(&self) -> Option<Arc<StructTag>> {
        self.0
            .as_struct_opt()
            .cloned()
            .map(Into::into)
            .map(Arc::new)
    }
}
