// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Address, Digest, MovePackage, ObjectId, StructTag, TypeTag, Version};

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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct ObjectReference {
    /// The object id of this object.
    pub object_id: ObjectId,
    /// The version of this object.
    pub version: Version,
    /// The digest of this object.
    pub digest: Digest,
}

impl ObjectReference {
    /// Creates a new object reference from the object's id, version, and
    /// digest.
    pub const fn new(object_id: ObjectId, version: Version, digest: Digest) -> Self {
        Self {
            object_id,
            version,
            digest,
        }
    }

    /// Returns a reference to the object id that this ObjectReference is
    /// referring to.
    pub fn object_id(&self) -> &ObjectId {
        &self.object_id
    }

    /// Returns the version of the object that this ObjectReference is referring
    /// to.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the digest of the object that this ObjectReference is referring
    /// to.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Returns a 3-tuple containing the object id, version, and digest.
    pub fn into_parts(self) -> (ObjectId, Version, Digest) {
        let Self {
            object_id,
            version,
            digest,
        } = self;

        (object_id, version, digest)
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
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
#[non_exhaustive]
pub enum Owner {
    /// Object is exclusively owned by a single address, and is mutable.
    Address(Address),
    /// Object is exclusively owned by a single object, and is mutable.
    Object(ObjectId),
    /// Object is shared, can be used by any address, and is mutable.
    Shared(
        /// The version at which the object became shared
        Version,
    ),
    /// Object is immutable, and hence ownership doesn't matter.
    Immutable,
}

impl Owner {
    crate::def_is!(Immutable);

    crate::def_is_as_into_opt!(Address, Object(ObjectId), Shared(Version));

    /// Returns an `Address` if this object is owned by an address or
    /// object, and None if it is shared or immutable.
    pub fn address_or_object(&self) -> Option<&Address> {
        Some(match self {
            Self::Address(address) => address,
            Self::Object(object_id) => object_id.as_address(),
            _ => return None,
        })
    }
}

impl PartialEq<Address> for Owner {
    fn eq(&self, other: &Address) -> bool {
        self.as_address_opt() == Some(other)
    }
}

impl PartialEq<ObjectId> for Owner {
    fn eq(&self, other: &ObjectId) -> bool {
        self.as_object_opt() == Some(other)
    }
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Owner::Address(address) => write!(f, "Address({address})"),
            Owner::Object(object_id) => write!(f, "Object({object_id})"),
            Owner::Shared(version) => write!(f, "Shared({version})"),
            Owner::Immutable => write!(f, "Immutable"),
        }
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[allow(clippy::large_enum_variant)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
// TODO think about hiding this type and not exposing it
pub enum ObjectData {
    /// An object whose governing logic lives in a published Move module
    Struct(MoveStruct),
    /// Map from each module name to raw serialized Move module bytes
    Package(MovePackage),
    // ... IOTA "native" types go here
}

impl ObjectData {
    crate::def_is_as_into_opt!(Struct(MoveStruct), Package(MovePackage));

    pub fn object_type(&self) -> Option<&MoveObjectType> {
        match self {
            Self::Struct(m) => Some(m.object_type()),
            Self::Package(_) => None,
        }
    }

    pub fn struct_tag(&self) -> Option<StructTag> {
        match self {
            Self::Struct(m) => Some(m.struct_tag().clone()),
            Self::Package(_) => None,
        }
    }

    pub fn id(&self) -> ObjectId {
        match self {
            Self::Struct(v) => v.id(),
            Self::Package(m) => m.id(),
        }
    }
}

/// A [`StructTag`] with optimized BCS serialization for object types.
///
/// GasCoin, StakedIota, and Coin variants use compact enum encoding
/// instead of the full StructTag representation. The Other variant
/// carries the full StructTag inline.
///
/// # BCS
///
/// ```text
/// compressed-struct-tag = other-struct-type / gas-coin-type / staked-iota-type / coin-type
/// other-struct-type     = %x00 struct-tag
/// gas-coin-type         = %x01
/// staked-iota-type      = %x02
/// coin-type             = %x03 type-tag
/// ```
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveObjectType(StructTag);

impl MoveObjectType {
    pub fn new(tag: StructTag) -> Self {
        Self(tag)
    }

    pub fn into_inner(self) -> StructTag {
        self.0
    }
}

impl std::ops::Deref for MoveObjectType {
    type Target = StructTag;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<StructTag> for MoveObjectType {
    fn from(tag: StructTag) -> Self {
        Self(tag)
    }
}

impl From<MoveObjectType> for StructTag {
    fn from(obj_type: MoveObjectType) -> Self {
        obj_type.0
    }
}

impl PartialEq<StructTag> for MoveObjectType {
    fn eq(&self, other: &StructTag) -> bool {
        &self.0 == other
    }
}

impl std::fmt::Display for MoveObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for MoveObjectType {
    type Err = crate::TypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StructTag::from_str(s).map(Self)
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct MoveStruct {
    /// The type of this object. Uses optimized BCS serialization.
    #[cfg_attr(feature = "bcs-schema", bcs_schema(as_type = "compressed-struct-tag"))]
    object_type: MoveObjectType,
    /// Number that increases each time a tx takes this object as a mutable
    /// input This is a lamport timestamp, not a sequentially increasing
    /// version
    version: Version,
    /// BCS bytes of a Move struct value.
    ///
    /// The first [`ObjectId::LENGTH`] bytes are always the object's
    /// [`ObjectId`].
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::_serde::ReadableBase64Encoded")
    )]
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(32..=1024).lift()))]
    contents: Vec<u8>,
}

impl MoveStruct {
    /// Creates a new `MoveStruct`.
    ///
    /// # Errors
    ///
    /// Returns an error if `contents` is shorter than [`ObjectId::LENGTH`]
    /// bytes, since every Move object must contain its [`ObjectId`] as the
    /// leading bytes.
    pub fn new(
        object_type: MoveObjectType,
        version: Version,
        contents: Vec<u8>,
    ) -> Result<Self, MoveStructContentsError> {
        if contents.len() < ObjectId::LENGTH {
            return Err(MoveStructContentsError {
                actual: contents.len(),
            });
        }
        Ok(Self {
            object_type,
            version,
            contents,
        })
    }

    /// Returns the type of this Move object.
    pub fn object_type(&self) -> &MoveObjectType {
        &self.object_type
    }

    /// Returns the object type as a [`StructTag`] reference.
    pub fn struct_tag(&self) -> &StructTag {
        &self.object_type
    }

    /// Returns `true` if the object's type matches the given [`StructTag`].
    pub fn is_struct_tag(&self, s: &StructTag) -> bool {
        &self.object_type == s
    }

    /// Returns the object's ID, extracted from the BCS-encoded contents.
    ///
    /// This is always valid because the constructor guarantees that `contents`
    /// is at least [`ObjectId::LENGTH`] bytes long.
    pub fn id(&self) -> ObjectId {
        ObjectId::from_bytes(&self.contents[..ObjectId::LENGTH]).unwrap()
    }

    /// Returns the version (lamport timestamp) of this object.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Sets the version (lamport timestamp) of this object.
    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    /// Sets the type of this object.
    ///
    /// The caller must ensure the existing [`contents`](Self::contents) are a
    /// valid BCS encoding of the new `object_type`; this is not verified.
    pub fn set_object_type(&mut self, object_type: MoveObjectType) {
        self.object_type = object_type;
    }

    /// Returns the raw BCS-encoded contents of this object.
    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    /// Replaces the BCS-encoded contents of this object.
    ///
    /// The caller must ensure the new contents are a valid BCS encoding of the
    /// object's [`object_type`](Self::object_type); this is not verified.
    ///
    /// # Errors
    ///
    /// Returns an error if `contents` is shorter than [`ObjectId::LENGTH`]
    /// bytes.
    pub fn set_contents(&mut self, contents: Vec<u8>) -> Result<(), MoveStructContentsError> {
        if contents.len() < ObjectId::LENGTH {
            return Err(MoveStructContentsError {
                actual: contents.len(),
            });
        }
        self.contents = contents;
        Ok(())
    }

    /// Consumes the object and returns the raw BCS-encoded contents.
    pub fn into_contents(self) -> Vec<u8> {
        self.contents
    }

    /// Returns the object type as a [`TypeTag`].
    pub fn type_tag(&self) -> TypeTag {
        TypeTag::Struct(Box::new(self.struct_tag().clone()))
    }

    /// Consumes the object and returns its type, version, and raw contents.
    pub fn into_parts(self) -> (MoveObjectType, Version, Vec<u8>) {
        (self.object_type, self.version, self.contents)
    }

    /// Deserializes the BCS-encoded contents into a Rust type.
    #[cfg(feature = "serde")]
    pub fn to_rust<'de, T: serde::Deserialize<'de>>(&'de self) -> Result<T, bcs::Error> {
        bcs::from_bytes(self.contents())
    }
}

/// Error returned when [`MoveStruct`] contents are too short to contain an
/// [`ObjectId`].
#[derive(Clone, Debug, thiserror::Error)]
#[error(
    "MoveStruct contents must be at least {} bytes to contain an ObjectId, got {actual}",
    ObjectId::LENGTH
)]
pub struct MoveStructContentsError {
    actual: usize,
}

/// Type of an IOTA object
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectType {
    /// Move package containing one or more bytecode modules
    Package,
    /// A Move struct of the given type
    Struct(StructTag),
}

impl ObjectType {
    crate::def_is!(Package);

    crate::def_is_as_into_opt!(Struct(StructTag));
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectType::Package => write!(f, "Package"),
            ObjectType::Struct(struct_tag) => write!(f, "Struct({struct_tag})"),
        }
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "bcs-schema", derive(iota_bcs_schema::BcsSchema))]
pub struct Object {
    /// The meat of the object
    pub data: ObjectData,
    /// The owner that unlocks this object
    pub owner: Owner,
    /// The digest of the transaction that created or last mutated this object
    pub previous_transaction: Digest,
    /// The amount of IOTA we would rebate if this object gets deleted.
    /// This number is re-calculated each time the object is mutated based on
    /// the present storage gas price.
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub storage_rebate: u64,
}

impl Object {
    /// Build an object
    pub fn new(
        data: ObjectData,
        owner: Owner,
        previous_transaction: Digest,
        storage_rebate: u64,
    ) -> Self {
        Self {
            data,
            owner,
            previous_transaction,
            storage_rebate,
        }
    }

    /// Return this object's id
    pub fn id(&self) -> ObjectId {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.id(),
            ObjectData::Package(package) => package.id,
        }
    }

    /// Return this object's reference
    #[cfg(all(feature = "hash", feature = "serde"))]
    pub fn object_ref(&self) -> ObjectReference {
        ObjectReference {
            object_id: self.id(),
            version: self.version(),
            digest: self.digest(),
        }
    }

    /// Return this object's version
    pub fn version(&self) -> Version {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.version(),
            ObjectData::Package(package) => package.version,
        }
    }

    /// Return this object's type
    pub fn object_type(&self) -> ObjectType {
        match &self.data {
            ObjectData::Struct(struct_) => ObjectType::Struct(struct_.struct_tag().clone()),
            ObjectData::Package(_) => ObjectType::Package,
        }
    }

    /// Try to interpret this object as a move struct
    pub fn as_struct_opt(&self) -> Option<&MoveStruct> {
        match &self.data {
            ObjectData::Struct(struct_) => Some(struct_),
            _ => None,
        }
    }

    /// Interpret this object as a move struct
    pub fn as_struct(&self) -> &MoveStruct {
        self.as_struct_opt().expect("not a move struct")
    }

    /// Try to interpret this object as a move package
    pub fn as_package_opt(&self) -> Option<&MovePackage> {
        match &self.data {
            ObjectData::Package(package) => Some(package),
            _ => None,
        }
    }

    /// Interpret this object as a move package
    pub fn as_package(&self) -> &MovePackage {
        self.as_package_opt().expect("not a move package")
    }

    /// Return this object's owner
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    /// Return this object's data
    pub fn data(&self) -> &ObjectData {
        &self.data
    }

    /// Return the digest of the transaction that last modified this object
    pub fn previous_transaction(&self) -> Digest {
        self.previous_transaction
    }

    /// Return the storage rebate locked in this object
    ///
    /// Storage rebates are credited to the gas coin used in a transaction that
    /// deletes this object.
    pub fn storage_rebate(&self) -> u64 {
        self.storage_rebate
    }

    #[cfg(feature = "serde")]
    pub fn to_rust<'de, T: serde::Deserialize<'de>>(
        &'de self,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let contents = self.as_struct_opt().ok_or("not a struct")?.contents();
        Ok(bcs::from_bytes::<T>(contents)?)
    }

    /// Returns true if the object is immutable.
    pub fn is_immutable(&self) -> bool {
        self.owner.is_immutable()
    }

    /// Returns true if the object is owned by an address.
    pub fn is_address_owned(&self) -> bool {
        self.owner.is_address()
    }

    /// Returns true if the object is owned by another object.
    pub fn is_child_object(&self) -> bool {
        self.owner.is_object()
    }

    /// Returns true if the object is shared.
    pub fn is_shared(&self) -> bool {
        self.owner.is_shared()
    }

    /// Returns true if this object is a Move package rather than a Move value.
    pub fn is_package(&self) -> bool {
        self.data.is_package()
    }

    /// Returns true if the object is a system package.
    pub fn is_system_package(&self) -> bool {
        self.is_package() && self.id().is_system_package()
    }

    /// Returns the struct tag of this object if it is a Move struct.
    pub fn struct_tag(&self) -> Option<StructTag> {
        self.data.struct_tag()
    }

    /// Returns true if this object is a gas coin.
    pub fn is_gas_coin(&self) -> bool {
        self.as_struct_opt()
            .is_some_and(|move_object| move_object.struct_tag().is_gas_coin())
    }

    /// Returns the coin's type parameter if this object is a coin.
    pub fn coin_type_opt(&self) -> Option<&TypeTag> {
        self.as_struct_opt()
            .and_then(|move_object| move_object.struct_tag().coin_type_opt())
    }

    /// Returns the address of the single owner of this object (address- or
    /// object-owned), or `None` if it is shared or immutable.
    pub fn single_owner(&self) -> Option<Address> {
        self.owner.address_or_object().copied()
    }

    /// Sets the owner of this object to `new_owner`.
    pub fn set_owner(&mut self, new_owner: Address) {
        self.owner = Owner::Address(new_owner);
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct GenesisObject {
    pub data: ObjectData,
    pub owner: Owner,
}

impl GenesisObject {
    pub fn new(data: ObjectData, owner: Owner) -> Self {
        Self { data, owner }
    }

    pub fn object_id(&self) -> ObjectId {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.id(),
            ObjectData::Package(package) => package.id,
        }
    }

    pub fn version(&self) -> Version {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.version(),
            ObjectData::Package(package) => package.version,
        }
    }

    pub fn object_type(&self) -> ObjectType {
        match &self.data {
            ObjectData::Struct(struct_) => ObjectType::Struct(struct_.struct_tag().clone()),
            ObjectData::Package(_) => ObjectType::Package,
        }
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn data(&self) -> &ObjectData {
        &self.data
    }

    pub fn id(&self) -> ObjectId {
        self.data.id()
    }
}

// TODO improve ser/de to do borrowing to avoid clones where possible
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;
    use crate::TypeTag;

    /// Wrapper around StructTag with a space-efficient representation for
    /// common types like coins The StructTag for a gas coin is 84 bytes, so
    /// using 1 byte instead is a win. The inner representation is private
    /// to prevent incorrectly constructing an `Other` instead of one of the
    /// specialized variants, e.g. `Other(GasCoin::type_())` instead of
    /// `GasCoin`
    #[derive(serde::Deserialize)]
    #[serde(rename = "MoveObjectType")]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "compressed-struct-tag")
    )]
    enum MoveObjectTypeWrapper {
        /// A type that is not `0x2::coin::Coin<T>`
        Other(StructTag),
        /// An IOTA coin (i.e., `0x2::coin::Coin<0x2::iota::IOTA>`)
        GasCoin,
        /// A record of a staked IOTA coin (i.e.,
        /// `0x3::staking_pool::StakedIota`)
        StakedIota,
        /// A non-IOTA coin type (i.e., `0x2::coin::Coin<T> where T !=
        /// 0x2::iota::IOTA`)
        Coin(TypeTag),
        // NOTE: if adding a new type here, and there are existing on-chain objects of that
        // type with Other(_), that is ok, but you must hand-roll PartialEq/Eq/Ord/maybe Hash
        // to make sure the new type and Other(_) are interpreted consistently.
    }

    /// See `MoveObjectType`
    #[derive(serde::Serialize)]
    #[serde(rename = "MoveObjectType")]
    enum MoveObjectTypeRef<'a> {
        /// A type that is not `0x2::coin::Coin<T>`
        Other(&'a StructTag),
        /// An IOTA coin (i.e., `0x2::coin::Coin<0x2::iota::IOTA>`)
        GasCoin,
        /// A record of a staked IOTA coin (i.e.,
        /// `0x3::staking_pool::StakedIota`)
        StakedIota,
        /// A non-IOTA coin type (i.e., `0x2::coin::Coin<T> where T !=
        /// 0x2::iota::IOTA`)
        Coin(&'a TypeTag),
        // NOTE: if adding a new type here, and there are existing on-chain objects of that
        // type with Other(_), that is ok, but you must hand-roll PartialEq/Eq/Ord/maybe Hash
        // to make sure the new type and Other(_) are interpreted consistently.
    }

    impl MoveObjectTypeWrapper {
        fn into_struct_tag(self) -> StructTag {
            match self {
                MoveObjectTypeWrapper::Other(tag) => tag,
                MoveObjectTypeWrapper::GasCoin => StructTag::new_gas_coin(),
                MoveObjectTypeWrapper::StakedIota => StructTag::new_staked_iota(),
                MoveObjectTypeWrapper::Coin(type_tag) => StructTag::new_coin(type_tag),
            }
        }
    }

    impl<'a> MoveObjectTypeRef<'a> {
        fn from_struct_tag(s: &'a StructTag) -> Self {
            if let Some(coin_type) = s.coin_type_opt() {
                if let TypeTag::Struct(s_inner) = coin_type
                    && s_inner.address() == Address::FRAMEWORK
                    && s_inner.module() == "iota"
                    && s_inner.name() == "IOTA"
                    && s_inner.type_params().is_empty()
                {
                    return Self::GasCoin;
                }

                Self::Coin(coin_type)
            } else if s.address() == Address::SYSTEM
                && s.module() == "staking_pool"
                && s.name() == "StakedIota"
                && s.type_params().is_empty()
            {
                Self::StakedIota
            } else {
                Self::Other(s)
            }
        }
    }

    impl Serialize for MoveObjectType {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                self.0.serialize(serializer)
            } else {
                MoveObjectTypeRef::from_struct_tag(&self.0).serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for MoveObjectType {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                StructTag::deserialize(deserializer).map(Self)
            } else {
                MoveObjectTypeWrapper::deserialize(deserializer).map(|t| Self(t.into_struct_tag()))
            }
        }
    }

    #[derive(serde::Serialize)]
    #[serde(rename = "GenesisObject")]
    struct ReadableGenesisObjectRef<'a> {
        data: &'a ObjectData,
        owner: &'a Owner,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "GenesisObject")]
    struct ReadableGenesisObject {
        data: ObjectData,
        owner: Owner,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(rename = "GenesisObject")]
    #[cfg_attr(
        feature = "bcs-schema",
        derive(iota_bcs_schema::BcsSchema),
        bcs_schema(name = "genesis-object")
    )]
    enum BinaryGenesisObject {
        RawObject { data: ObjectData, owner: Owner },
    }

    impl Serialize for GenesisObject {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                ReadableGenesisObjectRef {
                    data: &self.data,
                    owner: &self.owner,
                }
                .serialize(serializer)
            } else {
                BinaryGenesisObject::RawObject {
                    data: self.data.clone(),
                    owner: self.owner,
                }
                .serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for GenesisObject {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableGenesisObject { data, owner } = Deserialize::deserialize(deserializer)?;

                Ok(GenesisObject { data, owner })
            } else {
                let BinaryGenesisObject::RawObject { data, owner } =
                    Deserialize::deserialize(deserializer)?;

                Ok(GenesisObject { data, owner })
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeMap;

        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::*;
        use crate::{Identifier, TypeOrigin, UpgradeInfo, object::Object};

        #[test]
        fn package_object_json_snapshot() {
            let package = MovePackage {
                id: ObjectId::ZERO,
                version: Version::from_u64(12),
                modules: BTreeMap::from([(
                    Identifier::new("my_module").unwrap(),
                    vec![1, 2, 3, 4],
                )]),
                type_origin_table: vec![TypeOrigin {
                    module_name: Identifier::new("my_module").unwrap(),
                    datatype_name: Identifier::new("MyType").unwrap(),
                    package: ObjectId::ZERO,
                }],
                linkage_table: BTreeMap::from([(
                    ObjectId::ZERO,
                    UpgradeInfo {
                        upgraded_id: ObjectId::ZERO,
                        upgraded_version: Version::from_u64(13),
                    },
                )]),
            };
            let object = Object {
                data: ObjectData::Package(package),
                owner: Owner::Object(ObjectId::ZERO),
                previous_transaction: Digest::ZERO,
                storage_rebate: 100,
            };

            let json = serde_json::to_string_pretty(&object)
                .unwrap()
                // Re-indent to match the indented literal below.
                .replace('\n', "\n                ");
            assert_eq!(
                json,
                r#"{
                  "data": {
                    "Package": {
                      "id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                      "version": "12",
                      "modules": {
                        "my_module": "AQIDBA=="
                      },
                      "type_origin_table": [
                        {
                          "module_name": "my_module",
                          "datatype_name": "MyType",
                          "package": "0x0000000000000000000000000000000000000000000000000000000000000000"
                        }
                      ],
                      "linkage_table": {
                        "0x0000000000000000000000000000000000000000000000000000000000000000": {
                          "upgraded_id": "0x0000000000000000000000000000000000000000000000000000000000000000",
                          "upgraded_version": "13"
                        }
                      }
                    }
                  },
                  "owner": {
                    "Object": "0x0000000000000000000000000000000000000000000000000000000000000000"
                  },
                  "previous_transaction": "11111111111111111111111111111111",
                  "storage_rebate": "100"
                }"#
            );

            // The shape must survive a JSON round-trip unchanged.
            let roundtrip: Object = serde_json::from_str(&json).unwrap();
            assert_eq!(object, roundtrip);
        }

        #[test]
        fn object_reference_tuple_format() {
            let json = r#"["0x0000000000000000000000000000000000000000000000000000000000000000","0","11111111111111111111111111111111"]"#;
            let obj_ref: ObjectReference = serde_json::from_str(json).unwrap();
            assert_eq!(obj_ref.object_id, ObjectId::ZERO);
            assert_eq!(obj_ref.version, Version::from_u64(0));
            assert_eq!(obj_ref.digest, Digest::ZERO);

            // Roundtrip
            let serialized = serde_json::to_string(&obj_ref).unwrap();
            let roundtrip: ObjectReference = serde_json::from_str(&serialized).unwrap();
            assert_eq!(obj_ref, roundtrip);
        }

        #[test]
        fn object_reference_in_map() {
            use std::collections::BTreeMap;

            let json = r#"{"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi":[["0x0000000000000000000000000000000000000000000000000000000000000000","0","11111111111111111111111111111111"]],"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR":[["0x0000000000000000000000000000000000000000000000000000000000000000","0","11111111111111111111111111111111"]]}"#;

            let from_json: BTreeMap<String, Vec<ObjectReference>> =
                serde_json::from_str(json).unwrap();

            assert_eq!(from_json.len(), 2);
            for refs in from_json.values() {
                assert_eq!(refs.len(), 1);
                assert_eq!(refs[0].object_id, ObjectId::ZERO);
                assert_eq!(refs[0].version, Version::from_u64(0));
                assert_eq!(refs[0].digest, Digest::ZERO);
            }
        }

        #[test]
        fn object_fixture() {
            const IOTA_COIN: &[u8] = &[
                0, 1, 32, 79, 43, 0, 0, 0, 0, 0, 40, 35, 95, 175, 213, 151, 87, 206, 190, 35, 131,
                79, 35, 254, 22, 15, 181, 40, 108, 28, 77, 68, 229, 107, 254, 191, 160, 196, 186,
                42, 2, 122, 53, 52, 133, 199, 58, 0, 0, 0, 0, 0, 79, 255, 208, 0, 85, 34, 190, 75,
                192, 41, 114, 76, 127, 15, 110, 215, 9, 58, 107, 243, 160, 155, 144, 230, 47, 97,
                220, 21, 24, 30, 26, 62, 32, 17, 197, 192, 38, 64, 173, 142, 143, 49, 111, 15, 211,
                92, 84, 48, 160, 243, 102, 229, 253, 251, 137, 210, 101, 119, 173, 228, 51, 141,
                20, 15, 85, 96, 19, 15, 0, 0, 0, 0, 0,
            ];

            const IOTA_STAKE: &[u8] = &[
                0, 2, 154, 1, 52, 5, 0, 0, 0, 0, 80, 3, 112, 71, 231, 166, 234, 205, 164, 99, 237,
                29, 56, 97, 170, 21, 96, 105, 158, 227, 122, 22, 251, 60, 162, 12, 97, 151, 218,
                71, 253, 231, 239, 116, 138, 12, 233, 128, 195, 128, 77, 33, 38, 122, 77, 53, 154,
                197, 198, 75, 212, 12, 182, 163, 224, 42, 82, 123, 69, 248, 40, 207, 143, 211, 13,
                106, 1, 0, 0, 0, 0, 0, 0, 59, 81, 183, 246, 112, 0, 0, 0, 0, 79, 255, 208, 0, 85,
                34, 190, 75, 192, 41, 114, 76, 127, 15, 110, 215, 9, 58, 107, 243, 160, 155, 144,
                230, 47, 97, 220, 21, 24, 30, 26, 62, 32, 247, 239, 248, 71, 247, 102, 190, 149,
                232, 153, 138, 67, 169, 209, 203, 29, 255, 215, 223, 57, 159, 44, 40, 218, 166, 13,
                80, 71, 14, 188, 232, 68, 0, 0, 0, 0, 0, 0, 0, 0,
            ];

            const NFT: &[u8] = &[
                0, 0, 97, 201, 195, 159, 216, 97, 133, 173, 96, 215, 56, 212, 229, 43, 208, 139,
                218, 7, 29, 54, 106, 205, 224, 126, 7, 195, 145, 106, 45, 117, 168, 22, 12, 100,
                105, 115, 116, 114, 105, 98, 117, 116, 105, 111, 110, 11, 68, 69, 69, 80, 87, 114,
                97, 112, 112, 101, 114, 0, 124, 24, 223, 4, 0, 0, 0, 0, 40, 31, 8, 18, 84, 38, 164,
                252, 84, 115, 250, 246, 137, 132, 128, 186, 156, 36, 62, 18, 140, 21, 4, 90, 209,
                105, 85, 84, 92, 214, 97, 81, 207, 64, 194, 198, 208, 21, 0, 0, 0, 0, 79, 255, 208,
                0, 85, 34, 190, 75, 192, 41, 114, 76, 127, 15, 110, 215, 9, 58, 107, 243, 160, 155,
                144, 230, 47, 97, 220, 21, 24, 30, 26, 62, 32, 170, 4, 94, 114, 207, 155, 31, 80,
                62, 254, 220, 206, 240, 218, 83, 54, 204, 197, 255, 239, 41, 66, 199, 150, 56, 189,
                86, 217, 166, 216, 128, 241, 64, 205, 21, 0, 0, 0, 0, 0,
            ];

            const FUD_COIN: &[u8] = &[
                0, 3, 7, 118, 203, 129, 155, 1, 171, 237, 80, 43, 238, 138, 112, 43, 76, 45, 84,
                117, 50, 193, 47, 37, 0, 28, 157, 234, 121, 90, 94, 99, 28, 38, 241, 3, 102, 117,
                100, 3, 70, 85, 68, 0, 193, 89, 252, 3, 0, 0, 0, 0, 40, 33, 214, 90, 11, 56, 243,
                115, 10, 250, 121, 250, 28, 34, 237, 104, 130, 148, 40, 130, 29, 248, 137, 244, 27,
                138, 94, 150, 28, 182, 104, 162, 185, 0, 152, 247, 62, 93, 1, 0, 0, 0, 42, 95, 32,
                226, 13, 31, 128, 91, 188, 127, 235, 12, 75, 73, 116, 112, 3, 227, 244, 126, 59,
                81, 214, 118, 144, 243, 195, 17, 82, 216, 119, 170, 32, 239, 247, 71, 249, 241, 98,
                133, 53, 46, 37, 100, 242, 94, 231, 241, 184, 8, 69, 192, 69, 67, 1, 116, 251, 229,
                226, 99, 119, 79, 255, 71, 43, 64, 242, 19, 0, 0, 0, 0, 0,
            ];

            const BULLSHARK_PACKAGE: &[u8] = &[
                1, 135, 35, 29, 28, 138, 126, 114, 145, 204, 122, 145, 8, 244, 199, 188, 26, 10,
                28, 14, 182, 55, 91, 91, 97, 10, 245, 202, 35, 223, 14, 140, 86, 1, 0, 0, 0, 0, 0,
                0, 0, 1, 9, 98, 117, 108, 108, 115, 104, 97, 114, 107, 162, 6, 161, 28, 235, 11, 6,
                0, 0, 0, 10, 1, 0, 12, 2, 12, 36, 3, 48, 61, 4, 109, 12, 5, 121, 137, 1, 7, 130, 2,
                239, 1, 8, 241, 3, 96, 6, 209, 4, 82, 10, 163, 5, 5, 12, 168, 5, 75, 0, 7, 1, 16,
                2, 9, 2, 21, 2, 22, 2, 23, 0, 0, 2, 0, 1, 3, 7, 1, 0, 0, 2, 1, 12, 1, 0, 1, 2, 2,
                12, 1, 0, 1, 2, 4, 12, 1, 0, 1, 4, 5, 2, 0, 5, 6, 7, 0, 0, 12, 0, 1, 0, 0, 13, 2,
                1, 0, 0, 8, 3, 1, 0, 1, 20, 7, 8, 1, 0, 2, 8, 18, 19, 1, 0, 2, 10, 10, 11, 1, 2, 2,
                14, 17, 1, 1, 0, 3, 17, 7, 1, 1, 12, 3, 18, 16, 1, 1, 12, 4, 19, 13, 14, 0, 5, 15,
                5, 6, 0, 3, 6, 5, 9, 7, 12, 8, 15, 6, 9, 4, 9, 2, 8, 0, 7, 8, 5, 0, 4, 7, 11, 4, 1,
                8, 0, 3, 5, 7, 8, 5, 2, 7, 11, 4, 1, 8, 0, 11, 2, 1, 8, 0, 2, 11, 3, 1, 8, 0, 11,
                4, 1, 8, 0, 1, 10, 2, 1, 8, 6, 1, 9, 0, 1, 11, 1, 1, 9, 0, 1, 8, 0, 7, 9, 0, 2, 10,
                2, 10, 2, 10, 2, 11, 1, 1, 8, 6, 7, 8, 5, 2, 11, 4, 1, 9, 0, 11, 3, 1, 9, 0, 1, 11,
                3, 1, 8, 0, 1, 6, 8, 5, 1, 5, 1, 11, 4, 1, 8, 0, 2, 9, 0, 5, 4, 7, 11, 4, 1, 9, 0,
                3, 5, 7, 8, 5, 2, 7, 11, 4, 1, 9, 0, 11, 2, 1, 9, 0, 1, 3, 9, 66, 85, 76, 76, 83,
                72, 65, 82, 75, 4, 67, 111, 105, 110, 12, 67, 111, 105, 110, 77, 101, 116, 97, 100,
                97, 116, 97, 6, 79, 112, 116, 105, 111, 110, 11, 84, 114, 101, 97, 115, 117, 114,
                121, 67, 97, 112, 9, 84, 120, 67, 111, 110, 116, 101, 120, 116, 3, 85, 114, 108, 9,
                98, 117, 108, 108, 115, 104, 97, 114, 107, 4, 98, 117, 114, 110, 4, 99, 111, 105,
                110, 15, 99, 114, 101, 97, 116, 101, 95, 99, 117, 114, 114, 101, 110, 99, 121, 11,
                100, 117, 109, 109, 121, 95, 102, 105, 101, 108, 100, 4, 105, 110, 105, 116, 4,
                109, 105, 110, 116, 17, 109, 105, 110, 116, 95, 97, 110, 100, 95, 116, 114, 97,
                110, 115, 102, 101, 114, 21, 110, 101, 119, 95, 117, 110, 115, 97, 102, 101, 95,
                102, 114, 111, 109, 95, 98, 121, 116, 101, 115, 6, 111, 112, 116, 105, 111, 110,
                20, 112, 117, 98, 108, 105, 99, 95, 102, 114, 101, 101, 122, 101, 95, 111, 98, 106,
                101, 99, 116, 15, 112, 117, 98, 108, 105, 99, 95, 116, 114, 97, 110, 115, 102, 101,
                114, 6, 115, 101, 110, 100, 101, 114, 4, 115, 111, 109, 101, 8, 116, 114, 97, 110,
                115, 102, 101, 114, 10, 116, 120, 95, 99, 111, 110, 116, 101, 120, 116, 3, 117,
                114, 108, 135, 35, 29, 28, 138, 126, 114, 145, 204, 122, 145, 8, 244, 199, 188, 26,
                10, 28, 14, 182, 55, 91, 91, 97, 10, 245, 202, 35, 223, 14, 140, 86, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 2, 10, 2, 10, 9, 66, 85, 76, 76, 83, 72, 65, 82, 75, 10, 2, 20, 19, 66, 117,
                108, 108, 32, 83, 104, 97, 114, 107, 32, 83, 117, 105, 70, 114, 101, 110, 115, 10,
                2, 1, 0, 10, 2, 39, 38, 104, 116, 116, 112, 115, 58, 47, 47, 105, 46, 105, 98, 98,
                46, 99, 111, 47, 104, 87, 89, 50, 87, 53, 120, 47, 98, 117, 108, 108, 115, 104, 97,
                114, 107, 46, 112, 110, 103, 0, 2, 1, 11, 1, 0, 0, 0, 0, 4, 20, 11, 0, 49, 6, 7, 0,
                7, 1, 7, 2, 7, 3, 17, 10, 56, 0, 10, 1, 56, 1, 12, 2, 12, 3, 11, 2, 56, 2, 11, 3,
                11, 1, 46, 17, 9, 56, 3, 2, 1, 1, 4, 0, 1, 6, 11, 0, 11, 1, 11, 2, 11, 3, 56, 4, 2,
                2, 1, 4, 0, 1, 5, 11, 0, 11, 1, 56, 5, 1, 2, 0, 1, 9, 98, 117, 108, 108, 115, 104,
                97, 114, 107, 9, 66, 85, 76, 76, 83, 72, 65, 82, 75, 135, 35, 29, 28, 138, 126,
                114, 145, 204, 122, 145, 8, 244, 199, 188, 26, 10, 28, 14, 182, 55, 91, 91, 97, 10,
                245, 202, 35, 223, 14, 140, 86, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 0, 0, 0, 3, 32, 87, 145, 191, 231, 147, 185,
                46, 159, 240, 181, 95, 126, 236, 65, 154, 55, 16, 196, 229, 218, 47, 59, 99, 197,
                13, 89, 18, 159, 205, 129, 112, 131, 112, 192, 126, 0, 0, 0, 0, 0,
            ];

            for fixture in [IOTA_COIN, IOTA_STAKE, NFT, FUD_COIN, BULLSHARK_PACKAGE] {
                let object: Object = bcs::from_bytes(fixture).unwrap();
                assert_eq!(bcs::to_bytes(&object).unwrap(), fixture);

                let json = serde_json::to_string_pretty(&object).unwrap();
                println!("{json}");
                assert_eq!(object, serde_json::from_str(&json).unwrap());
            }
        }
    }
}
