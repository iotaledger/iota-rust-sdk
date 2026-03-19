// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use super::{
    Address, AddressParseError, Digest, Identifier, MovePackage, ObjectId, StructTag, TypeOrigin,
    TypeTag, UpgradeInfo, Version,
};

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
#[derive(Clone, Copy, Debug, Ord, PartialOrd, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
/// owner-address   = %x00 address
/// owner-object    = %x01 object-id
/// owner-shared    = %x02 u64
/// owner-immutable = %x03
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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

    /// Returns an address if this object is owned by an address or
    /// object, and None if it is shared or immutable.
    pub fn address(&self) -> Option<&Address> {
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
/// object-data-struct  = %x00 object-move-struct
/// object-data-package = %x01 object-move-package
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::large_enum_variant)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
}

/// A [`StructTag`] with optimized BCS serialization for object types.
///
/// GasCoin, StakedIota, and Coin variants use compact enum encoding
/// instead of the full StructTag representation.
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
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
// TODO hand-roll a Deserialize impl to enforce that an objectid is present
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveStruct {
    /// The type of this object. Uses optimized BCS serialization.
    pub type_: MoveObjectType,
    /// Number that increases each time a tx takes this object as a mutable
    /// input This is a lamport timestamp, not a sequentially increasing
    /// version
    #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
    pub version: Version,
    /// BCS bytes of a Move struct value
    #[cfg_attr(
        feature = "serde",
        serde(with = "::serde_with::As::<::serde_with::Bytes>")
    )]
    #[cfg_attr(feature = "proptest", any(proptest::collection::size_range(32..=1024).lift()))]
    pub contents: Vec<u8>,
}

impl MoveStruct {
    pub fn type_(&self) -> &MoveObjectType {
        &self.type_
    }

    pub fn is_type(&self, s: &StructTag) -> bool {
        self.type_.is(s)
    }

    pub fn id(&self) -> ObjectId {
        Self::id_opt(&self.contents).unwrap()
    }

    // TODO unsure about this
    pub fn id_opt(contents: &[u8]) -> Result<ObjectId, AddressParseError> {
        ObjectId::from_bytes(contents)
    }

    /// Return the `value: u64` field of a `Coin<T>` type.
    /// Useful for reading the coin without deserializing the object into a Move
    /// value. It is the caller's responsibility to check that `self` is a coin.
    /// This function may panic or do something unexpected otherwise.
    pub fn get_coin_value_unsafe(&self) -> u64 {
        debug_assert!(self.type_.is_coin());
        // 32 bytes for object ID, 8 for balance
        debug_assert!(self.contents.len() == 40);

        // unwrap safe because we checked that it is a coin
        u64::from_le_bytes(<[u8; 8]>::try_from(&self.contents[ObjectId::LENGTH..]).unwrap())
    }

    /// Update the `value: u64` field of a `Coin<T>` type.
    /// Useful for updating the coin without deserializing the object into a
    /// Move value. It is the caller's responsibility to check that `self` is a
    /// coin.
    /// This function may panic or do something unexpected otherwise.
    pub fn set_coin_value_unsafe(&mut self, value: u64) {
        debug_assert!(self.type_.is_coin());
        // 32 bytes for object ID, 8 for balance
        debug_assert!(self.contents.len() == 40);

        self.contents
            .splice(ObjectId::LENGTH.., value.to_le_bytes());
    }

    // /// Update the `timestamp_ms: u64` field of the `Clock` type.
    // ///
    // /// Panics if the object isn't a `Clock`.
    // pub fn set_clock_timestamp_ms_unsafe(&mut self, timestamp_ms: u64) {
    //     assert!(self.is_clock());
    //     // 32 bytes for object ID, 8 for timestamp
    //     assert!(self.contents.len() == 40);

    //     self.contents
    //         .splice(ID_END_INDEX.., timestamp_ms.to_le_bytes());
    // }

    pub fn is_coin(&self) -> bool {
        self.type_.is_coin()
    }

    pub fn is_staked_iota(&self) -> bool {
        self.type_.is_staked_iota()
    }

    pub fn is_clock(&self) -> bool {
        self.type_.is(&StructTag::new_clock())
    }

    pub fn version(&self) -> Version {
        self.version
    }

    // /// Contents of the object that are specific to its type--i.e., not its ID
    // /// and version, which all objects have For example if the object was
    // /// declared as `struct S has key { id: ID, f1: u64, f2: bool },
    // /// this returns the slice containing `f1` and `f2`.
    // #[cfg(test)]
    // pub fn type_specific_contents(&self) -> &[u8] {
    //     &self.contents[ID_END_INDEX..]
    // }

    // fn update_contents_with_limit(
    //     &mut self,
    //     new_contents: Vec<u8>,
    //     max_move_object_size: u64,
    // ) -> Result<(), ExecutionError> {
    //     if new_contents.len() as u64 > max_move_object_size {
    //         return Err(ExecutionError::from_kind(
    //             ExecutionErrorKind::ObjectTooBig {
    //                 object_size: new_contents.len() as u64,
    //                 max_object_size: max_move_object_size,
    //             },
    //         ));
    //     }

    //     #[cfg(debug_assertions)]
    //     let old_id = self.id();
    //     self.contents = new_contents;

    //     // Update should not modify ID
    //     #[cfg(debug_assertions)]
    //     debug_assert_eq!(self.id(), old_id);

    //     Ok(())
    // }

    /// Sets the version of this object to a new value which is assumed to be
    /// higher (and checked to be higher in debug).
    pub fn increment_version_to(&mut self, next: Version) {
        debug_assert!(
            self.version < next,
            "Not an increment: {} to {next}",
            self.version
        );
        self.version = next;
    }

    pub fn decrement_version_to(&mut self, prev: Version) {
        debug_assert!(
            prev < self.version,
            "Not a decrement: {} to {prev}",
            self.version
        );
        self.version = prev;
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn into_contents(self) -> Vec<u8> {
        self.contents
    }

    pub fn into_type(self) -> MoveObjectType {
        self.type_
    }

    pub fn into_inner(self) -> (MoveObjectType, Vec<u8>) {
        (self.type_, self.contents)
    }

    #[cfg(feature = "serde")]
    pub fn to_rust<'de, T: serde::Deserialize<'de>>(&'de self) -> Option<T> {
        bcs::from_bytes(self.contents()).ok()
    }

    /// Approximate size of the object in bytes. This is used for gas metering.
    /// For the type tag field, we serialize it on the spot to get the accurate
    /// size. This should not be very expensive since the type tag is
    /// usually simple, and we only do this once per object being mutated.
    pub fn object_size_for_gas_metering(&self) -> usize {
        let serialized_type_tag_size =
            bcs::serialized_size(&self.type_).expect("Serializing type tag should not fail");
        // + 8 for `version`
        self.contents.len() + serialized_type_tag_size + 8
    }
}

/// Type of an IOTA object
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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
    pub fn object_id(&self) -> ObjectId {
        match &self.data {
            ObjectData::Struct(struct_) => id_opt(&struct_.contents).unwrap(),
            ObjectData::Package(package) => package.id,
        }
    }

    /// Return this object's reference
    #[cfg(all(feature = "hash", feature = "serde"))]
    pub fn object_ref(&self) -> ObjectReference {
        ObjectReference {
            object_id: self.object_id(),
            version: self.version(),
            digest: self.digest(),
        }
    }

    /// Return this object's version
    pub fn version(&self) -> Version {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.version,
            ObjectData::Package(package) => package.version,
        }
    }

    /// Return this object's type
    pub fn object_type(&self) -> ObjectType {
        match &self.data {
            ObjectData::Struct(struct_) => ObjectType::Struct((*struct_.type_).clone()),
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
    pub fn to_rust<T: serde::de::DeserializeOwned>(
        &self,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
        let contents = &self.as_struct_opt().ok_or("not a struct")?.contents;
        Ok(bcs::from_bytes::<T>(contents)?)
    }
}

fn id_opt(contents: &[u8]) -> Option<ObjectId> {
    if ObjectId::LENGTH > contents.len() {
        return None;
    }

    Some(ObjectId::from(
        Address::from_bytes(&contents[..ObjectId::LENGTH]).unwrap(),
    ))
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
            ObjectData::Struct(struct_) => id_opt(&struct_.contents).unwrap(),
            ObjectData::Package(package) => package.id,
        }
    }

    pub fn version(&self) -> Version {
        match &self.data {
            ObjectData::Struct(struct_) => struct_.version,
            ObjectData::Package(package) => package.version,
        }
    }

    pub fn object_type(&self) -> ObjectType {
        match &self.data {
            ObjectData::Struct(struct_) => ObjectType::Struct((*struct_.type_).clone()),
            ObjectData::Package(_) => ObjectType::Package,
        }
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn data(&self) -> &ObjectData {
        &self.data
    }
}

// TODO improve ser/de to do borrowing to avoid clones where possible
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::{borrow::Cow, str::FromStr};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{DeserializeAs, SerializeAs};

    use super::*;
    use crate::TypeTag;

    #[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(rename = "Owner")]
    #[cfg_attr(
        feature = "schemars",
        derive(schemars::JsonSchema),
        schemars(rename = "Owner")
    )]
    enum ReadableOwner {
        /// Object is exclusively owned by a single address, and is mutable.
        AddressOwner(Address),
        /// Object is exclusively owned by a single object, and is mutable.
        /// The object ID is converted to IotaAddress as IotaAddress is
        /// universal.
        ObjectOwner(Address),
        /// Object is shared, can be used by any address, and is mutable.
        Shared {
            /// The version at which the object became shared
            initial_shared_version: Version,
        },
        /// Object is immutable, and hence ownership doesn't matter.
        Immutable,
    }

    impl Serialize for Owner {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let readable_owner = match self {
                Owner::Address(address) => ReadableOwner::AddressOwner(*address),
                Owner::Object(object_id) => ReadableOwner::ObjectOwner(*object_id.as_address()),
                Owner::Shared(initial_shared_version) => ReadableOwner::Shared {
                    initial_shared_version: *initial_shared_version,
                },
                Owner::Immutable => ReadableOwner::Immutable,
            };
            readable_owner.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Owner {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let readable_owner = ReadableOwner::deserialize(deserializer)?;
            Ok(match readable_owner {
                ReadableOwner::AddressOwner(address) => Owner::Address(address),
                ReadableOwner::ObjectOwner(address) => {
                    Owner::Object(ObjectId::from_address(address))
                }
                ReadableOwner::Shared {
                    initial_shared_version,
                } => Owner::Shared(initial_shared_version),
                ReadableOwner::Immutable => Owner::Immutable,
            })
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for Owner {
        fn schema_name() -> String {
            ReadableOwner::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            ReadableOwner::json_schema(generator)
        }
    }

    /// Wrapper around StructTag with a space-efficient representation for
    /// common types like coins The StructTag for a gas coin is 84 bytes, so
    /// using 1 byte instead is a win. The inner representation is private
    /// to prevent incorrectly constructing an `Other` instead of one of the
    /// specialized variants, e.g. `Other(GasCoin::type_())` instead of
    /// `GasCoin`
    #[derive(serde::Deserialize)]
    #[serde(rename = "MoveObjectType")]
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

    struct ReadableObjectType;

    impl SerializeAs<ObjectType> for ReadableObjectType {
        fn serialize_as<S>(source: &ObjectType, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match source {
                ObjectType::Package => "package".serialize(serializer),
                ObjectType::Struct(s) => s.serialize(serializer),
            }
        }
    }

    impl<'de> DeserializeAs<'de, ObjectType> for ReadableObjectType {
        fn deserialize_as<D>(deserializer: D) -> Result<ObjectType, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            if s == "package" {
                Ok(ObjectType::Package)
            } else {
                let struct_tag = StructTag::from_str(&s)
                    .map_err(|_| serde::de::Error::custom("invalid object type"))?;
                Ok(ObjectType::Struct(struct_tag))
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename = "Object")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct ReadableObject {
        object_id: ObjectId,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
        owner: Owner,
        #[serde(with = "::serde_with::As::<ReadableObjectType>")]
        #[serde(rename = "type")]
        #[cfg_attr(feature = "schemars", schemars(with = "String"))]
        type_: ObjectType,
        #[serde(flatten)]
        data: ReadableObjectData,
        previous_transaction: Digest,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        storage_rebate: u64,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for Object {
        fn schema_name() -> String {
            ReadableObject::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            ReadableObject::json_schema(generator)
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    #[cfg_attr(
        feature = "schemars",
        derive(schemars::JsonSchema),
        schemars(rename = "ObjectData")
    )]
    enum ReadableObjectData {
        Move(ReadableMoveStruct),
        Package(ReadablePackage),
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[cfg_attr(
        feature = "schemars",
        derive(schemars::JsonSchema),
        schemars(rename = "Package")
    )]
    struct ReadablePackage {
        #[serde(
            with = "::serde_with::As::<BTreeMap<::serde_with::Same, crate::_serde::Base64Encoded>>"
        )]
        #[cfg_attr(
            feature = "schemars",
            schemars(with = "BTreeMap<Identifier, crate::_schemars::Base64>")
        )]
        modules: BTreeMap<Identifier, Vec<u8>>,
        type_origin_table: Vec<TypeOrigin>,
        linkage_table: BTreeMap<ObjectId, UpgradeInfo>,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[cfg_attr(
        feature = "schemars",
        derive(schemars::JsonSchema),
        schemars(rename = "MoveStruct")
    )]
    struct ReadableMoveStruct {
        #[serde(with = "::serde_with::As::<crate::_serde::Base64Encoded>")]
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
        contents: Vec<u8>,
    }

    impl Object {
        fn readable_object_data(&self) -> ReadableObjectData {
            match &self.data {
                ObjectData::Struct(struct_) => ReadableObjectData::Move(ReadableMoveStruct {
                    contents: struct_.contents.clone(),
                }),
                ObjectData::Package(package) => ReadableObjectData::Package(ReadablePackage {
                    modules: package.modules.clone(),
                    type_origin_table: package.type_origin_table.clone(),
                    linkage_table: package.linkage_table.clone(),
                }),
            }
        }
    }

    impl Serialize for Object {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = ReadableObject {
                    object_id: self.object_id(),
                    version: self.version(),
                    // digest: todo!(),
                    owner: self.owner,
                    previous_transaction: self.previous_transaction,
                    storage_rebate: self.storage_rebate,
                    type_: self.object_type(),
                    data: self.readable_object_data(),
                };
                readable.serialize(serializer)
            } else {
                let binary = BinaryObject {
                    data: self.data.clone(),
                    owner: self.owner,
                    previous_transaction: self.previous_transaction,
                    storage_rebate: self.storage_rebate,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for Object {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableObject {
                    object_id,
                    version,
                    owner,
                    previous_transaction,
                    storage_rebate,
                    type_,
                    data,
                } = Deserialize::deserialize(deserializer)?;

                // check if package or struct
                let data = match (type_, data) {
                    (
                        ObjectType::Package,
                        ReadableObjectData::Package(ReadablePackage {
                            modules,
                            type_origin_table,
                            linkage_table,
                        }),
                    ) => ObjectData::Package(MovePackage {
                        id: object_id,
                        version,
                        modules,
                        type_origin_table,
                        linkage_table,
                    }),
                    (
                        ObjectType::Struct(type_),
                        ReadableObjectData::Move(ReadableMoveStruct { contents }),
                    ) => {
                        // check id matches in contents
                        if id_opt(&contents).is_none_or(|id| id != object_id) {
                            return Err(serde::de::Error::custom("id from contents doesn't match"));
                        }

                        ObjectData::Struct(MoveStruct {
                            type_: type_.into(),
                            version,
                            contents,
                        })
                    }
                    _ => return Err(serde::de::Error::custom("type and data don't match")),
                };

                Ok(Object {
                    data,
                    owner,
                    previous_transaction,
                    storage_rebate,
                })
            } else {
                let BinaryObject {
                    data,
                    owner,
                    previous_transaction,
                    storage_rebate,
                } = Deserialize::deserialize(deserializer)?;

                Ok(Object {
                    data,
                    owner,
                    previous_transaction,
                    storage_rebate,
                })
            }
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct BinaryObject {
        data: ObjectData,
        owner: Owner,
        previous_transaction: Digest,
        storage_rebate: u64,
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename = "GenesisObject")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct ReadableGenesisObject {
        object_id: ObjectId,
        #[serde(with = "crate::_serde::ReadableDisplay")]
        #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
        version: Version,
        owner: Owner,
        #[serde(with = "::serde_with::As::<ReadableObjectType>")]
        #[serde(rename = "type")]
        #[cfg_attr(feature = "schemars", schemars(with = "String"))]
        type_: ObjectType,
        #[serde(flatten)]
        data: ReadableObjectData,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for GenesisObject {
        fn schema_name() -> String {
            ReadableGenesisObject::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            ReadableGenesisObject::json_schema(generator)
        }
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    enum BinaryGenesisObject {
        RawObject { data: ObjectData, owner: Owner },
    }

    impl GenesisObject {
        fn readable_object_data(&self) -> ReadableObjectData {
            match &self.data {
                ObjectData::Struct(struct_) => ReadableObjectData::Move(ReadableMoveStruct {
                    contents: struct_.contents.clone(),
                }),
                ObjectData::Package(package) => ReadableObjectData::Package(ReadablePackage {
                    modules: package.modules.clone(),
                    type_origin_table: package.type_origin_table.clone(),
                    linkage_table: package.linkage_table.clone(),
                }),
            }
        }
    }

    impl Serialize for GenesisObject {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let readable = ReadableGenesisObject {
                    object_id: self.object_id(),
                    version: self.version(),
                    owner: self.owner,
                    type_: self.object_type(),
                    data: self.readable_object_data(),
                };
                readable.serialize(serializer)
            } else {
                let binary = BinaryGenesisObject::RawObject {
                    data: self.data.clone(),
                    owner: self.owner,
                };
                binary.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for GenesisObject {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let ReadableGenesisObject {
                    object_id,
                    version,
                    owner,
                    type_,
                    data,
                } = Deserialize::deserialize(deserializer)?;

                // check if package or struct
                let data = match (type_, data) {
                    (
                        ObjectType::Package,
                        ReadableObjectData::Package(ReadablePackage {
                            modules,
                            type_origin_table,
                            linkage_table,
                        }),
                    ) => ObjectData::Package(MovePackage {
                        id: object_id,
                        version,
                        modules,
                        type_origin_table,
                        linkage_table,
                    }),
                    (
                        ObjectType::Struct(type_),
                        ReadableObjectData::Move(ReadableMoveStruct { contents }),
                    ) => {
                        // check id matches in contents
                        if id_opt(&contents).is_none_or(|id| id != object_id) {
                            return Err(serde::de::Error::custom("id from contents doesn't match"));
                        }

                        ObjectData::Struct(MoveStruct {
                            type_: type_.into(),
                            version,
                            contents,
                        })
                    }
                    _ => return Err(serde::de::Error::custom("type and data don't match")),
                };

                Ok(GenesisObject { data, owner })
            } else {
                let BinaryGenesisObject::RawObject { data, owner } =
                    Deserialize::deserialize(deserializer)?;

                Ok(GenesisObject { data, owner })
            }
        }
    }

    // Custom serialization to be backwards compatible with the JSON RPC
    #[derive(serde::Serialize, serde::Deserialize)]
    #[cfg_attr(
        feature = "schemars",
        derive(schemars::JsonSchema),
        schemars(rename = "ObjectReference")
    )]
    struct TupleObjectReference(ObjectId, Version, Digest);

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for ObjectReference {
        fn schema_name() -> String {
            TupleObjectReference::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            TupleObjectReference::json_schema(generator)
        }
    }

    impl Serialize for ObjectReference {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            TupleObjectReference(self.object_id, self.version, self.digest).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectReference {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let TupleObjectReference(object_id, version, digest) =
                TupleObjectReference::deserialize(deserializer)?;

            Ok(ObjectReference {
                object_id,
                version,
                digest,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        #[cfg(target_arch = "wasm32")]
        use wasm_bindgen_test::wasm_bindgen_test as test;

        use super::*;
        use crate::object::Object;

        #[test]
        fn obj() {
            let o = Object {
                data: ObjectData::Struct(MoveStruct {
                    type_: MoveObjectType::new(StructTag::new(
                        Address::FRAMEWORK,
                        Identifier::new("bar").unwrap(),
                        Identifier::new("foo").unwrap(),
                        Vec::new(),
                    )),
                    version: Version::from_u64(12),
                    contents: ObjectId::ZERO.into(),
                }),
                // owner: Owner::Address(Address::ZERO),
                owner: Owner::Object(ObjectId::ZERO),
                // owner: Owner::Immutable,
                // owner: Owner::Shared {
                //     initial_shared_version: 14,
                // },
                previous_transaction: Digest::ZERO,
                storage_rebate: 100,
            };

            println!("{}", serde_json::to_string_pretty(&o).unwrap());
            println!(
                "{}",
                serde_json::to_string_pretty(&ObjectReference {
                    object_id: ObjectId::ZERO,
                    version: Version::from_u64(1),
                    digest: Digest::ZERO,
                })
                .unwrap()
            );
        }

        #[test]
        fn object_reference_tuple_format() {
            let json = r#"["0x0000000000000000000000000000000000000000000000000000000000000000",0,"11111111111111111111111111111111"]"#;
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

            let json = r#"{"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi":[["0x0000000000000000000000000000000000000000000000000000000000000000",0,"11111111111111111111111111111111"]],"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR":[["0x0000000000000000000000000000000000000000000000000000000000000000",0,"11111111111111111111111111111111"]]}"#;

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
