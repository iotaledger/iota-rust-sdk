// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

include!("../../../generated/iota.grpc.v1.types.rs");
include!("../../../generated/iota.grpc.v1.types.field_info.rs");
include!("../../../generated/iota.grpc.v1.types.accessors.rs");

use crate::proto::{TryFromProtoError, get_inner_field};

impl From<iota_types::Digest> for Digest {
    fn from(value: iota_types::Digest) -> Self {
        Self {
            digest: value.into_inner().to_vec().into(),
        }
    }
}

impl TryFrom<&Digest> for iota_types::Digest {
    type Error = TryFromProtoError;

    fn try_from(value: &Digest) -> Result<Self, Self::Error> {
        iota_types::Digest::from_bytes(&value.digest)
            .map_err(|e| TryFromProtoError::invalid("digest", e))
    }
}

/// The domain-specific digest newtypes are transparent wrappers around
/// [`iota_types::Digest`], so their proto conversions just delegate to it.
macro_rules! impl_digest_wrapper_conversion {
    ($wrapper:ty) => {
        impl From<$wrapper> for Digest {
            fn from(value: $wrapper) -> Self {
                iota_types::Digest::from(value).into()
            }
        }

        impl TryFrom<&Digest> for $wrapper {
            type Error = TryFromProtoError;

            fn try_from(value: &Digest) -> Result<Self, Self::Error> {
                iota_types::Digest::try_from(value).map(Into::into)
            }
        }
    };
}

impl_digest_wrapper_conversion!(iota_types::CheckpointDigest);
impl_digest_wrapper_conversion!(iota_types::CheckpointContentsDigest);
impl_digest_wrapper_conversion!(iota_types::TransactionDigest);
impl_digest_wrapper_conversion!(iota_types::TransactionEffectsDigest);
impl_digest_wrapper_conversion!(iota_types::TransactionEventsDigest);
impl_digest_wrapper_conversion!(iota_types::EffectsAuxDataDigest);
impl_digest_wrapper_conversion!(iota_types::ObjectDigest);
impl_digest_wrapper_conversion!(iota_types::ConsensusCommitDigest);

// Address conversions
impl From<iota_types::Address> for Address {
    fn from(value: iota_types::Address) -> Self {
        Self {
            address: value.as_bytes().to_vec().into(),
        }
    }
}

impl TryFrom<&Address> for iota_types::Address {
    type Error = TryFromProtoError;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        iota_types::Address::from_bytes(&value.address)
            .map_err(|e| TryFromProtoError::invalid("address", e))
    }
}

// ObjectId conversions
impl From<iota_types::ObjectId> for ObjectId {
    fn from(value: iota_types::ObjectId) -> Self {
        Self {
            object_id: Vec::from(value).into(),
        }
    }
}

impl TryFrom<&ObjectId> for iota_types::ObjectId {
    type Error = TryFromProtoError;

    fn try_from(value: &ObjectId) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value
            .object_id
            .as_ref()
            .try_into()
            .map_err(|_| TryFromProtoError::invalid("object_id", "expected 32 bytes"))?;
        Ok(bytes.into())
    }
}

// ObjectReference conversions
impl From<iota_types::ObjectReference> for ObjectReference {
    fn from(value: iota_types::ObjectReference) -> Self {
        Self {
            object_id: Some(value.object_id.into()),
            version: Some(value.version.as_u64()),
            digest: Some(value.digest.into()),
        }
    }
}

impl TryFrom<&ObjectReference> for iota_types::ObjectReference {
    type Error = TryFromProtoError;

    fn try_from(value: &ObjectReference) -> Result<Self, Self::Error> {
        let object_id = value
            .object_id
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing(ObjectReference::OBJECT_ID_FIELD.name))?
            .object_id()
            .map_err(|e| e.nested(ObjectReference::OBJECT_ID_FIELD.name))?;

        let version = value
            .version
            .ok_or_else(|| TryFromProtoError::missing(ObjectReference::VERSION_FIELD.name))?;

        let digest = value
            .digest
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing(ObjectReference::DIGEST_FIELD.name))?;

        let digest = digest
            .try_into()
            .map_err(|e| TryFromProtoError::invalid(ObjectReference::DIGEST_FIELD.name, e))?;

        Ok(iota_types::ObjectReference {
            object_id,
            version: version.into(),
            digest,
        })
    }
}

impl Address {
    /// Deserialize the address to SDK type.
    pub fn address(&self) -> Result<iota_types::Address, TryFromProtoError> {
        self.try_into()
    }
}

impl ObjectId {
    /// Deserialize the object ID to SDK type.
    pub fn object_id(&self) -> Result<iota_types::ObjectId, TryFromProtoError> {
        self.try_into()
    }
}

impl Digest {
    /// Deserialize the digest to SDK type.
    pub fn digest(&self) -> Result<iota_types::Digest, TryFromProtoError> {
        self.try_into()
    }
}

impl ObjectReference {
    /// Deserialize the full object reference to SDK type.
    pub fn object_reference(&self) -> Result<iota_types::ObjectReference, TryFromProtoError> {
        self.try_into()
    }

    /// Get the object ID parsed as SDK type.
    pub fn object_identifier(&self) -> Result<iota_types::ObjectId, TryFromProtoError> {
        self.object_id
            .as_ref()
            .ok_or_else(|| TryFromProtoError::missing(Self::OBJECT_ID_FIELD.name))?
            .object_id()
            .map_err(|e| e.nested(Self::OBJECT_ID_FIELD.name))
    }

    /// Get the object version number.
    pub fn object_version(&self) -> Result<iota_types::Version, TryFromProtoError> {
        self.version
            .map(Into::into)
            .ok_or_else(|| TryFromProtoError::missing(Self::VERSION_FIELD.name))
    }

    /// Get the object digest.
    pub fn digest(&self) -> Result<iota_types::Digest, TryFromProtoError> {
        get_inner_field!(self.digest, Self::DIGEST_FIELD, digest)
    }
}

impl From<&iota_types::TypeTag> for TypeTag {
    fn from(ty: &iota_types::TypeTag) -> Self {
        let type_tag = match ty {
            iota_types::TypeTag::Bool => type_tag::TypeTag::BoolTag(true),
            iota_types::TypeTag::U8 => type_tag::TypeTag::U8Tag(true),
            iota_types::TypeTag::U16 => type_tag::TypeTag::U16Tag(true),
            iota_types::TypeTag::U32 => type_tag::TypeTag::U32Tag(true),
            iota_types::TypeTag::U64 => type_tag::TypeTag::U64Tag(true),
            iota_types::TypeTag::U128 => type_tag::TypeTag::U128Tag(true),
            iota_types::TypeTag::U256 => type_tag::TypeTag::U256Tag(true),
            iota_types::TypeTag::Address => type_tag::TypeTag::AddressTag(true),
            iota_types::TypeTag::Signer => type_tag::TypeTag::SignerTag(true),
            iota_types::TypeTag::Vector(inner) => {
                type_tag::TypeTag::VectorTag(Box::new(TypeTagVector {
                    inner_type: Some(Box::new(inner.as_ref().into())),
                }))
            }
            iota_types::TypeTag::Struct(struct_tag) => {
                type_tag::TypeTag::StructTag(TypeTagStruct {
                    struct_tag: struct_tag.to_canonical_string(true),
                })
            }
        };

        Self {
            type_tag: Some(type_tag),
        }
    }
}

impl TryFrom<&TypeTag> for iota_types::TypeTag {
    type Error = TryFromProtoError;

    fn try_from(value: &TypeTag) -> Result<Self, Self::Error> {
        match &value.type_tag {
            Some(type_tag::TypeTag::BoolTag(_)) => Ok(iota_types::TypeTag::Bool),
            Some(type_tag::TypeTag::U8Tag(_)) => Ok(iota_types::TypeTag::U8),
            Some(type_tag::TypeTag::U16Tag(_)) => Ok(iota_types::TypeTag::U16),
            Some(type_tag::TypeTag::U32Tag(_)) => Ok(iota_types::TypeTag::U32),
            Some(type_tag::TypeTag::U64Tag(_)) => Ok(iota_types::TypeTag::U64),
            Some(type_tag::TypeTag::U128Tag(_)) => Ok(iota_types::TypeTag::U128),
            Some(type_tag::TypeTag::U256Tag(_)) => Ok(iota_types::TypeTag::U256),
            Some(type_tag::TypeTag::AddressTag(_)) => Ok(iota_types::TypeTag::Address),
            Some(type_tag::TypeTag::SignerTag(_)) => Ok(iota_types::TypeTag::Signer),
            Some(type_tag::TypeTag::VectorTag(inner)) => {
                let inner_type = inner
                    .inner_type
                    .as_ref()
                    .ok_or_else(|| TryFromProtoError::missing("type_tag.vector.inner_type"))?;
                let inner_sdk: iota_types::TypeTag = inner_type.as_ref().try_into()?;
                Ok(iota_types::TypeTag::Vector(Box::new(inner_sdk)))
            }
            Some(type_tag::TypeTag::StructTag(struct_tag)) => {
                let parsed: iota_types::StructTag = struct_tag
                    .struct_tag
                    .parse()
                    .map_err(|e| TryFromProtoError::invalid("type_tag.struct_tag", e))?;
                Ok(iota_types::TypeTag::Struct(Box::new(parsed)))
            }
            None => Err(TryFromProtoError::missing("type_tag")),
        }
    }
}

// TypeTag

impl TypeTag {
    /// Deserialize the type tag to SDK type.
    pub fn type_tag(&self) -> Result<iota_types::TypeTag, TryFromProtoError> {
        self.try_into()
    }
}
