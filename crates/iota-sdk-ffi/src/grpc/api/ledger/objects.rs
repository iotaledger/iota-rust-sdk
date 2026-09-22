// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use std::sync::Arc;

use iota_sdk::{grpc_client::read_mask_fields::ObjectReadMask, grpc_types::v1 as proto};

use crate::{
    error::{Result, SdkFfiError},
    grpc::client::GrpcClient,
    types::{
        digest::ObjectDigest,
        object::{Object, ObjectId},
        version::Version,
    },
};

/// A reference to an object to fetch with `objects_with_versions`, with an
/// optional version. If no version is provided, the latest version is
/// returned.
#[derive(uniffi::Record)]
pub struct ObjectRequest {
    /// The id of the object.
    pub object_id: Arc<ObjectId>,
    /// The optional version of the object.
    #[uniffi(default = None)]
    pub version: Option<Arc<Version>>,
}

/// An object as returned by the gRPC ledger service.
///
/// The `object_id`, `version` and `digest` fields come from the `reference`
/// sub-fields of the read mask. The `object` field is deserialized from BCS,
/// so the read mask must include `bcs` for it to be populated.
#[derive(uniffi::Record)]
pub struct GrpcObject {
    /// The id of the object.
    pub object_id: Option<Arc<ObjectId>>,
    /// The version of the object.
    pub version: Option<Arc<Version>>,
    /// The digest of the object.
    pub digest: Option<Arc<ObjectDigest>>,
    /// The object itself.
    pub object: Option<Arc<Object>>,
}

impl TryFrom<&proto::object::Object> for GrpcObject {
    type Error = SdkFfiError;

    fn try_from(value: &proto::object::Object) -> Result<Self> {
        let reference = value.reference.as_ref();
        Ok(Self {
            object_id: reference
                .and_then(|reference| reference.object_id.as_ref())
                .map(|object_id| object_id.object_id().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            version: reference
                .and_then(|reference| reference.version)
                .map(Version::from_u64)
                .map(Arc::new),
            digest: reference
                .and_then(|reference| reference.digest.as_ref())
                .map(iota_sdk::types::ObjectDigest::try_from)
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
            object: value
                .bcs
                .as_ref()
                .map(|_| value.object().map_err(SdkFfiError::new))
                .transpose()?
                .map(Into::into)
                .map(Arc::new),
        })
    }
}

fn convert_objects(
    objects: Vec<iota_sdk::grpc_client::GrpcResult<proto::object::Object>>,
) -> Result<Vec<GrpcObject>> {
    objects
        .into_iter()
        .map(|object| GrpcObject::try_from(&object?))
        .collect()
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the latest version of objects by their ids.
    ///
    /// Results are returned in the same order as the input ids.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the reference and the object are returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn objects(
        &self,
        object_ids: Vec<Arc<ObjectId>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<GrpcObject>> {
        let ids = object_ids.iter().map(|id| ***id).collect::<Vec<_>>();
        convert_objects(
            self.client()
                .objects(
                    ids,
                    crate::grpc::api::read_mask::<ObjectReadMask>(&read_mask),
                )
                .await?
                .into_inner(),
        )
    }

    /// Get objects by their ids and optional versions.
    ///
    /// Results are returned in the same order as the input requests.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the reference and the object are returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn objects_with_versions(
        &self,
        requests: Vec<ObjectRequest>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<GrpcObject>> {
        let refs = requests
            .iter()
            .map(|request| {
                (
                    **request.object_id,
                    request.version.as_ref().map(|version| ***version),
                )
            })
            .collect::<Vec<_>>();
        convert_objects(
            self.client()
                .objects_with_versions(
                    refs,
                    crate::grpc::api::read_mask::<ObjectReadMask>(&read_mask),
                )
                .await?
                .into_inner(),
        )
    }
}

#[cfg(test)]
mod tests {
    use iota_sdk::{
        grpc_types::v1::{self as proto, versioned::VersionedObject},
        types::{
            Address, MoveObjectType, MoveStruct, ObjectData, ObjectId, Owner, StructTag,
            TransactionDigest, Version,
        },
    };

    use super::GrpcObject;

    fn object() -> iota_sdk::types::Object {
        let object_id = ObjectId::from([7; 32]);
        let mut contents = object_id.as_bytes().to_vec();
        contents.extend_from_slice(&1_000u64.to_le_bytes());
        let data = MoveStruct::new(
            MoveObjectType::new(StructTag::new_gas_coin()),
            Version::from_u64(3),
            contents,
        )
        .unwrap();
        iota_sdk::types::Object::new(
            ObjectData::Struct(data),
            Owner::Address(Address::from([1; 32])),
            TransactionDigest::from([2; 32]),
            42,
        )
    }

    fn reference(object: &iota_sdk::types::Object) -> proto::types::ObjectReference {
        let mut reference = proto::types::ObjectReference::default();
        reference.object_id = Some(object.id().into());
        reference.version = Some(object.version().as_u64());
        reference.digest = Some(object.digest().into());
        reference
    }

    #[test]
    fn default_mask_populates_reference_and_object() {
        let object = object();
        let mut value = proto::object::Object::default();
        value.reference = Some(reference(&object));
        value.bcs =
            Some(proto::bcs::BcsData::serialize(&VersionedObject::V1(object.clone())).unwrap());

        let converted = GrpcObject::try_from(&value).unwrap();

        assert_eq!(converted.object_id.unwrap().0, object.id());
        assert_eq!(
            converted.version.unwrap().as_u64(),
            object.version().as_u64()
        );
        assert_eq!(converted.digest.unwrap().0, object.digest());
        assert_eq!(converted.object.unwrap().0, object);
    }

    #[test]
    fn reference_only_mask_leaves_the_object_unset() {
        let object = object();
        let mut value = proto::object::Object::default();
        value.reference = Some(reference(&object));

        let converted = GrpcObject::try_from(&value).unwrap();

        assert!(converted.object_id.is_some());
        assert!(converted.version.is_some());
        assert!(converted.digest.is_some());
        assert!(converted.object.is_none());
    }

    #[test]
    fn partial_reference_mask_populates_only_the_requested_fields() {
        let mut reference = proto::types::ObjectReference::default();
        reference.version = Some(5);
        let mut value = proto::object::Object::default();
        value.reference = Some(reference);

        let converted = GrpcObject::try_from(&value).unwrap();

        assert!(converted.object_id.is_none());
        assert_eq!(converted.version.unwrap().as_u64(), 5);
        assert!(converted.digest.is_none());
        assert!(converted.object.is_none());
    }

    #[test]
    fn invalid_bcs_is_an_error() {
        let mut value = proto::object::Object::default();
        value.bcs = Some(proto::bcs::BcsData::from(vec![0xff, 0xff]));

        assert!(GrpcObject::try_from(&value).is_err());
    }
}
