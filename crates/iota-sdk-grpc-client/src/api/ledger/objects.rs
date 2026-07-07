// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for object queries.

use iota_grpc_types::{
    read_mask_fields::ObjectReadMask,
    v1::{
        ledger_service::{GetObjectsRequest, ObjectRequest, ObjectRequests},
        object::Object,
        types::ObjectReference,
    },
};
use iota_types::{ObjectId, Version};

use crate::{
    Client,
    api::{
        Error, GET_OBJECTS_READ_MASK, MetadataEnvelope, ProtoResult, Result, collect_stream,
        field_mask_with_default, proto_object_id, saturating_usize_to_u32,
    },
};

impl Client {
    /// Get objects by their IDs.
    ///
    /// Returns proto `Object` types. Use `obj.object()` to convert to SDK
    /// type, or use `obj.object_reference()` to get the object reference.
    ///
    /// Results are returned in the same order as the input refs.
    /// If an object is not found, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `refs` is empty.
    ///
    /// # Read Mask
    ///
    /// The `read_mask` parameter controls which fields the server returns; pass
    /// `None` for the default mask, or an
    /// [`ObjectReadMask`](iota_grpc_types::read_mask_fields::ObjectReadMask)
    /// built from an
    /// [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField) or any
    /// slice/array/vec of fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ObjectField, ObjectReadMask};
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    ///
    /// // Default mask
    /// let objs = client.get_objects([object_id], None).await?;
    ///
    /// // Selected fields
    /// let objs = client
    ///     .get_objects(
    ///         [object_id],
    ///         ObjectReadMask::from([ObjectField::REFERENCE, ObjectField::BCS]),
    ///     )
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     // Convert proto object to SDK type
    ///     let sdk_obj = obj.object()?;
    ///     println!("Got object ID: {:?}", sdk_obj.id());
    ///     let obj_ref = obj.object_reference()?;
    ///     println!("Object version: {:?}", obj_ref.version());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_objects(
        &self,
        refs: impl IntoIterator<Item = ObjectId>,
        read_mask: impl Into<Option<ObjectReadMask>>,
    ) -> Result<MetadataEnvelope<Vec<Object>>> {
        let refs = refs
            .into_iter()
            .map(|id| {
                ObjectRequest::default()
                    .with_object_ref(ObjectReference::default().with_object_id(proto_object_id(id)))
            })
            .collect::<Vec<_>>();

        self.get_objects_internal(refs, read_mask.into()).await
    }

    /// Get objects by their IDs and optional versions.
    ///
    /// Returns proto `Object` types. Use `obj.object()` to convert to SDK
    /// type, or use `obj.object_reference()` to get the object reference.
    ///
    /// Results are returned in the same order as the input refs.
    /// If an object is not found, an error is returned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `refs` is empty.
    ///
    /// # Read Mask
    ///
    /// The `read_mask` parameter controls which fields the server returns; pass
    /// `None` for the default mask, or an
    /// [`ObjectReadMask`](iota_grpc_types::read_mask_fields::ObjectReadMask)
    /// built from an
    /// [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField) or any
    /// slice/array/vec of fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ObjectField, ObjectReadMask};
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    ///
    /// // Default mask
    /// let objs = client
    ///     .get_objects_with_versions([(object_id, None)], None)
    ///     .await?;
    ///
    /// // Selected fields
    /// let objs = client
    ///     .get_objects_with_versions(
    ///         [(object_id, None)],
    ///         ObjectReadMask::from(ObjectField::REFERENCE_OBJECT_ID),
    ///     )
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     // Convert proto object to SDK type
    ///     let sdk_obj = obj.object()?;
    ///     println!("Got object ID: {:?}", sdk_obj.id());
    ///     let obj_ref = obj.object_reference()?;
    ///     println!("Object version: {:?}", obj_ref.version());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_objects_with_versions(
        &self,
        refs: impl IntoIterator<Item = (ObjectId, Option<Version>)>,
        read_mask: impl Into<Option<ObjectReadMask>>,
    ) -> Result<MetadataEnvelope<Vec<Object>>> {
        let refs = refs
            .into_iter()
            .map(|(id, version)| {
                let mut object_ref = ObjectReference::default().with_object_id(proto_object_id(id));

                if let Some(v) = version {
                    object_ref = object_ref.with_version(v.as_u64());
                }

                ObjectRequest::default().with_object_ref(object_ref)
            })
            .collect::<Vec<_>>();

        self.get_objects_internal(refs, read_mask.into()).await
    }

    async fn get_objects_internal(
        &self,
        refs: Vec<ObjectRequest>,
        read_mask: Option<ObjectReadMask>,
    ) -> Result<MetadataEnvelope<Vec<Object>>> {
        if refs.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let requests = ObjectRequests::default().with_requests(refs);

        let mut request = GetObjectsRequest::default()
            .with_requests(requests)
            .with_read_mask(field_mask_with_default(
                read_mask.as_ref().map(|m| m.as_str()),
                GET_OBJECTS_READ_MASK,
            ));

        if let Some(max_size) = self.max_decoding_message_size() {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        let mut client = self.ledger_service_client();

        let response = client.get_objects(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        collect_stream(stream, metadata, |msg| {
            let items = msg
                .objects
                .into_iter()
                .map(|r| r.into_result())
                .collect::<Result<Vec<_>>>()?;
            Ok((msg.has_next, items))
        })
        .await
    }
}
