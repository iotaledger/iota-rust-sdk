// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for object queries.

use iota_grpc_types::v1::{
    ledger_service::{GetObjectsRequest, ObjectRequest, ObjectRequests},
    object::Object,
    types::ObjectReference,
};
use iota_types::{ObjectId, Version};

use crate::{
    Client,
    api::{
        Error, GET_OBJECTS_READ_MASK, MetadataEnvelope, ProtoResult, ReadMask, Result,
        collect_stream, field_mask_with_default, proto_object_id, saturating_usize_to_u32,
    },
};

impl Client {
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
    /// The optional `read_mask` parameter controls which fields the server
    /// returns. If `None`, uses [`GET_OBJECTS_READ_MASK`].
    ///
    /// Use [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField)
    /// constants with [`ReadMask::from`] for field selection.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{Client, ReadMask};
    /// # use iota_sdk_grpc_client::read_mask_fields::ObjectField;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new("http://localhost:9000")?;
    /// let object_id: ObjectId = "0x2".parse()?;
    ///
    /// // Get objects with default mask
    /// let objs = client.get_objects(&[(object_id, None)], None).await?;
    ///
    /// // Get objects with field mask (only reference object ID, no BCS)
    /// let objs = client
    ///     .get_objects(
    ///         &[(object_id, None)],
    ///         Some(ReadMask::from(ObjectField::REFERENCE_OBJECT_ID)),
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
        refs: &[(ObjectId, Option<Version>)],
        read_mask: Option<ReadMask<'_>>,
    ) -> Result<MetadataEnvelope<Vec<Object>>> {
        if refs.is_empty() {
            return Err(Error::EmptyRequest);
        }

        let requests = ObjectRequests::default().with_requests(
            refs.iter()
                .map(|(id, version)| {
                    let mut object_ref =
                        ObjectReference::default().with_object_id(proto_object_id(*id));

                    if let Some(v) = version {
                        object_ref = object_ref.with_version(v.as_u64());
                    }

                    ObjectRequest::default().with_object_ref(object_ref)
                })
                .collect(),
        );

        let mut request = GetObjectsRequest::default()
            .with_requests(requests)
            .with_read_mask(field_mask_with_default(read_mask, GET_OBJECTS_READ_MASK));

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
