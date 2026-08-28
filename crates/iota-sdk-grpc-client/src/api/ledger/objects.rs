// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for object queries.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, ObjectReadMask},
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
        Error, MetadataEnvelope, Result, check_object_identity, check_result_count, collect_stream,
        into_item_results, proto_object_id, saturating_usize_to_u32,
    },
};

impl Client {
    /// Get objects by their IDs.
    ///
    /// Returns proto `Object` types. Use `obj.object()` to convert to SDK
    /// type, or use `obj.object_reference()` to get the object reference.
    ///
    /// Results are returned in the same order as the input IDs, one per ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `refs` is empty.
    ///
    /// Each ID gets its own result: an object that is not found (never
    /// existed, was deleted, or has been pruned by the serving node) yields
    /// [`Error::Server`] with code `NOT_FOUND` in that slot only, leaving the
    /// other objects intact. The outer `Result` is reserved for failures of the
    /// call itself, such as a transport error, and for a server that answered
    /// with a different number of results than IDs requested
    /// ([`UnexpectedResultCount`]), which leaves no way to tell which ID each
    /// result belongs to, or answered a position with a different object than
    /// the one requested there ([`UnexpectedObject`]). The answered id is read
    /// from the object reference or its BCS, so a read mask that includes
    /// neither leaves nothing to check.
    ///
    /// [`UnexpectedResultCount`]: crate::ProtocolError::UnexpectedResultCount
    /// [`UnexpectedObject`]: crate::ProtocolError::UnexpectedObject
    ///
    /// Uses the default field mask `ObjectReadMask::default()`. Use
    /// [`get_objects_masked`](Self::get_objects_masked) to specify a custom
    /// mask.
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
    /// let ids = [object_id];
    ///
    /// let objs = client.get_objects(ids).await?;
    ///
    /// for obj in objs.body() {
    ///     let obj = match obj {
    ///         Ok(obj) => obj,
    ///         // Only this ID failed; the remaining objects are still usable
    ///         Err(e) => {
    ///             eprintln!("could not read object: {e}");
    ///             continue;
    ///         }
    ///     };
    ///
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
    ) -> Result<MetadataEnvelope<Vec<Result<Object>>>> {
        let refs = refs.into_iter().map(|id| (id, None)).collect::<Vec<_>>();

        self.get_objects_internal(refs, Default::default()).await
    }

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
    /// Each ID gets its own result: an object that is not found (never
    /// existed, was deleted, or has been pruned by the serving node) yields
    /// [`Error::Server`] with code `NOT_FOUND` in that slot only, leaving the
    /// other objects intact. The outer `Result` is reserved for failures of the
    /// call itself, such as a transport error, and for a server that answered
    /// with a different number of results than IDs requested
    /// ([`UnexpectedResultCount`]), which leaves no way to tell which ID each
    /// result belongs to, or answered a position with a different object than
    /// the one requested there ([`UnexpectedObject`]). The answered id is read
    /// from the object reference or its BCS, so a read mask that includes
    /// neither leaves nothing to check.
    ///
    /// [`UnexpectedResultCount`]: crate::ProtocolError::UnexpectedResultCount
    /// [`UnexpectedObject`]: crate::ProtocolError::UnexpectedObject
    ///
    /// # Read Mask
    ///
    /// The `read_mask` parameter controls which fields the server returns.
    /// Pass an [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField)
    /// or any slice/array/vec of fields — conversion is automatic.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::Client;
    /// # use iota_sdk_grpc_client::read_mask_fields::ObjectField;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    /// let ids = [object_id];
    ///
    /// // Single field
    /// let objs = client
    ///     .get_objects_masked(ids, ObjectField::REFERENCE_OBJECT_ID)
    ///     .await?;
    ///
    /// // Multiple fields
    /// let objs = client
    ///     .get_objects_masked(ids, [ObjectField::REFERENCE, ObjectField::BCS])
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     let obj = match obj {
    ///         Ok(obj) => obj,
    ///         // Only this ID failed; the remaining objects are still usable
    ///         Err(e) => {
    ///             eprintln!("could not read object: {e}");
    ///             continue;
    ///         }
    ///     };
    ///
    ///     // Convert proto object to SDK type
    ///     let sdk_obj = obj.object()?;
    ///     println!("Got object ID: {:?}", sdk_obj.id());
    ///     let obj_ref = obj.object_reference()?;
    ///     println!("Object version: {:?}", obj_ref.version());
    /// }
    ///
    /// // Results line up with the requested IDs, so pair them to find out
    /// // which objects the node does not have
    /// let missing: Vec<ObjectId> = ids
    ///     .iter()
    ///     .zip(objs.body())
    ///     .filter_map(|(id, result)| match result {
    ///         Err(e) if e.is_not_found() => Some(*id),
    ///         _ => None,
    ///     })
    ///     .collect();
    /// println!("Missing objects: {missing:?}");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_objects_masked(
        &self,
        refs: impl IntoIterator<Item = ObjectId>,
        read_mask: impl IntoReadMask<ObjectReadMask>,
    ) -> Result<MetadataEnvelope<Vec<Result<Object>>>> {
        let refs = refs.into_iter().map(|id| (id, None)).collect::<Vec<_>>();

        self.get_objects_internal(refs, read_mask.into_read_mask())
            .await
    }

    /// Get objects by their IDs and optional versions.
    ///
    /// Returns proto `Object` types. Use `obj.object()` to convert to SDK
    /// type, or use `obj.object_reference()` to get the object reference.
    ///
    /// Results are returned in the same order as the input refs, one per ref.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyRequest`] if `refs` is empty.
    ///
    /// Each ref gets its own result, with the same meaning as in
    /// [`get_objects`](Client::get_objects): a requested version the serving
    /// node does not have fails only its own slot.
    ///
    /// # Read Mask
    ///
    /// The `read_mask` parameter controls which fields the server returns; use
    /// `ObjectReadMask::default()` for the default mask, or pass an
    /// [`ObjectReadMask`](iota_grpc_types::read_mask_fields::ObjectReadMask)
    /// built from an
    /// [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField) or any
    /// slice/array/vec of fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::{Client, ReadMask};
    /// # use iota_sdk_grpc_client::read_mask_fields::ObjectField;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = Client::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    ///
    /// // Get objects with default mask
    /// let objs = client
    ///     .get_objects_with_versions([(object_id, None)])
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     let obj = match obj {
    ///         Ok(obj) => obj,
    ///         // Only this ID failed; the remaining objects are still usable
    ///         Err(e) => {
    ///             eprintln!("could not read object: {e}");
    ///             continue;
    ///         }
    ///     };
    ///
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
    ) -> Result<MetadataEnvelope<Vec<Result<Object>>>> {
        self.get_objects_internal(refs.into_iter().collect(), Default::default())
            .await
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
    /// The `read_mask` parameter controls which fields the server returns.
    /// Pass an [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField)
    /// or any slice/array/vec of fields — conversion is automatic.
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
    ///     .get_objects_with_versions_masked([(object_id, None)], ObjectReadMask::default())
    ///     .await?;
    ///
    /// // Selected fields
    /// let objs = client
    ///     .get_objects_with_versions_masked(
    ///         [(object_id, None)],
    ///         ObjectReadMask::from(ObjectField::REFERENCE_OBJECT_ID),
    ///     )
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     let obj = match obj {
    ///         Ok(obj) => obj,
    ///         // Only this ID failed; the remaining objects are still usable
    ///         Err(e) => {
    ///             eprintln!("could not read object: {e}");
    ///             continue;
    ///         }
    ///     };
    ///
    ///     // Convert proto object to SDK type
    ///     let sdk_obj = obj.object()?;
    ///     println!("Got object ID: {:?}", sdk_obj.id());
    ///     let obj_ref = obj.object_reference()?;
    ///     println!("Object version: {:?}", obj_ref.version());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_objects_with_versions_masked(
        &self,
        refs: impl IntoIterator<Item = (ObjectId, Option<Version>)>,
        read_mask: impl IntoReadMask<ObjectReadMask>,
    ) -> Result<MetadataEnvelope<Vec<Result<Object>>>> {
        self.get_objects_internal(refs.into_iter().collect(), read_mask.into_read_mask())
            .await
    }

    async fn get_objects_internal(
        &self,
        refs: Vec<(ObjectId, Option<Version>)>,
        read_mask: ObjectReadMask,
    ) -> Result<MetadataEnvelope<Vec<Result<Object>>>> {
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
            .with_read_mask(read_mask);

        if let Some(max_size) = self.max_decoding_message_size() {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        let mut client = self.ledger_service_client();

        let response = client.get_objects(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        let response = collect_stream(stream, metadata, |msg| {
            Ok((msg.has_next, into_item_results(msg.objects)))
        })
        .await?;
        check_result_count(response.body(), refs.len())?;
        check_object_identity(response.body(), &refs)?;

        Ok(response)
    }
}
