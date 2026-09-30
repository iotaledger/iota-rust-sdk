// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! High-level API for object queries.

use iota_grpc_types::{
    read_mask_fields::{IntoReadMask, ObjectField, ObjectReadMask},
    v1::{
        ledger_service::{
            GetObjectsRequest, ObjectRequest, ObjectRequests,
            ledger_service_client::LedgerServiceClient,
        },
        object::Object,
        types::ObjectReference,
    },
};
use iota_types::{ObjectId, Version};

use crate::{
    GrpcClient, InterceptedChannel,
    api::{
        GrpcError, GrpcResult, MetadataEnvelope, check_object_identity, check_result_count,
        collect_stream, define_query, into_item_results, proto_object_id, saturating_usize_to_u32,
    },
};

define_query! {
    /// Query for [`GrpcClient::objects`] and
    /// [`GrpcClient::objects_with_versions`]. Await it to send the request.
    pub struct GetObjectsQuery {
        service_client: LedgerServiceClient<InterceptedChannel>,
        max_message_size: Option<usize>,
        refs: Vec<(ObjectId, Option<Version>)>,
        read_mask: ObjectReadMask,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<Object>>>>;
}

impl GetObjectsQuery {
    /// Set the field mask controlling the returned fields.
    pub fn read_mask(mut self, read_mask: impl IntoReadMask<ObjectReadMask>) -> Self {
        self.read_mask = read_mask.into_read_mask();
        self
    }

    fn request(&self) -> GetObjectsRequest {
        let requests = ObjectRequests::default().with_requests(
            self.refs
                .iter()
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
            .with_read_mask(self.read_mask.clone());

        if let Some(max_size) = self.max_message_size {
            request = request.with_max_message_size_bytes(saturating_usize_to_u32(max_size));
        }

        request
    }

    async fn send(mut self) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<Object>>>> {
        if self.refs.is_empty() {
            return Err(GrpcError::EmptyRequest);
        }

        let request = self.request();
        let response = self.service_client.get_objects(request).await?;
        let (stream, metadata) = MetadataEnvelope::from(response).into_parts();

        // Server guarantees results are returned in request order
        let response = collect_stream(stream, metadata, |msg| {
            Ok((msg.has_next, into_item_results(msg.objects)))
        })
        .await?;
        check_result_count(response.body(), self.refs.len())?;
        check_object_identity(response.body(), &self.refs)?;

        Ok(response)
    }
}

define_query! {
    /// Request for [`GrpcClient::object_references`]. Await it to send the
    /// request.
    pub struct GetObjectReferencesQuery {
        objects: GetObjectsQuery,
    }
    output: GrpcResult<MetadataEnvelope<Vec<GrpcResult<iota_types::ObjectReference>>>>;
}

impl GetObjectReferencesQuery {
    async fn send(
        self,
    ) -> GrpcResult<MetadataEnvelope<Vec<GrpcResult<iota_types::ObjectReference>>>> {
        Ok(self.objects.send().await?.map(|objects| {
            objects
                .into_iter()
                .map(|object| Ok(object?.object_reference()?))
                .collect()
        }))
    }
}

impl GrpcClient {
    /// Get objects by their IDs.
    ///
    /// Returns proto `Object` types. Use `obj.object()` to convert to SDK
    /// type, or use `obj.object_reference()` to get the object reference.
    ///
    /// Results are returned in the same order as the input IDs, one per ID.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `refs` is empty.
    ///
    /// Each ID gets its own result: an object that is not found (never
    /// existed, was deleted, or has been pruned by the serving node) yields
    /// [`GrpcError::Server`] with code `NOT_FOUND` in that slot only, leaving
    /// the other objects intact. The outer `GrpcResult` is reserved for
    /// failures of the call itself, such as a transport error, and for a
    /// server that answered with a different number of results than IDs
    /// requested ([`UnexpectedResultCount`]), which leaves no way to tell
    /// which ID each result belongs to, or answered a position with a
    /// different object than the one requested there
    /// ([`UnexpectedObject`]). The answered id is read from the object
    /// reference or its BCS, so a read mask that includes neither leaves
    /// nothing to check.
    ///
    /// [`UnexpectedResultCount`]: crate::ProtocolError::UnexpectedResultCount
    /// [`UnexpectedObject`]: crate::ProtocolError::UnexpectedObject
    ///
    /// # Read Mask
    ///
    /// Without [`read_mask`](GetObjectsQuery::read_mask), the default mask is
    /// used. Pass an
    /// [`ObjectReadMask`](iota_grpc_types::read_mask_fields::ObjectReadMask)
    /// built from an
    /// [`ObjectField`](iota_grpc_types::read_mask_fields::ObjectField) or any
    /// slice/array/vec of fields to choose the returned fields.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ObjectField, ObjectReadMask};
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    /// let ids = [object_id];
    ///
    /// // Default mask
    /// let objs = client.objects(ids).await?;
    ///
    /// // Selected fields
    /// let objs = client
    ///     .objects(ids)
    ///     .read_mask(ObjectReadMask::from([
    ///         ObjectField::REFERENCE,
    ///         ObjectField::BCS,
    ///     ]))
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
    pub fn objects(&self, refs: impl IntoIterator<Item = ObjectId>) -> GetObjectsQuery {
        self.objects_query(refs.into_iter().map(|id| (id, None)).collect())
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
    /// Returns [`GrpcError::EmptyRequest`] if `refs` is empty.
    ///
    /// Each ref gets its own result, with the same meaning as in
    /// [`objects`](GrpcClient::objects): a requested version the serving
    /// node does not have fails only its own slot.
    ///
    /// # Read Mask
    ///
    /// As for [`objects`](GrpcClient::objects), set with
    /// [`read_mask`](GetObjectsQuery::read_mask).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_sdk_grpc_client::read_mask_fields::{ObjectField, ObjectReadMask};
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let object_id: ObjectId = "0x2".parse()?;
    ///
    /// // Default mask
    /// let objs = client.objects_with_versions([(object_id, None)]).await?;
    ///
    /// // Selected fields
    /// let objs = client
    ///     .objects_with_versions([(object_id, None)])
    ///     .read_mask(ObjectReadMask::from(ObjectField::REFERENCE_OBJECT_ID))
    ///     .await?;
    ///
    /// for obj in objs.body() {
    ///     let obj = match obj {
    ///         Ok(obj) => obj,
    ///         // Only this ref failed; the remaining objects are still usable
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
    pub fn objects_with_versions(
        &self,
        refs: impl IntoIterator<Item = (ObjectId, Option<Version>)>,
    ) -> GetObjectsQuery {
        self.objects_query(refs.into_iter().collect())
    }

    /// Get the current references of objects by their IDs.
    ///
    /// Requests the `reference` field only, so no object contents travel.
    /// Results are returned in the same order as the input IDs, one per ID.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::EmptyRequest`] if `ids` is empty. As for
    /// [`objects`](Self::objects), an ID that is not found yields
    /// [`GrpcError::Server`] with code `NOT_FOUND` in its slot only; the outer
    /// `GrpcResult` is reserved for failures of the call itself.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use iota_sdk_grpc_client::GrpcClient;
    /// # use iota_types::ObjectId;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = GrpcClient::new_localnet()?;
    /// let gas: ObjectId = "0x2".parse()?;
    /// let mut refs = client.object_references([gas]).await?.into_inner();
    /// let gas_ref = refs.remove(0)?;
    /// println!("gas version: {:?}", gas_ref.version());
    /// # Ok(())
    /// # }
    /// ```
    pub fn object_references(
        &self,
        ids: impl IntoIterator<Item = ObjectId>,
    ) -> GetObjectReferencesQuery {
        GetObjectReferencesQuery {
            objects: self.objects(ids).read_mask([ObjectField::REFERENCE]),
        }
    }

    fn objects_query(&self, refs: Vec<(ObjectId, Option<Version>)>) -> GetObjectsQuery {
        GetObjectsQuery {
            service_client: self.ledger_service_client(),
            max_message_size: self.max_decoding_message_size(),
            refs,
            read_mask: ObjectReadMask::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iota_grpc_types::read_mask_fields::{ObjectField, ObjectReadMask};
    use iota_types::{ObjectId, Version};

    use crate::{GrpcClient, GrpcError, api::proto_object_id};

    #[tokio::test]
    async fn objects_asks_for_the_latest_version_with_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.objects([ObjectId::ZERO]);
        assert_eq!(query.refs, vec![(ObjectId::ZERO, None)]);
        assert_eq!(query.read_mask.as_str(), ObjectReadMask::default().as_str());
    }

    #[tokio::test]
    async fn objects_with_versions_keeps_the_versions() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let version = Version::from_u64(7);
        let query = client.objects_with_versions([(ObjectId::ZERO, Some(version))]);
        assert_eq!(query.refs, vec![(ObjectId::ZERO, Some(version))]);
    }

    #[tokio::test]
    async fn read_mask_replaces_the_default_mask() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client
            .objects([ObjectId::ZERO])
            .read_mask(ObjectField::REFERENCE);
        assert_eq!(
            query.read_mask.as_str(),
            ObjectReadMask::from(ObjectField::REFERENCE).as_str()
        );
    }

    #[tokio::test]
    async fn object_references_asks_only_for_the_reference() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let query = client.object_references([ObjectId::ZERO]);
        assert_eq!(query.objects.refs, vec![(ObjectId::ZERO, None)]);
        assert_eq!(
            query.objects.read_mask.as_str(),
            ObjectReadMask::from(ObjectField::REFERENCE).as_str()
        );
    }

    #[tokio::test]
    async fn awaiting_no_ids_is_an_empty_request() {
        let client = GrpcClient::new("http://localhost").unwrap();
        let result = client.objects(Vec::new()).await;
        assert!(matches!(result, Err(GrpcError::EmptyRequest)));
    }

    #[tokio::test]
    async fn the_request_carries_every_ref_the_mask_and_the_message_size() {
        let client = GrpcClient::new("http://localhost")
            .unwrap()
            .with_max_decoding_message_size(1024);
        let pinned: ObjectId = "0x5".parse().unwrap();
        let query = client
            .objects_with_versions([(ObjectId::ZERO, None), (pinned, Some(Version::from_u64(7)))])
            .read_mask(ObjectField::REFERENCE);
        let request = query.request();

        let refs: Vec<_> = request
            .requests
            .unwrap()
            .requests
            .into_iter()
            .map(|r| {
                let object_ref = r.object_ref.unwrap();
                (object_ref.object_id, object_ref.version)
            })
            .collect();
        assert_eq!(
            refs,
            vec![
                (Some(proto_object_id(ObjectId::ZERO)), None),
                (Some(proto_object_id(pinned)), Some(7)),
            ]
        );
        assert_eq!(
            request.read_mask,
            Some(ObjectReadMask::from(ObjectField::REFERENCE).into())
        );
        assert_eq!(request.max_message_size_bytes, Some(1024));
    }
}
