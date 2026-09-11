// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use std::sync::Arc;

use iota_sdk::grpc_client::read_mask_fields::ObjectReadMask;

use crate::{
    error::Result,
    grpc::client::GrpcClient,
    types::{
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

fn convert_objects(
    objects: Vec<iota_sdk::grpc_client::Result<iota_sdk::grpc_types::v1::object::Object>>,
) -> Result<Vec<Arc<Object>>> {
    objects
        .into_iter()
        .map(|object| Ok(Arc::new(object?.object()?.into())))
        .collect()
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get the latest version of objects by their ids.
    ///
    /// Results are returned in the same order as the input ids.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    pub async fn objects(&self, object_ids: Vec<Arc<ObjectId>>) -> Result<Vec<Arc<Object>>> {
        let ids = object_ids.iter().map(|id| ***id).collect::<Vec<_>>();
        convert_objects(
            self.client()
                .objects(ids, ObjectReadMask::default())
                .await?
                .into_inner(),
        )
    }

    /// Get objects by their ids and optional versions.
    ///
    /// Results are returned in the same order as the input requests.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    pub async fn objects_with_versions(
        &self,
        requests: Vec<ObjectRequest>,
    ) -> Result<Vec<Arc<Object>>> {
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
                .objects_with_versions(refs, ObjectReadMask::default())
                .await?
                .into_inner(),
        )
    }
}
