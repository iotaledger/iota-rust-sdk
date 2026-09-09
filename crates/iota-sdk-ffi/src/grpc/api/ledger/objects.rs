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

/// A reference to an object to fetch with `objects`, with an optional
/// version. If no version is provided, the latest version is returned.
#[derive(uniffi::Record)]
pub struct ObjectRequest {
    /// The id of the object.
    pub object_id: Arc<ObjectId>,
    /// The optional version of the object.
    #[uniffi(default = None)]
    pub version: Option<Arc<Version>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get objects by their ids and optional versions.
    ///
    /// Results are returned in the same order as the input requests.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    pub async fn objects(&self, requests: Vec<ObjectRequest>) -> Result<Vec<Arc<Object>>> {
        let refs = requests
            .iter()
            .map(|request| {
                (
                    **request.object_id,
                    request.version.as_ref().map(|version| ***version),
                )
            })
            .collect::<Vec<_>>();
        self.client()
            .objects_with_versions(refs, ObjectReadMask::default())
            .await?
            .into_inner()
            .into_iter()
            .map(|object| Ok(Arc::new(object?.object()?.into())))
            .collect()
    }
}
