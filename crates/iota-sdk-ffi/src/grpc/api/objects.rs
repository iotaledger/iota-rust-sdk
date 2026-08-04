// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    grpc::{client::GrpcClient, output_types::ObjectRequest},
    types::object::Object,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get objects by their ids and optional versions.
    ///
    /// Results are returned in the same order as the input requests.
    /// If any object cannot be read — because it is not found, was deleted, or
    /// has been pruned by the serving node — the whole call fails.
    pub async fn get_objects(&self, requests: Vec<ObjectRequest>) -> Result<Vec<Arc<Object>>> {
        let refs = requests
            .iter()
            .map(|request| {
                (
                    **request.object_id,
                    request.version.as_ref().map(|version| ***version),
                )
            })
            .collect::<Vec<_>>();
        self.0
            .read()
            .await
            .get_objects(&refs, None)
            .await?
            .into_inner()
            .into_iter()
            .map(|object| Ok(Arc::new(object?.object()?.into())))
            .collect()
    }
}
