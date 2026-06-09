// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Objects API implementation.

use std::sync::Arc;

use crate::{
    error::{Result, SdkFfiError},
    grpc::{client::GrpcClient, output_types::ObjectRequest},
    types::object::Object,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get objects by their ids and optional versions.
    ///
    /// Results are returned in the same order as the input requests.
    /// If an object is not found, an error is returned.
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
        Ok(self
            .0
            .read()
            .await
            .get_objects(&refs, None)
            .await?
            .into_inner()
            .iter()
            .map(|object| object.object().map_err(SdkFfiError::new))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(Into::into)
            .map(Arc::new)
            .collect())
    }
}
