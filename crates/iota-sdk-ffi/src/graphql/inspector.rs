// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::thread_safety::ThreadSafety;

/// Information about a completed GraphQL request.
#[derive(Debug, uniffi::Record)]
pub struct GraphQlRequestResult {
    /// The URL of the GraphQL endpoint that was called.
    pub url: String,
    /// If the request failed, a description of the error. `None` on success.
    pub error: Option<String>,
    /// How long the request took, in milliseconds.
    pub duration_ms: u64,
}

/// A callback invoked after every GraphQL request completes.
///
/// Implement this trait to receive notifications about request outcomes,
/// for example to report errors to Sentry or a logging service.
#[allow(private_bounds)]
#[uniffi::export(with_foreign)]
pub trait GraphQlRequestInspectorFn: ThreadSafety + std::fmt::Debug {
    /// Called after each GraphQL request with the result.
    fn on_request_complete(&self, result: GraphQlRequestResult);
}

/// Adapter bridging FFI [`GraphQlRequestInspectorFn`] to the core
/// [`iota_sdk::graphql_client::RequestInspector`].
pub(crate) struct FfiInspectorAdapter(pub Arc<dyn GraphQlRequestInspectorFn>);

// SAFETY: On wasm32 the runtime is single-threaded so Send+Sync are trivially
// safe. On native targets, ThreadSafety already provides Send+Sync, making the
// inner Arc<dyn ...> Send+Sync and this auto-derives.
#[cfg(target_arch = "wasm32")]
unsafe impl Send for FfiInspectorAdapter {}
#[cfg(target_arch = "wasm32")]
unsafe impl Sync for FfiInspectorAdapter {}

impl iota_sdk::graphql_client::RequestInspector for FfiInspectorAdapter {
    fn inspect(&self, result: &iota_sdk::graphql_client::GraphQlRequestResult) {
        self.0.on_request_complete(GraphQlRequestResult {
            url: result.url.clone(),
            error: result.error.clone(),
            duration_ms: result.duration.as_millis() as u64,
        });
    }
}
