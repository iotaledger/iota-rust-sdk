// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Transactions API implementation.

use std::sync::Arc;

use crate::{
    error::Result,
    grpc::{client::GrpcClient, output_types::ExecutedTransaction},
    types::digest::TransactionDigest,
};

#[uniffi::export(async_runtime = "tokio")]
impl GrpcClient {
    /// Get transactions by their digests.
    ///
    /// Results are returned in the same order as the input digests.
    /// If a transaction is not found, an error is returned.
    ///
    /// The optional `read_mask` controls which fields the server returns.
    /// If `None`, the transaction, signatures, checkpoint, and timestamp are
    /// returned.
    #[uniffi::method(default(read_mask = None))]
    pub async fn get_transactions(
        &self,
        digests: Vec<Arc<TransactionDigest>>,
        read_mask: Option<Vec<String>>,
    ) -> Result<Vec<ExecutedTransaction>> {
        let digests = digests.iter().map(|digest| ***digest).collect::<Vec<_>>();
        self.0
            .read()
            .await
            .get_transactions(&digests, super::read_mask(&read_mask))
            .await?
            .into_inner()
            .iter()
            .map(TryInto::try_into)
            .collect()
    }
}
