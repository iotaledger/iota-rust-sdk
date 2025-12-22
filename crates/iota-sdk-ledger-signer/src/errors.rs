// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_graphql_client::error::Error as ClientError;
use iota_ledger::LedgerError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerSignerError {
    #[error("Ledger error: {0}")]
    Ledger(#[from] LedgerError),
    #[error("Client error: {0}")]
    Client(#[from] ClientError),
}
