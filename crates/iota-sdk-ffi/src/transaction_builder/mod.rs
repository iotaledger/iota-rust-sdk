// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

pub mod builder;
pub mod client_builder;
pub mod gas_station;
pub mod move_authenticator;
pub mod ptb_arg;
pub mod signer;

use std::sync::Arc;

use crate::{transaction_builder::ptb_arg::PTBArgument, types::address::Address};

/// A single payment: a recipient address paired with the amount to send.
#[derive(uniffi::Record)]
pub struct Payment {
    /// The recipient address.
    pub recipient: Arc<Address>,
    /// The amount to send, in the coin's smallest unit.
    pub amount: Arc<PTBArgument>,
}

/// Determines what to wait for after executing a transaction.
#[derive(uniffi::Enum)]
pub enum WaitForTransaction {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode, so queries
    /// served by the fullnode, such as gRPC, will find it.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer, so queries served by an indexer, such as GraphQL, may not
    /// find it yet. Use WaitForTransaction::Finalized with those clients.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and
    /// all queries may include it.
    Finalized,
}

impl From<WaitForTransaction> for iota_sdk::transaction_builder::WaitForTransaction {
    fn from(value: WaitForTransaction) -> Self {
        match value {
            WaitForTransaction::IndexedOnNode => Self::IndexedOnNode,
            WaitForTransaction::Finalized => Self::Finalized,
        }
    }
}
