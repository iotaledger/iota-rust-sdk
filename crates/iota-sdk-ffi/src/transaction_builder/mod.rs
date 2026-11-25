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
    /// Indicates that the transaction effects will be usable in subsequent transactions (you can
    /// reference objects created by this transaction), and that the fullnode returns the
    /// transaction when queried by its digest.
    ///
    /// **Warning:** This does not guarantee that queries depending on an index reflect the
    /// transaction yet, meaning queries served by an indexer may not find it, and queries served
    /// by the node may still return the state from before it. Use `WaitForTransaction::Finalized`
    /// instead if this is important.
    IndexedOnNode,
    /// Indicates that the transaction has been included in a checkpoint, and all queries may
    /// include it.
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
