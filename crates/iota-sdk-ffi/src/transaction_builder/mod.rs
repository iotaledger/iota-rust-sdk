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
///
/// Users should almost always use WaitForTransaction::Finalized (the default),
/// as clients may interact with the indexer and not the fullnode directly.
/// Using WaitForTransaction::IndexedOnNode only guarantees the transaction is
/// indexed on the fullnode (meaning you can submit transactions that reference
/// objects created by this transaction), but subsequent queries using the
/// transaction ID can still fail until the transaction is indexed on the
/// indexer.
#[derive(uniffi::Enum)]
pub enum WaitForTransaction {
    /// Indicates that the transaction effects will be usable in subsequent
    /// transactions (you can reference objects created by this transaction),
    /// and that the transaction itself is indexed on the fullnode.
    ///
    /// **Warning:** This does not guarantee the transaction is indexed on the
    /// indexer. Since the client may query the indexer, subsequent queries
    /// with this transaction ID may still fail. Prefer
    /// WaitForTransaction::Finalized unless you have a specific reason to use
    /// this.
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
