// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

mod builder;
mod client_builder;
pub mod move_authenticator;
pub mod move_view_arg;
pub mod move_view_call_builder;
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
