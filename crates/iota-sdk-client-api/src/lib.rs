// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(unreachable_pub)]

mod traits;
mod types;

pub use iota_types;

pub use self::{
    traits::{Client, ExecutionClient, LedgerClient, SimulationClient},
    types::{ObjectsPage, ProtocolConfig, WaitForTransaction},
};
