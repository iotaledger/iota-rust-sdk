// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust representations of Move system types used by the IOTA blockchain.
//!
//! Each top-level module corresponds to a system package, identified by the
//! address constants on [`iota_types::Address`]:
//!
//! - [`std`]          — `0x1`, the Move standard library
//! - [`framework`]    — `0x2`, the IOTA framework
//! - [`system`]       — `0x3`, the IOTA system package
//! - [`system_state`] — `0x5`, the IOTA system state
//! - [`stardust`]     — `0x107a`, the Stardust migration package

pub mod framework;
pub mod stardust;
pub mod std;
pub mod system;
pub mod system_state;
