// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust representations of Move system types used by the IOTA blockchain.
//!
//! Each top-level module corresponds to a system package, identified by the
//! address constants on [`iota_types::Address`]:
//!
//! - [`std`]         — `0x1`, the Move standard library
//! - [`framework`]   — `0x2`, the IOTA framework
//! - [`iota_system`] — `0x3`, the IOTA system package
//! - [`stardust`]    — `0x107a`, the Stardust migration package
//!
//! Inside each package, every Move source module is mirrored 1:1 as a Rust
//! `pub mod`. Generic Move types stay generic in Rust (with a
//! `PhantomData<T>` placeholder for phantom parameters).

pub mod framework;
pub mod iota_system;
pub mod stardust;
pub mod std;
