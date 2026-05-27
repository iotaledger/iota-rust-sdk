// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Rust mirrors of the IOTA system packages. Each child module corresponds to
//! one package; `lib.rs` re-exports them at the crate root so the public API
//! stays `iota_sdk_move_types::{framework,std,iota_system,stardust}::…`.

pub mod framework;
pub mod iota_system;
pub mod stardust;
pub mod std;
