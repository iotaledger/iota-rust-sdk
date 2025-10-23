// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Rust representation of upgrade policy constants in `iota::package`.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum UpgradePolicy {
    /// The least restrictive policy. Permits changes to all function
    /// implementations, the removal of ability constraints on generic type
    /// parameters in function signatures, and modifications to private,
    /// public(friend), and entry function signatures. However, public function
    /// signatures and existing types cannot be changed.
    Compatible = 0,
    /// Allows adding new functionalities (e.g., new public functions or
    /// structs) but restricts changes to existing functionalities.
    Additive = 128,
    /// Limits modifications to the package’s dependencies only.
    DepOnly = 192,
}
