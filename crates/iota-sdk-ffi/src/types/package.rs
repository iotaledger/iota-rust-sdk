// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// use iota_types::UpgradePolicy;

// /// Rust representation of upgrade policy constants in `iota::package`.
// #[uniffi::remote(Enum)]
// pub enum UpgradePolicy {
//     /// The least restrictive policy. Permits changes to all function
//     /// implementations, the removal of ability constraints on generic type
//     /// parameters in function signatures, and modifications to private,
//     /// public(friend), and entry function signatures. However, public
// function     /// signatures and existing types cannot be changed.
//     Compatible = 0,
//     /// Allows adding new functionalities (e.g., new public functions or
//     /// structs) but restricts changes to existing functionalities.
//     Additive = 128,
//     /// Limits modifications to the package’s dependencies only.
//     DepOnly = 192,
// }

// /// Returns the `UpgradePolicy` variant discriminant independent of the
// /// binding's language.
// #[uniffi::export]
// pub fn upgrade_policy_value(policy: UpgradePolicy) -> u8 {
//     policy as u8
// }

// Implemented as an Object, because bindings may not support enums with
// discriminat variants.
/// Rust representation of upgrade policy constants in `iota::package`.
#[derive(derive_more::From, derive_more::Display, uniffi::Object, PartialEq, Eq)]
#[uniffi::export(Display, Eq)]
pub struct UpgradePolicy(iota_types::UpgradePolicy);

#[uniffi::export]
impl UpgradePolicy {
    /// The least restrictive policy. Permits changes to all function
    /// implementations, the removal of ability constraints on generic type
    /// parameters in function signatures, and modifications to private,
    /// public(friend), and entry function signatures. However, public function
    /// signatures and existing types cannot be changed.
    #[uniffi::constructor]
    pub fn compatible() -> Self {
        Self(iota_types::UpgradePolicy::Compatible)
    }

    /// Allows adding new functionalities (e.g., new public functions or
    /// structs) but restricts changes to existing functionalities.
    #[uniffi::constructor]
    pub fn additive() -> Self {
        Self(iota_types::UpgradePolicy::Additive)
    }

    /// Limits modifications to the package’s dependencies only.
    #[uniffi::constructor]
    pub fn dep_only() -> Self {
        Self(iota_types::UpgradePolicy::DepOnly)
    }

    /// Returns the internal value.
    pub fn value(&self) -> u8 {
        self.0 as u8
    }
}
