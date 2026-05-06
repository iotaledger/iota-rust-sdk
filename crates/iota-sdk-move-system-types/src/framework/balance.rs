// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/// Rust version of the Move `iota::balance::Balance<T>` type.
///
/// The Move type is generic over the coin marker `T`; on the wire it is a
/// single `u64`, so this Rust type does not carry the type parameter.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Balance {
    value: u64,
}

impl Balance {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn value(&self) -> u64 {
        self.value
    }
}

/// Rust version of the Move `iota::balance::Supply<T>` type.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Supply {
    pub value: u64,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn balance_bcs_roundtrip() {
        let balance = Balance::new(0xdead_beef_u64);
        let bytes = bcs::to_bytes(&balance).unwrap();
        // Single u64 field — wire format is a little-endian u64.
        assert_eq!(bytes, 0xdead_beef_u64.to_le_bytes());
        let decoded: Balance = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(balance, decoded);
    }

    #[test]
    fn supply_bcs_roundtrip() {
        let supply = Supply { value: 1_000_000 };
        let bytes = bcs::to_bytes(&supply).unwrap();
        let decoded: Supply = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(supply, decoded);
    }
}
