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

// The file is named `iota.rs` to mirror the moverox snapshot's
// `generated/iota.rs`. The Rust module stays `framework` so the public
// API (`iota_move_system_types::framework::*`) and FFI shim paths don't
// shift.
#[path = "iota.rs"]
pub mod framework;
pub mod iota_system;
pub mod stardust;
pub mod std;

#[cfg(test)]
pub(crate) mod generated {
    #[allow(dead_code)]
    pub mod framework {
        include!("../generated/iota.rs");
    }

    #[allow(dead_code)]
    pub mod iota_system {
        include!("../generated/iota_system.rs");
    }

    #[allow(dead_code)]
    pub mod stardust {
        include!("../generated/stardust.rs");
    }

    #[allow(dead_code)]
    pub mod std {
        include!("../generated/std.rs");
    }
}

// Moverox emits absolute paths `crate::iota_framework::*` and
// `crate::move_stdlib::*` inside the generated files. The snapshot stays
// byte-identical to moverox's output so the Layer-1 drift diff is exact;
// these aliases bridge the paths to where we actually hold the code.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use generated::framework as iota_framework;
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) use generated::std as move_stdlib;

/// Shared helpers for the `*_moverox_parity` tests scattered across each
/// type's `#[cfg(all(test, feature = "serde"))] mod tests` block.
///
/// Each parity test takes a sample value from our hand-curated type,
/// BCS-encodes it, decodes as the moverox-generated counterpart under
/// [`crate::generated`], re-encodes, and asserts byte equality. If the
/// bytes survive the round trip, our hand-curated layout is wire-
/// compatible with what moverox emits from the Move source — any
/// reordered field, missing field, type swap, or generic-instantiation
/// drift surfaces as a `wire-format drift` test failure naming the
/// exact type whose `mod tests` holds the test.
#[cfg(test)]
pub(crate) mod parity_check {
    use iota_types::ObjectId;

    /// BCS-encode `ours`, decode the bytes as the moverox-generated type
    /// `M`, re-encode from `M`, and assert byte equality.
    pub(crate) fn assert_parity<O, M>(ours: &O)
    where
        O: serde::Serialize,
        M: serde::de::DeserializeOwned + serde::Serialize,
    {
        let bytes = bcs::to_bytes(ours).expect("encode ours");
        let mx_value: M =
            bcs::from_bytes(&bytes).expect("decode bytes as moverox-generated type");
        let bytes2 = bcs::to_bytes(&mx_value).expect("re-encode moverox-generated value");
        assert_eq!(
            bytes, bytes2,
            "wire-format drift: our type and the moverox snapshot disagree"
        );
    }

    /// Build a sample `ObjectId` whose every byte equals `byte`.
    #[allow(dead_code)]
    pub(crate) fn oid(byte: u8) -> ObjectId {
        ObjectId::new([byte; ObjectId::LENGTH])
    }
}

/// Error returned by the `try_from_object` constructors on type mirrors.
///
/// All Tier 1 types share this error shape: the caller passed an `Object`
/// that either isn't a Move struct, has a type tag that doesn't match the
/// expected type, or whose BCS contents fail to decode.
#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum FromObjectError {
    /// The object is a package, not a Move struct.
    NotAMoveStruct,
    /// The Move struct's type tag does not match the expected type.
    WrongType,
    /// BCS decoding of the struct contents failed.
    Bcs(bcs::Error),
}

#[cfg(feature = "serde")]
impl core::fmt::Display for FromObjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAMoveStruct => f.write_str("object is not a Move struct"),
            Self::WrongType => f.write_str("object's type tag does not match expected type"),
            Self::Bcs(e) => write!(f, "bcs decoding failed: {e}"),
        }
    }
}

#[cfg(feature = "serde")]
impl core::error::Error for FromObjectError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Bcs(e) => Some(e),
            _ => None,
        }
    }
}
