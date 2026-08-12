// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::error::Result;

/// A 32-byte Blake2b256 hash output.
///
/// # BCS
///
/// A `Digest`'s BCS serialized form is defined by the following:
///
/// ```text
/// digest = %d32 32OCTET
/// ```
///
/// Due to historical reasons, even though a `Digest` has a fixed-length of 32,
/// IOTA's binary representation of a `Digest` is prefixed with its length
/// meaning its serialized binary form (in bcs) is 33 bytes long vs a more
/// compact 32 bytes.
#[derive(
    Debug,
    derive_more::Deref,
    derive_more::Display,
    derive_more::From,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    uniffi::Object,
)]
#[uniffi::export(Debug, Display, Hash, Eq)]
pub struct Digest(pub iota_sdk::types::Digest);

#[uniffi::export]
impl Digest {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::Digest::from_bytes(bytes)?))
    }

    #[uniffi::constructor]
    pub fn from_base58(base58: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Digest::from_base58(base58)?))
    }

    #[uniffi::constructor]
    pub fn random() -> Self {
        Self(iota_sdk::types::Digest::random())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_base58(&self) -> String {
        self.0.to_base58()
    }

    /// Returns the next digest in byte-increasing order.
    pub fn next_lexicographical(&self) -> Self {
        Self(self.0.next_lexicographical())
    }

    /// Returns the next digest in byte-increasing order, or `None` if the
    /// result would overflow.
    pub fn next_lexicographical_opt(&self) -> Option<Arc<Self>> {
        self.0.next_lexicographical_opt().map(Self).map(Arc::new)
    }
}

crate::export_iota_types_objects_bcs_conversion!(Digest);
crate::export_iota_types_objects_json_conversion!(Digest);

/// Defines an FFI object mirroring one of the core SDK's domain-specific digest
/// newtypes (e.g. `TransactionDigest`). Each wraps the corresponding
/// `iota_sdk::types` digest and exposes the same shared surface as [`Digest`];
/// the optional trailing block adds type-specific items.
macro_rules! ffi_digest_wrapper {
    ($(#[$meta:meta])* $name:ident $({ $($extra:tt)* })?) => {
        $(#[$meta])*
        #[derive(
            Debug,
            derive_more::Deref,
            derive_more::Display,
            derive_more::From,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            uniffi::Object,
        )]
        #[uniffi::export(Debug, Display, Hash, Eq)]
        pub struct $name(pub iota_sdk::types::$name);

        #[uniffi::export]
        impl $name {
            #[uniffi::constructor]
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
                Ok(Self(iota_sdk::types::$name::from_bytes(bytes)?))
            }

            #[uniffi::constructor]
            pub fn from_base58(base58: &str) -> Result<Self> {
                Ok(Self(iota_sdk::types::$name::from_base58(base58)?))
            }

            #[uniffi::constructor]
            pub fn random() -> Self {
                Self(iota_sdk::types::$name::random())
            }

            pub fn to_bytes(&self) -> Vec<u8> {
                self.0.as_bytes().to_vec()
            }

            pub fn to_base58(&self) -> String {
                self.0.to_base58()
            }

            /// Returns the next digest in byte-increasing order.
            pub fn next_lexicographical(&self) -> Self {
                Self(self.0.next_lexicographical())
            }

            /// Returns the next digest in byte-increasing order, or `None` if
            /// the result would overflow.
            pub fn next_lexicographical_opt(&self) -> Option<Arc<Self>> {
                self.0.next_lexicographical_opt().map(Self).map(Arc::new)
            }

            $($($extra)*)?
        }

        crate::export_iota_types_objects_bcs_conversion!($name);
        crate::export_iota_types_objects_json_conversion!($name);
    };
}

ffi_digest_wrapper! {
    /// The digest of a `CheckpointSummary`.
    CheckpointDigest
}

ffi_digest_wrapper! {
    /// The digest of a `CheckpointContents`.
    CheckpointContentsDigest
}

ffi_digest_wrapper! {
    /// The digest of a certificate.
    CertificateDigest
}

ffi_digest_wrapper! {
    /// The digest of `SenderSignedData`.
    SenderSignedDataDigest
}

ffi_digest_wrapper! {
    /// The digest of a `Transaction`.
    TransactionDigest {
        /// The digest used to signify the parent transaction was the genesis.
        #[uniffi::constructor]
        pub fn genesis_marker() -> Self {
            Self(iota_sdk::types::TransactionDigest::genesis_marker())
        }
    }
}

ffi_digest_wrapper! {
    /// The digest of `TransactionEffects`.
    TransactionEffectsDigest
}

ffi_digest_wrapper! {
    /// The digest of `TransactionEvents`.
    TransactionEventsDigest
}

ffi_digest_wrapper! {
    /// The digest of the auxiliary data associated with `TransactionEffects`.
    EffectsAuxDataDigest
}

ffi_digest_wrapper! {
    /// The digest of an `Object`.
    ObjectDigest {
        /// A marker that signifies the object is deleted.
        #[uniffi::constructor]
        pub fn object_deleted() -> Self {
            Self(iota_sdk::types::ObjectDigest::OBJECT_DELETED)
        }

        /// A marker that signifies the object is wrapped into another object.
        #[uniffi::constructor]
        pub fn object_wrapped() -> Self {
            Self(iota_sdk::types::ObjectDigest::OBJECT_WRAPPED)
        }

        /// A marker that signifies the object is canceled.
        #[uniffi::constructor]
        pub fn object_canceled() -> Self {
            Self(iota_sdk::types::ObjectDigest::OBJECT_CANCELED)
        }

        /// Returns whether the digest represents an object that is neither
        /// deleted nor wrapped.
        pub fn is_alive(&self) -> bool {
            self.0.is_alive()
        }

        /// Returns whether the digest represents a deleted object.
        pub fn is_deleted(&self) -> bool {
            self.0.is_deleted()
        }

        /// Returns whether the digest represents an object wrapped in another
        /// object.
        pub fn is_wrapped(&self) -> bool {
            self.0.is_wrapped()
        }
    }
}

ffi_digest_wrapper! {
    /// The digest of a consensus commit.
    ConsensusCommitDigest
}

ffi_digest_wrapper! {
    /// The digest of a misbehavior report.
    MisbehaviorReportDigest
}

ffi_digest_wrapper! {
    /// The digest of a `MoveAuthenticator`.
    MoveAuthenticatorDigest
}
