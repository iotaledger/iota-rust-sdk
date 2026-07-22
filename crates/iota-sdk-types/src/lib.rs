// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Core type definitions for the IOTA blockchain.
//!
//! [IOTA] is a next-generation smart contract platform with high throughput,
//! low latency, and an asset-oriented programming model powered by the Move
//! programming language. This crate provides type definitions for working with
//! the data that makes up the IOTA blockchain.
//!
//! [IOTA]: https://iota.org
//!
//! # Feature flags
//!
//! This library uses a set of [feature flags] to reduce the number of
//! dependencies and amount of compiled code. By default, no features are
//! enabled which allows one to enable a subset specifically for their use case.
//! Below is a list of the available feature flags.
//!
//! - `serde`: Enables support for serializing and deserializing types to/from
//!   BCS utilizing [serde] library. Note: JSON serialization is NOT guaranteed
//!   to match the IOTA monorepo's JSON-RPC format.
//! - `rand`: Enables support for generating random instances of a number of
//!   types via the [rand] library.
//! - `hash`: Enables support for hashing, which is required for deriving
//!   addresses and calculating digests for various types.
//! - `proptest`: Enables support for the [proptest] library by providing
//!   implementations of [proptest::arbitrary::Arbitrary] for many types.
//!
//! [feature flags]: https://doc.rust-lang.org/cargo/reference/manifest.html#the-features-section
//! [serde]: https://docs.rs/serde
//! [rand]: https://docs.rs/rand
//! [proptest]: https://docs.rs/proptest
//! [proptest::arbitrary::Arbitrary]: https://docs.rs/proptest/latest/proptest/arbitrary/trait.Arbitrary.html
//!
//! # BCS
//!
//! [BCS] is the serialization format used to represent the state of the
//! blockchain and is used extensively throughout the IOTA ecosystem. In
//! particular the BCS format is leveraged because it _"guarantees canonical
//! serialization, meaning that for any given data type, there is a one-to-one
//! correspondence between in-memory values and valid byte representations."_
//! One benefit of this property of having a canonical serialized representation
//! is to allow different entities in the ecosystem to all agree on how a
//! particular type should be interpreted and more importantly define a
//! deterministic representation for hashing and signing.
//!
//! This library strives to guarantee that the types defined are fully
//! BCS-compatible with the data that the network produces. The one caveat to
//! this would be that as the IOTA protocol evolves, new type variants are added
//! and older versions of this library may not support those newly
//! added variants. The expectation is that the most recent release of this
//! library will support new variants and types as they are released to IOTA's
//! `testnet` network.
//!
//! See the documentation for the various types defined by this crate for a
//! specification of their BCS serialized representation which will be defined
//! using ABNF notation as described by [RFC-5234]. In addition to the format
//! itself, some types have an extra layer of verification and may impose
//! additional restrictions on valid byte representations above and beyond those
//! already provided by BCS. In these instances the documentation for those
//! types will clearly specify these additional restrictions.
//!
//! Here are some common rules:
//!
//! ```text
//! ; --- BCS Value ---
//! bcs-value           = bcs-struct / bcs-enum / bcs-length-prefixed / bcs-fixed-length
//! bcs-length-prefixed = bytes / string / vector / option
//! bcs-fixed-length    = u8 / u16 / u32 / u64 / u128 /
//!                       i8 / i16 / i32 / i64 / i128 /
//!                       bool
//! bcs-struct          = *bcs-value          ; Sequence of serialized fields
//! bcs-enum            = uleb128 bcs-value   ; Variant index (ULEB128) + associated value
//!
//! ; --- Named primitives ---
//! uleb128 = *(%x80-FF) %x00-7F   ; Variable-length unsigned integer
//! size    = uleb128               ; BCS sequence / string length
//! opt     = %d00                  ; None — no value follows
//!         / %d01                  ; Some — value follows
//!
//! ; --- Length-prefixed types ---
//! bytes   = size *OCTET          ; Raw bytes
//! string  = size *OCTET          ; UTF-8 string
//! vector  = size *bcs-value      ; Length-prefixed list of values
//! option  = %d00 / (%d01 bcs-value)  ; Optional value
//!
//! ; --- Fixed-length types ---
//! u8      = 1OCTET               ; 1-byte unsigned integer
//! u16     = 2OCTET               ; 2-byte unsigned integer, little-endian
//! u32     = 4OCTET               ; 4-byte unsigned integer, little-endian
//! u64     = 8OCTET               ; 8-byte unsigned integer, little-endian
//! u128    = 16OCTET              ; 16-byte unsigned integer, little-endian
//! i8      = 1OCTET               ; 1-byte signed integer
//! i16     = 2OCTET               ; 2-byte signed integer, little-endian
//! i32     = 4OCTET               ; 4-byte signed integer, little-endian
//! i64     = 8OCTET               ; 8-byte signed integer, little-endian
//! i128    = 16OCTET              ; 16-byte signed integer, little-endian
//! bool    = %d00                 ; false
//!         / %d01                 ; true
//! array   = *(bcs-value)         ; Fixed-length array (no length prefix)
//! ```
//!
//! [BCS]: https://docs.rs/bcs
//! [RFC-5234]: https://datatracker.ietf.org/doc/html/rfc5234

#![cfg_attr(doc_cfg, feature(doc_cfg))]

#[cfg(feature = "hash")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hash")))]
pub mod hash;

pub mod address;
pub mod checkpoint;
pub mod crypto;
pub mod digest;
pub mod effects;
pub mod events;
pub mod execution_status;
pub mod framework;
pub mod gas;
pub mod iota_names;
pub mod move_core;
pub mod move_package;
pub mod object;
pub mod object_id;
pub mod transaction;
pub mod u256;
pub mod utils;
pub mod validator;
pub mod version;

pub use address::{Address, AddressParseError};
pub use checkpoint::{
    CheckpointCommitment, CheckpointContents, CheckpointContentsV1, CheckpointData,
    CheckpointSequenceNumber, CheckpointSummary, CheckpointTimestamp, CheckpointTransaction,
    CheckpointTransactionInfo, EndOfEpochData, EpochId, ProtocolVersion, SignedCheckpointSummary,
    StakeUnit,
};
pub use crypto::{
    Bls12381PublicKey, Bls12381Signature, Ed25519PublicKey, Ed25519Signature, HashingIntentScope,
    INTENT_PREFIX_LENGTH, Intent, IntentAppId, IntentError, IntentMessage, IntentScope,
    IntentVersion, InvalidSignatureScheme, MoveAuthenticator, MoveAuthenticatorV1,
    MultisigAggregatedSignature, MultisigCommittee, MultisigMember, MultisigMemberSignature,
    PasskeyAuthenticator, PasskeyPublicKey, PersonalMessage, PublicKey, PublicKeyExt,
    RandomnessRound, Secp256k1PublicKey, Secp256k1Signature, Secp256r1PublicKey,
    Secp256r1Signature, SignatureScheme, SimpleSignature, UserSignature,
};
pub use digest::{
    CertificateDigest, CheckpointContentsDigest, CheckpointDigest, ConsensusCommitDigest, Digest,
    DigestParseError, EffectsAuxDataDigest, MisbehaviorReportDigest, MoveAuthenticatorDigest,
    ObjectDigest, SenderSignedDataDigest, SigningDigest, TransactionDigest,
    TransactionEffectsDigest, TransactionEventsDigest,
};
pub use effects::{
    ChangedObject, IdOperation, ObjectIn, ObjectOut, TransactionEffects, TransactionEffectsV1,
    UnchangedSharedKind, UnchangedSharedObject,
};
pub use events::{Event, TransactionEvents};
pub use execution_status::{
    CommandArgumentError, ExecutionError, ExecutionStatus, MoveLocation, PackageUpgradeError,
    TypeArgumentError,
};
pub use framework::Coin;
pub use gas::GasCostSummary;
pub use move_core::{Identifier, StructTag, TypeParseError, TypeTag};
pub use move_package::{MovePackage, MovePackageData, TypeOrigin, UpgradeInfo, UpgradePolicy};
pub use object::{
    GenesisObject, MoveObjectType, MoveStruct, MoveStructContentsError, Object, ObjectData,
    ObjectReference, ObjectType, Owner,
};
pub use object_id::ObjectId;
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
pub(crate) use transaction::SignedTransactionWithIntentMessage;
pub use transaction::{
    Argument, CancelledTransaction, ChangeEpoch, ChangeEpochV2, ChangeEpochV3, ChangeEpochV4,
    Command, ConsensusCommitPrologueV1, ConsensusDeterminedVersionAssignments,
    EndOfEpochTransactionKind, GasPayment, GenesisTransaction, Input, MakeMoveVector, MergeCoins,
    MoveCall, ProgrammableTransaction, Publish, RandomnessStateUpdate, SenderSignedTransaction,
    SharedObjectReference, SignedTransaction, SplitCoins, SystemPackage, Transaction,
    TransactionExpiration, TransactionKind, TransactionV1, TransferObjects, Upgrade,
    VersionAssignment,
};
pub use validator::{
    ValidatorAggregatedSignature, ValidatorCommittee, ValidatorCommitteeMember, ValidatorSignature,
};
pub use version::Version;

#[cfg(all(test, feature = "serde", feature = "proptest"))]
mod serialization_proptests;

/// Returns the next array in byte-increasing order.
pub const fn next_lexicographical_array<const N: usize>(array: &[u8; N]) -> [u8; N] {
    match next_lexicographical_array_opt(array) {
        Some(next) => next,
        None => [0; N],
    }
}

/// Returns the next array in byte-increasing order, or `None` if the result
/// would overflow.
pub const fn next_lexicographical_array_opt<const N: usize>(array: &[u8; N]) -> Option<[u8; N]> {
    let mut next = *array;
    let mut i = N;

    while i > 0 {
        i -= 1;
        let (new_byte, overflow) = next[i].overflowing_add(1);
        next[i] = new_byte;

        if !overflow {
            return Some(next);
        }
    }

    None
}

#[macro_export]
macro_rules! def_is {
    ($($variant:ident),* $(,)?) => {
        paste::paste! {$(
        #[doc = "Checks if this is a " $variant:snake " variant."]
        #[inline]
        pub fn [< is_ $variant:snake >](&self) -> bool {
            matches!(self, Self::$variant { .. })
        }
        )*}
    };
}

#[macro_export]
macro_rules! def_is_as_into_opt {
    (@into $variant:ident ($rename:ident) [Box<$inner:ty>]) => {
        paste::paste! {
        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or returns `None` otherwise."]
        #[inline]
        pub fn [< into_ $rename _opt >](self) -> Option<$inner> {
            #[allow(irrefutable_let_patterns)]
            if let Self::$variant(inner) = self {
                Some(*inner)
            } else {
                None
            }
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or panics otherwise."]
        #[inline]
        pub fn [< into_ $rename >](self) -> $inner {
            self.[< into_ $rename _opt >]().expect(&format!("not a {}", stringify!($rename)))
        }
        }
    };
    (@into $variant:ident ($rename:ident) [$inner:ty]) => {
        paste::paste! {
        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or returns `None` otherwise."]
        #[inline]
        pub fn [< into_opt_ $rename >](self) -> Option<$inner> {
            #[allow(irrefutable_let_patterns)]
            if let Self::$variant(inner) = self {
                Some(inner)
            } else {
                None
            }
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or panics otherwise."]
        #[inline]
        pub fn [< into_ $rename >](self) -> $inner {
            self.[< into_opt_ $rename >]().expect(&format!("not a {}", stringify!($variant)))
        }
        }
    };
    (@impl $variant:ident ($rename:ident) [Box<$inner:ty>]) => {
        paste::paste! {
        #[doc = "Checks if this is a " $rename:snake " variant."]
        #[inline]
        pub fn [< is_ $rename >](&self) -> bool {
            matches!(self, Self::$variant(_))
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or panics otherwise."]
        #[inline]
        pub fn [< as_ $rename >](&self) -> &$inner {
            self.[< as_ $rename _opt >]().expect(&format!("not a {}", stringify!($variant)))
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or returns `None` otherwise."]
        #[inline]
        pub fn [< as_opt_ $rename >](&self) -> Option<&$inner> {
            #[allow(irrefutable_let_patterns)]
            if let Self::$variant(inner) = self {
                Some(inner)
            } else {
                None
            }
        }
        }

        $crate::def_is_as_into_opt!{@into $variant($rename) [Box<$inner>]}
    };
    (@impl $variant:ident ($rename:ident) [$inner:ty]) => {
        paste::paste! {
        #[doc = "Checks if this is a " $rename:snake " variant."]
        #[inline]
        pub fn [< is_ $rename >](&self) -> bool {
            matches!(self, Self::$variant(_))
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or panics otherwise."]
        #[inline]
        pub fn [< as_ $rename >](&self) -> &$inner {
            self.[< as_opt_ $rename >]().expect(&format!("not a {}", stringify!($variant)))
        }

        #[doc = "Converts this into a mut " $rename:snake " if it is a " $variant:snake " variant, or panics otherwise."]
        #[inline]
        pub fn [< as_mut_ $rename >](&mut self) -> &mut $inner {
            self.[< as_opt_mut_ $rename >]().expect(&format!("not a {}", stringify!($variant)))
        }

        #[doc = "Converts this into a " $rename:snake " if it is a " $variant:snake " variant, or returns `None` otherwise."]
        #[inline]
        pub fn [< as_opt_ $rename >](&self) -> Option<&$inner> {
            #[allow(irrefutable_let_patterns)]
            if let Self::$variant(inner) = self {
                Some(inner)
            } else {
                None
            }
        }

        #[doc = "Converts this into a mut " $rename:snake " if it is a " $variant:snake " variant, or returns `None` otherwise."]
        #[inline]
        pub fn [< as_opt_mut_ $rename >](&mut self) -> Option<&mut $inner> {
            #[allow(irrefutable_let_patterns)]
            if let Self::$variant(inner) = self {
                Some(inner)
            } else {
                None
            }
        }
        }

        $crate::def_is_as_into_opt!{@into $variant($rename) [$inner]}
    };
    (@parse $variant:ident ($rename:ident) [$($inner:tt)*]) => {
        $crate::def_is_as_into_opt!{@impl $variant($rename) [$($inner)*]}
    };
    (@parse $variant:ident ($rename:ident)) => {
        $crate::def_is_as_into_opt!{@impl $variant($rename) [$variant]}
    };
    (@parse $variant:ident [$($inner:tt)*]) => {
        paste::paste! { $crate::def_is_as_into_opt!{@impl $variant ([< $variant:snake >]) [$($inner)*]} }
    };
    (@parse $variant:ident) => {
        paste::paste! { $crate::def_is_as_into_opt!{@impl $variant ([< $variant:snake >]) [$variant]} }
    };
    ($($variant:ident $( as $rename:ident)? $(($($inner:tt)*))?),* $(,)?) => {
        $(
        $crate::def_is_as_into_opt!{@parse $variant $(($rename))? $([$($inner)*])?}
        )*
    };
}

#[cfg(feature = "serde")]
mod _serde {
    use std::borrow::Cow;

    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs, SerializeAs};

    pub(crate) type ReadableDisplay =
        ::serde_with::As<::serde_with::IfIsHumanReadable<::serde_with::DisplayFromStr>>;

    pub(crate) type OptionReadableDisplay =
        ::serde_with::As<Option<::serde_with::IfIsHumanReadable<::serde_with::DisplayFromStr>>>;

    pub(crate) type ReadableBase64Encoded =
        ::serde_with::As<::serde_with::IfIsHumanReadable<Base64Encoded, ::serde_with::Bytes>>;

    pub(crate) struct Base64Encoded;

    impl<T: AsRef<[u8]>> SerializeAs<T> for Base64Encoded {
        fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = source.as_ref();
            let b64 = Base64::encode_string(bytes);
            b64.serialize(serializer)
        }
    }

    impl<'de, T: TryFrom<Vec<u8>>> DeserializeAs<'de, T> for Base64Encoded {
        fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            let length = bytes.len();
            T::try_from(bytes).map_err(|_| {
                serde::de::Error::custom(format_args!(
                    "Can't convert a Byte Vector of length {length} to the output type."
                ))
            })
        }
    }

    /// Serializes a bitmap according to the roaring bitmap on-disk standard.
    /// <https://github.com/RoaringBitmap/RoaringFormatSpec>
    pub(crate) struct BinaryRoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            Bytes::serialize_as(&bytes, serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for BinaryRoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub(crate) struct Base64RoaringBitmap;

    impl SerializeAs<roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn serialize_as<S>(
            source: &roaring::RoaringBitmap,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut bytes = vec![];

            source
                .serialize_into(&mut bytes)
                .map_err(serde::ser::Error::custom)?;
            let b64 = Base64::encode_string(&bytes);
            b64.serialize(serializer)
        }
    }

    impl<'de> DeserializeAs<'de, roaring::RoaringBitmap> for Base64RoaringBitmap {
        fn deserialize_as<D>(deserializer: D) -> Result<roaring::RoaringBitmap, D::Error>
        where
            D: Deserializer<'de>,
        {
            let b64: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
            let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
            roaring::RoaringBitmap::deserialize_from(&bytes[..]).map_err(serde::de::Error::custom)
        }
    }

    pub(crate) use super::SignedTransactionWithIntentMessage;
}

#[cfg(test)]
mod test {
    use super::{next_lexicographical_array, next_lexicographical_array_opt};

    #[test]
    fn test_lexical_order() {
        fn array_from_str(s: &str) -> [u8; 32] {
            hex::decode(s).unwrap().try_into().unwrap()
        }
        assert_eq!(
            next_lexicographical_array(&array_from_str(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            array_from_str("0000000000000000000000000000000000000000000000000000000000000001"),
        );
        assert_eq!(
            next_lexicographical_array(&array_from_str(
                "000000000000000000000000000000000000000000000000000000000000ffff"
            )),
            array_from_str("0000000000000000000000000000000000000000000000000000000000010000"),
        );
        assert_eq!(
            next_lexicographical_array(&array_from_str(
                "000000000000000000000000000000000000000000000000000000000001002c"
            )),
            array_from_str("000000000000000000000000000000000000000000000000000000000001002d"),
        );
        assert_eq!(
            next_lexicographical_array(&array_from_str(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )),
            array_from_str("0000000000000000000000000000000000000000000000000000000000000000"),
        );
    }

    #[test]
    fn test_lexical_order_opt() {
        fn array_from_str(s: &str) -> [u8; 32] {
            hex::decode(s).unwrap().try_into().unwrap()
        }
        assert_eq!(
            next_lexicographical_array_opt(&array_from_str(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            Some(array_from_str(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )),
        );
        assert_eq!(
            next_lexicographical_array_opt(&array_from_str(
                "000000000000000000000000000000000000000000000000000000000000ffff"
            )),
            Some(array_from_str(
                "0000000000000000000000000000000000000000000000000000000000010000"
            )),
        );
        assert_eq!(
            next_lexicographical_array_opt(&array_from_str(
                "000000000000000000000000000000000000000000000000000000000001002c"
            )),
            Some(array_from_str(
                "000000000000000000000000000000000000000000000000000000000001002d"
            )),
        );
        assert_eq!(
            next_lexicographical_array_opt(&array_from_str(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )),
            None,
        );
    }
}
