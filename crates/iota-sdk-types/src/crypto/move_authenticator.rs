// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::{
    hash::{Hash, Hasher},
    sync::OnceLock,
};

use crate::{
    Address, Input, ObjectId, ObjectReference, TypeTag, Version, transaction::SharedObjectReference,
};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MoveAuthenticator {
    pub(crate) inner: MoveAuthenticatorInner,
    /// A bytes representation of [struct MoveAuthenticator]. This helps with
    /// implementing trait [AsRef](core::convert::AsRef).
    bytes: OnceLock<Vec<u8>>,
}

/// MoveAuthenticatorInner is an enum that represents the different versions
/// of MoveAuthenticator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MoveAuthenticatorInner {
    V1(MoveAuthenticatorV1),
}

impl MoveAuthenticatorInner {
    crate::def_is_as_into_opt!(V1(MoveAuthenticatorV1));
}

/// Version 1 of the [`MoveAuthenticator`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MoveAuthenticatorV1 {
    /// Input objects or primitive values
    call_args: Vec<Input>,
    /// Type arguments for the Move authenticate function
    type_args: Vec<TypeTag>,
    /// The object that is authenticated. Represents the account being the
    /// sender of the transaction.
    object_to_authenticate: Input,
}

impl MoveAuthenticatorV1 {
    /// Create a new move authenticator from an immutable object.
    pub fn new_immutable(
        call_args: Vec<Input>,
        type_args: Vec<TypeTag>,
        object_to_authenticate: ObjectReference,
    ) -> Self {
        Self {
            call_args,
            type_args,
            object_to_authenticate: Input::ImmutableOrOwned(object_to_authenticate),
        }
    }

    /// Create a new move authenticator from a shared object.
    pub fn new_shared(
        call_args: Vec<Input>,
        type_args: Vec<TypeTag>,
        object_to_authenticate: ObjectId,
        initial_shared_version: Version,
    ) -> Self {
        Self {
            call_args,
            type_args,
            object_to_authenticate: Input::Shared(SharedObjectReference {
                object_id: object_to_authenticate,
                initial_shared_version,
                mutable: false,
            }),
        }
    }

    /// Returns the address of the object being authenticated, which acts as the
    /// sender of the transaction.
    pub fn address(&self) -> Address {
        match self.object_to_authenticate {
            Input::ImmutableOrOwned(ObjectReference { object_id, .. })
            | Input::Shared(SharedObjectReference { object_id, .. }) => object_id.into(),
            _ => unreachable!(),
        }
    }

    /// Returns the input objects or primitive values passed to the authenticate
    /// function.
    pub fn call_args(&self) -> &[Input] {
        &self.call_args
    }

    /// Returns the type arguments for the Move authenticate function.
    pub fn type_args(&self) -> &[TypeTag] {
        &self.type_args
    }

    /// Returns the object that is being authenticated (the account/sender).
    pub fn object_to_authenticate(&self) -> &Input {
        &self.object_to_authenticate
    }
}

// #[cfg(feature = "serde")]
// #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
// mod serialization {
//     use std::borrow::Cow;

//     use serde::{Deserialize, Deserializer, Serialize, Serializer};
//     use serde_with::{Bytes, DeserializeAs};

//     use super::*;
//     use crate::{SignatureScheme, crypto::SignatureFromBytesError};

//     #[derive(serde::Serialize)]
//     enum MoveAuthenticatorRef<'a> {
//         V1(&'a MoveAuthenticatorV1),
//     }

//     #[derive(serde::Deserialize)]
//     enum MoveAuthenticatorOwned {
//         V1(MoveAuthenticatorV1),
//     }

//     impl From<MoveAuthenticatorOwned> for MoveAuthenticator {
//         fn from(value: MoveAuthenticatorOwned) -> Self {
//             match value {
//                 MoveAuthenticatorOwned::V1(v1) => Self::V1(v1),
//             }
//         }
//     }

//     impl MoveAuthenticator {
//         pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self,
// SignatureFromBytesError> {             let bytes = bytes.as_ref();
//             let flag =
//                 SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
//                     SignatureFromBytesError::new("missing signature scheme
// flag")                 })?)
//                 .map_err(SignatureFromBytesError::new)?;
//             if flag != SignatureScheme::MoveAuthenticator {
//                 return Err(SignatureFromBytesError::new(
//                     "invalid move authenticator flag",
//                 ));
//             }
//             let bcs_bytes = &bytes[1..];

//             let authenticator =
// bcs::from_bytes::<MoveAuthenticatorOwned>(bcs_bytes)                 
// .map_err(SignatureFromBytesError::new)?;

//             Ok(authenticator.into())
//         }

//         pub fn to_bytes(&self) -> Vec<u8> {
//             let authenticator = match self {
//                 Self::V1(v1) => MoveAuthenticatorRef::V1(v1),
//             };
//             let as_bytes =
//                 bcs::to_bytes(&authenticator).expect("BCS serialization
// should not fail");             let mut bytes = Vec::with_capacity(1 +
// as_bytes.len());             bytes.push(SignatureScheme::MoveAuthenticator as
// u8);             bytes.extend(as_bytes);
//             bytes
//         }
//     }

//     impl Serialize for MoveAuthenticator {
//         fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where
//             S: Serializer,
//         {
//             if serializer.is_human_readable() {
//                 match self {
//                     Self::V1(v1) =>
// MoveAuthenticatorRef::V1(v1).serialize(serializer),                 }
//             } else {
//                 let bytes = self.to_bytes();
//                 serializer.serialize_bytes(&bytes)
//             }
//         }
//     }

//     impl<'de> Deserialize<'de> for MoveAuthenticator {
//         fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//         where
//             D: Deserializer<'de>,
//         {
//             if deserializer.is_human_readable() {
//                 let authenticator =
// MoveAuthenticatorOwned::deserialize(deserializer)?;                 
// Ok(authenticator.into())             } else {
//                 let bytes: Cow<'de, [u8]> =
// Bytes::deserialize_as(deserializer)?;                 
// Self::from_bytes(bytes).map_err(serde::de::Error::custom)             }
//         }
//     }
// }
