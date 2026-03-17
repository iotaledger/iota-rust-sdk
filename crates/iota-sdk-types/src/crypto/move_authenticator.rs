// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Address, Input, ObjectId, ObjectReference, TypeTag};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum MoveAuthenticator {
    V1(MoveAuthenticatorV1),
}

impl MoveAuthenticator {
    crate::def_is_as_into_opt!(V1(MoveAuthenticatorV1));
}

/// Version 1 of the [`MoveAuthenticator`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
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
        initial_shared_version: u64,
    ) -> Self {
        Self {
            call_args,
            type_args,
            object_to_authenticate: Input::Shared {
                object_id: object_to_authenticate,
                initial_shared_version,
                mutable: false,
            },
        }
    }

    /// Returns the address of the object being authenticated, which acts as the
    /// sender of the transaction.
    pub fn address(&self) -> Address {
        match self.object_to_authenticate {
            Input::ImmutableOrOwned(ObjectReference { object_id, .. })
            | Input::Shared { object_id, .. } => object_id.into(),
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

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::{SignatureScheme, crypto::SignatureFromBytesError};

    #[derive(serde::Serialize)]
    enum MoveAuthenticatorRef<'a> {
        V1(&'a MoveAuthenticatorV1),
    }

    #[derive(serde::Deserialize)]
    enum MoveAuthenticatorOwned {
        V1(MoveAuthenticatorV1),
    }

    #[cfg(feature = "schemars")]
    #[derive(schemars::JsonSchema)]
    #[schemars(rename = "MoveAuthenticator", deny_unknown_fields)]
    #[allow(dead_code, non_snake_case)]
    struct MoveAuthenticatorSchema {
        V1: MoveAuthenticatorV1,
    }

    impl From<MoveAuthenticatorOwned> for MoveAuthenticator {
        fn from(value: MoveAuthenticatorOwned) -> Self {
            match value {
                MoveAuthenticatorOwned::V1(v1) => Self::V1(v1),
            }
        }
    }

    impl MoveAuthenticator {
        pub fn from_serialized_bytes(
            bytes: impl AsRef<[u8]>,
        ) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            if flag != SignatureScheme::MoveAuthenticator {
                return Err(SignatureFromBytesError::new(
                    "invalid move authenticator flag",
                ));
            }
            let bcs_bytes = &bytes[1..];

            let authenticator = bcs::from_bytes::<MoveAuthenticatorOwned>(bcs_bytes)
                .map_err(SignatureFromBytesError::new)?;

            Ok(authenticator.into())
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let authenticator = match self {
                Self::V1(v1) => MoveAuthenticatorRef::V1(v1),
            };
            let as_bytes =
                bcs::to_bytes(&authenticator).expect("BCS serialization should not fail");
            let mut bytes = Vec::with_capacity(1 + as_bytes.len());
            bytes.push(SignatureScheme::MoveAuthenticator as u8);
            bytes.extend(as_bytes);
            bytes
        }
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for MoveAuthenticator {
        fn schema_name() -> String {
            MoveAuthenticatorSchema::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            MoveAuthenticatorSchema::json_schema(generator)
        }
    }

    impl Serialize for MoveAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                match self {
                    Self::V1(v1) => MoveAuthenticatorRef::V1(v1).serialize(serializer),
                }
            } else {
                let bytes = self.to_bytes();
                serializer.serialize_bytes(&bytes)
            }
        }
    }

    impl<'de> Deserialize<'de> for MoveAuthenticator {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let authenticator = MoveAuthenticatorOwned::deserialize(deserializer)?;
                Ok(authenticator.into())
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Digest, ObjectId, ObjectReference};

    fn test_object_id() -> ObjectId {
        ObjectId::new([1; 32])
    }

    fn test_object_ref() -> ObjectReference {
        ObjectReference::new(ObjectId::new([1; 32]), 1, Digest::new([2; 32]))
    }

    // --- Construction logic ---

    #[test]
    fn new_immutable_creates_immutable_or_owned_input() {
        let auth = MoveAuthenticator::new_immutable(vec![], vec![], test_object_ref());
        assert!(matches!(
            auth.object_to_authenticate(),
            Input::ImmutableOrOwned(_)
        ));
    }

    #[test]
    fn new_shared_creates_shared_input_with_mutable_false() {
        let auth =
            MoveAuthenticator::new_shared(vec![], vec![], test_object_id(), 42);
        match auth.object_to_authenticate() {
            Input::Shared {
                object_id,
                initial_shared_version,
                mutable,
            } => {
                assert_eq!(*object_id, test_object_id());
                assert_eq!(*initial_shared_version, 42);
                assert!(!mutable, "new_shared must set mutable to false");
            }
            _ => panic!("expected Shared input"),
        }
    }

    // --- address() pattern matching ---

    #[test]
    fn address_from_immutable_extracts_object_id() {
        let auth = MoveAuthenticator::new_immutable(vec![], vec![], test_object_ref());
        let addr = auth.address();
        assert_eq!(addr, Address::from(test_object_id()));
    }

    #[test]
    fn address_from_shared_extracts_object_id() {
        let auth =
            MoveAuthenticator::new_shared(vec![], vec![], test_object_id(), 1);
        let addr = auth.address();
        assert_eq!(addr, Address::from(test_object_id()));
    }

    // --- Serialization roundtrip ---

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_serialization_immutable() {
        let auth = MoveAuthenticator::new_immutable(vec![], vec![], test_object_ref());
        let bytes = auth.to_bytes();
        let recovered = MoveAuthenticator::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(auth, recovered);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_serialization_shared() {
        let auth =
            MoveAuthenticator::new_shared(vec![], vec![], test_object_id(), 99);
        let bytes = auth.to_bytes();
        let recovered = MoveAuthenticator::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(auth, recovered);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_with_call_args_and_type_args() {
        let pure_input = Input::Pure {
            value: vec![1, 2, 3],
        };
        let auth = MoveAuthenticator::new_immutable(
            vec![pure_input],
            vec![TypeTag::Bool],
            test_object_ref(),
        );
        let bytes = auth.to_bytes();
        let recovered = MoveAuthenticator::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(auth, recovered);
    }

    // --- from_serialized_bytes error paths ---

    #[cfg(feature = "serde")]
    #[test]
    fn from_serialized_bytes_empty_fails() {
        let result = MoveAuthenticator::from_serialized_bytes(&[]);
        assert!(result.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_serialized_bytes_wrong_flag_fails() {
        // 0x00 is Ed25519 flag
        let result = MoveAuthenticator::from_serialized_bytes(&[0x00]);
        assert!(result.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_serialized_bytes_invalid_bcs_fails() {
        use crate::SignatureScheme;
        let mut bytes = vec![SignatureScheme::MoveAuthenticator as u8];
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]);
        let result = MoveAuthenticator::from_serialized_bytes(&bytes);
        assert!(result.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn from_serialized_bytes_unknown_flag_fails() {
        // 0xFE is not a valid signature scheme
        let result = MoveAuthenticator::from_serialized_bytes(&[0xFE]);
        assert!(result.is_err());
    }
}
