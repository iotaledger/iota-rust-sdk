// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Address, Input, ObjectId, ObjectReference, TypeTag};

/// MoveAuthenticator is a signature variant that enables a new
/// method of authentication through Move code.
/// This function represents the data received by the Move authenticate function
/// during the Account Abstraction authentication flow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveAuthenticator {
    /// Input objects or primitive values
    inputs: Vec<Input>,
    /// Type arguments for the Move authenticate function
    type_arguments: Vec<TypeTag>,
    /// The object that is authenticated. Represents the account being the
    /// sender of the transaction.
    object_to_authenticate: Input,
}

impl MoveAuthenticator {
    /// Create a new move authenticator with an input. Will return Some only if
    /// the input is valid. If possible, use [`Self::new_immutable_or_owned`] or
    /// [`Self::new_immutable_shared`].
    pub fn new(
        inputs: Vec<Input>,
        type_arguments: Vec<TypeTag>,
        object_to_authenticate: Input,
    ) -> Option<Self> {
        Some(match object_to_authenticate {
            Input::ImmutableOrOwned(obj) => {
                Self::new_immutable_or_owned(inputs, type_arguments, obj)
            }
            Input::Shared {
                object_id,
                initial_shared_version,
                mutable,
            } if !mutable => Self::new_immutable_shared(
                inputs,
                type_arguments,
                object_id,
                initial_shared_version,
            ),
            _ => return None,
        })
    }

    pub fn new_immutable_or_owned(
        inputs: Vec<Input>,
        type_arguments: Vec<TypeTag>,
        object_to_authenticate: ObjectReference,
    ) -> Self {
        Self {
            inputs,
            type_arguments,
            object_to_authenticate: Input::ImmutableOrOwned(object_to_authenticate),
        }
    }

    pub fn new_immutable_shared(
        inputs: Vec<Input>,
        type_arguments: Vec<TypeTag>,
        object_to_authenticate: ObjectId,
        initial_shared_version: u64,
    ) -> Self {
        Self {
            inputs,
            type_arguments,
            object_to_authenticate: Input::Shared {
                object_id: object_to_authenticate,
                initial_shared_version,
                mutable: false,
            },
        }
    }

    pub fn address(&self) -> Address {
        match self.object_to_authenticate {
            Input::ImmutableOrOwned(ObjectReference { object_id, .. })
            | Input::Shared { object_id, .. } => object_id.into(),
            _ => unreachable!(),
        }
    }

    #[cfg(feature = "hash")]
    pub fn digest(&self) -> crate::Digest {
        let mut hasher = crate::hash::Hasher::new();
        hasher.update(self.to_bytes());
        hasher.finalize()
    }

    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    pub fn inputs_mut(&mut self) -> &mut Vec<Input> {
        &mut self.inputs
    }

    pub fn type_arguments(&self) -> &[TypeTag] {
        &self.type_arguments
    }

    pub fn type_arguments_mut(&mut self) -> &mut Vec<TypeTag> {
        &mut self.type_arguments
    }

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

            let auth = bcs::from_bytes::<Authenticator>(bcs_bytes)
                .map_err(SignatureFromBytesError::new)?;

            Ok(Self {
                inputs: auth.inputs,
                type_arguments: auth.type_arguments,
                object_to_authenticate: auth.object_to_authenticate,
            })
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let as_bytes = bcs::to_bytes(&AuthenticatorRef {
                inputs: &self.inputs,
                type_arguments: &self.type_arguments,
                object_to_authenticate: &self.object_to_authenticate,
            })
            .expect("BCS serialization should not fail");
            let mut bytes = Vec::with_capacity(1 + as_bytes.len());
            bytes.push(SignatureScheme::MoveAuthenticator as u8);
            bytes.extend(as_bytes);
            bytes
        }
    }

    #[derive(serde::Serialize)]
    struct AuthenticatorRef<'a> {
        inputs: &'a Vec<Input>,
        type_arguments: &'a Vec<TypeTag>,
        object_to_authenticate: &'a Input,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "MoveAuthenticator")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct Authenticator {
        inputs: Vec<Input>,
        #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
        type_arguments: Vec<TypeTag>,
        object_to_authenticate: Input,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for MoveAuthenticator {
        fn schema_name() -> String {
            Authenticator::schema_name()
        }

        fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
            Authenticator::json_schema(gen)
        }
    }

    impl Serialize for MoveAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let authenticator_ref = AuthenticatorRef {
                    inputs: &self.inputs,
                    type_arguments: &self.type_arguments,
                    object_to_authenticate: &self.object_to_authenticate,
                };

                authenticator_ref.serialize(serializer)
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
                let Authenticator {
                    inputs,
                    type_arguments,
                    object_to_authenticate,
                } = Authenticator::deserialize(deserializer)?;
                Ok(Self {
                    inputs,
                    type_arguments,
                    object_to_authenticate,
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes)
            }
            .map_err(serde::de::Error::custom)
        }
    }
}
