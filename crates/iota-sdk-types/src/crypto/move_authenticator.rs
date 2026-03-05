// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{Address, Input, ObjectId, ObjectReference, TypeTag};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveAuthenticator {
    /// Input objects or primitive values
    call_args: Vec<Input>,
    /// Type arguments for the Move authenticate function
    type_args: Vec<TypeTag>,
    /// The object that is authenticated. Represents the account being the
    /// sender of the transaction.
    object_to_authenticate: Input,
}

impl MoveAuthenticator {
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

    pub fn address(&self) -> Address {
        match self.object_to_authenticate {
            Input::ImmutableOrOwned(ObjectReference { object_id, .. })
            | Input::Shared { object_id, .. } => object_id.into(),
            _ => unreachable!(),
        }
    }

    pub fn call_args(&self) -> &[Input] {
        &self.call_args
    }

    pub fn type_args(&self) -> &[TypeTag] {
        &self.type_args
    }

    pub fn object_to_authenticate(&self) -> &Input {
        &self.object_to_authenticate
    }
}

impl crate::TreeDisplay for MoveAuthenticator {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Move Authenticator")?;
        w.vec_inline("Call Args", &self.call_args, false)?;
        w.vec_inline("Type Args", &self.type_args, false)?;
        w.leaf("Object to Authenticate", &self.object_to_authenticate, true)
    }
}

crate::impl_tree_display!(MoveAuthenticator);

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
                call_args: auth.call_args,
                type_args: auth.type_args,
                object_to_authenticate: auth.object_to_authenticate,
            })
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let as_bytes = bcs::to_bytes(&AuthenticatorRef {
                call_args: &self.call_args,
                type_args: &self.type_args,
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
        call_args: &'a Vec<Input>,
        type_args: &'a Vec<TypeTag>,
        object_to_authenticate: &'a Input,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "MoveAuthenticator")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct Authenticator {
        call_args: Vec<Input>,
        #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
        type_args: Vec<TypeTag>,
        object_to_authenticate: Input,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for MoveAuthenticator {
        fn schema_name() -> String {
            Authenticator::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            Authenticator::json_schema(generator)
        }
    }

    impl Serialize for MoveAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let authenticator_ref = AuthenticatorRef {
                    call_args: &self.call_args,
                    type_args: &self.type_args,
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
                    call_args,
                    type_args,
                    object_to_authenticate,
                } = Authenticator::deserialize(deserializer)?;
                Ok(Self {
                    call_args,
                    type_args,
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
