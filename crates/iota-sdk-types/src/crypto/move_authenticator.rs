// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::hash::{Hash, Hasher};

use crate::{
    Address, Input, ObjectId, ObjectReference, TypeTag, Version, transaction::SharedObjectReference,
};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq)]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum MoveAuthenticator {
    V1(MoveAuthenticatorV1),
}

impl MoveAuthenticator {
    crate::def_is_as_into_opt!(V1(MoveAuthenticatorV1));

    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
        }
    }

    pub fn address(&self) -> Address {
        match self {
            Self::V1(v1) => v1.address(),
        }
    }

    pub fn call_args(&self) -> &[Input] {
        match self {
            Self::V1(v1) => v1.call_args(),
        }
    }

    pub fn type_args(&self) -> &[TypeTag] {
        match self {
            Self::V1(v1) => v1.type_args(),
        }
    }

    pub fn object_to_authenticate(&self) -> &Input {
        match self {
            Self::V1(v1) => v1.object_to_authenticate(),
        }
    }
}

#[cfg(feature = "serde")]
impl Hash for MoveAuthenticator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
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
        object_to_authenticate: impl Into<ObjectId>,
        initial_shared_version: Version,
    ) -> Self {
        Self {
            call_args,
            type_args,
            object_to_authenticate: Input::Shared(SharedObjectReference {
                object_id: object_to_authenticate.into(),
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

    impl From<MoveAuthenticatorOwned> for MoveAuthenticator {
        fn from(value: MoveAuthenticatorOwned) -> Self {
            match value {
                MoveAuthenticatorOwned::V1(v1) => Self::V1(v1),
            }
        }
    }

    impl MoveAuthenticator {
        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            match bytes.as_ref().split_first() {
                Some((flag, tail)) if flag == &(SignatureScheme::MoveAuthenticator as u8) => {
                    let authenticator = bcs::from_bytes::<MoveAuthenticatorOwned>(tail)
                        .map_err(SignatureFromBytesError::new)?;
                    Ok(authenticator.into())
                }
                None => Err(SignatureFromBytesError::new(
                    "missing signature scheme flag",
                )),
                _ => Err(SignatureFromBytesError::new(
                    "invalid move authenticator flag",
                )),
            }
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            let authenticator = match self {
                Self::V1(v1) => MoveAuthenticatorRef::V1(v1),
            };
            let mut bytes = vec![SignatureScheme::MoveAuthenticator as u8];
            bcs::serialize_into(&mut bytes, &authenticator)
                .expect("BCS serialization should not fail");
            bytes
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
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Digest, SignatureScheme};

    #[cfg(feature = "proptest")]
    #[test_strategy::proptest]
    fn to_from_bytes_roundtrip(authenticator: MoveAuthenticator) {
        let bytes = authenticator.to_bytes();
        let decoded = MoveAuthenticator::from_bytes(&bytes).unwrap();
        assert_eq!(authenticator, decoded);
    }

    fn make_simple_authenticator() -> MoveAuthenticator {
        MoveAuthenticatorV1::new_immutable(
            vec![],
            vec![],
            ObjectReference {
                object_id: ObjectId::ZERO,
                version: Version::default(),
                digest: Digest::MIN,
            },
        )
        .into()
    }

    #[test]
    fn round_trip() {
        let auth = make_simple_authenticator();
        let bytes = auth.to_bytes();
        let decoded = MoveAuthenticator::from_bytes(&bytes).expect("round-trip should succeed");
        assert_eq!(auth, decoded);
    }

    #[test]
    fn as_ref_starts_with_flag_byte() {
        let auth = make_simple_authenticator();
        let bytes = auth.to_bytes();
        assert_eq!(bytes[0], SignatureScheme::MoveAuthenticator as u8);
    }

    #[test]
    fn from_bytes_rejects_wrong_flag() {
        let auth = make_simple_authenticator();
        let mut bytes = auth.to_bytes();
        bytes[0] = SignatureScheme::Ed25519 as u8;
        assert!(MoveAuthenticator::from_bytes(&bytes).is_err());
    }

    #[test]
    fn from_bytes_rejects_empty_input() {
        assert!(MoveAuthenticator::from_bytes([]).is_err());
    }

    #[test]
    fn from_bytes_rejects_flag_only() {
        let flag = SignatureScheme::MoveAuthenticator as u8;
        assert!(MoveAuthenticator::from_bytes([flag]).is_err());
    }

    // // ---- Signable / SignableBytes round-trip tests ----

    // use crate::crypto::{Signable, SignableBytes};

    // /// Helper: produce the signable bytes for a MoveAuthenticator (the
    // /// `"MoveAuthenticator::" ++ BCS(inner)` format).
    // fn signable_bytes(auth: &MoveAuthenticator) -> Vec<u8> {
    //     let mut buf = Vec::new();
    //     auth.write(&mut buf);
    //     buf
    // }

    // #[test]
    // fn signable_round_trip() {
    //     let auth = make_simple_authenticator();
    //     let bytes = signable_bytes(&auth);
    //     let decoded = MoveAuthenticator::from_signable_bytes(&bytes)
    //         .expect("round-trip via signable bytes should succeed");
    //     assert_eq!(auth, decoded);
    // }

    // #[test]
    // fn signable_bytes_start_with_name_tag() {
    //     let auth = make_simple_authenticator();
    //     let bytes = signable_bytes(&auth);
    //     let tag = b"MoveAuthenticator::";
    //     assert!(
    //         bytes.starts_with(tag),
    //         "signable bytes must start with the hardcoded name tag"
    //     );
    // }

    // #[test]
    // fn signable_bytes_payload_is_bcs_of_inner() {
    //     let auth = make_simple_authenticator();
    //     let bytes = signable_bytes(&auth);
    //     let tag_len = "MoveAuthenticator::".len();
    //     let payload = &bytes[tag_len..];
    //     let expected_bcs = bcs::to_bytes(&auth.inner).expect("BCS
    // serialization should not fail");     assert_eq!(payload,
    // expected_bcs.as_slice()); }

    // #[test]
    // fn from_signable_bytes_rejects_empty() {
    //     assert!(MoveAuthenticator::from_signable_bytes(&[]).is_err());
    // }

    // #[test]
    // fn from_signable_bytes_rejects_short_input() {
    //     // Shorter than the name tag — should fail, not panic.
    //     assert!(MoveAuthenticator::from_signable_bytes(b"Move").is_err());
    // }

    // #[test]
    // fn from_signable_bytes_rejects_tag_only() {
    //     // Exact tag with no BCS payload.
    //     assert!(MoveAuthenticator::from_signable_bytes(b"MoveAuthenticator::"
    // ).is_err()); }

    // #[test]
    // fn from_signable_bytes_rejects_corrupt_payload() {
    //     let auth = make_simple_authenticator();
    //     let mut bytes = signable_bytes(&auth);
    //     // Truncate the BCS payload so it is incomplete.
    //     let tag_len = "MoveAuthenticator::".len();
    //     bytes.truncate(tag_len + 1);
    //     assert!(MoveAuthenticator::from_signable_bytes(&bytes).is_err());
    // }

    #[test]
    fn digest_is_stable() {
        let auth = make_simple_authenticator();
        let d1 = auth.digest();
        let d2 = auth.digest();
        assert_eq!(d1, d2, "digest must be deterministic");
    }
}
