// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "serde")]
use std::hash::{Hash, Hasher};

use crate::{Address, Input, ObjectReference, TypeTag, transaction::SharedObjectReference};

/// MoveAuthenticator is a signature variant that enables a method of
/// authentication through Move code. This type represents the data received
/// by the Move authenticate function during the Account Abstraction
/// authentication flow.
#[derive(Clone, Debug, derive_more::From, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
#[non_exhaustive]
pub enum MoveAuthenticator {
    V1(MoveAuthenticatorV1),
    // When new variants are introduced, it is important that we consciously gate
    // version support (e.g. in transaction validity checks based on the protocol
    // config), as is done for `Transaction`.
}

impl MoveAuthenticator {
    crate::def_is_as_into_opt!(V1(MoveAuthenticatorV1));

    /// Returns the version number of this authenticator variant.
    pub fn version(&self) -> u64 {
        match self {
            Self::V1(_) => 1,
        }
    }

    /// Returns the address of the object being authenticated, which acts as
    /// the sender of the transaction.
    pub fn address(&self) -> Address {
        match self {
            Self::V1(v1) => v1.address(),
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
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct MoveAuthenticatorV1 {
    /// Input objects or primitive values
    call_args: Vec<Input>,
    /// Type arguments for the Move authenticate function
    type_args: Vec<TypeTag>,
    /// The object that is authenticated. Represents the account being the
    /// sender of the transaction.
    ///
    /// Only [`Input::ImmutableOrOwned`] and [`Input::Shared`] are valid here;
    /// deserialization rejects any other [`Input`] variant.
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "deserialize_object_to_authenticate")
    )]
    #[cfg_attr(feature = "proptest", strategy(arb_object_to_authenticate()))]
    object_to_authenticate: Input,
}

/// Deserializes [`MoveAuthenticatorV1::object_to_authenticate`], rejecting any
/// [`Input`] variant other than [`Input::ImmutableOrOwned`] or
/// [`Input::Shared`].
#[cfg(feature = "serde")]
fn deserialize_object_to_authenticate<'de, D>(deserializer: D) -> Result<Input, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let input = <Input as serde::Deserialize>::deserialize(deserializer)?;
    if !matches!(input, Input::ImmutableOrOwned(_) | Input::Shared(_)) {
        return Err(serde::de::Error::custom(
            "object_to_authenticate must be an immutable/owned or shared object",
        ));
    }
    Ok(input)
}

/// Strategy generating only the [`Input`] variants valid for
/// [`MoveAuthenticatorV1::object_to_authenticate`], keeping proptest-generated
/// values in sync with what [`deserialize_object_to_authenticate`] accepts.
#[cfg(feature = "proptest")]
fn arb_object_to_authenticate() -> impl proptest::strategy::Strategy<Value = Input> {
    use proptest::prelude::*;

    prop_oneof![
        any::<ObjectReference>().prop_map(Input::ImmutableOrOwned),
        any::<SharedObjectReference>().prop_map(Input::Shared),
    ]
}

impl MoveAuthenticatorV1 {
    /// Create a new move authenticator with an immutable object.
    pub fn new_with_immutable_account_object(
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

    /// Create a new move authenticator with a shared object.
    pub fn new_with_shared_account_object(
        call_args: Vec<Input>,
        type_args: Vec<TypeTag>,
        object_to_authenticate: SharedObjectReference,
    ) -> Self {
        Self {
            call_args,
            type_args,
            object_to_authenticate: Input::Shared(object_to_authenticate),
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

impl crate::TreeDisplay for MoveAuthenticator {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        match self {
            Self::V1(v1) => v1.fmt_tree(w),
        }
    }
}

impl crate::TreeDisplay for MoveAuthenticatorV1 {
    fn fmt_tree(&self, w: &mut crate::TreeWriter<'_, '_>) -> std::fmt::Result {
        w.header("Move Authenticator V1")?;
        w.vec_inline("Call Args", &self.call_args, false)?;
        w.vec_inline("Type Args", &self.type_args, false)?;
        w.leaf("Object to Authenticate", &self.object_to_authenticate, true)
    }
}

crate::impl_tree_display!(MoveAuthenticator, MoveAuthenticatorV1);

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {

    use super::*;
    use crate::{SignatureScheme, crypto::SignatureFromBytesError};

    impl MoveAuthenticator {
        pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SignatureFromBytesError> {
            match bytes.as_ref().split_first() {
                Some((flag, tail)) if flag == &(SignatureScheme::MoveAuthenticator as u8) => {
                    let authenticator =
                        bcs::from_bytes(tail).map_err(SignatureFromBytesError::new)?;
                    Ok(authenticator)
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
            let mut bytes = vec![SignatureScheme::MoveAuthenticator as u8];
            bcs::serialize_into(&mut bytes, self).expect("BCS serialization should not fail");
            bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};

    use super::*;
    use crate::{ObjectDigest, ObjectId, SignatureScheme, StructTag, Version};

    #[cfg(feature = "proptest")]
    #[test_strategy::proptest]
    fn to_from_bytes_roundtrip(authenticator: MoveAuthenticator) {
        let bytes = authenticator.to_bytes();
        let decoded = MoveAuthenticator::from_bytes(&bytes).unwrap();
        assert_eq!(authenticator, decoded);
    }

    fn make_simple_authenticator() -> MoveAuthenticator {
        MoveAuthenticatorV1::new_with_immutable_account_object(
            vec![],
            vec![],
            ObjectReference {
                object_id: ObjectId::ZERO,
                version: Version::default(),
                digest: ObjectDigest::MIN,
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

    #[test]
    fn deserialization_rejects_non_object_to_authenticate() {
        // Serialization is unchecked and the field is private, so craft the
        // forbidden values directly to confirm only deserialization rejects
        // them.
        let bad_inputs = [
            Input::Pure(vec![1, 2, 3]),
            Input::Receiving(ObjectReference {
                object_id: ObjectId::ZERO,
                version: Version::default(),
                digest: ObjectDigest::MIN,
            }),
        ];

        for bad in bad_inputs {
            let auth: MoveAuthenticator = MoveAuthenticatorV1 {
                call_args: vec![],
                type_args: vec![],
                object_to_authenticate: bad,
            }
            .into();

            let bytes = auth.to_bytes();
            assert!(
                MoveAuthenticator::from_bytes(&bytes).is_err(),
                "from_bytes accepted an invalid object_to_authenticate"
            );
            assert!(
                bcs::from_bytes::<MoveAuthenticator>(&bytes[1..]).is_err(),
                "bcs::from_bytes accepted an invalid object_to_authenticate"
            );
        }
    }

    #[test]
    fn digest_is_stable() {
        let auth = make_simple_authenticator();
        let d1 = auth.digest();
        let d2 = auth.digest();
        assert_eq!(d1, d2, "digest must be deterministic");
    }

    /// An on-chain `MoveAuthenticator` fixture, decoded along both
    /// deserialization paths.
    struct OnchainFixture {
        /// Human-readable label: `<network>/<object-id> (<module::Type>)`.
        name: &'static str,
        /// Base64 of the full serialized authenticator, including the leading
        /// `0x07` `SignatureScheme::MoveAuthenticator` flag byte.
        b64: &'static str,
        /// Base58 `MoveAuthenticator::digest()`, frozen to pin the digest.
        digest: &'static str,
    }

    const ONCHAIN_FIXTURES: &[OnchainFixture] = &[
        OnchainFixture {
            name: "testnet/ALZRemHMDS7L5hTvNbsqBo3m9ppHdss9fnYBrhg5Goj1 (aa_account::AaAccount)",
            b64: "BwABAEFAdejeXdVxX1N3uRLMiN0JwVpjv6eHBifT8UArw4pbtWm97VsuumR+8hMtjM2mEjb\
                  Ee/jkfaT56XpJV0z7jkJlCAABAc3u5+O9aBuquT6Im52SkO0kkwEhc7Wrg6ZHdv6fiStAR\
                  CtCLAAAAAAA",
            digest: "AWeraivr6263NnYKJrcjY2VVLK2WxpzaDEF2QgND6HBK",
        },
        OnchainFixture {
            name: "devnet/41oDCfQCGfDzKMfjaU86QYaMBAGzq8bnZNzwsLAtMPk8 (account::Account)",
            b64: "BwAAAAEB8kJHXl+LL+m/5ObJe9HzZIWcZmfJyMy8lbdwmVs8yj7bEgAAAAAAAAA=",
            digest: "CRiTQyu66bKqSeJxFQkkfBT6J6Jii3fYsU6PrtR9oyrQ",
        },
        OnchainFixture {
            name: "devnet/DYTjjcdMLU3VNnisMC64WRrVkYKqPWWsL1EnTwoxAJm8 (hello_auth::HelloAccount)",
            b64: "BwABAAYFaGVsbG8AAQFOFRfoxTE0XBbAomMfZPtKexQDDQSZI+5aR9rxRkLeiQAVAAAAAAAAAA==",
            digest: "H1Y9d4EwDyHY5NG4UDgapZB3rNKurmR5uBX8K2kLsaqb",
        },
        OnchainFixture {
            name: "devnet/CEjBf3YYX6hNsZJEaaZPkjWchuEz9MWPc9W5EBuJktNN (account::Account)",
            b64: "BwACAAYFaGVsbG8BAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAQAAAAAAAAAA\
                  AAEB92KcqQiZnqkHF28wCqvXRn88hVPa40M1sqVvigXR+ScpHAAAAAAAAAA=",
            digest: "HJkQMWprAUKPb9TrNS1et24E3W14mAj3zhnaMhzvs9xX",
        },
        OnchainFixture {
            name: "devnet/FQgayuRhjKFqGwkLgvVN4jgH6myPdG7w1e7q1RzscrF1 (aa_account::AaAccount)",
            b64: "BwABAEFAh64Dfrb0dplbEEzUQLurZmsa+vs3MyztJcWMFHl6cqhE5trBvkD6/ZXiQZc0YtB\
                  rQQz6dT/81A+OvPbjHFoeDAABAQIZcv04vZKmCHTOHBMuF5nxVFvZMhvMBokb8gMb0XHadH\
                  sAAAAAAAAA",
            digest: "omshjh4rvYCa26vGEkpAkgNArwSVYYUwFkNczvctAXQ",
        },
    ];

    /// A synthetic `MoveAuthenticator` fixture: a value built in code together
    /// with its frozen wire encoding. The builder catches accidental value
    /// changes; the frozen `b64` catches encoding drift (e.g. a `Input`
    /// variant being reordered).
    struct SyntheticFixture {
        name: &'static str,
        auth: MoveAuthenticator,
        b64: &'static str,
        digest: &'static str,
    }

    /// Synthetic fixtures exercising structural shapes absent from the on-chain
    /// fixtures: an owned (`ImmutableOrOwned`) object to authenticate,
    /// non-empty and nested `type_arguments`, and `call_args` containing
    /// owned / receiving / mutable-shared inputs.
    fn synthetic_fixtures() -> Vec<SyntheticFixture> {
        let owned = |b: u8, v: u64| {
            ObjectReference::new(
                ObjectId::new([b; 32]),
                Version::from_u64(v),
                ObjectDigest::MIN,
            )
        };
        let shared = |b: u8, v: u64, mutable: bool| {
            SharedObjectReference::new(ObjectId::new([b; 32]), Version::from_u64(v), mutable)
        };
        let receiving = |b: u8, v: u64| {
            Input::Receiving(ObjectReference::new(
                ObjectId::new([b; 32]),
                Version::from_u64(v),
                ObjectDigest::MIN,
            ))
        };

        vec![
            SyntheticFixture {
                name: "synthetic/owned-object-to-authenticate",
                auth: MoveAuthenticatorV1::new_with_immutable_account_object(
                    vec![],
                    vec![],
                    owned(0x11, 7),
                )
                .into(),
                b64: "BwAAAAEAEREREREREREREREREREREREREREREREREREREREREREHAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                digest: "C3YqVQTCABN3t2bZqv9vbJfVroEA4Bd1t2EvesuxGiMX",
            },
            SyntheticFixture {
                name: "synthetic/nested-type-arguments",
                auth: MoveAuthenticatorV1::new_with_shared_account_object(
                    vec![],
                    vec![
                        TypeTag::U64,
                        TypeTag::Vector(Box::new(TypeTag::U8)),
                        TypeTag::Struct(Box::new(StructTag::new_gas_coin())),
                    ],
                    shared(0x22, 3, false),
                )
                .into(),
                b64: "BwAAAwIGAQcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgRjb2luBENvaW4BBwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBGlvdGEESU9UQQABASIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAwAAAAAAAAAA",
                digest: "36UQmS8XFEqLJBDRpMP5WTvgsRu59TFGdr5cxJCviAc4",
            },
            SyntheticFixture {
                name: "synthetic/owned-and-receiving-call-args",
                auth: MoveAuthenticatorV1::new_with_shared_account_object(
                    vec![Input::ImmutableOrOwned(owned(0x33, 1)), receiving(0x44, 2)],
                    vec![],
                    shared(0x55, 9, false),
                )
                .into(),
                b64: "BwACAQAzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMwEAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQJERERERERERERERERERERERERERERERERERERERERERAIAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVUJAAAAAAAAAAA=",
                digest: "FBYGx2eA5qqFPwG6H1aoe4Psrj7w66TF7VnibULUdT9S",
            },
            SyntheticFixture {
                name: "synthetic/mutable-shared-call-arg-owned-target",
                auth: MoveAuthenticatorV1::new_with_immutable_account_object(
                    vec![Input::Shared(shared(0x66, 5, true))],
                    vec![],
                    owned(0x77, 8),
                )
                .into(),
                b64: "BwABAQFmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgUAAAAAAAAAAQABAHd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3CAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                digest: "6y4vmN1UG2ncjNwRpoH7xw5fGmRmkRDTduKWLf9VNZXB",
            },
            SyntheticFixture {
                name: "synthetic/kitchen-sink",
                auth: MoveAuthenticatorV1::new_with_immutable_account_object(
                    vec![
                        Input::Pure(vec![1, 2, 3, 4]),
                        Input::ImmutableOrOwned(owned(0x88, 10)),
                        Input::Shared(shared(0x99, 11, true)),
                        receiving(0xaa, 12),
                    ],
                    vec![
                        TypeTag::Address,
                        TypeTag::Struct(Box::new(StructTag::new_gas_coin())),
                    ],
                    owned(0xbb, 13),
                )
                .into(),
                b64: "BwAEAAQBAgMEAQCIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAoAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmQsAAAAAAAAAAQECqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqoMAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEBwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACBGNvaW4EQ29pbgEHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIEaW90YQRJT1RBAAEAu7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7sNAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                digest: "9btfpDWStq2SBr6FeQuK1WwgPHdgajd3fipwwqr65ce7",
            },
        ]
    }

    /// Asserts the full encode/decode contract for a fixture given its base64
    /// wire bytes. When `expected` is supplied, the decoded value must equal
    /// it.
    fn check_round_trip(name: &str, b64: &str, digest: &str, expected: Option<&MoveAuthenticator>) {
        let bytes =
            Base64::decode_vec(b64).unwrap_or_else(|e| panic!("{name}: invalid base64: {e:?}"));

        // Flag-aware decode.
        let auth_from_bytes = MoveAuthenticator::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{name}: MoveAuthenticator::from_bytes: {e:?}"));

        // Re-encoding reproduces the exact bytes.
        assert_eq!(
            auth_from_bytes.to_bytes(),
            bytes,
            "{name}: re-serialization mismatch"
        );

        // Raw BCS of the tail into the inner enum agrees with the flag-aware path.
        let auth_from_bcs = bcs::from_bytes::<MoveAuthenticator>(&bytes[1..])
            .unwrap_or_else(|e| panic!("{name}: bcs::from_bytes: {e:?}"));

        // Mirror of the raw-BCS decode path: encoding the inner enum reproduces
        // the flag-stripped tail (`to_bytes` is just this prefixed with the flag).
        assert_eq!(
            bcs::to_bytes(&auth_from_bytes)
                .expect("BCS serialization should not fail")
                .as_slice(),
            &bytes[1..],
            "{name}: bcs::to_bytes(inner) != flag-stripped tail",
        );

        assert_eq!(
            auth_from_bytes, auth_from_bcs,
            "{name}: the two decode paths disagree",
        );

        if let Some(expected) = expected {
            assert_eq!(
                &auth_from_bytes, expected,
                "{name}: decoded value differs from the builder"
            );
            assert_eq!(
                &auth_from_bcs, expected,
                "{name}: decoded value differs from the builder"
            );
        }

        // The authenticator's digest matches the frozen value.
        assert_eq!(
            auth_from_bytes.digest().to_string(),
            digest,
            "{name}: MoveAuthenticator::digest() drifted"
        );
    }

    #[test]
    fn onchain_fixtures_round_trip() {
        for f in ONCHAIN_FIXTURES {
            check_round_trip(f.name, f.b64, f.digest, None);
        }
    }

    #[test]
    fn synthetic_fixtures_round_trip() {
        for f in synthetic_fixtures() {
            check_round_trip(f.name, f.b64, f.digest, Some(&f.auth));
        }
    }
}
