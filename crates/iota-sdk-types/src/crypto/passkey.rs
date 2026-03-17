// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::{Secp256r1PublicKey, Secp256r1Signature, SimpleSignature};

/// A passkey authenticator.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// passkey-bcs = bytes               ; where the contents of the bytes are
///                                   ; defined by <passkey>
/// passkey     = passkey-flag
///               bytes               ; passkey authenticator data
///               client-data-json    ; valid json
///               simple-signature    ; required to be a secp256r1 signature
///
/// client-data-json = string ; valid json
/// ```
///
/// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata) for
/// the required json-schema for the `client-data-json` rule. In addition, IOTA
/// currently requires that the `CollectedClientData.type` field is required to
/// be `webauthn.get`.
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAuthenticator {
    /// The secp256r1 public key for this passkey.
    public_key: Secp256r1PublicKey,
    /// The secp256r1 signature from the passkey.
    signature: Secp256r1Signature,
    /// Parsed base64url decoded challenge bytes from
    /// `client_data_json.challenge`.
    challenge: Vec<u8>,
    /// Opaque authenticator data for this passkey signature.
    ///
    /// See [Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) for
    /// more information on this field.
    authenticator_data: Vec<u8>,
    /// Structured, unparsed, JSON for this passkey signature.
    ///
    /// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata)
    /// for more information on this field.
    client_data_json: String,
}

impl PasskeyAuthenticator {
    /// Opaque authenticator data for this passkey signature.
    ///
    /// See [Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) for
    /// more information on this field.
    pub fn authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }

    /// Structured, unparsed, JSON for this passkey signature.
    ///
    /// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata)
    /// for more information on this field.
    pub fn client_data_json(&self) -> &str {
        &self.client_data_json
    }

    /// The parsed challenge message for this passkey signature.
    ///
    /// This is parsed by decoding the base64url data from the
    /// `client_data_json.challenge` field.
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }

    /// The passkey signature.
    pub fn signature(&self) -> SimpleSignature {
        SimpleSignature::Secp256r1 {
            signature: self.signature,
            public_key: self.public_key,
        }
    }

    /// The passkey public key
    pub fn public_key(&self) -> PasskeyPublicKey {
        PasskeyPublicKey::new(self.public_key)
    }
}

/// Public key of a `PasskeyAuthenticator`.
///
/// This is used to derive the onchain `Address` for a `PasskeyAuthenticator`.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// passkey-public-key = passkey-flag secp256r1-public-key
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyPublicKey(Secp256r1PublicKey);

impl PasskeyPublicKey {
    pub fn new(public_key: Secp256r1PublicKey) -> Self {
        Self(public_key)
    }

    /// The underlying `Secp256r1PublicKey` for this passkey.
    pub fn inner(&self) -> &Secp256r1PublicKey {
        &self.0
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs};

    use super::*;
    use crate::{SignatureScheme, SimpleSignature, crypto::SignatureFromBytesError};

    #[derive(serde::Serialize)]
    struct AuthenticatorRef<'a> {
        authenticator_data: &'a Vec<u8>,
        client_data_json: &'a String,
        signature: SimpleSignature,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename = "PasskeyAuthenticator")]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    struct Authenticator {
        authenticator_data: Vec<u8>,
        client_data_json: String,
        signature: SimpleSignature,
    }

    #[cfg(feature = "schemars")]
    impl schemars::JsonSchema for PasskeyAuthenticator {
        fn schema_name() -> String {
            Authenticator::schema_name()
        }

        fn json_schema(
            generator: &mut schemars::r#gen::SchemaGenerator,
        ) -> schemars::schema::Schema {
            Authenticator::json_schema(generator)
        }
    }

    impl Serialize for PasskeyAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let authenticator_ref = AuthenticatorRef {
                    authenticator_data: &self.authenticator_data,
                    client_data_json: &self.client_data_json,
                    signature: SimpleSignature::Secp256r1 {
                        signature: self.signature,
                        public_key: self.public_key,
                    },
                };

                authenticator_ref.serialize(serializer)
            } else {
                let bytes = self.to_bytes();
                serializer.serialize_bytes(&bytes)
            }
        }
    }

    impl<'de> Deserialize<'de> for PasskeyAuthenticator {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let authenticator = Authenticator::deserialize(deserializer)?;
                Self::try_from_raw(authenticator)
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes)
            }
            .map_err(serde::de::Error::custom)
        }
    }

    impl PasskeyAuthenticator {
        pub fn new(
            authenticator_data: Vec<u8>,
            client_data_json: String,
            signature: SimpleSignature,
        ) -> Option<Self> {
            Self::try_from_raw(Authenticator {
                authenticator_data,
                client_data_json,
                signature,
            })
            .ok()
        }

        fn try_from_raw(
            Authenticator {
                authenticator_data,
                client_data_json,
                signature,
            }: Authenticator,
        ) -> Result<Self, SignatureFromBytesError> {
            let SimpleSignature::Secp256r1 {
                signature,
                public_key,
            } = signature
            else {
                return Err(SignatureFromBytesError::new(
                    "expected passkey with secp256r1 signature",
                ));
            };

            let CollectedClientData {
                ty: _,
                challenge,
                origin: _,
            } = serde_json::from_str(&client_data_json).map_err(SignatureFromBytesError::new)?;

            // decode unpadded url endoded base64 data per spec:
            // https://w3c.github.io/webauthn/#base64url-encoding
            let challenge = <base64ct::Base64UrlUnpadded as base64ct::Encoding>::decode_vec(
                &challenge,
            )
            .map_err(|e| {
                SignatureFromBytesError::new(format!(
                    "unable to decode base64urlunpadded into 3-byte intent and 32-byte digest: {e}"
                ))
            })?;

            Ok(Self {
                public_key,
                signature,
                challenge,
                authenticator_data,
                client_data_json,
            })
        }

        pub fn from_serialized_bytes(
            bytes: impl AsRef<[u8]>,
        ) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            if flag != SignatureScheme::PasskeyAuthenticator {
                return Err(SignatureFromBytesError::new("invalid passkey flag"));
            }
            let bcs_bytes = &bytes[1..];

            let authenticator = bcs::from_bytes(bcs_bytes).map_err(SignatureFromBytesError::new)?;

            Self::try_from_raw(authenticator)
        }

        pub(crate) fn to_bytes(&self) -> Vec<u8> {
            let authenticator_ref = AuthenticatorRef {
                authenticator_data: &self.authenticator_data,
                client_data_json: &self.client_data_json,
                signature: SimpleSignature::Secp256r1 {
                    signature: self.signature,
                    public_key: self.public_key,
                },
            };

            let mut buf = Vec::new();
            buf.push(SignatureScheme::PasskeyAuthenticator as u8);

            bcs::serialize_into(&mut buf, &authenticator_ref).expect("serialization cannot fail");
            buf
        }
    }

    /// The client data represents the contextual bindings of both the Relying
    /// Party and the client. It is a key-value mapping whose keys are
    /// strings. Values can be any type that has a valid encoding in JSON.
    ///
    /// > Note: The [`CollectedClientData`] may be extended in the future.
    /// > Therefore it’s critical when
    /// > parsing to be tolerant of unknown keys and of any reordering of the
    /// > keys
    ///
    /// This struct conforms to the JSON byte serialization format expected of
    /// `CollectedClientData`, detailed in section [5.8.1.1 Serialization]
    /// of the WebAuthn spec. Namely the following requirements:
    ///
    /// * `type`, `challenge`, `origin`, `crossOrigin` must always be present in
    ///   the serialized format _in that order_.
    ///
    /// <https://w3c.github.io/webauthn/#dictionary-client-data>
    ///
    /// [5.8.1.1 Serialization]: https://w3c.github.io/webauthn/#clientdatajson-serialization
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(super) struct CollectedClientData {
        /// This member contains the value [`ClientDataType::Create`] when
        /// creating new credentials, and [`ClientDataType::Get`] when
        /// getting an assertion from an existing credential. The purpose
        /// of this member is to prevent certain types of signature confusion
        /// attacks (where an attacker  substitutes one legitimate
        /// signature for another).
        #[serde(rename = "type")]
        pub ty: ClientDataType,
        /// This member contains the base64url encoding of the challenge
        /// provided by the Relying Party. See the [Cryptographic
        /// Challenges] security consideration.
        ///
        /// [Cryptographic Challenges]: https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
        ///
        /// https://w3c.github.io/webauthn/#base64url-encoding
        ///
        /// The term Base64url Encoding refers to the base64 encoding using the
        /// URL- and filename-safe character set defined in Section 5 of
        /// [RFC4648], with all trailing '=' characters omitted
        /// (as permitted by Section 3.2) and without the inclusion of any line
        /// breaks, whitespace, or other additional characters.
        pub challenge: String,
        /// This member contains the fully qualified origin of the requester, as
        /// provided to the authenticator by the client, in the syntax
        /// defined by [RFC6454].
        ///
        /// [RFC6454]: https://www.rfc-editor.org/rfc/rfc6454
        pub origin: String,
        // /// This OPTIONAL member contains the inverse of the sameOriginWithAncestors argument
        // value that /// was passed into the internal method
        // #[serde(default, serialize_with = "truthiness")]
        // #[serde(rename = "type")]
        // pub cross_origin: Option<bool>,
    }

    /// Used to limit the values of [`CollectedClientData::ty`] and serializes
    /// to static strings.
    #[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
    pub(super) enum ClientDataType {
        /// Serializes to the string `"webauthn.get"`
        ///
        /// Passkey's in IOTA only support the value `"webauthn.get"`, other
        /// values will be rejected.
        #[serde(rename = "webauthn.get")]
        Get,
        // /// Serializes to the string `"webauthn.create"`
        // #[serde(rename = "webauthn.create")]
        // Create,
        // /// Serializes to the string `"payment.get"`
        // /// This variant is part of the Secure Payment Confirmation specification
        // ///
        // /// See <https://www.w3.org/TR/secure-payment-confirmation/#client-extension-processing-authentication>
        // #[serde(rename = "payment.get")]
        // PaymentGet,
    }
}

#[cfg(feature = "proptest")]
impl proptest::arbitrary::Arbitrary for PasskeyAuthenticator {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{collection::vec, prelude::*};
        use serialization::{ClientDataType, CollectedClientData};

        (
            any::<Secp256r1PublicKey>(),
            any::<Secp256r1Signature>(),
            vec(any::<u8>(), 32),
            vec(any::<u8>(), 0..32),
        )
            .prop_map(
                |(public_key, signature, challenge_bytes, authenticator_data)| {
                    let challenge =
                        <base64ct::Base64UrlUnpadded as base64ct::Encoding>::encode_string(
                            &challenge_bytes,
                        );
                    let client_data_json = serde_json::to_string(&CollectedClientData {
                        ty: ClientDataType::Get,
                        challenge,
                        origin: "http://example.com".to_owned(),
                    })
                    .unwrap();

                    Self {
                        public_key,
                        signature,
                        challenge: challenge_bytes,
                        authenticator_data,
                        client_data_json,
                    }
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use crate::UserSignature;

    const PASSKEY_B64: &str = "BiVYDmenOnqS+thmz5m5SrZnWaKXZLVxgh+rri6LHXs25B0AAAAAnQF7InR5cGUiOiJ3ZWJhdXRobi5nZXQiLCAiY2hhbGxlbmdlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTE3MyIsImNyb3NzT3JpZ2luIjpmYWxzZSwgInVua25vd24iOiAidW5rbm93biJ9YgJMwqcOmZI7F/N+K5SMe4DRYCb4/cDWW68SFneSHoD2GxKKhksbpZ5rZpdrjSYABTCsFQQBpLORzTvbj4edWKd/AsEBeovrGvHR9Ku7critg6k7qvfFlPUngujXfEzXd8Eg";

    #[test]
    fn base64_encoded_passkey_user_signature() {
        let sig = UserSignature::from_base64(PASSKEY_B64).unwrap();
        assert!(matches!(sig, UserSignature::PasskeyAuthenticator(_)));
    }

    // --- Roundtrip serialization (exercises to_bytes + from_serialized_bytes) ---

    #[test]
    fn passkey_roundtrip_serialization() {
        let sig = UserSignature::from_base64(PASSKEY_B64).unwrap();
        if let UserSignature::PasskeyAuthenticator(passkey) = sig {
            let bytes = passkey.to_bytes();
            let recovered =
                super::PasskeyAuthenticator::from_serialized_bytes(&bytes).unwrap();
            assert_eq!(passkey, recovered);
        } else {
            panic!("expected passkey authenticator");
        }
    }

    // --- from_serialized_bytes error paths ---

    #[test]
    fn passkey_from_serialized_bytes_empty() {
        let result = super::PasskeyAuthenticator::from_serialized_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn passkey_from_serialized_bytes_wrong_flag() {
        // 0x00 is Ed25519 flag, not Passkey
        let result = super::PasskeyAuthenticator::from_serialized_bytes(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn passkey_from_serialized_bytes_invalid_bcs() {
        use crate::SignatureScheme;
        let mut bytes = vec![SignatureScheme::PasskeyAuthenticator as u8];
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]);
        let result = super::PasskeyAuthenticator::from_serialized_bytes(&bytes);
        assert!(result.is_err());
    }

    // --- try_from_raw validation logic via new() ---

    #[test]
    fn passkey_new_rejects_ed25519_signature() {
        use crate::{Ed25519PublicKey, Ed25519Signature, SimpleSignature};

        let sig = SimpleSignature::Ed25519 {
            signature: Ed25519Signature::new([0; 64]),
            public_key: Ed25519PublicKey::new([0; 32]),
        };
        let json = r#"{"type":"webauthn.get","challenge":"AAAA","origin":"http://example.com"}"#
            .to_string();
        let result = super::PasskeyAuthenticator::new(vec![0; 37], json, sig);
        assert!(result.is_none());
    }

    #[test]
    fn passkey_new_rejects_invalid_json() {
        use crate::{Secp256r1PublicKey, Secp256r1Signature, SimpleSignature};

        let sig = SimpleSignature::Secp256r1 {
            signature: Secp256r1Signature::new([0; 64]),
            public_key: Secp256r1PublicKey::new([0; 33]),
        };
        let result =
            super::PasskeyAuthenticator::new(vec![0; 37], "not json".to_string(), sig);
        assert!(result.is_none());
    }

    #[test]
    fn passkey_new_rejects_invalid_challenge_base64() {
        use crate::{Secp256r1PublicKey, Secp256r1Signature, SimpleSignature};

        let sig = SimpleSignature::Secp256r1 {
            signature: Secp256r1Signature::new([0; 64]),
            public_key: Secp256r1PublicKey::new([0; 33]),
        };
        // Valid JSON but challenge field has invalid base64url
        let json =
            r#"{"type":"webauthn.get","challenge":"!!!invalid!!!","origin":"http://example.com"}"#
                .to_string();
        let result = super::PasskeyAuthenticator::new(vec![0; 37], json, sig);
        assert!(result.is_none());
    }

    #[test]
    fn passkey_new_valid_secp256r1() {
        use crate::{Secp256r1PublicKey, Secp256r1Signature, SimpleSignature};

        let sig = SimpleSignature::Secp256r1 {
            signature: Secp256r1Signature::new([0; 64]),
            public_key: Secp256r1PublicKey::new([0; 33]),
        };
        let json = r#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"http://example.com"}"#
            .to_string();
        let result = super::PasskeyAuthenticator::new(vec![0; 37], json, sig);
        assert!(result.is_some());
        let passkey = result.unwrap();
        assert!(!passkey.challenge().is_empty());
        assert!(!passkey.client_data_json().is_empty());
    }

    // --- Parsed field validation ---

    #[test]
    fn passkey_challenge_is_decoded_from_client_data() {
        let sig = UserSignature::from_base64(PASSKEY_B64).unwrap();
        if let UserSignature::PasskeyAuthenticator(passkey) = sig {
            // The challenge in the test data is all zeros (base64url "AAAA...AAA")
            assert!(!passkey.challenge().is_empty());
            // Verify the signature is secp256r1
            assert!(matches!(
                passkey.signature(),
                crate::SimpleSignature::Secp256r1 { .. }
            ));
        } else {
            panic!("expected passkey");
        }
    }
}
