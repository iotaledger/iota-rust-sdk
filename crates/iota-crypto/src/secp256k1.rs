// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "bech32")]
use bech32::Hrp;
use iota_sdk_types::{
    Secp256k1PublicKey, Secp256k1Signature, SignatureScheme, SimpleSignature, UserSignature,
};
use k256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::group::GroupEncoding,
};
use signature::{Signer, Verifier};

#[cfg(feature = "bech32")]
use crate::IOTA_PRIV_KEY_PREFIX;
use crate::SignatureError;

#[derive(Clone, Eq, PartialEq)]
pub struct Secp256k1PrivateKey(SigningKey);

impl std::fmt::Debug for Secp256k1PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secp256k1PrivateKey")
            .field(&"__elided__")
            .finish()
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for Secp256k1PrivateKey {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_filter_map("invalid secp256k1 private key", |bytes| {
                Self::new(bytes).ok()
            })
            .boxed()
    }
}

impl Secp256k1PrivateKey {
    /// The length of an secp256k1 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        SigningKey::from_bytes(&bytes.into()).map(Self)
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    pub fn verifying_key(&self) -> Secp256k1VerifyingKey {
        let verifying_key = self.0.verifying_key();
        Secp256k1VerifyingKey(*verifying_key)
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::new(self.0.verifying_key().as_ref().to_bytes().into())
    }

    /// Return the raw 32-byte private key
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes().into()
    }

    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        Self(SigningKey::random(&mut rng))
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use k256::pkcs8::EncodePrivateKey;

        self.0
            .to_pkcs8_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.as_bytes().to_owned())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8-encoded private key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePrivateKey;

        self.0
            .to_pkcs8_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
            .map(|pem| (*pem).to_owned())
    }

    #[cfg(feature = "bech32")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "bech32")))]
    /// Encode this private key as `flag || privkey` in Bech32 starting with
    /// "iotaprivkey" to a string.
    pub fn to_bech32(&self) -> Result<String, SignatureError> {
        let hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| SignatureError::from_source(format!("invalid HRP: {e}")))?;

        let mut bytes = Vec::new();
        bytes.push(SignatureScheme::Secp256k1.to_u8());
        bytes.extend_from_slice(&self.to_bytes());

        bech32::encode::<bech32::Bech32m>(hrp, &bytes)
            .map_err(|e| SignatureError::from_source(format!("bech32 encoding failed: {e}")))
    }

    #[cfg(feature = "bech32")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "bech32")))]
    /// Decode a private key from `flag || privkey` in Bech32 starting with
    /// "iotaprivkey".
    pub fn from_bech32(value: &str) -> Result<Self, SignatureError> {
        let expected_hrp = Hrp::parse(IOTA_PRIV_KEY_PREFIX)
            .map_err(|e| SignatureError::from_source(format!("invalid HRP: {e}")))?;

        let (hrp, data) = bech32::decode(value)
            .map_err(|e| SignatureError::from_source(format!("bech32 decoding failed: {e}")))?;

        if hrp != expected_hrp {
            return Err(SignatureError::from_source(format!(
                "invalid HRP: expected {IOTA_PRIV_KEY_PREFIX}, got {hrp}"
            )));
        }

        if data.is_empty() {
            return Err(SignatureError::from_source("empty bech32 data"));
        }

        let flag = SignatureScheme::from_byte(data[0])
            .map_err(|e| SignatureError::from_source(format!("invalid signature scheme: {e:?}")))?;

        if flag != SignatureScheme::Secp256k1 {
            return Err(SignatureError::from_source(format!(
                "invalid signature scheme: expected Secp256k1, got {flag:?}"
            )));
        }

        let key_bytes = &data[1..];
        if key_bytes.len() != Self::LENGTH {
            return Err(SignatureError::from_source("invalid secp256k1 key length"));
        }

        let mut arr = [0u8; Self::LENGTH];
        arr.copy_from_slice(key_bytes);
        Self::new(arr)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_k256(private_key: SigningKey) -> Self {
        Self(private_key)
    }
}

impl Signer<Secp256k1Signature> for Secp256k1PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<Secp256k1Signature, SignatureError> {
        let signature: k256::ecdsa::Signature = self.0.try_sign(message)?;
        Ok(Secp256k1Signature::new(signature.to_bytes().into()))
    }
}

impl Signer<SimpleSignature> for Secp256k1PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<SimpleSignature, SignatureError> {
        <Self as Signer<Secp256k1Signature>>::try_sign(self, msg).map(|signature| {
            SimpleSignature::Secp256k1 {
                signature,
                public_key: self.public_key(),
            }
        })
    }
}

impl Signer<UserSignature> for Secp256k1PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<UserSignature, SignatureError> {
        <Self as Signer<SimpleSignature>>::try_sign(self, msg).map(UserSignature::Simple)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Secp256k1VerifyingKey(VerifyingKey);

impl Secp256k1VerifyingKey {
    pub fn new(public_key: &Secp256k1PublicKey) -> Result<Self, SignatureError> {
        VerifyingKey::try_from(public_key.inner().as_ref()).map(Self)
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::new(self.0.as_ref().to_bytes().into())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.0
            .to_public_key_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.into_vec())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePublicKey::from_public_key_pem(s)
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key into PEM
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.0
            .to_public_key_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_k256(verifying_key: VerifyingKey) -> Self {
        Self(verifying_key)
    }
}

impl Verifier<Secp256k1Signature> for Secp256k1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> Result<(), SignatureError> {
        let signature = k256::ecdsa::Signature::from_bytes(signature.inner().into())?;
        self.0.verify(message, &signature)
    }
}

impl Verifier<SimpleSignature> for Secp256k1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Secp256k1 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not a secp256k1 signature"));
        };

        if public_key.inner() != self.public_key().inner() {
            return Err(SignatureError::from_source(
                "public_key in signature does not match",
            ));
        }

        <Self as Verifier<Secp256k1Signature>>::verify(self, message, signature)
    }
}

impl Verifier<UserSignature> for Secp256k1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not a secp256k1 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[derive(Default, Clone, Debug)]
pub struct Secp256k1Verifier {}

impl Secp256k1Verifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl Verifier<SimpleSignature> for Secp256k1Verifier {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Secp256k1 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not a secp256k1 signature"));
        };

        let verifying_key = Secp256k1VerifyingKey::new(public_key)?;

        verifying_key.verify(message, signature)
    }
}

impl Verifier<UserSignature> for Secp256k1Verifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not a secp256k1 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[cfg(test)]
mod test {
    use iota_sdk_types::PersonalMessage;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{IotaSigner, IotaVerifier};

    // TODO need to export proptest impl from core crate
    // #[proptest]
    // fn transaction_signing(signer: Secp256k1PrivateKey, transaction: Transaction)
    // {     let signature = signer.sign_transaction(&transaction).unwrap();
    //     let verifier = signer.public_key();
    //     verifier
    //         .verify_transaction(&transaction, &signature)
    //         .unwrap();
    // }

    #[proptest]
    fn personal_message_signing(signer: Secp256k1PrivateKey, message: Vec<u8>) {
        let message = PersonalMessage(message.into());
        let signature = signer.sign_personal_message(&message).unwrap();
        let verifying_key = signer.verifying_key();
        verifying_key
            .verify_personal_message(&message, &signature)
            .unwrap();

        let verifier = Secp256k1Verifier::default();
        verifier
            .verify_personal_message(&message, &signature)
            .unwrap();
    }

    #[test]
    fn personal_message_signing_fixture() {
        let key = [
            172, 12, 96, 180, 207, 143, 111, 151, 81, 57, 242, 89, 74, 5, 150, 51, 56, 111, 245,
            150, 182, 30, 149, 178, 29, 255, 188, 27, 48, 241, 151, 193,
        ];

        let signer = Secp256k1PrivateKey::new(key).unwrap();

        let message = PersonalMessage(b"hello".into());
        let sig = signer.sign_personal_message(&message).unwrap();
        let external_sig = "AVFAWGjuD8+xUoc6jMC0lKqMtT+4ukln7vz+8Nuv+EbYKl47jwzOWn39maDsqu81kezLPgLzz6o/AfSE0M9+jVwClcrtiuyUggEt/6CEZi8+JQ+NS9TmOhPBZV2X1KjhGCw=";
        let b64 = sig.to_base64();
        assert_eq!(external_sig, b64);
    }
}
