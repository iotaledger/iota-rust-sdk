// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::{
    secp256r1::{
        Secp256r1KeyPair, Secp256r1PublicKey as FcSecp256r1PublicKey,
        Secp256r1Signature as FcSecp256r1Signature,
    },
    traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _},
};
use iota_types::{
    Secp256r1PublicKey, Secp256r1Signature, SignatureScheme, SimpleSignature, UserSignature,
};
use signature::{Signer, Verifier};

use crate::SignatureError;

#[derive(Clone, Eq, PartialEq)]
pub struct Secp256r1PrivateKey([u8; Self::LENGTH]);

impl std::fmt::Debug for Secp256r1PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secp256r1PrivateKey")
            .field(&"__elided__")
            .finish()
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for Secp256r1PrivateKey {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_map(Self::new)
            .boxed()
    }
}

impl Secp256r1PrivateKey {
    /// The length of an secp256r1 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Self {
        // Validate that the bytes form a well-formed secp256r1 private key.
        Secp256r1KeyPair::from_bytes(&bytes).expect("invalid secp256r1 private key");
        Self(bytes)
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256r1
    }

    /// Reconstruct the fastcrypto keypair, which performs all signing.
    fn keypair(&self) -> Secp256r1KeyPair {
        Secp256r1KeyPair::from_bytes(&self.0).expect("validated on construction")
    }

    pub fn verifying_key(&self) -> Secp256r1VerifyingKey {
        Secp256r1VerifyingKey(self.keypair().public().clone())
    }

    pub fn public_key(&self) -> Secp256r1PublicKey {
        Secp256r1PublicKey::new(
            self.keypair()
                .public()
                .as_ref()
                .try_into()
                .expect("secp256r1 public key is 33 bytes"),
        )
    }

    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as DER-encoded PKCS#8
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use p256::pkcs8::EncodePrivateKey;

        self.to_p256()?
            .to_pkcs8_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.as_bytes().to_owned())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize PKCS#8-encoded private key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this private key as PEM-encoded PKCS#8
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePrivateKey;

        self.to_p256()?
            .to_pkcs8_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
            .map(|pem| (*pem).to_owned())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_p256(private_key: p256::ecdsa::SigningKey) -> Self {
        Self::new(private_key.to_bytes().into())
    }

    /// Re-expose the raw private key through p256, used only as a PKCS#8/PEM
    /// codec. Don't sign with the returned key — use this type's `Signer` impl
    /// (`try_sign`) instead, so signing goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_p256(&self) -> Result<p256::ecdsa::SigningKey, SignatureError> {
        p256::ecdsa::SigningKey::from_slice(&self.0).map_err(SignatureError::from_source)
    }
}

impl crate::ToFromBytes for Secp256r1PrivateKey {
    type Error = crate::PrivateKeyError;
    type ByteArray = [u8; Self::LENGTH];

    /// Return the raw 32-byte private key
    fn to_bytes(&self) -> Self::ByteArray {
        self.0
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Self::Error> {
        let bytes = bytes.as_ref();
        if bytes.len() != Self::LENGTH {
            return Err(crate::PrivateKeyError::InvalidScheme(
                "invalid secp256r1 key length".to_string(),
            ));
        }

        let mut arr = [0u8; Self::LENGTH];
        arr.copy_from_slice(bytes);

        // Reject scalars that aren't a well-formed secp256r1 private key (e.g.
        // all-zeros or >= the curve order) rather than panicking in `new`.
        Secp256r1KeyPair::from_bytes(&arr).map_err(|e| {
            crate::PrivateKeyError::InvalidScheme(format!("invalid secp256r1 private key: {e}"))
        })?;
        Ok(Self(arr))
    }
}

impl crate::PrivateKeyScheme for Secp256r1PrivateKey {
    const SCHEME: SignatureScheme = SignatureScheme::Secp256r1;
}

#[cfg(feature = "mnemonic")]
impl crate::FromMnemonic for Secp256r1PrivateKey {
    type Error = crate::PrivateKeyError;

    fn from_mnemonic(
        phrase: &str,
        account_index: impl Into<Option<u64>>,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let path = format!(
            "m/{}'/{}'/0'/0/{}",
            crate::DERIVATION_PATH_PURPOSE_SECP256R1,
            crate::DERIVATION_PATH_COIN_TYPE,
            account_index.into().unwrap_or_default()
        );
        Self::from_mnemonic_with_path(phrase, path, password)
    }

    fn from_mnemonic_with_path(
        phrase: &str,
        path: String,
        password: impl Into<Option<String>>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        use std::str::FromStr;

        use crate::ToFromBytes;

        let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)?;
        let seed = mnemonic.to_seed(password.into().unwrap_or_default());
        let child_xprv =
            bip32::XPrv::derive_from_path(seed, &bip32::DerivationPath::from_str(&path)?)?;
        Self::from_bytes(child_xprv.private_key().to_bytes())
    }
}

impl Signer<Secp256r1Signature> for Secp256r1PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<Secp256r1Signature, SignatureError> {
        // fastcrypto signs with SHA-256 and normalizes the signature to low-S.
        let signature: FcSecp256r1Signature = self.keypair().sign(message);
        Ok(Secp256r1Signature::new(
            signature
                .as_ref()
                .try_into()
                .expect("secp256r1 signature is 64 bytes"),
        ))
    }
}

impl Signer<SimpleSignature> for Secp256r1PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<SimpleSignature, SignatureError> {
        <Self as Signer<Secp256r1Signature>>::try_sign(self, msg).map(|signature| {
            SimpleSignature::Secp256r1 {
                signature,
                public_key: self.public_key(),
            }
        })
    }
}

impl Signer<UserSignature> for Secp256r1PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<UserSignature, SignatureError> {
        <Self as Signer<SimpleSignature>>::try_sign(self, msg).map(UserSignature::Simple)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256r1VerifyingKey(FcSecp256r1PublicKey);

impl Secp256r1VerifyingKey {
    pub fn new(public_key: &Secp256r1PublicKey) -> Result<Self, SignatureError> {
        FcSecp256r1PublicKey::from_bytes(public_key.inner().as_ref())
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Secp256r1PublicKey {
        Secp256r1PublicKey::new(
            self.0
                .as_ref()
                .try_into()
                .expect("secp256r1 public key is 33 bytes"),
        )
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key as DER-encoded data
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_p256()?
            .to_public_key_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.into_vec())
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Deserialize public key from PEM.
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePublicKey::from_public_key_pem(s)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    /// Serialize this public key into PEM
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_p256()?
            .to_public_key_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_p256(verifying_key: p256::ecdsa::VerifyingKey) -> Self {
        let compressed = verifying_key.to_encoded_point(true);
        Self(
            FcSecp256r1PublicKey::from_bytes(compressed.as_bytes())
                .expect("p256 public key is a valid secp256r1 point"),
        )
    }

    /// Re-expose the public key through p256, used only as a PKCS#8/PEM codec.
    /// Don't verify with the returned key — use this type's `Verifier` impl
    /// instead, so verification goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_p256(&self) -> Result<p256::ecdsa::VerifyingKey, SignatureError> {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(self.0.as_ref())
            .map_err(SignatureError::from_source)
    }
}

impl Verifier<Secp256r1Signature> for Secp256r1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Secp256r1Signature) -> Result<(), SignatureError> {
        // fastcrypto hashes with SHA-256 and rejects high-S signatures.
        let signature = FcSecp256r1Signature::from_bytes(signature.inner())
            .map_err(SignatureError::from_source)?;
        self.0
            .verify(message, &signature)
            .map_err(SignatureError::from_source)
    }
}

impl Verifier<SimpleSignature> for Secp256r1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Secp256r1 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not a secp256r1 signature"));
        };

        if public_key.inner() != self.public_key().inner() {
            return Err(SignatureError::from_source(
                "public_key in signature does not match",
            ));
        }

        <Self as Verifier<Secp256r1Signature>>::verify(self, message, signature)
    }
}

impl Verifier<UserSignature> for Secp256r1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not a secp256r1 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Secp256r1Verifier {}

impl Secp256r1Verifier {
    pub fn new() -> Self {
        Self {}
    }
}

impl Verifier<SimpleSignature> for Secp256r1Verifier {
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        let SimpleSignature::Secp256r1 {
            signature,
            public_key,
        } = signature
        else {
            return Err(SignatureError::from_source("not a secp256r1 signature"));
        };

        let verifying_key = Secp256r1VerifyingKey::new(public_key)?;

        verifying_key.verify(message, signature)
    }
}

impl Verifier<UserSignature> for Secp256r1Verifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not a secp256r1 signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use iota_types::PersonalMessage;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{IotaSigner, IotaVerifier};

    // TODO need to export proptest impl from core crate
    // #[proptest]
    // fn transaction_signing(signer: Secp256r1PrivateKey, transaction: Transaction)
    // {     let signature = signer.sign_transaction(&transaction).unwrap();
    //     let verifier = signer.public_key();
    //     verifier
    //         .verify_transaction(&transaction, &signature)
    //         .unwrap();
    // }

    #[proptest]
    fn personal_message_signing(signer: Secp256r1PrivateKey, message: Vec<u8>) {
        let message = PersonalMessage(message.into());
        let signature = signer.sign_personal_message(&message).unwrap();
        let verifying_key = signer.verifying_key();
        verifying_key
            .verify_personal_message(&message, &signature)
            .unwrap();

        let verifier = Secp256r1Verifier::default();
        verifier
            .verify_personal_message(&message, &signature)
            .unwrap();
    }

    #[test]
    fn personal_message_signing_fixture() {
        let key = [
            167, 44, 116, 0, 51, 221, 254, 179, 210, 44, 93, 196, 125, 155, 85, 94, 29, 41, 13, 60,
            59, 132, 69, 84, 176, 217, 77, 49, 25, 113, 118, 125,
        ];
        let signer = Secp256r1PrivateKey::new(key);

        let message = PersonalMessage(b"hello".into());
        let sig = signer.sign_personal_message(&message).unwrap();
        let external_sig = "AlqWPdkIE2bZAUquKv2Tdh9i+Ih+rVSQXH/YsgvwkmeOJR0YLjL/kadivoPtiQkvZBQ1ZI8eDZxe8SaLniwoT88Dh+/vAuGf1UrouFTdefpBEWn3apy8x3EexN5c5ESzGDc=";
        let b64 = sig.to_base64();
        assert_eq!(external_sig, b64);
    }

    #[test]
    fn from_bytes_rejects_invalid_scalar() {
        use crate::ToFromBytes;

        // The all-zeros scalar is not a valid secp256r1 private key; `from_bytes`
        // must surface this as an error rather than panicking.
        let err = Secp256r1PrivateKey::from_bytes([0u8; Secp256r1PrivateKey::LENGTH]);
        assert!(err.is_err());
    }
}
