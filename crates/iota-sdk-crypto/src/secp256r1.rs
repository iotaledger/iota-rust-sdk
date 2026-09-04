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
    PersonalMessage, Secp256r1PublicKey, Secp256r1Signature, SignatureScheme, SimpleSignature,
    Transaction, UserSignature,
};
use signature::{Signer, Verifier};

use crate::{IotaVerifier, SignatureError};

#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
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
            .prop_filter_map("invalid secp256r1 private key", |bytes| {
                Self::new(bytes).ok()
            })
            .boxed()
    }
}

impl Secp256r1PrivateKey {
    /// The length of an secp256r1 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        // Validate that the bytes represent a well-formed secp256r1 private key.
        Secp256r1KeyPair::from_bytes(&bytes).map_err(SignatureError::from_source)?;
        Ok(Self(bytes))
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
                .expect("secp256r1 public key must be 33 bytes"),
        )
    }

    pub fn random_with<R>(mut rng: R) -> Self
    where
        R: rand_core::CryptoRng,
    {
        // Almost every 32-byte value is a valid secp256r1 private key, but a
        // few (zero, or values at/above the curve order) are not. Draw fresh
        // bytes until we get a valid key; in practice this never repeats.
        loop {
            let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
            rng.fill_bytes(&mut buf);
            if let Ok(key) = Self::new(buf) {
                return key;
            }
        }
    }

    /// Generate a new private key using the operating system's random number
    /// generator.
    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn random() -> Self {
        Self::random_with(rand_core::UnwrapErr(getrandom_4::SysRng))
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this private key as DER-encoded PKCS#8
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use p256::pkcs8::EncodePrivateKey;

        self.to_p256()
            .to_pkcs8_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.as_bytes().to_owned())
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePrivateKey;

        self.to_p256()
            .to_pkcs8_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
            .map(|pem| (*pem).to_owned())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_p256(private_key: p256::ecdsa::SigningKey) -> Self {
        // A p256 SigningKey is by construction a valid secp256r1 scalar.
        Self(private_key.to_bytes().into())
    }

    /// Re-expose the raw private key through p256, used only as a PKCS#8/PEM
    /// codec. Don't sign with the returned key — use this type's `Signer` impl
    /// (`try_sign`) instead, so signing goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_p256(&self) -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&self.0).expect("validated on construction")
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
        Self::new(arr).map_err(|e| crate::PrivateKeyError::InvalidScheme(e.to_string()))
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
        let signature: FcSecp256r1Signature = self.keypair().sign(message);
        Ok(Secp256r1Signature::new(
            signature
                .as_ref()
                .try_into()
                .expect("secp256r1 signature must be 64 bytes"),
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
        FcSecp256r1PublicKey::from_bytes(public_key.bytes())
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Secp256r1PublicKey {
        Secp256r1PublicKey::new(
            self.0
                .as_ref()
                .try_into()
                .expect("secp256r1 public key must be 33 bytes"),
        )
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this public key as DER-encoded data
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_p256()
            .to_public_key_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.into_vec())
    }

    /// Deserialize public key from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        p256::pkcs8::DecodePublicKey::from_public_key_pem(s)
            .map(Self::from_p256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this public key into PEM
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_p256()
            .to_public_key_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_p256(verifying_key: p256::ecdsa::VerifyingKey) -> Self {
        let compressed = verifying_key.to_sec1_point(true);
        Self(
            FcSecp256r1PublicKey::from_bytes(compressed.as_bytes())
                .expect("p256 public key is a valid secp256r1 point"),
        )
    }

    /// Re-expose the public key through p256, used only as a PKCS#8/PEM codec.
    /// Don't verify with the returned key — use this type's `Verifier` impl
    /// instead, so verification goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_p256(&self) -> p256::ecdsa::VerifyingKey {
        p256::ecdsa::VerifyingKey::from_sec1_bytes(self.0.as_ref())
            .expect("validated on construction")
    }
}

impl Verifier<Secp256r1Signature> for Secp256r1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Secp256r1Signature) -> Result<(), SignatureError> {
        let signature = FcSecp256r1Signature::from_bytes(signature.bytes())
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

        if public_key.bytes() != self.public_key().bytes() {
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

crate::impl_iota_verifier!(Secp256r1VerifyingKey);

impl IotaVerifier for Secp256r1PublicKey {
    fn verify_transaction(
        &self,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        Secp256r1VerifyingKey::new(self)?.verify_transaction(transaction, signature)
    }

    fn verify_personal_message(
        &self,
        message: &PersonalMessage<'_>,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        Secp256r1VerifyingKey::new(self)?.verify_personal_message(message, signature)
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

crate::impl_iota_verifier!(Secp256r1Verifier);

#[cfg(test)]
mod tests {
    use iota_types::{PersonalMessage, PublicKey};
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{IotaSigner, IotaVerifier};

    #[proptest]
    fn transaction_signing(signer: Secp256r1PrivateKey, transaction: Transaction) {
        let signature = signer.sign_transaction(&transaction).unwrap();
        let verifier = signer.verifying_key();
        verifier
            .verify_transaction(&transaction, &signature)
            .unwrap();

        let public_key = signer.public_key();
        public_key
            .verify_transaction(&transaction, &signature)
            .unwrap();
        PublicKey::Secp256r1(public_key)
            .verify_transaction(&transaction, &signature)
            .unwrap();

        // a different public key must not verify the signature
        Secp256r1PrivateKey::new([7; 32])
            .unwrap()
            .public_key()
            .verify_transaction(&transaction, &signature)
            .unwrap_err();
    }

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

        let public_key = signer.public_key();
        public_key
            .verify_personal_message(&message, &signature)
            .unwrap();
        PublicKey::Secp256r1(public_key)
            .verify_personal_message(&message, &signature)
            .unwrap();

        // a different public key must not verify the signature
        Secp256r1PrivateKey::new([7; 32])
            .unwrap()
            .public_key()
            .verify_personal_message(&message, &signature)
            .unwrap_err();
    }

    #[test]
    fn personal_message_signing_fixture() {
        let key = [
            167, 44, 116, 0, 51, 221, 254, 179, 210, 44, 93, 196, 125, 155, 85, 94, 29, 41, 13, 60,
            59, 132, 69, 84, 176, 217, 77, 49, 25, 113, 118, 125,
        ];
        let signer = Secp256r1PrivateKey::new(key).unwrap();

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

    #[proptest]
    fn base64_roundtrip(signer: Secp256r1PrivateKey) {
        use crate::{ToFromBase64, ToFromBytes};

        let b64 = signer.to_base64();
        let decoded = Secp256r1PrivateKey::from_base64(&b64).unwrap();
        assert_eq!(decoded.to_bytes(), signer.to_bytes());
        assert_eq!(decoded.to_base64(), b64);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn random_key_signing() {
        let signer = Secp256r1PrivateKey::random();
        assert_ne!(
            signer.public_key(),
            Secp256r1PrivateKey::random().public_key()
        );

        let message = PersonalMessage(b"hello".into());
        let signature = signer.sign_personal_message(&message).unwrap();
        signer
            .verifying_key()
            .verify_personal_message(&message, &signature)
            .unwrap();
    }
}
