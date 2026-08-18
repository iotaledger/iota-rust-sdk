// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::{
    secp256k1::{
        Secp256k1KeyPair, Secp256k1PublicKey as FcSecp256k1PublicKey,
        Secp256k1Signature as FcSecp256k1Signature,
    },
    traits::{KeyPair as _, Signer as _, ToFromBytes as _, VerifyingKey as _},
};
use iota_types::{
    PersonalMessage, Secp256k1PublicKey, Secp256k1Signature, SignatureScheme, SimpleSignature,
    Transaction, UserSignature,
};
use signature::{Signer, Verifier};

use crate::{IotaVerifier, SignatureError};

#[derive(Clone, Eq, PartialEq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Secp256k1PrivateKey([u8; Self::LENGTH]);

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
        // Validate that the bytes represent a well-formed secp256k1 private key.
        Secp256k1KeyPair::from_bytes(&bytes).map_err(SignatureError::from_source)?;
        Ok(Self(bytes))
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }

    /// Reconstruct the fastcrypto keypair, which performs all signing.
    fn keypair(&self) -> Secp256k1KeyPair {
        Secp256k1KeyPair::from_bytes(&self.0).expect("validated on construction")
    }

    pub fn verifying_key(&self) -> Secp256k1VerifyingKey {
        Secp256k1VerifyingKey(self.keypair().public().clone())
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::new(
            self.keypair()
                .public()
                .as_ref()
                .try_into()
                .expect("secp256k1 public key must be 33 bytes"),
        )
    }

    pub fn random_with<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        // Almost every 32-byte value is a valid secp256k1 private key, but a
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
        Self::random_with(rand_core::OsRng)
    }

    /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
    /// format).
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePrivateKey::from_pkcs8_der(bytes)
            .map(Self::from_k256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this private key as DER-encoded PKCS#8
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use k256::pkcs8::EncodePrivateKey;

        self.to_k256()
            .to_pkcs8_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.as_bytes().to_owned())
    }

    /// Deserialize PKCS#8-encoded private key from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePrivateKey::from_pkcs8_pem(s)
            .map(Self::from_k256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this private key as PEM-encoded PKCS#8
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePrivateKey;

        self.to_k256()
            .to_pkcs8_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
            .map(|pem| (*pem).to_owned())
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_k256(private_key: k256::ecdsa::SigningKey) -> Self {
        // A k256 SigningKey is by construction a valid secp256k1 scalar.
        Self(private_key.to_bytes().into())
    }

    /// Re-expose the raw private key through k256, used only as a PKCS#8/PEM
    /// codec. Don't sign with the returned key — use this type's `Signer` impl
    /// (`try_sign`) instead, so signing goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_k256(&self) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&self.0).expect("validated on construction")
    }
}

impl crate::ToFromBytes for Secp256k1PrivateKey {
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
                "invalid secp256k1 key length".to_string(),
            ));
        }

        let mut arr = [0u8; Self::LENGTH];
        arr.copy_from_slice(bytes);
        Self::new(arr).map_err(|e| crate::PrivateKeyError::InvalidScheme(e.to_string()))
    }
}

impl crate::PrivateKeyScheme for Secp256k1PrivateKey {
    const SCHEME: SignatureScheme = SignatureScheme::Secp256k1;
}

#[cfg(feature = "mnemonic")]
impl crate::FromMnemonic for Secp256k1PrivateKey {
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
            crate::DERIVATION_PATH_PURPOSE_SECP256K1,
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

impl Signer<Secp256k1Signature> for Secp256k1PrivateKey {
    fn try_sign(&self, message: &[u8]) -> Result<Secp256k1Signature, SignatureError> {
        let signature: FcSecp256k1Signature = self.keypair().sign(message);
        Ok(Secp256k1Signature::new(
            signature
                .as_ref()
                .try_into()
                .expect("secp256k1 signature must be 64 bytes"),
        ))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secp256k1VerifyingKey(FcSecp256k1PublicKey);

impl Secp256k1VerifyingKey {
    pub fn new(public_key: &Secp256k1PublicKey) -> Result<Self, SignatureError> {
        FcSecp256k1PublicKey::from_bytes(public_key.inner().as_ref())
            .map(Self)
            .map_err(SignatureError::from_source)
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey::new(
            self.0
                .as_ref()
                .try_into()
                .expect("secp256k1 public key must be 33 bytes"),
        )
    }

    /// Deserialize public key from ASN.1 DER-encoded data (binary format).
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePublicKey::from_public_key_der(bytes)
            .map(Self::from_k256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this public key as DER-encoded data
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_k256()
            .to_public_key_der()
            .map_err(SignatureError::from_source)
            .map(|der| der.into_vec())
    }

    /// Deserialize public key from PEM.
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
        k256::pkcs8::DecodePublicKey::from_public_key_pem(s)
            .map(Self::from_k256)
            .map_err(SignatureError::from_source)
    }

    /// Serialize this public key into PEM
    #[cfg(feature = "pem")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
    pub fn to_pem(&self) -> Result<String, SignatureError> {
        use pkcs8::EncodePublicKey;

        self.to_k256()
            .to_public_key_pem(pkcs8::LineEnding::default())
            .map_err(SignatureError::from_source)
    }

    #[cfg(feature = "pem")]
    pub(crate) fn from_k256(verifying_key: k256::ecdsa::VerifyingKey) -> Self {
        let compressed = verifying_key.to_encoded_point(true);
        Self(
            FcSecp256k1PublicKey::from_bytes(compressed.as_bytes())
                .expect("k256 public key is a valid secp256k1 point"),
        )
    }

    /// Re-expose the public key through k256, used only as a PKCS#8/PEM codec.
    /// Don't verify with the returned key — use this type's `Verifier` impl
    /// instead, so verification goes through fastcrypto.
    #[cfg(feature = "pem")]
    fn to_k256(&self) -> k256::ecdsa::VerifyingKey {
        k256::ecdsa::VerifyingKey::from_sec1_bytes(self.0.as_ref())
            .expect("validated on construction")
    }
}

impl Verifier<Secp256k1Signature> for Secp256k1VerifyingKey {
    fn verify(&self, message: &[u8], signature: &Secp256k1Signature) -> Result<(), SignatureError> {
        let signature = FcSecp256k1Signature::from_bytes(signature.inner())
            .map_err(SignatureError::from_source)?;
        self.0
            .verify(message, &signature)
            .map_err(SignatureError::from_source)
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

crate::impl_iota_verifier!(Secp256k1VerifyingKey);

impl IotaVerifier for Secp256k1PublicKey {
    fn verify_transaction(
        &self,
        transaction: &Transaction,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        Secp256k1VerifyingKey::new(self)?.verify_transaction(transaction, signature)
    }

    fn verify_personal_message(
        &self,
        message: &PersonalMessage<'_>,
        signature: &UserSignature,
    ) -> Result<(), SignatureError> {
        Secp256k1VerifyingKey::new(self)?.verify_personal_message(message, signature)
    }
}

#[derive(Clone, Debug, Default)]
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

crate::impl_iota_verifier!(Secp256k1Verifier);

#[cfg(test)]
mod tests {
    use iota_types::PersonalMessage;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::{IotaSigner, IotaVerifier};

    #[proptest]
    fn transaction_signing(signer: Secp256k1PrivateKey, transaction: Transaction) {
        let signature = signer.sign_transaction(&transaction).unwrap();
        let verifier = signer.verifying_key();
        verifier
            .verify_transaction(&transaction, &signature)
            .unwrap();

        let public_key = signer.public_key();
        public_key
            .verify_transaction(&transaction, &signature)
            .unwrap();
        iota_types::PublicKey::Secp256k1(public_key)
            .verify_transaction(&transaction, &signature)
            .unwrap();

        // a different public key must not verify the signature
        Secp256k1PrivateKey::new([7; 32])
            .unwrap()
            .public_key()
            .verify_transaction(&transaction, &signature)
            .unwrap_err();
    }

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

        let public_key = signer.public_key();
        public_key
            .verify_personal_message(&message, &signature)
            .unwrap();
        iota_types::PublicKey::Secp256k1(public_key)
            .verify_personal_message(&message, &signature)
            .unwrap();

        // a different public key must not verify the signature
        Secp256k1PrivateKey::new([7; 32])
            .unwrap()
            .public_key()
            .verify_personal_message(&message, &signature)
            .unwrap_err();
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

    // The secp256k1 order n. A signature `(r, s)` has a malleable counterpart
    // `(r, n - s)`; fastcrypto (libsecp256k1) only accepts the low-S form.
    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    // Big-endian 256-bit subtraction `a - b`.
    fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut diff = a[i] as i16 - b[i] as i16 - borrow;
            if diff < 0 {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            result[i] = diff as u8;
        }
        result
    }

    #[test]
    fn verify_rejects_high_s() {
        let key = [
            172, 12, 96, 180, 207, 143, 111, 151, 81, 57, 242, 89, 74, 5, 150, 51, 56, 111, 245,
            150, 182, 30, 149, 178, 29, 255, 188, 27, 48, 241, 151, 193,
        ];
        let signer = Secp256k1PrivateKey::new(key).unwrap();
        let verifying_key = signer.verifying_key();

        let message = b"hello";
        // fastcrypto produces a low-S signature, which verifies.
        let sig: Secp256k1Signature = signer.try_sign(message.as_slice()).unwrap();
        verifying_key.verify(message, &sig).unwrap();

        // Malleate to the equivalent high-S signature `(r, n - s)`.
        let bytes = sig.inner();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        let high_s = sub_be(&SECP256K1_ORDER, &s);

        let mut malleated = [0u8; 64];
        malleated[..32].copy_from_slice(&r);
        malleated[32..].copy_from_slice(&high_s);
        let malleated = Secp256k1Signature::new(malleated);

        // The high-S variant must be rejected even though it is algebraically valid.
        verifying_key.verify(message, &malleated).unwrap_err();
    }

    #[proptest]
    fn base64_roundtrip(signer: Secp256k1PrivateKey) {
        use crate::{ToFromBase64, ToFromBytes};

        let b64 = signer.to_base64();
        let decoded = Secp256k1PrivateKey::from_base64(&b64).unwrap();
        assert_eq!(decoded.to_bytes(), signer.to_bytes());
        assert_eq!(decoded.to_base64(), b64);
    }

    #[cfg(feature = "rand")]
    #[test]
    fn random_key_signing() {
        let signer = Secp256k1PrivateKey::random();
        assert_ne!(
            signer.public_key(),
            Secp256k1PrivateKey::random().public_key()
        );

        let message = PersonalMessage(b"hello".into());
        let signature = signer.sign_personal_message(&message).unwrap();
        signer
            .verifying_key()
            .verify_personal_message(&message, &signature)
            .unwrap();
    }
}
