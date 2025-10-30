// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_types::{SimpleSignature, UserSignature};
use signature::Verifier;

use crate::SignatureError;

pub struct SimpleVerifier;

impl Verifier<SimpleSignature> for SimpleVerifier {
    #[allow(unused_variables)]
    fn verify(&self, message: &[u8], signature: &SimpleSignature) -> Result<(), SignatureError> {
        match signature {
            #[cfg(feature = "ed25519")]
            SimpleSignature::Ed25519 {
                signature,
                public_key,
            } => {
                let verifying_key = crate::ed25519::Ed25519VerifyingKey::new(public_key)?;
                verifying_key.verify(message, signature)
            }
            #[cfg(not(feature = "ed25519"))]
            SimpleSignature::Ed25519 { .. } => Err(SignatureError::from_source(
                "support for ed25519 is not enabled",
            )),
            #[cfg(feature = "secp256k1")]
            SimpleSignature::Secp256k1 {
                signature,
                public_key,
            } => {
                let verifying_key = crate::secp256k1::Secp256k1VerifyingKey::new(public_key)?;
                verifying_key.verify(message, signature)
            }
            #[cfg(not(feature = "secp256k1"))]
            SimpleSignature::Secp256k1 { .. } => Err(SignatureError::from_source(
                "support for secp256k1 is not enabled",
            )),
            #[cfg(feature = "secp256r1")]
            SimpleSignature::Secp256r1 {
                signature,
                public_key,
            } => {
                let verifying_key = crate::secp256r1::Secp256r1VerifyingKey::new(public_key)?;
                verifying_key.verify(message, signature)
            }
            #[cfg(not(feature = "secp256r1"))]
            SimpleSignature::Secp256r1 { .. } => Err(SignatureError::from_source(
                "support for secp256r1 is not enabled",
            )),
        }
    }
}

impl Verifier<UserSignature> for SimpleVerifier {
    fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
        let UserSignature::Simple(signature) = signature else {
            return Err(SignatureError::from_source("not a simple signature"));
        };

        <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
    }
}

#[cfg(any(feature = "ed25519", feature = "secp256r1", feature = "secp256k1",))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(any(feature = "ed25519", feature = "secp256r1", feature = "secp256k1",)))
)]
#[rustfmt::skip]
pub use keypair::{SimpleKeypair, SimpleVerifyingKey};

#[cfg(any(feature = "ed25519", feature = "secp256r1", feature = "secp256k1",))]
#[cfg_attr(
    doc_cfg,
    doc(cfg(any(feature = "ed25519", feature = "secp256r1", feature = "secp256k1",)))
)]
mod keypair {
    use iota_types::{
        MultisigMemberPublicKey, PublicKeyExt, SignatureScheme, SimpleSignature, UserSignature,
    };
    use signature::{Signer, Verifier};

    use crate::SignatureError;

    #[derive(Debug, Clone)]
    pub struct SimpleKeypair {
        inner: InnerKeypair,
    }

    #[derive(Debug, Clone)]
    enum InnerKeypair {
        #[cfg(feature = "ed25519")]
        Ed25519(crate::ed25519::Ed25519PrivateKey),
        #[cfg(feature = "secp256k1")]
        Secp256k1(crate::secp256k1::Secp256k1PrivateKey),
        #[cfg(feature = "secp256r1")]
        Secp256r1(crate::secp256r1::Secp256r1PrivateKey),
    }

    impl SimpleKeypair {
        pub fn scheme(&self) -> SignatureScheme {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => private_key.scheme(),
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => private_key.scheme(),
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => private_key.scheme(),
            }
        }

        pub fn verifying_key(&self) -> SimpleVerifyingKey {
            let verifying_key = match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => {
                    InnerVerifyingKey::Ed25519(private_key.verifying_key())
                }
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => {
                    InnerVerifyingKey::Secp256k1(private_key.verifying_key())
                }
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => {
                    InnerVerifyingKey::Secp256r1(private_key.verifying_key())
                }
            };

            SimpleVerifyingKey {
                inner: verifying_key,
            }
        }

        pub fn public_key(&self) -> MultisigMemberPublicKey {
            self.verifying_key().public_key()
        }

        /// Encode a SimpleKeypair as `flag || privkey` in bytes
        pub fn to_bytes(&self) -> Vec<u8> {
            use crate::ToFromBytes;

            let mut bytes = Vec::new();
            bytes.push(self.scheme().to_u8());

            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => {
                    bytes.extend_from_slice(&private_key.to_bytes());
                }
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => {
                    bytes.extend_from_slice(&private_key.to_bytes());
                }
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => {
                    bytes.extend_from_slice(&private_key.to_bytes());
                }
            }

            bytes
        }

        /// Decode a SimpleKeypair from `flag || privkey` bytes
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
            if bytes.is_empty() {
                return Err(SignatureError::from_source("empty bytes"));
            }

            let flag = SignatureScheme::from_byte(bytes[0]).map_err(|e| {
                SignatureError::from_source(format!("invalid signature scheme: {:?}", e))
            })?;
            let key_bytes = &bytes[1..];

            match flag {
                #[cfg(feature = "ed25519")]
                SignatureScheme::Ed25519 => {
                    if key_bytes.len() != crate::ed25519::Ed25519PrivateKey::LENGTH {
                        return Err(SignatureError::from_source("invalid ed25519 key length"));
                    }
                    let mut arr = [0u8; crate::ed25519::Ed25519PrivateKey::LENGTH];
                    arr.copy_from_slice(key_bytes);
                    Ok(Self {
                        inner: InnerKeypair::Ed25519(crate::ed25519::Ed25519PrivateKey::new(arr)),
                    })
                }
                #[cfg(feature = "secp256k1")]
                SignatureScheme::Secp256k1 => {
                    if key_bytes.len() != crate::secp256k1::Secp256k1PrivateKey::LENGTH {
                        return Err(SignatureError::from_source("invalid secp256k1 key length"));
                    }
                    let mut arr = [0u8; crate::secp256k1::Secp256k1PrivateKey::LENGTH];
                    arr.copy_from_slice(key_bytes);
                    crate::secp256k1::Secp256k1PrivateKey::new(arr)
                        .map(InnerKeypair::Secp256k1)
                        .map(|inner| Self { inner })
                }
                #[cfg(feature = "secp256r1")]
                SignatureScheme::Secp256r1 => {
                    if key_bytes.len() != crate::secp256r1::Secp256r1PrivateKey::LENGTH {
                        return Err(SignatureError::from_source("invalid secp256r1 key length"));
                    }
                    let mut arr = [0u8; crate::secp256r1::Secp256r1PrivateKey::LENGTH];
                    arr.copy_from_slice(key_bytes);
                    Ok(Self {
                        inner: InnerKeypair::Secp256r1(crate::secp256r1::Secp256r1PrivateKey::new(
                            arr,
                        )),
                    })
                }
                _ => Err(SignatureError::from_source(
                    "unsupported signature scheme for SimpleKeypair",
                )),
            }
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Deserialize PKCS#8 private key from ASN.1 DER-encoded data (binary
        /// format).
        pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
            let private_key =
                pkcs8::PrivateKeyInfo::try_from(bytes).map_err(SignatureError::from_source)?;

            match private_key
                .algorithm
                .oids()
                .map_err(SignatureError::from_source)?
            {
                #[cfg(feature = "ed25519")]
                (ed25519_dalek::pkcs8::ALGORITHM_OID, None) => private_key
                    .try_into()
                    .map(crate::ed25519::Ed25519PrivateKey::from_dalek)
                    .map(InnerKeypair::Ed25519)
                    .map_err(SignatureError::from_source),
                #[cfg(feature = "secp256r1")]
                (
                    p256::elliptic_curve::ALGORITHM_OID,
                    Some(<p256::NistP256 as pkcs8::AssociatedOid>::OID),
                ) => private_key
                    .try_into()
                    .map(crate::secp256r1::Secp256r1PrivateKey::from_p256)
                    .map(InnerKeypair::Secp256r1)
                    .map_err(SignatureError::from_source),
                #[cfg(feature = "secp256k1")]
                (
                    k256::elliptic_curve::ALGORITHM_OID,
                    Some(<k256::Secp256k1 as pkcs8::AssociatedOid>::OID),
                ) => private_key
                    .try_into()
                    .map(crate::secp256k1::Secp256k1PrivateKey::from_k256)
                    .map(InnerKeypair::Secp256k1)
                    .map_err(SignatureError::from_source),
                _ => Err(SignatureError::from_source(
                    "unsupported or invalid private key type",
                )),
            }
            .map(|inner| Self { inner })
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Serialize this private key as DER-encoded PKCS#8
        pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => private_key.to_der(),
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => private_key.to_der(),
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => private_key.to_der(),
            }
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Deserialize PKCS#8-encoded private key from PEM.
        pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
            use pkcs8::der::pem::PemLabel;

            let (label, doc) =
                pkcs8::SecretDocument::from_pem(s).map_err(SignatureError::from_source)?;
            pkcs8::PrivateKeyInfo::validate_pem_label(label)
                .map_err(SignatureError::from_source)?;
            Self::from_der(doc.as_bytes())
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Serialize this private key as DER-encoded PKCS#8
        pub fn to_pem(&self) -> Result<String, SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => private_key.to_pem(),
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => private_key.to_pem(),
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => private_key.to_pem(),
            }
        }
    }

    impl Signer<SimpleSignature> for SimpleKeypair {
        fn try_sign(&self, message: &[u8]) -> Result<SimpleSignature, SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerKeypair::Ed25519(private_key) => private_key.try_sign(message),
                #[cfg(feature = "secp256k1")]
                InnerKeypair::Secp256k1(private_key) => private_key.try_sign(message),
                #[cfg(feature = "secp256r1")]
                InnerKeypair::Secp256r1(private_key) => private_key.try_sign(message),
            }
        }
    }

    impl Signer<UserSignature> for SimpleKeypair {
        fn try_sign(&self, msg: &[u8]) -> Result<UserSignature, SignatureError> {
            <Self as Signer<SimpleSignature>>::try_sign(self, msg).map(UserSignature::Simple)
        }
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "ed25519")))]
    impl From<crate::ed25519::Ed25519PrivateKey> for SimpleKeypair {
        fn from(private_key: crate::ed25519::Ed25519PrivateKey) -> Self {
            Self {
                inner: InnerKeypair::Ed25519(private_key),
            }
        }
    }

    #[cfg(feature = "secp256r1")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "secp256r1")))]
    impl From<crate::secp256r1::Secp256r1PrivateKey> for SimpleKeypair {
        fn from(private_key: crate::secp256r1::Secp256r1PrivateKey) -> Self {
            Self {
                inner: InnerKeypair::Secp256r1(private_key),
            }
        }
    }

    #[cfg(feature = "secp256k1")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "secp256k1")))]
    impl From<crate::secp256k1::Secp256k1PrivateKey> for SimpleKeypair {
        fn from(private_key: crate::secp256k1::Secp256k1PrivateKey) -> Self {
            Self {
                inner: InnerKeypair::Secp256k1(private_key),
            }
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    pub struct SimpleVerifyingKey {
        inner: InnerVerifyingKey,
    }

    #[derive(Debug, Clone, Eq, PartialEq)]
    enum InnerVerifyingKey {
        #[cfg(feature = "ed25519")]
        Ed25519(crate::ed25519::Ed25519VerifyingKey),
        #[cfg(feature = "secp256k1")]
        Secp256k1(crate::secp256k1::Secp256k1VerifyingKey),
        #[cfg(feature = "secp256r1")]
        Secp256r1(crate::secp256r1::Secp256r1VerifyingKey),
    }

    impl SimpleVerifyingKey {
        pub fn scheme(&self) -> SignatureScheme {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerVerifyingKey::Ed25519(verifying_key) => verifying_key.public_key().scheme(),
                #[cfg(feature = "secp256k1")]
                InnerVerifyingKey::Secp256k1(verifying_key) => verifying_key.public_key().scheme(),
                #[cfg(feature = "secp256r1")]
                InnerVerifyingKey::Secp256r1(verifying_key) => verifying_key.public_key().scheme(),
            }
        }

        pub fn public_key(&self) -> MultisigMemberPublicKey {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerVerifyingKey::Ed25519(verifying_key) => {
                    MultisigMemberPublicKey::Ed25519(verifying_key.public_key())
                }
                #[cfg(feature = "secp256k1")]
                InnerVerifyingKey::Secp256k1(verifying_key) => {
                    MultisigMemberPublicKey::Secp256k1(verifying_key.public_key())
                }
                #[cfg(feature = "secp256r1")]
                InnerVerifyingKey::Secp256r1(verifying_key) => {
                    MultisigMemberPublicKey::Secp256r1(verifying_key.public_key())
                }
            }
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Deserialize public key from ASN.1 DER-encoded data (binary format).
        pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
            let public_key = pkcs8::SubjectPublicKeyInfoRef::try_from(bytes)
                .map_err(SignatureError::from_source)?;

            match public_key
                .algorithm
                .oids()
                .map_err(SignatureError::from_source)?
            {
                #[cfg(feature = "ed25519")]
                (ed25519_dalek::pkcs8::ALGORITHM_OID, None) => public_key
                    .try_into()
                    .map(crate::ed25519::Ed25519VerifyingKey::from_dalek)
                    .map(InnerVerifyingKey::Ed25519)
                    .map_err(SignatureError::from_source),
                #[cfg(feature = "secp256r1")]
                (
                    p256::elliptic_curve::ALGORITHM_OID,
                    Some(<p256::NistP256 as pkcs8::AssociatedOid>::OID),
                ) => public_key
                    .try_into()
                    .map(crate::secp256r1::Secp256r1VerifyingKey::from_p256)
                    .map(InnerVerifyingKey::Secp256r1)
                    .map_err(SignatureError::from_source),
                #[cfg(feature = "secp256k1")]
                (
                    k256::elliptic_curve::ALGORITHM_OID,
                    Some(<k256::Secp256k1 as pkcs8::AssociatedOid>::OID),
                ) => public_key
                    .try_into()
                    .map(crate::secp256k1::Secp256k1VerifyingKey::from_k256)
                    .map(InnerVerifyingKey::Secp256k1)
                    .map_err(SignatureError::from_source),
                _ => Err(SignatureError::from_source(
                    "unsupported or invalid public key type",
                )),
            }
            .map(|inner| Self { inner })
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Serialize this public key as DER-encoded data
        pub fn to_der(&self) -> Result<Vec<u8>, SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerVerifyingKey::Ed25519(verifying_key) => verifying_key.to_der(),
                #[cfg(feature = "secp256k1")]
                InnerVerifyingKey::Secp256k1(verifying_key) => verifying_key.to_der(),
                #[cfg(feature = "secp256r1")]
                InnerVerifyingKey::Secp256r1(verifying_key) => verifying_key.to_der(),
            }
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Deserialize public key from PEM.
        pub fn from_pem(s: &str) -> Result<Self, SignatureError> {
            use pkcs8::der::pem::PemLabel;

            let (label, doc) = pkcs8::Document::from_pem(s).map_err(SignatureError::from_source)?;
            pkcs8::SubjectPublicKeyInfoRef::validate_pem_label(label)
                .map_err(SignatureError::from_source)?;
            Self::from_der(doc.as_bytes())
        }

        #[cfg(feature = "pem")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "pem")))]
        /// Serialize this public key as PEM
        pub fn to_pem(&self) -> Result<String, SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerVerifyingKey::Ed25519(verifying_key) => verifying_key.to_pem(),
                #[cfg(feature = "secp256k1")]
                InnerVerifyingKey::Secp256k1(verifying_key) => verifying_key.to_pem(),
                #[cfg(feature = "secp256r1")]
                InnerVerifyingKey::Secp256r1(verifying_key) => verifying_key.to_pem(),
            }
        }
    }

    impl Verifier<SimpleSignature> for SimpleVerifyingKey {
        fn verify(
            &self,
            message: &[u8],
            signature: &SimpleSignature,
        ) -> Result<(), SignatureError> {
            match &self.inner {
                #[cfg(feature = "ed25519")]
                InnerVerifyingKey::Ed25519(verifying_key) => {
                    verifying_key.verify(message, signature)
                }
                #[cfg(feature = "secp256k1")]
                InnerVerifyingKey::Secp256k1(verifying_key) => {
                    verifying_key.verify(message, signature)
                }
                #[cfg(feature = "secp256r1")]
                InnerVerifyingKey::Secp256r1(verifying_key) => {
                    verifying_key.verify(message, signature)
                }
            }
        }
    }

    impl Verifier<UserSignature> for SimpleVerifyingKey {
        fn verify(&self, message: &[u8], signature: &UserSignature) -> Result<(), SignatureError> {
            let UserSignature::Simple(signature) = signature else {
                return Err(SignatureError::from_source("not a simple signature"));
            };

            <Self as Verifier<SimpleSignature>>::verify(self, message, signature)
        }
    }

    #[cfg(feature = "ed25519")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "ed25519")))]
    impl From<crate::ed25519::Ed25519VerifyingKey> for SimpleVerifyingKey {
        fn from(verifying_key: crate::ed25519::Ed25519VerifyingKey) -> Self {
            Self {
                inner: InnerVerifyingKey::Ed25519(verifying_key),
            }
        }
    }

    #[cfg(feature = "secp256r1")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "secp256r1")))]
    impl From<crate::secp256r1::Secp256r1VerifyingKey> for SimpleVerifyingKey {
        fn from(verifying_key: crate::secp256r1::Secp256r1VerifyingKey) -> Self {
            Self {
                inner: InnerVerifyingKey::Secp256r1(verifying_key),
            }
        }
    }

    #[cfg(feature = "secp256k1")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "secp256k1")))]
    impl From<crate::secp256k1::Secp256k1VerifyingKey> for SimpleVerifyingKey {
        fn from(verifying_key: crate::secp256k1::Secp256k1VerifyingKey) -> Self {
            Self {
                inner: InnerVerifyingKey::Secp256k1(verifying_key),
            }
        }
    }

    impl crate::ToFromFlaggedBytes for SimpleKeypair {
        type Error = crate::PrivateKeyError;

        fn to_flagged_bytes(&self) -> Vec<u8> {
            self.to_bytes()
        }

        fn from_flagged_bytes(bytes: &[u8]) -> Result<Self, crate::PrivateKeyError>
        where
            Self: Sized,
        {
            Self::from_bytes(bytes)
                .map_err(|e| crate::PrivateKeyError::InvalidScheme(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use test_strategy::proptest;

    use super::*;
    use crate::{
        ToFromBech32,
        ed25519::{Ed25519PrivateKey, Ed25519VerifyingKey},
        secp256k1::{Secp256k1PrivateKey, Secp256k1VerifyingKey},
        secp256r1::{Secp256r1PrivateKey, Secp256r1VerifyingKey},
    };

    #[proptest]
    fn ed25519_pem_der(signer: Ed25519PrivateKey) {
        // Private Key
        //
        let public_key = signer.public_key();
        let ed25519_der = signer.to_der().unwrap();
        let ed25519_pem = signer.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Ed25519PrivateKey::from_der(&ed25519_der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Ed25519PrivateKey::from_pem(&ed25519_pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to secp256r1 or secp256k1
        Secp256r1PrivateKey::from_der(&ed25519_der).unwrap_err();
        Secp256r1PrivateKey::from_pem(&ed25519_pem).unwrap_err();
        Secp256k1PrivateKey::from_der(&ed25519_der).unwrap_err();
        Secp256k1PrivateKey::from_pem(&ed25519_pem).unwrap_err();

        // SimpleKeypair parses
        let keypair_from_der = SimpleKeypair::from_der(&ed25519_der).unwrap();
        assert_eq!(ed25519_der, keypair_from_der.to_der().unwrap());
        let keypair_from_pem = SimpleKeypair::from_pem(&ed25519_pem).unwrap();
        assert_eq!(ed25519_pem, keypair_from_pem.to_pem().unwrap());

        // Verifying Key
        //
        let verifying_key = signer.verifying_key();
        let der = verifying_key.to_der().unwrap();
        let pem = verifying_key.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Ed25519VerifyingKey::from_der(&der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Ed25519VerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to secp256r1 or secp256k1
        Secp256r1VerifyingKey::from_der(&der).unwrap_err();
        Secp256r1VerifyingKey::from_pem(&pem).unwrap_err();
        Secp256k1VerifyingKey::from_der(&der).unwrap_err();
        Secp256k1VerifyingKey::from_pem(&pem).unwrap_err();

        // SimpleKeypair parses
        let from_der = SimpleVerifyingKey::from_der(&der).unwrap();
        assert_eq!(der, from_der.to_der().unwrap());
        let from_pem = SimpleVerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(pem, from_pem.to_pem().unwrap());
    }

    #[proptest]
    fn secp256r1_pem_der(signer: Secp256r1PrivateKey) {
        // Private Key
        //
        let public_key = signer.public_key();
        let secp256r1_der = signer.to_der().unwrap();
        let secp256r1_pem = signer.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Secp256r1PrivateKey::from_der(&secp256r1_der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Secp256r1PrivateKey::from_pem(&secp256r1_pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to ed25519 or secp256k1
        Ed25519PrivateKey::from_der(&secp256r1_der).unwrap_err();
        Ed25519PrivateKey::from_pem(&secp256r1_pem).unwrap_err();
        Secp256k1PrivateKey::from_der(&secp256r1_der).unwrap_err();
        Secp256k1PrivateKey::from_pem(&secp256r1_pem).unwrap_err();

        // SimpleKeypair parses
        let keypair_from_der = SimpleKeypair::from_der(&secp256r1_der).unwrap();
        assert_eq!(secp256r1_der, keypair_from_der.to_der().unwrap());
        let keypair_from_pem = SimpleKeypair::from_pem(&secp256r1_pem).unwrap();
        assert_eq!(secp256r1_pem, keypair_from_pem.to_pem().unwrap());

        // Verifying Key
        //
        let verifying_key = signer.verifying_key();
        let der = verifying_key.to_der().unwrap();
        let pem = verifying_key.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Secp256r1VerifyingKey::from_der(&der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Secp256r1VerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to ed25519 or secp256k1
        Ed25519VerifyingKey::from_der(&der).unwrap_err();
        Ed25519VerifyingKey::from_pem(&pem).unwrap_err();
        Secp256k1VerifyingKey::from_der(&der).unwrap_err();
        Secp256k1VerifyingKey::from_pem(&pem).unwrap_err();

        // SimpleKeypair parses
        let from_der = SimpleVerifyingKey::from_der(&der).unwrap();
        assert_eq!(der, from_der.to_der().unwrap());
        let from_pem = SimpleVerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(pem, from_pem.to_pem().unwrap());
    }

    #[proptest]
    fn secp256k1_pem_der(signer: Secp256k1PrivateKey) {
        // Private Key
        //
        let public_key = signer.public_key();
        let secp256k1_der = signer.to_der().unwrap();
        let secp256k1_pem = signer.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Secp256k1PrivateKey::from_der(&secp256k1_der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Secp256k1PrivateKey::from_pem(&secp256k1_pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to secp256r1 or ed25519
        Ed25519PrivateKey::from_der(&secp256k1_der).unwrap_err();
        Ed25519PrivateKey::from_pem(&secp256k1_pem).unwrap_err();
        Secp256r1PrivateKey::from_der(&secp256k1_der).unwrap_err();
        Secp256r1PrivateKey::from_pem(&secp256k1_pem).unwrap_err();

        // SimpleKeypair parses
        let keypair_from_der = SimpleKeypair::from_der(&secp256k1_der).unwrap();
        assert_eq!(secp256k1_der, keypair_from_der.to_der().unwrap());
        let keypair_from_pem = SimpleKeypair::from_pem(&secp256k1_pem).unwrap();
        assert_eq!(secp256k1_pem, keypair_from_pem.to_pem().unwrap());

        // Verifying Key
        //
        let verifying_key = signer.verifying_key();
        let der = verifying_key.to_der().unwrap();
        let pem = verifying_key.to_pem().unwrap();

        // der and pem round-trip
        let from_der = Secp256k1VerifyingKey::from_der(&der).unwrap();
        assert_eq!(from_der.public_key(), public_key);
        let from_pem = Secp256k1VerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(from_pem.public_key(), public_key);

        // der and pem bytes don't convert to ed25519 or secp256r1
        Ed25519VerifyingKey::from_der(&der).unwrap_err();
        Ed25519VerifyingKey::from_pem(&pem).unwrap_err();
        Secp256r1VerifyingKey::from_der(&der).unwrap_err();
        Secp256r1VerifyingKey::from_pem(&pem).unwrap_err();

        // SimpleKeypair parses
        let from_der = SimpleVerifyingKey::from_der(&der).unwrap();
        assert_eq!(der, from_der.to_der().unwrap());
        let from_pem = SimpleVerifyingKey::from_pem(&pem).unwrap();
        assert_eq!(pem, from_pem.to_pem().unwrap());
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn test_bech32_roundtrip_ed25519() {
        use rand::{SeedableRng, rngs::StdRng};

        let keypair: SimpleKeypair = Ed25519PrivateKey::generate(StdRng::from_seed([1; 32])).into();
        let encoded = keypair.to_bech32().unwrap();
        let decoded = SimpleKeypair::from_bech32(&encoded).unwrap();
        assert_eq!(keypair.public_key(), decoded.public_key());

        // Verify it encodes to the same string
        let re_encoded = decoded.to_bech32().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn test_bech32_roundtrip_secp256k1() {
        use rand::{SeedableRng, rngs::StdRng};

        let keypair: SimpleKeypair =
            Secp256k1PrivateKey::generate(StdRng::from_seed([2; 32])).into();
        let encoded = keypair.to_bech32().unwrap();
        let decoded = SimpleKeypair::from_bech32(&encoded).unwrap();
        assert_eq!(keypair.public_key(), decoded.public_key());

        // Verify it encodes to the same string
        let re_encoded = decoded.to_bech32().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn test_bech32_roundtrip_secp256r1() {
        use rand::{SeedableRng, rngs::StdRng};

        let keypair: SimpleKeypair =
            Secp256r1PrivateKey::generate(StdRng::from_seed([3; 32])).into();
        let encoded = keypair.to_bech32().unwrap();
        let decoded = SimpleKeypair::from_bech32(&encoded).unwrap();
        assert_eq!(keypair.public_key(), decoded.public_key());

        // Verify it encodes to the same string
        let re_encoded = decoded.to_bech32().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn test_bech32_invalid_hrp() {
        let invalid_hrp =
            "invalidprivkey1qzdlfxn2qa2lj5uprl8pyhexs02sg2wrhdy7qaq50cqgnffw4c247zslwv6";
        let result = SimpleKeypair::from_bech32(invalid_hrp);
        assert!(result.is_err());
    }

    #[cfg(feature = "bech32")]
    #[test]
    fn test_bech32_invalid_data() {
        let invalid_data = "iotaprivkey1invalid";
        let result = SimpleKeypair::from_bech32(invalid_data);
        assert!(result.is_err());
    }
}
