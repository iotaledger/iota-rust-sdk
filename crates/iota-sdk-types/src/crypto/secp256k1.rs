// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of secp256k1 public-key cryptography.

use crate::crypto::{PublicKeyExt, SignatureScheme};

/// A secp256k1 public key.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// secp256k1-public-key = 33OCTET
/// ```
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Secp256k1PublicKey(
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<::serde_with::IfIsHumanReadable<super::Base64Array33, [::serde_with::Same; 33]>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    [u8; Self::LENGTH],
);

impl Secp256k1PublicKey {
    /// The length of an secp256k1 public key in bytes.
    pub const LENGTH: usize = 33;

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    /// Return the underlying byte array of an Secp256k1PublicKey.
    pub const fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub const fn inner(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl PublicKeyExt for Secp256k1PublicKey {
    type FromBytesErr = std::array::TryFromSliceError;

    /// Returns the public key as bytes.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Tries to create a Secp256k1PublicKey from bytes.
    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, Self::FromBytesErr> {
        <[u8; Self::LENGTH]>::try_from(bytes.as_ref()).map(Self)
    }

    /// Returns the signature scheme for this public key.
    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Secp256k1
    }
}

impl std::str::FromStr for Secp256k1PublicKey {
    type Err = base64ct::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        super::Base64FromStr33::from_str(s).map(|a| Self::new(a.0))
    }
}

impl AsRef<[u8]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; Self::LENGTH]> for Secp256k1PublicKey {
    fn as_ref(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<Secp256k1PublicKey> for [u8; Secp256k1PublicKey::LENGTH] {
    fn from(public_key: Secp256k1PublicKey) -> Self {
        public_key.into_inner()
    }
}

impl From<[u8; Self::LENGTH]> for Secp256k1PublicKey {
    fn from(public_key: [u8; Self::LENGTH]) -> Self {
        Self::new(public_key)
    }
}

impl std::fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&super::Base64Display33(&self.0), f)
    }
}

impl std::fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secp256k1PublicKey")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

/// A secp256k1 signature.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// secp256k1-signature = 64OCTET
/// ```
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Secp256k1Signature(
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<::serde_with::IfIsHumanReadable<super::Base64Array64, [::serde_with::Same; 64]>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    [u8; Self::LENGTH],
);

impl Secp256k1Signature {
    /// The length of an secp256k1 signature key in bytes.
    pub const LENGTH: usize = 64;

    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    #[cfg(feature = "rand")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "rand")))]
    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        Self::new(buf)
    }

    /// Return the underlying byte array of an Secp256k1Signature.
    pub const fn into_inner(self) -> [u8; Self::LENGTH] {
        self.0
    }

    pub const fn inner(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Self, std::array::TryFromSliceError> {
        <[u8; Self::LENGTH]>::try_from(bytes.as_ref()).map(Self)
    }
}

impl std::str::FromStr for Secp256k1Signature {
    type Err = base64ct::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        super::Base64FromStr64::from_str(s).map(|a| Self::new(a.0))
    }
}

impl AsRef<[u8]> for Secp256k1Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; Self::LENGTH]> for Secp256k1Signature {
    fn as_ref(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<Secp256k1Signature> for [u8; Secp256k1Signature::LENGTH] {
    fn from(signature: Secp256k1Signature) -> Self {
        signature.into_inner()
    }
}

impl From<[u8; Self::LENGTH]> for Secp256k1Signature {
    fn from(signature: [u8; Self::LENGTH]) -> Self {
        Self::new(signature)
    }
}

impl std::fmt::Display for Secp256k1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&super::Base64Display64(&self.0), f)
    }
}

impl std::fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Secp256k1Signature")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PublicKeyExt, SignatureScheme};
    use std::str::FromStr;

    #[test]
    fn test_secp256k1_public_key_roundtrip() {
        let bytes = [1u8; 33];
        let pk = Secp256k1PublicKey::new(bytes);
        
        assert_eq!(pk.into_inner(), bytes);
        assert_eq!(pk.inner(), &bytes);
        assert_eq!(pk.as_bytes(), &bytes);
        assert_eq!(AsRef::<[u8]>::as_ref(&pk), &bytes);
        
        // Scheme
        assert_eq!(pk.scheme(), SignatureScheme::Secp256k1);
    }

    #[test]
    fn test_secp256k1_public_key_display_debug() {
        let bytes = [1u8; 33];
        let pk = Secp256k1PublicKey::new(bytes);
        
        // Display should be base64
        let s = pk.to_string();
        assert!(!s.is_empty());
        let pk_from_str = Secp256k1PublicKey::from_str(&s).unwrap();
        assert_eq!(pk, pk_from_str);
        
        // Debug
        let debug = format!("{:?}", pk);
        assert!(debug.contains("Secp256k1PublicKey"));
        assert!(debug.contains(&s));
    }

    #[test]
    fn test_secp256k1_signature_roundtrip() {
        let bytes = [2u8; 64];
        let sig = Secp256k1Signature::new(bytes);
        
        assert_eq!(sig.into_inner(), bytes);
        assert_eq!(sig.inner(), &bytes);
        assert_eq!(sig.as_bytes(), &bytes);
        
        let sig2 = Secp256k1Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }
    
    #[cfg(feature = "serde")]
    #[test]
    fn test_secp256k1_serde() {
        let pk = Secp256k1PublicKey::new([1u8; 33]);
        let json = serde_json::to_string(&pk).unwrap();
        let pk2: Secp256k1PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, pk2);
        
        let sig = Secp256k1Signature::new([2u8; 64]);
        let json_sig = serde_json::to_string(&sig).unwrap();
        let sig2: Secp256k1Signature = serde_json::from_str(&json_sig).unwrap();
        assert_eq!(sig, sig2);
    }
}
