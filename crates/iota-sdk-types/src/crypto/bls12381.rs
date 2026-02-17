// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Implementation of bls12381 min-sig public-key cryptography.

/// A bls12381 min-sig public key.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// bls-public-key = %x60 96OCTET
/// ```
///
/// Due to historical reasons, even though a min-sig `Bls12381PublicKey` has a
/// fixed-length of 96, IOTA's binary representation of a min-sig
/// `Bls12381PublicKey` is prefixed with its length meaning its serialized
/// binary form (in bcs) is 97 bytes long vs a more compact 96 bytes.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Bls12381PublicKey(
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<::serde_with::IfIsHumanReadable<super::Base64Array96, ::serde_with::Bytes>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    [u8; Self::LENGTH],
);

impl Bls12381PublicKey {
    /// The length of an bls12381 public key in bytes.
    pub const LENGTH: usize = 96;

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

    /// Return the underlying byte array of an Bls12381PublicKey.
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

impl std::str::FromStr for Bls12381PublicKey {
    type Err = base64ct::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        super::Base64FromStr96::from_str(s).map(|a| Self(a.0))
    }
}

impl AsRef<[u8]> for Bls12381PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; Self::LENGTH]> for Bls12381PublicKey {
    fn as_ref(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<Bls12381PublicKey> for [u8; Bls12381PublicKey::LENGTH] {
    fn from(public_key: Bls12381PublicKey) -> Self {
        public_key.into_inner()
    }
}

impl From<[u8; Self::LENGTH]> for Bls12381PublicKey {
    fn from(public_key: [u8; Self::LENGTH]) -> Self {
        Self::new(public_key)
    }
}

impl std::fmt::Display for Bls12381PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&super::Base64Display96(&self.0), f)
    }
}

impl std::fmt::Debug for Bls12381PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bls12381PublicKey")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

/// A bls12381 min-sig signature.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// bls-signature = 48OCTET
/// ```
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Bls12381Signature(
    #[cfg_attr(
        feature = "serde",
        serde(
            with = "::serde_with::As::<::serde_with::IfIsHumanReadable<super::Base64Array48, [::serde_with::Same; 48]>>"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::Base64"))]
    [u8; Self::LENGTH],
);

impl Bls12381Signature {
    /// The length of an bls12381 signature key in bytes.
    pub const LENGTH: usize = 48;

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

    /// Return the underlying byte array of an Bls12381Signature.
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

impl std::str::FromStr for Bls12381Signature {
    type Err = base64ct::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        super::Base64FromStr48::from_str(s).map(|a| Self::new(a.0))
    }
}

impl AsRef<[u8]> for Bls12381Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; Self::LENGTH]> for Bls12381Signature {
    fn as_ref(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl From<Bls12381Signature> for [u8; Bls12381Signature::LENGTH] {
    fn from(signature: Bls12381Signature) -> Self {
        signature.into_inner()
    }
}

impl From<[u8; Self::LENGTH]> for Bls12381Signature {
    fn from(signature: [u8; Self::LENGTH]) -> Self {
        Self::new(signature)
    }
}

impl std::fmt::Display for Bls12381Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&super::Base64Display48(&self.0), f)
    }
}

impl std::fmt::Debug for Bls12381Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bls12381Signature")
            .field(&format_args!("\"{self}\""))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_bls12381_public_key_roundtrip() {
        let bytes = [1u8; 96];
        let pk = Bls12381PublicKey::new(bytes);
        
        assert_eq!(pk.into_inner(), bytes);
        assert_eq!(pk.inner(), &bytes);
        assert_eq!(pk.as_bytes(), &bytes);
        assert_eq!(AsRef::<[u8]>::as_ref(&pk), &bytes);
    }

    #[test]
    fn test_bls12381_public_key_display_debug() {
        let bytes = [1u8; 96];
        let pk = Bls12381PublicKey::new(bytes);
        
        // Display should be base64
        let s = pk.to_string();
        assert!(!s.is_empty());
        let pk_from_str = Bls12381PublicKey::from_str(&s).unwrap();
        assert_eq!(pk, pk_from_str);
        
        // Debug
        let debug = format!("{:?}", pk);
        assert!(debug.contains("Bls12381PublicKey"));
        assert!(debug.contains(&s));
    }

    #[test]
    fn test_bls12381_signature_roundtrip() {
        let bytes = [2u8; 48];
        let sig = Bls12381Signature::new(bytes);
        
        assert_eq!(sig.into_inner(), bytes);
        assert_eq!(sig.inner(), &bytes);
        assert_eq!(sig.as_bytes(), &bytes);
        
        let sig2 = Bls12381Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }
    
    #[cfg(feature = "serde")]
    #[test]
    fn test_bls12381_serde() {
        let pk = Bls12381PublicKey::new([1u8; 96]);
        let json = serde_json::to_string(&pk).unwrap();
        let pk2: Bls12381PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, pk2);
        
        let sig = Bls12381Signature::new([2u8; 48]);
        let json_sig = serde_json::to_string(&sig).unwrap();
        let sig2: Bls12381Signature = serde_json::from_str(&json_sig).unwrap();
        assert_eq!(sig, sig2);
    }
}
