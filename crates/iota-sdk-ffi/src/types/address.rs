// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use base64ct::Encoding;

use crate::{
    base64_encode,
    error::{Result, SdkFfiError},
};

/// Unique identifier for an Account on the IOTA blockchain.
///
/// An `Address` is a 32-byte pseudonymous identifier used to uniquely identify
/// an account and asset-ownership on the IOTA blockchain. Often, human-readable
/// addresses are encoded in hexadecimal with a `0x` prefix. For example, this
/// is a valid IOTA address:
/// `0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331`.
///
/// ```
/// use iota_types::Address;
///
/// let hex = "0x02a212de6a9dfa3a69e22387acfbafbb1a9e591bd9d636e7895dcfc8de05f331";
/// let address = Address::from_hex(hex).unwrap();
/// println!("Address: {}", address);
/// assert_eq!(hex, address.to_string());
/// ```
///
/// # Deriving an Address
///
/// Addresses are cryptographically derived from a number of user account
/// authenticators, the simplest of which is an
/// [`Ed25519PublicKey`](iota_types::Ed25519PublicKey).
///
/// Deriving an address consists of the Blake2b256 hash of the sequence of bytes
/// of its corresponding authenticator, prefixed with a domain-separator (except
/// ed25519, for compatibility reasons). For each other authenticator, this
/// domain-separator is the single byte-value of its
/// [`SignatureScheme`](iota_types::SignatureScheme) flag. E.g. `hash(signature
/// schema flag || authenticator bytes)`.
///
/// Each authenticator has a method for deriving its `Address` as well as
/// documentation for the specifics of how the derivation is done. See
/// [`Ed25519PublicKey::derive_address`] for an example.
///
/// [`Ed25519PublicKey::derive_address`]: iota_types::Ed25519PublicKey::derive_address
///
/// ## Relationship to ObjectIds
///
/// [`ObjectId`]s and [`Address`]es share the same 32-byte addressable space but
/// are derived leveraging different domain-separator values to ensure that,
/// cryptographically, there won't be any overlap, e.g. there can't be a
/// valid `Object` who's `ObjectId` is equal to that of the `Address` of a user
/// account.
///
/// [`ObjectId`]: iota_types::ObjectId
///
/// # BCS
///
/// An `Address`'s BCS serialized form is defined by the following:
///
/// ```text
/// address = 32OCTET
/// ```
#[derive(derive_more::From, derive_more::Deref, uniffi::Object)]
pub struct Address(pub iota_types::Address);

#[uniffi::export]
impl Address {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_types::Address::from_bytes(bytes)?))
    }

    #[uniffi::constructor]
    pub fn from_hex(hex: &str) -> Result<Self> {
        Ok(Self(iota_types::Address::from_hex(hex)?))
    }

    #[uniffi::constructor]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(iota_types::Address::generate(&mut rng))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

macro_rules! named_address {
    ($($constant:ident),+ $(,)?) => {
        paste::paste! {
            #[uniffi::export]
            impl Address {$(
                #[uniffi::constructor]
                pub const fn [< $constant:lower >]() -> Self {
                    Self(iota_types::Address::$constant)
                }
            )+}
        }
    }
}

named_address!(ZERO, STD_LIB, FRAMEWORK, SYSTEM);

crate::export_iota_types_objects_bcs_conversion!(Address);
