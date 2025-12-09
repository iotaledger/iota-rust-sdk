// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::crypto::Verifier;

use crate::{
    error::Result,
    types::{address::Address, crypto::Secp256r1PublicKey, signature::SimpleSignature},
};

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
/// See <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata> for
/// the required json-schema for the `client-data-json` rule. In addition, IOTA
/// currently requires that the `CollectedClientData.type` field is required to
/// be `webauthn.get`.
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(derive_more::From, uniffi::Object)]
pub struct PasskeyAuthenticator(pub iota_sdk::types::PasskeyAuthenticator);

#[uniffi::export]
impl PasskeyAuthenticator {
    /// Opaque authenticator data for this passkey signature.
    ///
    /// See <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
    /// for more information on this field.
    pub fn authenticator_data(&self) -> Vec<u8> {
        self.0.authenticator_data().to_vec()
    }

    /// Structured, unparsed, JSON for this passkey signature.
    ///
    /// See <https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata>
    /// for more information on this field.
    pub fn client_data_json(&self) -> String {
        self.0.client_data_json().to_owned()
    }

    /// The parsed challenge message for this passkey signature.
    ///
    /// This is parsed by decoding the base64url data from the
    /// `client_data_json.challenge` field.
    pub fn challenge(&self) -> Vec<u8> {
        self.0.challenge().to_vec()
    }

    /// The passkey signature.
    pub fn signature(&self) -> SimpleSignature {
        self.0.signature().into()
    }

    /// The passkey public key
    pub fn public_key(&self) -> PasskeyPublicKey {
        self.0.public_key().into()
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
#[derive(derive_more::From, uniffi::Object)]
pub struct PasskeyPublicKey(iota_sdk::types::PasskeyPublicKey);

#[uniffi::export]
impl PasskeyPublicKey {
    #[uniffi::constructor]
    pub fn new(public_key: &Secp256r1PublicKey) -> Self {
        Self(iota_sdk::types::PasskeyPublicKey::new(**public_key))
    }

    pub fn inner(&self) -> Secp256r1PublicKey {
        (*self.0.inner()).into()
    }

    /// Derive an `Address` from this Passkey Public Key
    ///
    /// An `Address` can be derived from a `PasskeyPublicKey` by hashing the
    /// bytes of the `Secp256r1PublicKey` that corresponds to this passkey
    /// prefixed with the Passkey `SignatureScheme` flag (`0x06`).
    ///
    /// `hash( 0x06 || 33-byte secp256r1 public key)`
    pub fn derive_address(&self) -> Address {
        self.0.derive_address().into()
    }
}

crate::export_iota_types_objects_bcs_conversion!(PasskeyAuthenticator);
