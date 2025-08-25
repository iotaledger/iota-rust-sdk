// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use iota_crypto::Verifier;

use crate::{error::Result, types::signature::SimpleSignature};

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
#[derive(derive_more::From, uniffi::Object)]
pub struct PasskeyAuthenticator(pub iota_types::PasskeyAuthenticator);

#[uniffi::export]
impl PasskeyAuthenticator {
    /// Opaque authenticator data for this passkey signature.
    ///
    /// See [Authenticator Data](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) for
    /// more information on this field.
    pub fn authenticator_data(&self) -> Vec<u8> {
        self.0.authenticator_data().to_vec()
    }

    /// Structured, unparsed, JSON for this passkey signature.
    ///
    /// See [CollectedClientData](https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata)
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
}
