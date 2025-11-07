// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use iota_sdk::types::{Jwk, JwkId, ZkLoginClaim};

use crate::{
    error::{Result, SdkFfiError},
    types::{address::Address, signature::SimpleSignature},
};

/// A zklogin authenticator
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// zklogin-bcs = bytes             ; contents are defined by <zklogin-authenticator>
/// zklogin     = zklogin-flag
///               zklogin-inputs
///               u64               ; max epoch
///               simple-signature    
/// ```
///
/// Note: Due to historical reasons, signatures are serialized slightly
/// different from the majority of the types in IOTA. In particular if a
/// signature is ever embedded in another structure it generally is serialized
/// as `bytes` meaning it has a length prefix that defines the length of
/// the completely serialized signature.
#[derive(derive_more::From, uniffi::Object)]
pub struct ZkLoginAuthenticator(pub iota_sdk::types::ZkLoginAuthenticator);

#[uniffi::export]
impl ZkLoginAuthenticator {
    #[uniffi::constructor]
    pub fn new(inputs: &ZkLoginInputs, max_epoch: u64, signature: &SimpleSignature) -> Self {
        Self(iota_sdk::types::ZkLoginAuthenticator {
            inputs: inputs.0.clone(),
            max_epoch,
            signature: signature.0.clone(),
        })
    }

    pub fn inputs(&self) -> ZkLoginInputs {
        self.0.inputs.clone().into()
    }

    pub fn max_epoch(&self) -> u64 {
        self.0.max_epoch
    }

    pub fn signature(&self) -> SimpleSignature {
        self.0.signature.clone().into()
    }
}

/// Public Key equivalent for Zklogin authenticators
///
/// A `ZkLoginPublicIdentifier` is the equivalent of a public key for other
/// account authenticators, and contains the information required to derive the
/// onchain account `Address` for a Zklogin authenticator.
///
/// ## Note
///
/// Due to a historical bug that was introduced in the IOTA Typescript SDK when
/// the zklogin authenticator was first introduced, there are now possibly two
/// "valid" addresses for each zklogin authenticator depending on the
/// bit-pattern of the `address_seed` value.
///
/// The original bug incorrectly derived a zklogin's address by stripping any
/// leading zero-bytes that could have been present in the 32-byte length
/// `address_seed` value prior to hashing, leading to a different derived
/// address. This incorrectly derived address was presented to users of various
/// wallets, leading them to sending funds to these addresses that they couldn't
/// access. Instead of letting these users lose any assets that were sent to
/// these addresses, the IOTA network decided to change the protocol to allow
/// for a zklogin authenticator who's `address_seed` value had leading
/// zero-bytes be authorized to sign for both the addresses derived from both
/// the unpadded and padded `address_seed` value.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// zklogin-public-identifier-bcs = bytes ; where the contents are defined by
///                                       ; <zklogin-public-identifier>
///
/// zklogin-public-identifier = zklogin-public-identifier-iss
///                             address-seed
///
/// zklogin-public-identifier-unpadded = zklogin-public-identifier-iss
///                                      address-seed-unpadded
///
/// ; The iss, or issuer, is a utf8 string that is less than 255 bytes long
/// ; and is serialized with the iss's length in bytes as a u8 followed by
/// ; the bytes of the iss
/// zklogin-public-identifier-iss = u8 *255(OCTET)
///
/// ; A Bn254FieldElement serialized as a 32-byte big-endian value
/// address-seed = 32(OCTET)
///
/// ; A Bn254FieldElement serialized as a 32-byte big-endian value
/// ; with any leading zero bytes stripped
/// address-seed-unpadded = %x00 / %x01-ff *31(OCTET)
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ZkLoginPublicIdentifier(pub iota_sdk::types::ZkLoginPublicIdentifier);

#[uniffi::export]
impl ZkLoginPublicIdentifier {
    #[uniffi::constructor]
    pub fn new(iss: String, address_seed: &Bn254FieldElement) -> Result<Self> {
        iota_sdk::types::ZkLoginPublicIdentifier::new(iss, address_seed.0.clone())
            .ok_or_else(|| SdkFfiError::custom("iss length must be <= 255"))
            .map(Self)
    }

    pub fn iss(&self) -> String {
        self.0.iss().to_owned()
    }

    pub fn address_seed(&self) -> Bn254FieldElement {
        self.0.address_seed().clone().into()
    }

    /// Derive an `Address` from this `ZkLoginPublicIdentifier` by hashing the
    /// byte length of the `iss` followed by the `iss` bytes themselves and
    /// the full 32 byte `address_seed` value, all prefixed with the zklogin
    /// `SignatureScheme` flag (`0x05`).
    ///
    /// `hash( 0x05 || iss_bytes_len || iss_bytes || 32_byte_address_seed )`
    pub fn derive_address_padded(&self) -> Address {
        self.0.derive_address_padded().into()
    }

    /// Derive an `Address` from this `ZkLoginPublicIdentifier` by hashing the
    /// byte length of the `iss` followed by the `iss` bytes themselves and
    /// the `address_seed` bytes with any leading zero-bytes stripped, all
    /// prefixed with the zklogin `SignatureScheme` flag (`0x05`).
    ///
    /// `hash( 0x05 || iss_bytes_len || iss_bytes ||
    /// unpadded_32_byte_address_seed )`
    pub fn derive_address_unpadded(&self) -> Address {
        self.0.derive_address_unpadded().into()
    }

    /// Provides an iterator over the addresses that correspond to this zklogin
    /// authenticator.
    ///
    /// In the majority of instances this will only yield a single address,
    /// except for the instances where the `address_seed` value has a
    /// leading zero-byte, in such cases the returned iterator will yield
    /// two addresses.
    pub fn derive_address(&self) -> Vec<Arc<Address>> {
        self.0
            .derive_address()
            .map(Into::into)
            .map(Arc::new)
            .collect()
    }
}

/// A zklogin groth16 proof and the required inputs to perform proof
/// verification.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// zklogin-inputs = zklogin-proof
///                  zklogin-claim
///                  string              ; base64url-unpadded encoded JwtHeader
///                  bn254-field-element ; address_seed
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ZkLoginInputs(pub iota_sdk::types::ZkLoginInputs);

#[uniffi::export]
impl ZkLoginInputs {
    #[uniffi::constructor]
    pub fn new(
        proof_points: &ZkLoginProof,
        iss_base64_details: ZkLoginClaim,
        header_base64: String,
        address_seed: &Bn254FieldElement,
    ) -> Result<Self> {
        Ok(Self(iota_sdk::types::ZkLoginInputs::new(
            proof_points.0.clone(),
            iss_base64_details,
            header_base64,
            address_seed.0.clone(),
        )?))
    }

    pub fn proof_points(&self) -> ZkLoginProof {
        self.0.proof_points().clone().into()
    }

    pub fn iss_base64_details(&self) -> ZkLoginClaim {
        self.0.iss_base64_details().clone()
    }

    pub fn header_base64(&self) -> String {
        self.0.header_base64().to_owned()
    }

    pub fn address_seed(&self) -> Bn254FieldElement {
        self.0.address_seed().clone().into()
    }

    pub fn jwk_id(&self) -> JwkId {
        self.0.jwk_id().clone()
    }

    pub fn iss(&self) -> String {
        self.0.iss().to_owned()
    }

    pub fn public_identifier(&self) -> ZkLoginPublicIdentifier {
        self.0.public_identifier().clone().into()
    }
}

/// A zklogin groth16 proof
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// zklogin-proof = circom-g1 circom-g2 circom-g1
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct ZkLoginProof(pub iota_sdk::types::ZkLoginProof);

#[uniffi::export]
impl ZkLoginProof {
    #[uniffi::constructor]
    pub fn new(a: &CircomG1, b: &CircomG2, c: &CircomG1) -> Self {
        Self(iota_sdk::types::ZkLoginProof {
            a: a.0.clone(),
            b: b.0.clone(),
            c: c.0.clone(),
        })
    }

    pub fn a(&self) -> CircomG1 {
        self.0.a.clone().into()
    }

    pub fn b(&self) -> CircomG2 {
        self.0.b.clone().into()
    }

    pub fn c(&self) -> CircomG1 {
        self.0.c.clone().into()
    }
}

/// A claim of the iss in a zklogin proof
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// zklogin-claim = string u8
/// ```
#[uniffi::remote(Record)]
pub struct ZkLoginClaim {
    pub value: String,
    pub index_mod_4: u8,
}

/// A G1 point
///
/// This represents the canonical decimal representation of the projective
/// coordinates in Fq.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// circom-g1 = %x03 3(bn254-field-element)
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CircomG1(pub iota_sdk::types::CircomG1);

#[uniffi::export]
impl CircomG1 {
    #[uniffi::constructor]
    pub fn new(
        el_0: &Bn254FieldElement,
        el_1: &Bn254FieldElement,
        el_2: &Bn254FieldElement,
    ) -> Self {
        Self(iota_sdk::types::CircomG1([
            el_0.0.clone(),
            el_1.0.clone(),
            el_2.0.clone(),
        ]))
    }
}

/// A G2 point
///
/// This represents the canonical decimal representation of the coefficients of
/// the projective coordinates in Fq2.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// circom-g2 = %x03 3(%x02 2(bn254-field-element))
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct CircomG2(pub iota_sdk::types::CircomG2);

#[uniffi::export]
impl CircomG2 {
    #[uniffi::constructor]
    pub fn new(
        el_0_0: &Bn254FieldElement,
        el_0_1: &Bn254FieldElement,
        el_1_0: &Bn254FieldElement,
        el_1_1: &Bn254FieldElement,
        el_2_0: &Bn254FieldElement,
        el_2_1: &Bn254FieldElement,
    ) -> Self {
        Self(iota_sdk::types::CircomG2([
            [el_0_0.0.clone(), el_0_1.0.clone()],
            [el_1_0.0.clone(), el_1_1.0.clone()],
            [el_2_0.0.clone(), el_2_1.0.clone()],
        ]))
    }
}

/// A point on the BN254 elliptic curve.
///
/// This is a 32-byte, or 256-bit, value that is generally represented as
/// radix10 when a human-readable display format is needed, and is represented
/// as a 32-byte big-endian value while in memory.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// bn254-field-element = *DIGIT ; which is then interpreted as a radix10 encoded 32-byte value
/// ```
#[derive(derive_more::From, uniffi::Object)]
pub struct Bn254FieldElement(pub iota_sdk::types::Bn254FieldElement);

#[uniffi::export]
impl Bn254FieldElement {
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Ok(Self(iota_sdk::types::Bn254FieldElement::new(
            bytes.try_into().map_err(|v: Vec<u8>| {
                SdkFfiError::custom(format!("expected bytes of length 32, found {}", v.len()))
            })?,
        )))
    }

    #[uniffi::constructor]
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(Self(s.parse()?))
    }

    #[uniffi::constructor]
    pub fn from_str_radix_10(s: &str) -> Result<Self> {
        Ok(Self(iota_sdk::types::Bn254FieldElement::from_str_radix_10(
            s,
        )?))
    }

    pub fn unpadded(&self) -> Vec<u8> {
        self.0.unpadded().to_vec()
    }

    pub fn padded(&self) -> Vec<u8> {
        self.0.padded().to_vec()
    }
}

/// Key to uniquely identify a JWK
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// jwk-id = string string
/// ```
#[uniffi::remote(Record)]
pub struct JwkId {
    /// The issuer or identity of the OIDC provider.
    pub iss: String,
    /// A key id use to uniquely identify a key from an OIDC provider.
    pub kid: String,
}

/// A JSON Web Key
///
/// Struct that contains info for a JWK. A list of them for different kids can
/// be retrieved from the JWK endpoint (e.g. <https://www.googleapis.com/oauth2/v3/certs>).
/// The JWK is used to verify the JWT token.
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// jwk = string string string string
/// ```
#[uniffi::remote(Record)]
pub struct Jwk {
    /// Key type parameter, <https://datatracker.ietf.org/doc/html/rfc7517#section-4.1>
    pub kty: String,
    /// RSA public exponent, <https://datatracker.ietf.org/doc/html/rfc7517#section-9.3>
    pub e: String,
    /// RSA modulus, <https://datatracker.ietf.org/doc/html/rfc7517#section-9.3>
    pub n: String,
    /// Algorithm parameter, <https://datatracker.ietf.org/doc/html/rfc7517#section-4.4>
    pub alg: String,
}

crate::export_iota_types_objects_bcs_conversion!(
    ZkLoginAuthenticator,
    ZkLoginPublicIdentifier,
    ZkLoginProof,
    CircomG1,
    CircomG2,
    Bn254FieldElement
);

crate::export_iota_types_bcs_conversion!(ZkLoginClaim, JwkId, Jwk);
