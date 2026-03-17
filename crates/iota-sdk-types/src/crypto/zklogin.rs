// Copyright (c) Mysten Labs, Inc.
// Modifications Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use super::SimpleSignature;
use crate::{checkpoint::EpochId, u256::U256};

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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ZkLoginAuthenticator {
    /// Zklogin proof and inputs required to perform proof verification.
    pub inputs: ZkLoginInputs,
    /// Maximum epoch for which the proof is valid.
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U64"))]
    pub max_epoch: EpochId,
    /// User signature with the pubkey attested to by the provided proof.
    pub signature: SimpleSignature,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkLoginInputs {
    proof_points: ZkLoginProof,
    iss_base64_details: ZkLoginClaim,
    header_base64: String,
    // Validated types
    jwt_header: JwtHeader,
    jwk_id: JwkId,
    public_identifier: ZkLoginPublicIdentifier,
}

impl ZkLoginInputs {
    #[cfg(feature = "serde")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
    pub fn new(
        proof_points: ZkLoginProof,
        iss_base64_details: ZkLoginClaim,
        header_base64: String,
        address_seed: Bn254FieldElement,
    ) -> Result<Self, InvalidZkLoginAuthenticatorError> {
        let iss = {
            const ISS: &str = "iss";

            let iss = iss_base64_details.verify_extended_claim(ISS)?;

            if iss.len() > 255 {
                return Err(InvalidZkLoginAuthenticatorError::new(
                    "invalid iss: too long",
                ));
            }
            iss
        };

        let jwt_header = JwtHeader::from_base64(&header_base64)?;
        let jwk_id = JwkId {
            iss: iss.clone(),
            kid: jwt_header.kid.clone(),
        };

        let public_identifier = ZkLoginPublicIdentifier { iss, address_seed };

        Ok(Self {
            proof_points,
            iss_base64_details,
            header_base64,
            jwt_header,
            jwk_id,
            public_identifier,
        })
    }

    pub fn proof_points(&self) -> &ZkLoginProof {
        &self.proof_points
    }

    pub fn iss_base64_details(&self) -> &ZkLoginClaim {
        &self.iss_base64_details
    }

    pub fn header_base64(&self) -> &str {
        &self.header_base64
    }

    pub fn address_seed(&self) -> &Bn254FieldElement {
        &self.public_identifier.address_seed
    }

    pub fn jwk_id(&self) -> &JwkId {
        &self.jwk_id
    }

    pub fn iss(&self) -> &str {
        &self.public_identifier.iss
    }

    pub fn public_identifier(&self) -> &ZkLoginPublicIdentifier {
        &self.public_identifier
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for ZkLoginInputs {
    fn schema_name() -> String {
        "ZkLoginInputs".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        #[derive(schemars::JsonSchema)]
        #[schemars(rename_all = "camelCase")]
        #[expect(unused)]
        struct Inputs {
            proof_points: ZkLoginProof,
            iss_base64_details: ZkLoginClaim,
            header_base64: String,
            address_seed: Bn254FieldElement,
        }

        Inputs::json_schema(generator)
    }
}

#[cfg(feature = "proptest")]
impl proptest::arbitrary::Arbitrary for ZkLoginInputs {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;

        (any::<ZkLoginProof>(), any::<Bn254FieldElement>())
            .prop_map(|(proof_points, address_seed)| {
                // TODO implement Arbitrary for real for ZkLoginClaim and header_base64 values
                let iss_base64_details = ZkLoginClaim {
                    value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
                    index_mod_4: 2,
                };
                let header_base64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ".to_owned();
                Self::new(
                    proof_points,
                    iss_base64_details,
                    header_base64,
                    address_seed,
                )
                .unwrap()
            })
            .boxed()
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ZkLoginClaim {
    pub value: String,
    pub index_mod_4: u8,
}

#[derive(Debug)]
pub struct InvalidZkLoginAuthenticatorError(String);

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl InvalidZkLoginAuthenticatorError {
    fn new<T: Into<String>>(err: T) -> Self {
        Self(err.into())
    }
}

impl std::fmt::Display for InvalidZkLoginAuthenticatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid zklogin claim: {}", self.0)
    }
}

impl std::error::Error for InvalidZkLoginAuthenticatorError {}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
impl ZkLoginClaim {
    fn verify_extended_claim(
        &self,
        expected_key: &str,
    ) -> Result<String, InvalidZkLoginAuthenticatorError> {
        /// Map a base64 string to a bit array by taking each char's index and
        /// convert it to binary form with one bit per u8 element in the
        /// output. Returns InvalidZkLoginClaimError if one of the characters is
        /// not in the base64 charset.
        fn base64_to_bitarray(input: &str) -> Result<Vec<u8>, InvalidZkLoginAuthenticatorError> {
            use itertools::Itertools;

            const BASE64_URL_CHARSET: &str =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

            input
                .chars()
                .map(|c| {
                    BASE64_URL_CHARSET
                        .find(c)
                        .map(|index| index as u8)
                        .map(|index| (0..6).rev().map(move |i| (index >> i) & 1))
                        .ok_or_else(|| {
                            InvalidZkLoginAuthenticatorError::new(
                                "base64_to_bitarray invalid input",
                            )
                        })
                })
                .flatten_ok()
                .collect()
        }

        /// Convert a bitarray (each bit is represented by a u8) to a byte array
        /// by taking each 8 bits as a byte in big-endian format.
        fn bitarray_to_bytearray(bits: &[u8]) -> Result<Vec<u8>, InvalidZkLoginAuthenticatorError> {
            if !bits.len().is_multiple_of(8) {
                return Err(InvalidZkLoginAuthenticatorError::new(
                    "bitarray_to_bytearray invalid input",
                ));
            }
            Ok(bits
                .chunks(8)
                .map(|chunk| {
                    let mut byte = 0u8;
                    for (i, bit) in chunk.iter().rev().enumerate() {
                        byte |= bit << i;
                    }
                    byte
                })
                .collect())
        }

        /// Parse the base64 string, add paddings based on offset, and convert
        /// to a bytearray.
        fn decode_base64_url(
            s: &str,
            index_mod_4: &u8,
        ) -> Result<String, InvalidZkLoginAuthenticatorError> {
            if s.len() < 2 {
                return Err(InvalidZkLoginAuthenticatorError::new(
                    "Base64 string smaller than 2",
                ));
            }
            let mut bits = base64_to_bitarray(s)?;
            match index_mod_4 {
                0 => {}
                1 => {
                    bits.drain(..2);
                }
                2 => {
                    bits.drain(..4);
                }
                _ => {
                    return Err(InvalidZkLoginAuthenticatorError::new(
                        "Invalid first_char_offset",
                    ));
                }
            }

            let last_char_offset = (index_mod_4 + s.len() as u8 - 1) % 4;
            match last_char_offset {
                3 => {}
                2 => {
                    bits.drain(bits.len() - 2..);
                }
                1 => {
                    bits.drain(bits.len() - 4..);
                }
                _ => {
                    return Err(InvalidZkLoginAuthenticatorError::new(
                        "Invalid last_char_offset",
                    ));
                }
            }

            if bits.len() % 8 != 0 {
                return Err(InvalidZkLoginAuthenticatorError::new("Invalid bits length"));
            }

            Ok(std::str::from_utf8(&bitarray_to_bytearray(&bits)?)
                .map_err(|_| InvalidZkLoginAuthenticatorError::new("Invalid UTF8 string"))?
                .to_owned())
        }

        let extended_claim = decode_base64_url(&self.value, &self.index_mod_4)?;

        // Last character of each extracted_claim must be '}' or ','
        if !(extended_claim.ends_with('}') || extended_claim.ends_with(',')) {
            return Err(InvalidZkLoginAuthenticatorError::new(
                "Invalid extended claim",
            ));
        }

        let json_str = format!("{{{}}}", &extended_claim[..extended_claim.len() - 1]);

        serde_json::from_str::<serde_json::Value>(&json_str)
            .map_err(|e| InvalidZkLoginAuthenticatorError::new(e.to_string()))?
            .as_object_mut()
            .and_then(|o| o.get_mut(expected_key))
            .map(serde_json::Value::take)
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s),
                _ => None,
            })
            .ok_or_else(|| InvalidZkLoginAuthenticatorError::new("invalid extended claim"))
    }
}

/// Struct that represents a standard JWT header according to
/// https://openid.net/specs/openid-connect-core-1_0.html
#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtHeader {
    alg: String,
    kid: String,
    typ: Option<String>,
}

impl JwtHeader {
    #[cfg(feature = "serde")]
    fn from_base64(s: &str) -> Result<Self, InvalidZkLoginAuthenticatorError> {
        use base64ct::{Base64UrlUnpadded, Encoding};

        #[derive(serde::Serialize, serde::Deserialize)]
        struct Header {
            alg: String,
            kid: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            typ: Option<String>,
        }

        let header_bytes = Base64UrlUnpadded::decode_vec(s)
            .map_err(|e| InvalidZkLoginAuthenticatorError::new(format!("invalid base64: {e}")))?;
        let Header { alg, kid, typ } = serde_json::from_slice(&header_bytes)
            .map_err(|e| InvalidZkLoginAuthenticatorError::new(format!("invalid json: {e}")))?;
        if alg != "RS256" {
            return Err(InvalidZkLoginAuthenticatorError::new(
                "jwt alg must be RS256",
            ));
        }
        Ok(Self { alg, kid, typ })
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ZkLoginProof {
    pub a: CircomG1,
    pub b: CircomG2,
    pub c: CircomG1,
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct CircomG1(pub [Bn254FieldElement; 3]);

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
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct CircomG2(pub [[Bn254FieldElement; 2]; 3]);

/// Public Key equivalent for Zklogin authenticators
///
/// A `ZkLoginPublicIdentifier` is the equivalent of a public key for other
/// account authenticators, and contains the information required to derive the
/// onchain account [`Address`] for a Zklogin authenticator.
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
///
/// [`Address`]: crate::Address
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct ZkLoginPublicIdentifier {
    iss: String,
    address_seed: Bn254FieldElement,
}

impl ZkLoginPublicIdentifier {
    pub fn new(iss: String, address_seed: Bn254FieldElement) -> Option<Self> {
        if iss.len() > 255 {
            None
        } else {
            Some(Self { iss, address_seed })
        }
    }

    pub fn iss(&self) -> &str {
        &self.iss
    }

    pub fn address_seed(&self) -> &Bn254FieldElement {
        &self.address_seed
    }
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
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

/// Key to uniquely identify a JWK
///
/// # BCS
///
/// The BCS serialized form for this type is defined by the following ABNF:
///
/// ```text
/// jwk-id = string string
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct JwkId {
    /// The issuer or identity of the OIDC provider.
    pub iss: String,
    /// A key id use to uniquely identify a key from an OIDC provider.
    pub kid: String,
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "proptest", derive(test_strategy::Arbitrary))]
pub struct Bn254FieldElement(
    #[cfg_attr(feature = "schemars", schemars(with = "crate::_schemars::U256"))] [u8; 32],
);

impl Bn254FieldElement {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn from_str_radix_10(s: &str) -> Result<Self, Bn254FieldElementParseError> {
        let u256 = match U256::from_str_radix(s, 10) {
            Ok(u256) => u256,
            Err(e) => return Err(Bn254FieldElementParseError(e)),
        };
        let be = u256.to_be();
        Ok(Self(*be.digits()))
    }

    pub fn unpadded(&self) -> &[u8] {
        let mut buf = self.0.as_slice();

        while !buf.is_empty() && buf[0] == 0 {
            buf = &buf[1..];
        }

        // If the value is '0' then just return a slice of length 1 of the final byte
        if buf.is_empty() { &self.0[31..] } else { buf }
    }

    pub fn padded(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Bn254FieldElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let u256 = U256::from_be(U256::from_digits(self.0));
        let radix10 = u256.to_str_radix(10);
        f.write_str(&radix10)
    }
}

#[derive(Debug)]
pub struct Bn254FieldElementParseError(bnum::errors::ParseIntError);

impl std::fmt::Display for Bn254FieldElementParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unable to parse radix10 encoded value {}", self.0)
    }
}

impl std::error::Error for Bn254FieldElementParseError {}

impl std::str::FromStr for Bn254FieldElement {
    type Err = Bn254FieldElementParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let u256 = U256::from_str_radix(s, 10).map_err(Bn254FieldElementParseError)?;
        let be = u256.to_be();
        Ok(Self(*be.digits()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use base64ct::Encoding;
    use num_bigint::BigUint;
    use proptest::prelude::*;
    use test_strategy::proptest;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    // --- Bn254FieldElement ---

    #[test]
    fn unpadded_slice() {
        let seed = Bn254FieldElement([0; 32]);
        let zero: [u8; 1] = [0];
        assert_eq!(seed.unpadded(), zero.as_slice());

        let mut seed = Bn254FieldElement([1; 32]);
        seed.0[0] = 0;
        assert_eq!(seed.unpadded(), [1; 31].as_slice());
    }

    #[test]
    fn unpadded_all_zeros_returns_single_zero_byte() {
        let seed = Bn254FieldElement::new([0; 32]);
        assert_eq!(seed.unpadded().len(), 1);
        assert_eq!(seed.unpadded()[0], 0);
    }

    #[test]
    fn unpadded_no_leading_zeros() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xff;
        let seed = Bn254FieldElement::new(bytes);
        assert_eq!(seed.unpadded().len(), 32);
    }

    #[test]
    fn unpadded_single_nonzero_at_end() {
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let seed = Bn254FieldElement::new(bytes);
        assert_eq!(seed.unpadded(), &[42]);
    }

    #[test]
    fn padded_always_32_bytes() {
        let seed = Bn254FieldElement::new([0; 32]);
        assert_eq!(seed.padded().len(), 32);
    }

    #[test]
    fn from_str_radix_10_valid() {
        let seed = Bn254FieldElement::from_str_radix_10("12345").unwrap();
        assert_eq!(seed.to_string(), "12345");
    }

    #[test]
    fn from_str_radix_10_zero() {
        let seed = Bn254FieldElement::from_str_radix_10("0").unwrap();
        assert_eq!(seed.to_string(), "0");
    }

    #[test]
    fn from_str_radix_10_invalid() {
        assert!(Bn254FieldElement::from_str_radix_10("not_a_number").is_err());
    }

    #[test]
    fn from_str_roundtrip() {
        let original = "999999999999999999";
        let seed = Bn254FieldElement::from_str(original).unwrap();
        assert_eq!(seed.to_string(), original);
    }

    #[test]
    fn display_and_parse_error() {
        let err = Bn254FieldElement::from_str("abc").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unable to parse"));
    }

    // --- ZkLoginPublicIdentifier ---

    #[test]
    fn zklogin_public_identifier_valid() {
        let seed = Bn254FieldElement::new([1; 32]);
        let id = ZkLoginPublicIdentifier::new("https://accounts.google.com".to_string(), seed);
        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.iss(), "https://accounts.google.com");
    }

    #[test]
    fn zklogin_public_identifier_iss_too_long() {
        let seed = Bn254FieldElement::new([1; 32]);
        let long_iss = "a".repeat(256);
        assert!(ZkLoginPublicIdentifier::new(long_iss, seed).is_none());
    }

    #[test]
    fn zklogin_public_identifier_iss_at_limit() {
        let seed = Bn254FieldElement::new([1; 32]);
        let iss_255 = "a".repeat(255);
        assert!(ZkLoginPublicIdentifier::new(iss_255, seed).is_some());
    }

    // --- ZkLoginClaim::verify_extended_claim ---

    #[test]
    fn verify_extended_claim_valid_iss() {
        // This is the real base64url-encoded claim from the proptest Arbitrary impl
        let claim = ZkLoginClaim {
            value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
            index_mod_4: 2,
        };
        let result = claim.verify_extended_claim("iss");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://id.twitch.tv/oauth2");
    }

    #[test]
    fn verify_extended_claim_invalid_base64_char() {
        let claim = ZkLoginClaim {
            value: "!!!invalid!!!".to_owned(),
            index_mod_4: 0,
        };
        let result = claim.verify_extended_claim("iss");
        assert!(result.is_err());
    }

    #[test]
    fn verify_extended_claim_too_short() {
        let claim = ZkLoginClaim {
            value: "a".to_owned(),
            index_mod_4: 0,
        };
        let result = claim.verify_extended_claim("iss");
        assert!(result.is_err());
    }

    #[test]
    fn verify_extended_claim_invalid_index_mod_4() {
        let claim = ZkLoginClaim {
            value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
            index_mod_4: 3, // invalid: must be 0, 1, or 2
        };
        let result = claim.verify_extended_claim("iss");
        assert!(result.is_err());
    }

    #[test]
    fn verify_extended_claim_missing_key() {
        let claim = ZkLoginClaim {
            value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
            index_mod_4: 2,
        };
        // Looking for a key that doesn't exist
        let result = claim.verify_extended_claim("nonexistent");
        assert!(result.is_err());
    }

    // --- JwtHeader::from_base64 ---

    #[test]
    fn jwt_header_valid() {
        // {"alg":"RS256","typ":"JWT","kid":"1"}
        let header_b64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ";
        let header = JwtHeader::from_base64(header_b64).unwrap();
        assert_eq!(header.alg, "RS256");
        assert_eq!(header.kid, "1");
        assert_eq!(header.typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn jwt_header_wrong_algorithm() {
        // {"alg":"HS256","kid":"1"}
        let header_b64 = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ";
        let result = JwtHeader::from_base64(header_b64);
        assert!(result.is_err());
        assert!(result.unwrap_err().0.contains("RS256"));
    }

    #[test]
    fn jwt_header_invalid_base64() {
        let result = JwtHeader::from_base64("!!!not-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn jwt_header_invalid_json() {
        // Valid base64 but not valid JSON
        let not_json = base64ct::Base64UrlUnpadded::encode_string(b"not json");
        let result = JwtHeader::from_base64(&not_json);
        assert!(result.is_err());
    }

    #[test]
    fn jwt_header_without_typ() {
        // {"alg":"RS256","kid":"2"}
        let header_b64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIifQ";
        let header = JwtHeader::from_base64(header_b64).unwrap();
        assert_eq!(header.kid, "2");
        assert!(header.typ.is_none());
    }

    // --- ZkLoginInputs::new ---

    fn make_proof() -> ZkLoginProof {
        ZkLoginProof {
            a: CircomG1([
                Bn254FieldElement::new([0; 32]),
                Bn254FieldElement::new([0; 32]),
                Bn254FieldElement::new([0; 32]),
            ]),
            b: CircomG2([
                [Bn254FieldElement::new([0; 32]), Bn254FieldElement::new([0; 32])],
                [Bn254FieldElement::new([0; 32]), Bn254FieldElement::new([0; 32])],
                [Bn254FieldElement::new([0; 32]), Bn254FieldElement::new([0; 32])],
            ]),
            c: CircomG1([
                Bn254FieldElement::new([0; 32]),
                Bn254FieldElement::new([0; 32]),
                Bn254FieldElement::new([0; 32]),
            ]),
        }
    }

    #[test]
    fn zklogin_inputs_new_valid() {
        let claim = ZkLoginClaim {
            value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
            index_mod_4: 2,
        };
        let header_b64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ".to_owned();
        let seed = Bn254FieldElement::new([1; 32]);

        let inputs = ZkLoginInputs::new(make_proof(), claim, header_b64, seed);
        assert!(inputs.is_ok());
        let inputs = inputs.unwrap();
        assert_eq!(inputs.iss(), "https://id.twitch.tv/oauth2");
        assert_eq!(inputs.jwk_id().kid, "1");
        assert_eq!(inputs.jwk_id().iss, "https://id.twitch.tv/oauth2");
    }

    #[test]
    fn zklogin_inputs_new_invalid_claim() {
        let claim = ZkLoginClaim {
            value: "!!!".to_owned(),
            index_mod_4: 0,
        };
        let header_b64 = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ".to_owned();
        let seed = Bn254FieldElement::new([1; 32]);

        assert!(ZkLoginInputs::new(make_proof(), claim, header_b64, seed).is_err());
    }

    #[test]
    fn zklogin_inputs_new_invalid_header() {
        let claim = ZkLoginClaim {
            value: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw".to_owned(),
            index_mod_4: 2,
        };
        // Invalid header
        let header_b64 = "!!!".to_owned();
        let seed = Bn254FieldElement::new([1; 32]);

        assert!(ZkLoginInputs::new(make_proof(), claim, header_b64, seed).is_err());
    }

    #[test]
    fn zklogin_inputs_new_iss_too_long() {
        // Craft a claim that would produce an iss > 255 chars
        // This is hard to do with real base64, so we test the iss length check
        // indirectly via ZkLoginPublicIdentifier
        let seed = Bn254FieldElement::new([1; 32]);
        let long_iss = "a".repeat(256);
        assert!(ZkLoginPublicIdentifier::new(long_iss, seed).is_none());
    }

    // --- InvalidZkLoginAuthenticatorError ---

    #[test]
    fn invalid_zklogin_error_display() {
        let err = InvalidZkLoginAuthenticatorError("test error".to_string());
        assert_eq!(err.to_string(), "invalid zklogin claim: test error");
    }

    #[proptest]
    fn dont_crash_on_large_inputs(
        #[strategy(proptest::collection::vec(any::<u8>(), 33..1024))] bytes: Vec<u8>,
    ) {
        let big_int = BigUint::from_bytes_be(&bytes);
        let radix10 = big_int.to_str_radix(10);

        // doesn't crash
        let _ = Bn254FieldElement::from_str(&radix10);
    }

    #[proptest]
    fn valid_address_seeds(
        #[strategy(proptest::collection::vec(any::<u8>(), 1..=32))] bytes: Vec<u8>,
    ) {
        let big_int = BigUint::from_bytes_be(&bytes);
        let radix10 = big_int.to_str_radix(10);

        let seed = Bn254FieldElement::from_str(&radix10).unwrap();
        assert_eq!(radix10, seed.to_string());
        // Ensure unpadded doesn't crash
        seed.unpadded();
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
mod serialization {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::{Bytes, DeserializeAs, SerializeAs};

    use super::*;
    use crate::{SignatureScheme, crypto::SignatureFromBytesError};

    // Serialized format is: iss_bytes_len || iss_bytes ||
    // padded_32_byte_address_seed.
    impl Serialize for ZkLoginPublicIdentifier {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                #[derive(serde::Serialize)]
                struct Readable<'a> {
                    iss: &'a str,
                    address_seed: &'a Bn254FieldElement,
                }
                let readable = Readable {
                    iss: &self.iss,
                    address_seed: &self.address_seed,
                };
                readable.serialize(serializer)
            } else {
                let mut buf = Vec::new();
                let iss_bytes = self.iss.as_bytes();
                buf.push(iss_bytes.len() as u8);
                buf.extend(iss_bytes);

                buf.extend(&self.address_seed.0);

                serializer.serialize_bytes(&buf)
            }
        }
    }

    impl<'de> Deserialize<'de> for ZkLoginPublicIdentifier {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                #[derive(serde::Deserialize)]
                struct Readable {
                    iss: String,
                    address_seed: Bn254FieldElement,
                }

                let Readable { iss, address_seed } = Deserialize::deserialize(deserializer)?;
                Self::new(iss, address_seed)
                    .ok_or_else(|| serde::de::Error::custom("invalid zklogin public identifier"))
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                let iss_len = *bytes
                    .first()
                    .ok_or_else(|| serde::de::Error::custom("invalid zklogin public identifier"))?;
                let iss_bytes = bytes
                    .get(1..(1 + iss_len as usize))
                    .ok_or_else(|| serde::de::Error::custom("invalid zklogin public identifier"))?;
                let iss = std::str::from_utf8(iss_bytes).map_err(serde::de::Error::custom)?;
                let address_seed_bytes = bytes
                    .get((1 + iss_len as usize)..)
                    .ok_or_else(|| serde::de::Error::custom("invalid zklogin public identifier"))?;

                let address_seed = <[u8; 32]>::try_from(address_seed_bytes)
                    .map_err(serde::de::Error::custom)
                    .map(Bn254FieldElement)?;

                Self::new(iss.into(), address_seed)
                    .ok_or_else(|| serde::de::Error::custom("invalid zklogin public identifier"))
            }
        }
    }

    #[derive(serde::Serialize)]
    struct AuthenticatorRef<'a> {
        inputs: &'a ZkLoginInputs,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_epoch: EpochId,
        signature: &'a SimpleSignature,
    }

    #[derive(serde::Deserialize)]
    struct Authenticator {
        inputs: ZkLoginInputs,
        #[cfg_attr(feature = "serde", serde(with = "crate::_serde::ReadableDisplay"))]
        max_epoch: EpochId,
        signature: SimpleSignature,
    }

    impl Serialize for ZkLoginAuthenticator {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            if serializer.is_human_readable() {
                let authenticator_ref = AuthenticatorRef {
                    inputs: &self.inputs,
                    max_epoch: self.max_epoch,
                    signature: &self.signature,
                };

                authenticator_ref.serialize(serializer)
            } else {
                let bytes = self.to_bytes();
                serializer.serialize_bytes(&bytes)
            }
        }
    }

    impl<'de> Deserialize<'de> for ZkLoginAuthenticator {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            if deserializer.is_human_readable() {
                let Authenticator {
                    inputs,
                    max_epoch,
                    signature,
                } = Authenticator::deserialize(deserializer)?;
                Ok(Self {
                    inputs,
                    max_epoch,
                    signature,
                })
            } else {
                let bytes: Cow<'de, [u8]> = Bytes::deserialize_as(deserializer)?;
                Self::from_serialized_bytes(bytes).map_err(serde::de::Error::custom)
            }
        }
    }

    impl ZkLoginAuthenticator {
        pub(crate) fn to_bytes(&self) -> Vec<u8> {
            let authenticator_ref = AuthenticatorRef {
                inputs: &self.inputs,
                max_epoch: self.max_epoch,
                signature: &self.signature,
            };

            let mut buf = Vec::new();
            buf.push(SignatureScheme::ZkLoginAuthenticator as u8);

            bcs::serialize_into(&mut buf, &authenticator_ref).expect("serialization cannot fail");
            buf
        }

        pub fn from_serialized_bytes(
            bytes: impl AsRef<[u8]>,
        ) -> Result<Self, SignatureFromBytesError> {
            let bytes = bytes.as_ref();
            let flag =
                SignatureScheme::from_byte(*bytes.first().ok_or_else(|| {
                    SignatureFromBytesError::new("missing signature scheme flag")
                })?)
                .map_err(SignatureFromBytesError::new)?;
            if flag != SignatureScheme::ZkLoginAuthenticator {
                return Err(SignatureFromBytesError::new("invalid zklogin flag"));
            }
            let bcs_bytes = &bytes[1..];

            let Authenticator {
                inputs,
                max_epoch,
                signature,
            } = bcs::from_bytes(bcs_bytes).map_err(SignatureFromBytesError::new)?;
            Ok(Self {
                inputs,
                max_epoch,
                signature,
            })
        }
    }

    impl Serialize for ZkLoginInputs {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Inputs<'a> {
                proof_points: &'a ZkLoginProof,
                iss_base64_details: &'a ZkLoginClaim,
                header_base64: &'a str,
                address_seed: &'a Bn254FieldElement,
            }

            Inputs {
                proof_points: self.proof_points(),
                iss_base64_details: self.iss_base64_details(),
                header_base64: self.header_base64(),
                address_seed: self.address_seed(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ZkLoginInputs {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            struct Inputs {
                proof_points: ZkLoginProof,
                iss_base64_details: ZkLoginClaim,
                header_base64: String,
                address_seed: Bn254FieldElement,
            }

            let Inputs {
                proof_points,
                iss_base64_details,
                header_base64,
                address_seed,
            } = Inputs::deserialize(deserializer)?;
            Self::new(
                proof_points,
                iss_base64_details,
                header_base64,
                address_seed,
            )
            .map_err(serde::de::Error::custom)
        }
    }

    // AddressSeed's serialized format is as a radix10 encoded string
    impl Serialize for Bn254FieldElement {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serde_with::DisplayFromStr::serialize_as(self, serializer)
        }
    }

    impl<'de> Deserialize<'de> for Bn254FieldElement {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            serde_with::DisplayFromStr::deserialize_as(deserializer)
        }
    }

    impl Serialize for CircomG1 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeSeq;
            let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
            for element in &self.0 {
                seq.serialize_element(element)?;
            }
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for CircomG1 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let inner = <Vec<_>>::deserialize(deserializer)?;
            Ok(Self(inner.try_into().map_err(|_| {
                serde::de::Error::custom("expected array of length 3")
            })?))
        }
    }

    impl Serialize for CircomG2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeSeq;

            struct Inner<'a>(&'a [Bn254FieldElement; 2]);

            impl Serialize for Inner<'_> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer,
                {
                    let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
                    for element in self.0 {
                        seq.serialize_element(element)?;
                    }
                    seq.end()
                }
            }

            let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
            for element in &self.0 {
                seq.serialize_element(&Inner(element))?;
            }
            seq.end()
        }
    }

    impl<'de> Deserialize<'de> for CircomG2 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let vecs = <Vec<Vec<Bn254FieldElement>>>::deserialize(deserializer)?;
            let mut inner: [[Bn254FieldElement; 2]; 3] = Default::default();

            if vecs.len() != 3 {
                return Err(serde::de::Error::custom(
                    "vector of three vectors each being a vector of two strings",
                ));
            }

            for (i, v) in vecs.into_iter().enumerate() {
                if v.len() != 2 {
                    return Err(serde::de::Error::custom(
                        "vector of three vectors each being a vector of two strings",
                    ));
                }

                for (j, point) in v.into_iter().enumerate() {
                    inner[i][j] = point;
                }
            }

            Ok(Self(inner))
        }
    }
}
