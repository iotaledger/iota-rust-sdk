// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Roundtrip conversion tests for gRPC proto types <-> iota-sdk-types.
//!
//! Each test converts an SDK type to its proto representation and back,
//! verifying that the value survives the roundtrip unchanged.

use base64ct::Encoding;
use iota_sdk_grpc_types::v1;

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

#[test]
fn digest_roundtrip() {
    let original = iota_types::Digest::new([42u8; 32]);

    let proto: v1::types::Digest = original.into();
    let back: iota_types::Digest = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn digest_roundtrip_zero() {
    let original = iota_types::Digest::ZERO;

    let proto: v1::types::Digest = original.into();
    let back: iota_types::Digest = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

#[test]
fn address_roundtrip() {
    let original = iota_types::Address::new([0xAB; 32]);

    let proto: v1::types::Address = original.into();
    let back: iota_types::Address = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn address_roundtrip_zero() {
    let original = iota_types::Address::ZERO;

    let proto: v1::types::Address = original.into();
    let back: iota_types::Address = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// ObjectId
// ---------------------------------------------------------------------------

#[test]
fn object_id_roundtrip() {
    let original = iota_types::ObjectId::new([0xCD; 32]);

    let proto: v1::types::ObjectId = original.into();
    let back: iota_types::ObjectId = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// ObjectReference
// ---------------------------------------------------------------------------

#[test]
fn object_reference_roundtrip() {
    let original = iota_types::ObjectReference {
        object_id: iota_types::ObjectId::new([1u8; 32]),
        version: 42u64.into(),
        digest: iota_types::ObjectDigest::new([2u8; 32]),
    };

    let proto: v1::types::ObjectReference = original.into();
    let back: iota_types::ObjectReference = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// TypeTag
// ---------------------------------------------------------------------------

#[test]
fn type_tag_roundtrip_primitives() {
    let primitives = [
        iota_types::TypeTag::Bool,
        iota_types::TypeTag::U8,
        iota_types::TypeTag::U16,
        iota_types::TypeTag::U32,
        iota_types::TypeTag::U64,
        iota_types::TypeTag::U128,
        iota_types::TypeTag::U256,
        iota_types::TypeTag::Address,
        iota_types::TypeTag::Signer,
    ];

    for original in primitives {
        let proto: v1::types::TypeTag = (&original).into();
        let back: iota_types::TypeTag = (&proto).try_into().unwrap();
        assert_eq!(original, back);
    }
}

#[test]
fn type_tag_roundtrip_vector() {
    let original = iota_types::TypeTag::Vector(Box::new(iota_types::TypeTag::U64));

    let proto: v1::types::TypeTag = (&original).into();
    let back: iota_types::TypeTag = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn type_tag_roundtrip_nested_vector() {
    let original = iota_types::TypeTag::Vector(Box::new(iota_types::TypeTag::Vector(Box::new(
        iota_types::TypeTag::Bool,
    ))));

    let proto: v1::types::TypeTag = (&original).into();
    let back: iota_types::TypeTag = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn type_tag_roundtrip_struct() {
    let struct_tag = iota_types::StructTag::new(
        iota_types::Address::new([0u8; 32]),
        "module_name".parse::<iota_types::Identifier>().unwrap(),
        "TypeName".parse::<iota_types::Identifier>().unwrap(),
        vec![iota_types::TypeTag::U8, iota_types::TypeTag::Bool],
    );
    let original = iota_types::TypeTag::Struct(Box::new(struct_tag));

    let proto: v1::types::TypeTag = (&original).into();
    let back: iota_types::TypeTag = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// ValidatorCommitteeMember
// ---------------------------------------------------------------------------

#[test]
fn validator_committee_member_roundtrip() {
    let original = iota_types::ValidatorCommitteeMember {
        public_key: iota_types::Bls12381PublicKey::from_bytes([7u8; 96]).unwrap(),
        stake: 1000,
    };

    let proto: v1::epoch::ValidatorCommitteeMember = original.clone().into();
    let back: iota_types::ValidatorCommitteeMember = (&proto).try_into().unwrap();

    assert_eq!(original.public_key, back.public_key);
    assert_eq!(original.stake, back.stake);
}

// ---------------------------------------------------------------------------
// ValidatorCommittee
// ---------------------------------------------------------------------------

#[test]
fn validator_committee_roundtrip() {
    let member = iota_types::ValidatorCommitteeMember {
        public_key: iota_types::Bls12381PublicKey::from_bytes([9u8; 96]).unwrap(),
        stake: 500,
    };
    let original = iota_types::ValidatorCommittee {
        epoch: 42,
        members: vec![member],
    };

    let proto: v1::epoch::ValidatorCommittee = original.clone().into();
    let back: iota_types::ValidatorCommittee = (&proto).try_into().unwrap();

    assert_eq!(original.epoch, back.epoch);
    assert_eq!(original.members.len(), back.members.len());
    assert_eq!(original.members[0].public_key, back.members[0].public_key);
    assert_eq!(original.members[0].stake, back.members[0].stake);
}

#[test]
fn validator_committee_roundtrip_empty_members() {
    let original = iota_types::ValidatorCommittee {
        epoch: 0,
        members: vec![],
    };

    let proto: v1::epoch::ValidatorCommittee = original.clone().into();
    let back: iota_types::ValidatorCommittee = (&proto).try_into().unwrap();

    assert_eq!(original.epoch, back.epoch);
    assert!(back.members.is_empty());
}

// ---------------------------------------------------------------------------
// ValidatorAggregatedSignature (BCS-based roundtrip)
// ---------------------------------------------------------------------------

#[test]
fn validator_aggregated_signature_roundtrip() {
    // Use a known-good BCS fixture to construct a valid
    // ValidatorAggregatedSignature (the roaring bitmap field requires the
    // `roaring` crate which isn't a direct dep).
    let bcs_bytes = base64ct::Base64::decode_vec(
        "CgAAAAAAAACZrBcXiqa0ttztfwrBxKzQRzIRnZhbmsQV7tqNXwiZQrRC+dVDbdua1Ety9uy2pCUSOjAAAAEAAAAAAAAAEAAAAAAA",
    ).unwrap();
    let original: iota_types::ValidatorAggregatedSignature = bcs::from_bytes(&bcs_bytes).unwrap();

    let proto: v1::signatures::ValidatorAggregatedSignature = original.clone().into();
    let back: iota_types::ValidatorAggregatedSignature = (&proto).try_into().unwrap();

    // Compare via BCS since ValidatorAggregatedSignature doesn't derive Eq
    assert_eq!(
        bcs::to_bytes(&original).unwrap(),
        bcs::to_bytes(&back).unwrap()
    );
}

// ---------------------------------------------------------------------------
// UserSignature (BCS-based roundtrip)
// ---------------------------------------------------------------------------

#[test]
fn user_signature_roundtrip() {
    let original = iota_types::UserSignature::Simple(iota_types::SimpleSignature::Ed25519 {
        signature: iota_types::Ed25519Signature::new([4u8; 64]),
        public_key: iota_types::Ed25519PublicKey::new([5u8; 32]),
    });

    let proto: v1::signatures::UserSignature = original.clone().try_into().unwrap();
    let back: iota_types::UserSignature = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// Argument
// ---------------------------------------------------------------------------

#[test]
fn argument_roundtrip_gas() {
    let original = iota_types::transaction::Argument::Gas;

    let proto: v1::command::Argument = original.try_into().unwrap();
    let back: iota_types::transaction::Argument = (&proto).try_into().unwrap();

    assert_eq!(iota_types::transaction::Argument::Gas, back);
}

#[test]
fn argument_roundtrip_input() {
    let original = iota_types::transaction::Argument::Input(7);

    let proto: v1::command::Argument = original.try_into().unwrap();
    let back: iota_types::transaction::Argument = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn argument_roundtrip_result() {
    let original = iota_types::transaction::Argument::Result(3);

    let proto: v1::command::Argument = original.try_into().unwrap();
    let back: iota_types::transaction::Argument = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

#[test]
fn argument_roundtrip_nested_result() {
    let original = iota_types::transaction::Argument::NestedResult(2, 5);

    let proto: v1::command::Argument = original.try_into().unwrap();
    let back: iota_types::transaction::Argument = (&proto).try_into().unwrap();

    assert_eq!(original, back);
}

// ---------------------------------------------------------------------------
// BcsData
// ---------------------------------------------------------------------------

#[test]
fn bcs_data_roundtrip_vec() {
    let original: Vec<u8> = vec![1, 2, 3, 4, 5];

    let proto: v1::bcs::BcsData = original.clone().into();
    let back: Vec<u8> = (&proto).into();

    assert_eq!(original, back);
}

#[test]
fn bcs_data_roundtrip_bytes() {
    let original = prost::bytes::Bytes::from_static(&[10, 20, 30]);

    let proto: v1::bcs::BcsData = original.clone().into();
    let back: prost::bytes::Bytes = (&proto).into();

    assert_eq!(original, back);
}

#[test]
fn bcs_data_roundtrip_empty() {
    let original: Vec<u8> = vec![];

    let proto: v1::bcs::BcsData = original.clone().into();
    let back: Vec<u8> = (&proto).into();

    assert_eq!(original, back);
}
