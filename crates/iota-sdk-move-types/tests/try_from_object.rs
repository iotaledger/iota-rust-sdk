// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Type-tag validation tests for the generic `try_from_object`
//! constructors.
//!
//! The coin marker `T` is phantom, so the BCS contents of e.g. a
//! `BasicOutput<IOTA>` and a `BasicOutput<FOO>` are byte-identical — the
//! type tag is the only place the coin type is recorded. These tests wrap
//! the committed fixtures in synthetic [`Object`]s with correct and forged
//! tags and assert that the constructors accept the former and reject the
//! latter with [`FromObjectError::WrongType`].

#![cfg(feature = "serde")]
use iota_sdk_move_types::{
    FromObjectError, MoveType,
    framework::{coin::CoinMetadata, iota::IOTA},
    stardust::{alias_output::AliasOutput, basic_output::BasicOutput, nft_output::NftOutput},
};
use iota_types::{
    Digest, MoveObjectType, MoveStruct, Object, ObjectData, Owner, StructTag, TypeTag, Version,
};
/// Wrap fixture contents in an [`Object`] carrying the given type tag.
fn object_with_tag(tag: &str, contents: &[u8]) -> Object {
    let tag: StructTag = tag.parse().expect("valid struct tag");
    let move_struct = MoveStruct::new(
        MoveObjectType::new(tag),
        Version::from_u64(1),
        contents.to_vec(),
    )
    .expect("fixture contents start with an ObjectId");
    Object::new(
        ObjectData::Struct(move_struct),
        Owner::Immutable,
        Digest::ZERO,
        0,
    )
}

fn foo_type_tag() -> TypeTag {
    "0x123::foo::FOO".parse().unwrap()
}

/// Stand-in for a third-party coin marker; represents `0x123::foo::FOO`.
#[derive(serde::Deserialize)]
struct Foo;

impl MoveType for Foo {
    fn type_tag() -> TypeTag {
        foo_type_tag()
    }
}

macro_rules! coin_marker_validation_tests {
    ($mod_name:ident, $ty:ident, $tag_base:literal, $fixture:literal) => {
        mod $mod_name {
            // An explicit (non-glob) import may shadow the prelude's `test`
            // attribute; a glob from `super` may not, so this can't live at
            // the file level.
            #[cfg(target_arch = "wasm32")]
            use wasm_bindgen_test::wasm_bindgen_test as test;

            use super::*;

            const IOTA_TAG: &str = concat!($tag_base, "<0x2::iota::IOTA>");
            const FOO_TAG: &str = concat!($tag_base, "<0x123::foo::FOO>");
            const FIXTURE: &[u8] = include_bytes!($fixture);

            #[test]
            fn accepts_matching_coin_marker() {
                let object = object_with_tag(IOTA_TAG, FIXTURE);
                $ty::<IOTA>::try_from_object(&object).expect("tag matches T");
            }

            #[test]
            fn rejects_mismatched_coin_marker() {
                // Same bytes, different coin in the tag — without the
                // type-param check this would silently decode as `<IOTA>`.
                let object = object_with_tag(FOO_TAG, FIXTURE);
                assert!(matches!(
                    $ty::<IOTA>::try_from_object(&object),
                    Err(FromObjectError::WrongType)
                ));
            }

            #[test]
            fn marker_trait_works_for_custom_coins() {
                let object = object_with_tag(FOO_TAG, FIXTURE);
                $ty::<Foo>::try_from_object(&object).expect("tag matches custom T");
            }

            #[test]
            fn runtime_tag_escape_hatch() {
                let object = object_with_tag(FOO_TAG, FIXTURE);
                $ty::<IOTA>::try_from_object_with_type(&object, &foo_type_tag())
                    .expect("explicit tag matches");
                assert!(matches!(
                    $ty::<IOTA>::try_from_object_with_type(&object, &IOTA::type_tag()),
                    Err(FromObjectError::WrongType)
                ));
            }
        }
    };
}

coin_marker_validation_tests!(
    basic_output,
    BasicOutput,
    "0x107a::basic_output::BasicOutput",
    "fixtures/basic_output_iota.bcs"
);

coin_marker_validation_tests!(
    nft_output,
    NftOutput,
    "0x107a::nft_output::NftOutput",
    "fixtures/nft_output_iota.bcs"
);

coin_marker_validation_tests!(
    alias_output,
    AliasOutput,
    "0x107a::alias_output::AliasOutput",
    "fixtures/alias_output_iota.bcs"
);

coin_marker_validation_tests!(
    coin_metadata,
    CoinMetadata,
    "0x2::coin::CoinMetadata",
    "fixtures/coin_metadata_iota.bcs"
);
