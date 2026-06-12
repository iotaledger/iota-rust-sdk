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
    framework::{
        balance::Balance,
        clock::Clock,
        coin::{Coin, CoinMetadata},
        iota::IOTA,
        kiosk::{Kiosk, KioskOwnerCap},
        object::{ID, UID},
        package::{Publisher, UpgradeCap},
        timelock::TimeLock,
    },
    iota_system::iota_system::IotaSystemState,
    stardust::{alias_output::AliasOutput, basic_output::BasicOutput, nft_output::NftOutput},
    std::ascii,
};
use iota_types::{
    Address, Digest, MoveObjectType, MoveStruct, Object, ObjectData, ObjectId, Owner, StructTag,
    TypeTag, Version,
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

coin_marker_validation_tests!(coin, Coin, "0x2::coin::Coin", "fixtures/coin_iota.bcs");

/// Tag-validation tests for non-generic mirrors: the constructor must
/// accept the type's own tag and reject any other.
macro_rules! object_tag_validation_tests {
    ($mod_name:ident, $ty:ty, $tag:literal, $fixture:literal) => {
        mod $mod_name {
            // An explicit (non-glob) import may shadow the prelude's `test`
            // attribute; a glob from `super` may not, so this can't live at
            // the file level.
            #[cfg(target_arch = "wasm32")]
            use wasm_bindgen_test::wasm_bindgen_test as test;

            use super::*;

            const FIXTURE: &[u8] = include_bytes!($fixture);

            #[test]
            fn accepts_matching_tag() {
                let object = object_with_tag($tag, FIXTURE);
                <$ty>::try_from_object(&object).expect("tag matches");
            }

            #[test]
            fn rejects_mismatched_tag() {
                let object = object_with_tag("0x123::foo::FOO", FIXTURE);
                assert!(matches!(
                    <$ty>::try_from_object(&object),
                    Err(FromObjectError::WrongType)
                ));
            }
        }
    };
}

object_tag_validation_tests!(clock, Clock, "0x2::clock::Clock", "fixtures/clock.bcs");

object_tag_validation_tests!(
    upgrade_cap,
    UpgradeCap,
    "0x2::package::UpgradeCap",
    "fixtures/upgrade_cap.bcs"
);

object_tag_validation_tests!(
    iota_system_state,
    IotaSystemState,
    "0x3::iota_system::IotaSystemState",
    "fixtures/iota_system_state.bcs"
);

/// Mirrors without a committed fixture are exercised with synthetic
/// values: encode a hand-built value, wrap it in an object with the
/// matching (or a forged) tag, and decode it back.
mod synthetic {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    fn synthetic_object<T: serde::Serialize>(tag: &str, value: &T) -> Object {
        object_with_tag(tag, &bcs::to_bytes(value).expect("encode synthetic value"))
    }

    #[test]
    fn publisher_roundtrip_and_tag_check() {
        let value = Publisher {
            id: UID::new(ObjectId::ZERO),
            package: ascii::String::new(b"deadbeef".to_vec()),
            module_name: ascii::String::new(b"my_module".to_vec()),
        };
        let object = synthetic_object("0x2::package::Publisher", &value);
        let decoded = Publisher::try_from_object(&object).expect("tag matches");
        assert_eq!(decoded, value);

        let object = synthetic_object("0x2::package::UpgradeCap", &value);
        assert!(matches!(
            Publisher::try_from_object(&object),
            Err(FromObjectError::WrongType)
        ));
    }

    #[test]
    fn kiosk_roundtrip_and_tag_check() {
        let value = Kiosk {
            id: UID::new(ObjectId::ZERO),
            profits: Balance::new(7),
            owner: Address::ZERO,
            item_count: 3,
        };
        let object = synthetic_object("0x2::kiosk::Kiosk", &value);
        let decoded = Kiosk::try_from_object(&object).expect("tag matches");
        assert_eq!(decoded, value);

        let object = synthetic_object("0x2::kiosk::KioskOwnerCap", &value);
        assert!(matches!(
            Kiosk::try_from_object(&object),
            Err(FromObjectError::WrongType)
        ));
    }

    #[test]
    fn kiosk_owner_cap_roundtrip_and_tag_check() {
        let value = KioskOwnerCap {
            id: UID::new(ObjectId::ZERO),
            r#for: ID::new(ObjectId::ZERO),
        };
        let object = synthetic_object("0x2::kiosk::KioskOwnerCap", &value);
        let decoded = KioskOwnerCap::try_from_object(&object).expect("tag matches");
        assert_eq!(decoded, value);

        let object = synthetic_object("0x2::kiosk::Kiosk", &value);
        assert!(matches!(
            KioskOwnerCap::try_from_object(&object),
            Err(FromObjectError::WrongType)
        ));
    }

    #[test]
    fn timelocked_balance_validates_locked_type() {
        let value = TimeLock::new(
            UID::new(ObjectId::ZERO),
            Balance::<IOTA>::new(100),
            42,
            None,
        );

        let object = synthetic_object(
            "0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>",
            &value,
        );
        let decoded = TimeLock::<Balance<IOTA>>::try_from_object(&object).expect("tag matches");
        assert_eq!(decoded, value);

        // Same bytes labeled as a different coin's balance must be
        // rejected for `Balance<IOTA>` …
        let object = synthetic_object(
            "0x2::timelock::TimeLock<0x2::balance::Balance<0x123::foo::FOO>>",
            &value,
        );
        assert!(matches!(
            TimeLock::<Balance<IOTA>>::try_from_object(&object),
            Err(FromObjectError::WrongType)
        ));

        // … while `Balance<Foo>` composes the matching tag through the
        // blanket `MoveType` impl on `Balance<T>`.
        TimeLock::<Balance<Foo>>::try_from_object(&object).expect("composed tag matches");
    }
}
