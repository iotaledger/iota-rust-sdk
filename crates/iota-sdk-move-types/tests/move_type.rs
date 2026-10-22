// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! The type tags of the mirrors the IOTA node uses as dynamic field keys.
//! Dynamic field IDs are hashed from the key's type tag, so these must not
//! change.

use iota_sdk_move_types::{
    MoveType,
    iota_framework::{
        config::Setting,
        deny_list::{AddressKey, ConfigKey, GlobalPauseKey},
        dynamic_object_field::Wrapper,
        object::ID,
    },
};
use iota_types::{Address, Identifier, ObjectId, StructTag, TypeTag};

fn framework_tag(module: &'static str, name: &'static str, type_params: Vec<TypeTag>) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag::new(
        Address::FRAMEWORK,
        Identifier::from_static(module),
        Identifier::from_static(name),
        type_params,
    )))
}

#[test]
fn object_id_is_an_address() {
    assert_eq!(ObjectId::type_tag(), TypeTag::Address);
}

#[test]
fn id() {
    assert_eq!(ID::type_tag(), framework_tag("object", "ID", vec![]));
}

#[test]
fn dynamic_object_field_wrapper() {
    assert_eq!(
        Wrapper::<ID>::type_tag(),
        framework_tag(
            "dynamic_object_field",
            "Wrapper",
            vec![framework_tag("object", "ID", vec![])]
        )
    );
}

#[test]
fn deny_list_keys() {
    assert_eq!(
        ConfigKey::type_tag(),
        framework_tag("deny_list", "ConfigKey", vec![])
    );
    assert_eq!(
        AddressKey::type_tag(),
        framework_tag("deny_list", "AddressKey", vec![])
    );
    assert_eq!(
        GlobalPauseKey::type_tag(),
        framework_tag("deny_list", "GlobalPauseKey", vec![])
    );
}

#[test]
fn config_setting() {
    assert_eq!(
        Setting::<bool>::type_tag(),
        framework_tag("config", "Setting", vec![TypeTag::Bool])
    );
}
