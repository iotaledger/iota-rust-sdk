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
use iota_types::ObjectId;

#[test]
fn object_id_is_an_address() {
    assert_eq!(ObjectId::type_tag().to_string(), "address");
}

#[test]
fn id() {
    assert_eq!(ID::type_tag().to_string(), "0x2::object::ID");
}

#[test]
fn dynamic_object_field_wrapper() {
    assert_eq!(
        Wrapper::<ID>::type_tag().to_string(),
        "0x2::dynamic_object_field::Wrapper<0x2::object::ID>"
    );
}

#[test]
fn deny_list_keys() {
    assert_eq!(
        ConfigKey::type_tag().to_string(),
        "0x2::deny_list::ConfigKey"
    );
    assert_eq!(
        AddressKey::type_tag().to_string(),
        "0x2::deny_list::AddressKey"
    );
    assert_eq!(
        GlobalPauseKey::type_tag().to_string(),
        "0x2::deny_list::GlobalPauseKey"
    );
}

#[test]
fn config_setting() {
    assert_eq!(
        Setting::<bool>::type_tag().to_string(),
        "0x2::config::Setting<bool>"
    );
}
