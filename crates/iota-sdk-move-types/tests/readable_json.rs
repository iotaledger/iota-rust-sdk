// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "serde")]
use iota_sdk_move_types::{
    iota_framework::vec_map::{Entry, VecMap},
    iota_system::iota_system_state_inner::IotaSystemStateV2,
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn validator_set_u64_collections_serialize_as_strings_in_json() {
    let mut state: IotaSystemStateV2 =
        bcs::from_bytes(include_bytes!("fixtures/iota_system_state_inner_v2.bcs")).unwrap();
    state.validators.committee_members = vec![u64::MAX];
    state.validators.pending_removals = vec![u64::MAX];
    state.validators.at_risk_validators =
        VecMap::new(vec![Entry::new(iota_types::Address::ZERO, u64::MAX)]);

    let json = serde_json::to_value(&state).unwrap();
    let max = serde_json::json!("18446744073709551615");
    let validators = &json["validators"];
    assert_eq!(validators["committee_members"][0], max);
    assert_eq!(validators["pending_removals"][0], max);
    assert_eq!(
        validators["at_risk_validators"]["contents"][0]["value"],
        max
    );
    assert_eq!(
        serde_json::from_value::<IotaSystemStateV2>(json).unwrap(),
        state
    );
}
