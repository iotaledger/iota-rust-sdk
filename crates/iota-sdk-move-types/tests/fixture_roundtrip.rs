// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! BCS roundtrip tests against real on-chain bytes.
//!
//! Each test loads a fixture captured from mainnet by the
//! `capture_move_type_fixtures` example in the `iota-sdk` crate, decodes
//! it into the corresponding hand-curated Move-mirror type, re-encodes,
//! and asserts the bytes are bit-identical. A wire-shape mismatch
//! (renamed field, wrong type, reordered fields, missing variant) fails
//! the assertion.
//!
//! To refresh the fixtures against current chain state, run:
//!
//! ```bash
//! cargo run -p iota-sdk --example capture_move_type_fixtures
//! ```

#![cfg(feature = "serde")]
use iota_sdk_move_types::{
    framework::{
        clock::Clock,
        coin::{Coin, CoinMetadata},
        deny_list::DenyList,
        iota::IOTA,
        package::UpgradeCap,
        random::Random,
    },
    iota_system::{
        iota_system::IotaSystemState, iota_system_state_inner::IotaSystemStateV2,
        staking_pool::StakedIota, timelocked_staking::TimelockedStakedIota,
    },
    stardust::{
        alias::Alias, alias_output::AliasOutput, basic_output::BasicOutput, nft::Nft,
        nft_output::NftOutput,
    },
};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

fn roundtrip<T>(bytes: &[u8])
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let value: T = bcs::from_bytes(bytes).expect("decode fixture");
    let encoded = bcs::to_bytes(&value).expect("encode value");
    assert_eq!(bytes, encoded.as_slice(), "wire-shape mismatch");
}

#[test]
fn iota_system_state() {
    roundtrip::<IotaSystemState>(include_bytes!("fixtures/iota_system_state.bcs"));
}

#[test]
fn iota_system_state_inner_v2() {
    roundtrip::<IotaSystemStateV2>(include_bytes!("fixtures/iota_system_state_inner_v2.bcs"));
}

#[test]
fn clock() {
    roundtrip::<Clock>(include_bytes!("fixtures/clock.bcs"));
}

#[test]
fn staked_iota() {
    roundtrip::<StakedIota>(include_bytes!("fixtures/staked_iota.bcs"));
}

#[test]
fn coin_iota() {
    roundtrip::<Coin<IOTA>>(include_bytes!("fixtures/coin_iota.bcs"));
}

#[test]
fn coin_metadata_iota() {
    roundtrip::<CoinMetadata<IOTA>>(include_bytes!("fixtures/coin_metadata_iota.bcs"));
}

#[test]
fn nft() {
    roundtrip::<Nft>(include_bytes!("fixtures/nft.bcs"));
}

#[test]
fn basic_output_iota() {
    roundtrip::<BasicOutput<IOTA>>(include_bytes!("fixtures/basic_output_iota.bcs"));
}

#[test]
fn nft_output_iota() {
    roundtrip::<NftOutput<IOTA>>(include_bytes!("fixtures/nft_output_iota.bcs"));
}

#[test]
fn alias() {
    roundtrip::<Alias>(include_bytes!("fixtures/alias.bcs"));
}

#[test]
fn alias_output_iota() {
    roundtrip::<AliasOutput<IOTA>>(include_bytes!("fixtures/alias_output_iota.bcs"));
}

#[test]
fn random() {
    roundtrip::<Random>(include_bytes!("fixtures/random.bcs"));
}

#[test]
fn deny_list() {
    roundtrip::<DenyList>(include_bytes!("fixtures/deny_list.bcs"));
}

#[test]
fn timelocked_staked_iota() {
    roundtrip::<TimelockedStakedIota>(include_bytes!("fixtures/timelocked_staked_iota.bcs"));
}

#[test]
fn upgrade_cap() {
    roundtrip::<UpgradeCap>(include_bytes!("fixtures/upgrade_cap.bcs"));
}
