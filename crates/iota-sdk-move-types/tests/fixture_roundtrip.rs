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
        balance::Balance,
        clock::Clock,
        coin::{Coin, CoinMetadata, DenyCapV1, RegulatedCoinMetadata, TreasuryCap},
        coin_manager::{CoinManaged, CoinManager, CoinManagerMetadataCap, CoinManagerTreasuryCap},
        config::Config,
        deny_list::{ConfigWriteCap, DenyList},
        display::{Display, DisplayCreated, VersionUpdated},
        dynamic_field::Field,
        iota::IOTA,
        kiosk::{Item, Kiosk, KioskOwnerCap, Listing, Lock},
        object::ID,
        package::{Publisher, UpgradeCap},
        random::{Random, RandomInner},
        timelock::TimeLock,
        token::{Token, TokenPolicy, TokenPolicyCap, TokenPolicyCreated},
        transfer_policy::{TransferPolicy, TransferPolicyCap, TransferPolicyCreated},
    },
    iota_system::{
        iota_system::IotaSystemState,
        iota_system_state_inner::{IotaSystemStateV2, SystemEpochInfoEventV2},
        staking_pool::{PoolTokenExchangeRate, StakedIota},
        timelocked_staking::TimelockedStakedIota,
        validator::{StakingRequestEvent, UnstakingRequestEvent},
        validator_cap::UnverifiedValidatorOperationCap,
        validator_set::{
            CommitteeValidatorJoinEvent, CommitteeValidatorLeaveEvent, ValidatorEpochInfoEventV1,
            ValidatorJoinEvent, ValidatorLeaveEvent,
        },
        validator_wrapper,
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

// For the generic mirrors below, the on-chain type parameter is some
// arbitrary third-party type (recorded only in the object's type tag, the
// pinned ID of which lives in the capture script). The parameter is
// phantom — it never affects the BCS bytes — so `IOTA` stands in for it.

#[test]
fn treasury_cap() {
    roundtrip::<TreasuryCap<IOTA>>(include_bytes!("fixtures/treasury_cap.bcs"));
}

#[test]
fn deny_cap_v1() {
    roundtrip::<DenyCapV1<IOTA>>(include_bytes!("fixtures/deny_cap_v1.bcs"));
}

#[test]
fn regulated_coin_metadata() {
    roundtrip::<RegulatedCoinMetadata<IOTA>>(include_bytes!(
        "fixtures/regulated_coin_metadata.bcs"
    ));
}

#[test]
fn coin_manager() {
    roundtrip::<CoinManager<IOTA>>(include_bytes!("fixtures/coin_manager.bcs"));
}

#[test]
fn coin_manager_treasury_cap() {
    roundtrip::<CoinManagerTreasuryCap<IOTA>>(include_bytes!(
        "fixtures/coin_manager_treasury_cap.bcs"
    ));
}

#[test]
fn coin_manager_metadata_cap() {
    roundtrip::<CoinManagerMetadataCap<IOTA>>(include_bytes!(
        "fixtures/coin_manager_metadata_cap.bcs"
    ));
}

#[test]
fn token() {
    roundtrip::<Token<IOTA>>(include_bytes!("fixtures/token.bcs"));
}

#[test]
fn token_policy() {
    roundtrip::<TokenPolicy<IOTA>>(include_bytes!("fixtures/token_policy.bcs"));
}

#[test]
fn token_policy_cap() {
    roundtrip::<TokenPolicyCap<IOTA>>(include_bytes!("fixtures/token_policy_cap.bcs"));
}

#[test]
fn timelock_balance_iota() {
    roundtrip::<TimeLock<Balance<IOTA>>>(include_bytes!("fixtures/timelock_balance_iota.bcs"));
}

#[test]
fn random_inner() {
    roundtrip::<RandomInner>(include_bytes!("fixtures/random_inner.bcs"));
}

#[test]
fn deny_list_config() {
    roundtrip::<Config<ConfigWriteCap>>(include_bytes!("fixtures/deny_list_config.bcs"));
}

#[test]
fn validator_operation_cap() {
    roundtrip::<UnverifiedValidatorOperationCap>(include_bytes!(
        "fixtures/validator_operation_cap.bcs"
    ));
}

#[test]
fn field_pool_token_exchange_rate() {
    roundtrip::<Field<u64, PoolTokenExchangeRate>>(include_bytes!(
        "fixtures/field_pool_token_exchange_rate.bcs"
    ));
}

#[test]
fn field_validator_wrapper() {
    roundtrip::<Field<ID, validator_wrapper::Validator>>(include_bytes!(
        "fixtures/field_validator_wrapper.bcs"
    ));
}

#[test]
fn publisher() {
    roundtrip::<Publisher>(include_bytes!("fixtures/publisher.bcs"));
}

#[test]
fn display() {
    roundtrip::<Display<IOTA>>(include_bytes!("fixtures/display.bcs"));
}

#[test]
fn kiosk() {
    roundtrip::<Kiosk>(include_bytes!("fixtures/kiosk.bcs"));
}

#[test]
fn kiosk_owner_cap() {
    roundtrip::<KioskOwnerCap>(include_bytes!("fixtures/kiosk_owner_cap.bcs"));
}

// `Item`/`Listing`/`Lock` exist only as dynamic-field name structs on a
// `Kiosk`; the fixtures hold the real on-chain name bytes.

#[test]
fn kiosk_item() {
    roundtrip::<Item>(include_bytes!("fixtures/kiosk_item.bcs"));
}

#[test]
fn kiosk_listing() {
    roundtrip::<Listing>(include_bytes!("fixtures/kiosk_listing.bcs"));
}

#[test]
fn kiosk_lock() {
    roundtrip::<Lock>(include_bytes!("fixtures/kiosk_lock.bcs"));
}

#[test]
fn transfer_policy() {
    roundtrip::<TransferPolicy<IOTA>>(include_bytes!("fixtures/transfer_policy.bcs"));
}

#[test]
fn transfer_policy_cap() {
    roundtrip::<TransferPolicyCap<IOTA>>(include_bytes!("fixtures/transfer_policy_cap.bcs"));
}

// -- Events ----------------------------------------------------------------

#[test]
fn staking_request_event() {
    roundtrip::<StakingRequestEvent>(include_bytes!("fixtures/staking_request_event.bcs"));
}

#[test]
fn unstaking_request_event() {
    roundtrip::<UnstakingRequestEvent>(include_bytes!("fixtures/unstaking_request_event.bcs"));
}

#[test]
fn validator_epoch_info_event_v1() {
    roundtrip::<ValidatorEpochInfoEventV1>(include_bytes!(
        "fixtures/validator_epoch_info_event_v1.bcs"
    ));
}

#[test]
fn validator_join_event() {
    roundtrip::<ValidatorJoinEvent>(include_bytes!("fixtures/validator_join_event.bcs"));
}

#[test]
fn validator_leave_event() {
    roundtrip::<ValidatorLeaveEvent>(include_bytes!("fixtures/validator_leave_event.bcs"));
}

#[test]
fn committee_validator_join_event() {
    roundtrip::<CommitteeValidatorJoinEvent>(include_bytes!(
        "fixtures/committee_validator_join_event.bcs"
    ));
}

#[test]
fn committee_validator_leave_event() {
    roundtrip::<CommitteeValidatorLeaveEvent>(include_bytes!(
        "fixtures/committee_validator_leave_event.bcs"
    ));
}

#[test]
fn system_epoch_info_event_v2() {
    roundtrip::<SystemEpochInfoEventV2>(include_bytes!("fixtures/system_epoch_info_event_v2.bcs"));
}

#[test]
fn display_created() {
    roundtrip::<DisplayCreated<IOTA>>(include_bytes!("fixtures/display_created.bcs"));
}

#[test]
fn version_updated() {
    roundtrip::<VersionUpdated<IOTA>>(include_bytes!("fixtures/version_updated.bcs"));
}

#[test]
fn transfer_policy_created() {
    roundtrip::<TransferPolicyCreated<IOTA>>(include_bytes!(
        "fixtures/transfer_policy_created.bcs"
    ));
}

#[test]
fn token_policy_created() {
    roundtrip::<TokenPolicyCreated<IOTA>>(include_bytes!("fixtures/token_policy_created.bcs"));
}

#[test]
fn coin_managed() {
    roundtrip::<CoinManaged>(include_bytes!("fixtures/coin_managed.bcs"));
}
