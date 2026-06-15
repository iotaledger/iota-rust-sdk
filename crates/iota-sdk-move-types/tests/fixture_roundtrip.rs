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

/// Emits one `#[test]` per `Type => fixture` row. The fixture name doubles
/// as the test function name, and the bytes are loaded from
/// `fixtures/<fixture>.bcs`.
macro_rules! fixture_roundtrip {
    ($($ty:ty => $fixture:ident),* $(,)?) => {
        $(
            #[test]
            fn $fixture() {
                roundtrip::<$ty>(include_bytes!(concat!(
                    "fixtures/",
                    stringify!($fixture),
                    ".bcs"
                )));
            }
        )*
    };
}

fixture_roundtrip! {
    IotaSystemState => iota_system_state,
    IotaSystemStateV2 => iota_system_state_inner_v2,
    Clock => clock,
    StakedIota => staked_iota,
    Coin<IOTA> => coin_iota,
    CoinMetadata<IOTA> => coin_metadata_iota,
    Nft => nft,
    BasicOutput<IOTA> => basic_output_iota,
    NftOutput<IOTA> => nft_output_iota,
    Alias => alias,
    AliasOutput<IOTA> => alias_output_iota,
    Random => random,
    DenyList => deny_list,
    TimelockedStakedIota => timelocked_staked_iota,
    UpgradeCap => upgrade_cap,
    TreasuryCap<IOTA> => treasury_cap,
    DenyCapV1<IOTA> => deny_cap_v1,
    RegulatedCoinMetadata<IOTA> => regulated_coin_metadata,
    CoinManager<IOTA> => coin_manager,
    CoinManagerTreasuryCap<IOTA> => coin_manager_treasury_cap,
    CoinManagerMetadataCap<IOTA> => coin_manager_metadata_cap,
    Token<IOTA> => token,
    TokenPolicy<IOTA> => token_policy,
    TokenPolicyCap<IOTA> => token_policy_cap,
    TimeLock<Balance<IOTA>> => timelock_balance_iota,
    RandomInner => random_inner,
    Config<ConfigWriteCap> => deny_list_config,
    UnverifiedValidatorOperationCap => validator_operation_cap,
    Field<u64, PoolTokenExchangeRate> => field_pool_token_exchange_rate,
    Field<ID, validator_wrapper::Validator> => field_validator_wrapper,
    Publisher => publisher,
    Display<IOTA> => display,
    Kiosk => kiosk,
    KioskOwnerCap => kiosk_owner_cap,
    Item => kiosk_item,
    Listing => kiosk_listing,
    Lock => kiosk_lock,
    TransferPolicy<IOTA> => transfer_policy,
    TransferPolicyCap<IOTA> => transfer_policy_cap,
    StakingRequestEvent => staking_request_event,
    UnstakingRequestEvent => unstaking_request_event,
    ValidatorEpochInfoEventV1 => validator_epoch_info_event_v1,
    ValidatorJoinEvent => validator_join_event,
    ValidatorLeaveEvent => validator_leave_event,
    CommitteeValidatorJoinEvent => committee_validator_join_event,
    CommitteeValidatorLeaveEvent => committee_validator_leave_event,
    SystemEpochInfoEventV2 => system_epoch_info_event_v2,
    DisplayCreated<IOTA> => display_created,
    VersionUpdated<IOTA> => version_updated,
    TransferPolicyCreated<IOTA> => transfer_policy_created,
    TokenPolicyCreated<IOTA> => token_policy_created,
    CoinManaged => coin_managed,
}
