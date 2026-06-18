// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Capture real on-chain BCS fixtures for the Move types mirrored by
//! `iota-sdk-move-types`.
//!
//! For each entry in [`FIXTURES`], the script queries a live IOTA
//! GraphQL endpoint, fetches the pinned object, extracts the raw BCS
//! bytes of the inner Move struct, and writes them to
//! `crates/iota-sdk-move-types/tests/fixtures/<name>.bcs`.
//!
//! This is a standalone package (rather than an example of
//! `iota-sdk-move-types`) so its GraphQL/`tokio` dependencies stay out of
//! `iota-sdk-move-types`' own dependency graph — that crate runs its tests
//! under wasm, where `tokio`/`reqwest` don't build.
//!
//! Invocation:
//!
//! ```bash
//! cargo run -p capture-move-type-fixtures
//! # optional: pick a different network (defaults to mainnet)
//! IOTA_NETWORK=testnet cargo run -p capture-move-type-fixtures
//! IOTA_NETWORK=devnet cargo run -p capture-move-type-fixtures
//! ```
//!
//! # Capture strategies
//!
//! - [`Source::ObjectId`]: fetch a specific object by its known address. The
//!   default for almost all fixtures — every entry carries a hard-pinned
//!   mainnet object ID so re-runs produce the same bytes byte-for-byte. When a
//!   pinned object is spent / deleted, capture for that fixture fails loudly;
//!   the operator picks a fresh ID (often via [`Source::TypeFilter`] locally)
//!   and commits the new pin alongside the new fixture.
//! - [`Source::TypeFilter`]: ask the GraphQL endpoint for any object matching
//!   the given fully-qualified type tag and take the first one returned. Useful
//!   for *discovery* (finding a candidate to pin), but inherently
//!   non-deterministic across runs so we don't leave this in `FIXTURES`
//!   permanently.
//! - [`Source::DynamicField`]: walk a dynamic field of a parent object. Used
//!   for the versioned inner state (`IotaSystemStateInnerV2` sits as a dynamic
//!   field of the 0x5 wrapper, keyed by version number).
//! - [`Source::Event`]: fetch the BCS contents of an event, pinned by the
//!   digest of the transaction that emitted it plus its fully-qualified type.
//!   Events are immutable history, so unlike object pins these can never be
//!   spent or deleted — re-runs always produce the same bytes.
//! - [`Source::DynamicFieldName`]: capture the BCS of a dynamic field's *name*
//!   struct (not its value). Used for the small key types that only ever exist
//!   as dynamic-field names — e.g. `kiosk::Item`/`Listing`/`Lock`, which key
//!   the items, listings and locks stored on a `Kiosk`. Takes the first field
//!   on the parent whose name type matches, so the bytes are stable as long as
//!   the parent's dynamic fields are unchanged.
//!
//! Run this manually whenever you want to refresh the fixtures
//! against current chain state — there is no automated CI job that
//! re-runs it.

use std::path::PathBuf;

use iota_sdk::{
    graphql_client::Client,
    types::{Address, ObjectId, TypeTag},
};

/// What to capture and where to put it.
struct Fixture {
    /// Output file name (without extension). Written to
    /// `crates/iota-sdk-move-types/tests/fixtures/<file>.bcs`.
    file: &'static str,
    /// How to find an instance.
    source: Source,
}

enum Source {
    /// Fetch the singleton object at the given address.
    ObjectId(&'static str),
    /// Find any object whose top-level type tag matches the given
    /// fully-qualified Move type string. *Not used in committed
    /// fixtures* — non-deterministic, only useful locally to find a
    /// candidate to pin.
    TypeFilter(&'static str),
    /// Walk a dynamic field off the given parent.
    ///
    /// `name_bcs` is the BCS-encoded value of the field name (e.g. a
    /// `u64` epoch number, BCS-encoded as little-endian).
    DynamicField {
        parent: &'static str,
        name_type: &'static str,
        name_bcs: &'static [u8],
    },
    /// Fetch the first event of the given fully-qualified type emitted by
    /// the given transaction. Events are immutable once the transaction is
    /// checkpointed, so this pin is deterministic forever.
    Event {
        event_type: &'static str,
        tx_digest: &'static str,
    },
    /// Capture the BCS of the *name* of the first dynamic field on `parent`
    /// whose name type matches `name_type`. Used for key structs that only
    /// live as dynamic-field names (e.g. `kiosk::Item`).
    DynamicFieldName {
        parent: &'static str,
        name_type: &'static str,
    },
}

/// One representative fixture per Move struct we care about. The
/// object IDs below were captured once from mainnet (via
/// `Source::TypeFilter` against the live GraphQL endpoint) and
/// pinned here for byte-for-byte stability across CI runs.
const FIXTURES: &[Fixture] = &[
    // -- System singletons --------------------------------------------------
    Fixture {
        file: "iota_system_state",
        source: Source::ObjectId("0x5"),
    },
    Fixture {
        file: "clock",
        source: Source::ObjectId("0x6"),
    },
    // -- Coin / token --------------------------------------------------------
    Fixture {
        file: "staked_iota",
        // mainnet `0x3::staking_pool::StakedIota`
        source: Source::ObjectId(
            "0x0000008408a8c770c379b2884c3d7e51e93dab4319c8e466c9529d75ba4b73b5",
        ),
    },
    Fixture {
        file: "coin_iota",
        // mainnet `0x2::coin::Coin<0x2::iota::IOTA>`
        source: Source::ObjectId(
            "0x0000013d3dfa797c8f323f3064a69e09a96dfa7f20cb585d3f96c85f92a302ad",
        ),
    },
    Fixture {
        file: "coin_metadata_iota",
        // mainnet `0x2::coin::CoinMetadata<0x2::iota::IOTA>` (frozen singleton)
        source: Source::ObjectId(
            "0xd02db1bb647dfcc94f35b82a14e8bab07661be3e6d4b022bdc7ee63eed0728f8",
        ),
    },
    Fixture {
        file: "treasury_cap",
        // mainnet `0x2::coin::TreasuryCap<…::demo_krill_coin::DEMO_KRILL_COIN>` (shared)
        source: Source::ObjectId(
            "0x0262bcf534e9946e6887382abc00e8efb04bb104e47e9ffe642f7ea1e3d0248f",
        ),
    },
    Fixture {
        file: "deny_cap_v1",
        // mainnet `0x2::coin::DenyCapV1<…::usdt0::USDT0>`
        source: Source::ObjectId(
            "0x1d6a304d5f6349091fc235e63d558477d1b68ccf3aaf28f35d7d3e79fcaeba5c",
        ),
    },
    Fixture {
        file: "regulated_coin_metadata",
        // mainnet `0x2::coin::RegulatedCoinMetadata<…::tln_token::TLN_TOKEN>` (frozen)
        source: Source::ObjectId(
            "0x3910559ffc302c089e245071442735e481cde5aa62bbfa2557e15385ff5c819f",
        ),
    },
    Fixture {
        file: "coin_manager",
        // mainnet `0x2::coin_manager::CoinManager<…::ape::APE>` (shared)
        source: Source::ObjectId(
            "0x009e5db7ee421d05fe652305d77e0cc5eee82c994b836ac89b3bcef876cb6159",
        ),
    },
    Fixture {
        file: "coin_manager_treasury_cap",
        // mainnet `0x2::coin_manager::CoinManagerTreasuryCap<…::ock::OCK>`
        source: Source::ObjectId(
            "0x038eb3a9448aebcb22ed6411f1efb2d2fa84aed4cf413622da921edc136f4571",
        ),
    },
    Fixture {
        file: "coin_manager_metadata_cap",
        // mainnet `0x2::coin_manager::CoinManagerMetadataCap<…::spec_coin::SPEC_COIN>`
        source: Source::ObjectId(
            "0x44bc7586906f63f7ecf9dc729feae69e79f29631f80eea1045191235f49c67b7",
        ),
    },
    Fixture {
        file: "token",
        // mainnet `0x2::token::Token<…::oid_credit::OID_CREDIT>`
        source: Source::ObjectId(
            "0x01700f283c9e3a527ef75445d380752f7ab88fefe105238012f1bd1820e150e9",
        ),
    },
    Fixture {
        file: "token_policy",
        // mainnet `0x2::token::TokenPolicy<…::oid_credit::OID_CREDIT>` (shared)
        source: Source::ObjectId(
            "0x0f5d3e7ff929222c19e164de4116197d67b37e2f8709e6ccc8d68782249c2f26",
        ),
    },
    Fixture {
        file: "token_policy_cap",
        // mainnet `0x2::token::TokenPolicyCap<…::oid_credit::OID_CREDIT>`
        source: Source::ObjectId(
            "0x059ceb5e5825d97c56965165883476491cd9bfcc7140b11f3e69cd5001a59954",
        ),
    },
    // -- Stardust migration objects -----------------------------------------
    Fixture {
        file: "nft",
        source: Source::ObjectId(
            "0x00000000ac1c072073a9faca62ea671a885ff8b1e99f57d3ceb4dd4eadc9f641",
        ),
    },
    Fixture {
        file: "basic_output_iota",
        source: Source::ObjectId(
            "0x0000d3961b9701e3061e98d580d7451b42d975a0af4a9dc3364773252c0f632a",
        ),
    },
    Fixture {
        file: "nft_output_iota",
        source: Source::ObjectId(
            "0x0000c304504584135601b856c143037ad777aa16d49fdfae5e8696c5b72dbb95",
        ),
    },
    Fixture {
        file: "alias",
        source: Source::ObjectId(
            "0x000808a18f03ddeb132fad4955ea7541db7e351c178fcbb24b61a37757b4fc4e",
        ),
    },
    Fixture {
        file: "alias_output_iota",
        source: Source::ObjectId(
            "0x000b06477ae3642b92f0198760652691d9826fa699abd56ed26dd763fc01e32a",
        ),
    },
    Fixture {
        file: "timelock_balance_iota",
        // mainnet `0x2::timelock::TimeLock<0x2::balance::Balance<0x2::iota::IOTA>>`
        // (staking-rewards vesting schedule from the Stardust migration)
        source: Source::ObjectId(
            "0x000012c0de6d9ac34dbe8f022f3afac57c24f76c6845460e58109ed69c3be22d",
        ),
    },
    // -- Versioned inner state (dynamic-field walk) -------------------------
    // The `IotaSystemState` wrapper at 0x5 stores its inner versioned state
    // as a dynamic field keyed by version. V1 was migrated away long ago and
    // no longer exists on chain; V2 is the current state shape.
    Fixture {
        file: "iota_system_state_inner_v2",
        source: Source::DynamicField {
            parent: "0x5",
            name_type: "u64",
            name_bcs: &2u64.to_le_bytes(),
        },
    },
    // -- Other system singletons --------------------------------------------
    // Note: 0x7 (`AuthenticatorState`) is not present on IOTA mainnet —
    // the zkLogin feature it backs is not activated here, so we skip it.
    Fixture {
        file: "random",
        source: Source::ObjectId("0x8"),
    },
    Fixture {
        file: "random_inner",
        // `RandomInner` hangs off the UID of the `Versioned` embedded in
        // the `Random` wrapper at 0x8, keyed by version. Both the UID and
        // the version below are read out of the `random` fixture bytes
        // (offsets 32..64 and 64..72); they only change on a protocol
        // upgrade of the randomness state, in which case capture fails
        // loudly and the pin is refreshed the same way.
        source: Source::DynamicField {
            parent: "0xf036d71864eb9287330110df7475b5b98ba0564c8c69fd5f844d398560c0b41a",
            name_type: "u64",
            name_bcs: &1u64.to_le_bytes(),
        },
    },
    Fixture {
        file: "deny_list",
        source: Source::ObjectId("0x403"),
    },
    Fixture {
        file: "deny_list_config",
        // mainnet `0x2::config::Config<0x2::deny_list::ConfigWriteCap>` —
        // a per-coin-type deny list (v2) config, child object of 0x403.
        source: Source::ObjectId(
            "0x1f4ecb57b09ec861ba44832cd3678f2db21a7ea19ee4bed90286068398048a58",
        ),
    },
    // -- Validator / staking auxiliary -------------------------------------
    Fixture {
        file: "timelocked_staked_iota",
        // mainnet `0x3::timelocked_staking::TimelockedStakedIota`
        source: Source::ObjectId(
            "0x000526665a4137147b17cf4ea84d6df809ef28b0586b6c497423ce866b57dabc",
        ),
    },
    Fixture {
        file: "validator_operation_cap",
        // mainnet `0x3::validator_cap::UnverifiedValidatorOperationCap`
        source: Source::ObjectId(
            "0x004d0b7c639f711a5f7b34298faaca2ff9e69fdc25c994b282e6c6026c6489d0",
        ),
    },
    Fixture {
        file: "field_pool_token_exchange_rate",
        // mainnet `0x2::dynamic_field::Field<u64, 0x3::staking_pool::PoolTokenExchangeRate>`
        // — an entry of a staking pool's exchange-rate table. Exchange
        // rates are append-only per epoch, so the entry is never deleted.
        source: Source::ObjectId(
            "0x000211cf08b3a4dd4c26992afdb88a535395f297170105880cdb079298a35e3f",
        ),
    },
    Fixture {
        file: "field_validator_wrapper",
        // mainnet `0x2::dynamic_field::Field<0x2::object::ID, 0x3::validator_wrapper::Validator>`
        // — an inactive validator entry in the system state's validator table.
        source: Source::ObjectId(
            "0x010634284fa0ffe3061a692e112dcef78f1768bf8631a0a1c1856d42fcf23a4b",
        ),
    },
    // -- Packages ---------------------------------------------------------
    Fixture {
        file: "upgrade_cap",
        // mainnet `0x2::package::UpgradeCap`
        source: Source::ObjectId(
            "0x00339e728b01f73e07c30da31fafc8f72d975cfdd176c5913ff516bd294b47f3",
        ),
    },
    Fixture {
        file: "publisher",
        // mainnet `0x2::package::Publisher`
        source: Source::ObjectId(
            "0x01848d922b4925306197c733766c202c9514b34fa004b1103b5924b4daf9d6b0",
        ),
    },
    Fixture {
        file: "display",
        // mainnet `0x2::display::Display<…::nft_minter::SimpleNFT>`
        source: Source::ObjectId(
            "0x01bd532ee6ce11dfe8520c1134c56b630b20527e7ebcf779ad44c5824fa52508",
        ),
    },
    // -- Kiosk / transfer policy --------------------------------------------
    Fixture {
        file: "kiosk",
        // mainnet `0x2::kiosk::Kiosk` (shared)
        source: Source::ObjectId(
            "0x0020d8bbc4457c230d6aec10ce9113682630fbdeda88bdff6187eaa1b5d6a048",
        ),
    },
    Fixture {
        file: "kiosk_owner_cap",
        // mainnet `0x2::kiosk::KioskOwnerCap`
        source: Source::ObjectId(
            "0x081c9339cc0f8a2a458f85c48d73b57821d6fcfd3037157dacc26120b00f3066",
        ),
    },
    // `Item`/`Listing`/`Lock` only exist as dynamic-field *names* on a
    // `Kiosk`. The parent below is a personal (locked) kiosk holding
    // several NFTs, so its fields are stable across re-runs.
    Fixture {
        file: "kiosk_item",
        source: Source::DynamicFieldName {
            parent: "0x150995b23fe7e5126c84698304d71d1069f372dfb9e73547d1b7dc0153eb81f6",
            name_type: "0x2::kiosk::Item",
        },
    },
    Fixture {
        file: "kiosk_listing",
        source: Source::DynamicFieldName {
            parent: "0x150995b23fe7e5126c84698304d71d1069f372dfb9e73547d1b7dc0153eb81f6",
            name_type: "0x2::kiosk::Listing",
        },
    },
    Fixture {
        file: "kiosk_lock",
        source: Source::DynamicFieldName {
            parent: "0x150995b23fe7e5126c84698304d71d1069f372dfb9e73547d1b7dc0153eb81f6",
            name_type: "0x2::kiosk::Lock",
        },
    },
    Fixture {
        file: "transfer_policy",
        // mainnet `0x2::transfer_policy::TransferPolicy<…>` (shared)
        source: Source::ObjectId(
            "0x012e588fa67529383bc0be142f73dde76a44e1d2bd343574d0fd33acd6a035db",
        ),
    },
    Fixture {
        file: "transfer_policy_cap",
        // mainnet `0x2::transfer_policy::TransferPolicyCap<…>`
        source: Source::ObjectId(
            "0x001aea5785ec9e93a6587421f38f9fa1a5fb06d3f49f46b23253c80ed50e9953",
        ),
    },
    // -- Events ---------------------------------------------------------
    // Pinned by (transaction digest, event type); events are immutable
    // history so these pins can never go stale.
    Fixture {
        file: "staking_request_event",
        source: Source::Event {
            event_type: "0x3::validator::StakingRequestEvent",
            tx_digest: "CLaQs7kJ4SXXqaQvp7h6SmQW5skVfWE7KUiTcgHY6GFD",
        },
    },
    Fixture {
        file: "unstaking_request_event",
        source: Source::Event {
            event_type: "0x3::validator::UnstakingRequestEvent",
            tx_digest: "918HEwyqRizNtEJn6ARNgQVmPXVJh5aJxYQ3TE7fmWg",
        },
    },
    Fixture {
        file: "validator_epoch_info_event_v1",
        source: Source::Event {
            event_type: "0x3::validator_set::ValidatorEpochInfoEventV1",
            tx_digest: "DvsQrzbjgdK6YYH9AhQkfuSZgDbDS6F16LAi16jXrrmk",
        },
    },
    Fixture {
        file: "validator_join_event",
        source: Source::Event {
            event_type: "0x3::validator_set::ValidatorJoinEvent",
            tx_digest: "9AQX2nSzubL7MxQnSgXhaymYxC8dM7ZSEKvcmw2mvy6W",
        },
    },
    Fixture {
        file: "validator_leave_event",
        source: Source::Event {
            event_type: "0x3::validator_set::ValidatorLeaveEvent",
            tx_digest: "DvsQrzbjgdK6YYH9AhQkfuSZgDbDS6F16LAi16jXrrmk",
        },
    },
    Fixture {
        file: "committee_validator_join_event",
        source: Source::Event {
            event_type: "0x3::validator_set::CommitteeValidatorJoinEvent",
            tx_digest: "3xorGzB5dfkZV2FrQTGGpMkQnsRvSKco6wsoUmtb9pWb",
        },
    },
    Fixture {
        file: "committee_validator_leave_event",
        source: Source::Event {
            event_type: "0x3::validator_set::CommitteeValidatorLeaveEvent",
            tx_digest: "DvsQrzbjgdK6YYH9AhQkfuSZgDbDS6F16LAi16jXrrmk",
        },
    },
    // `SystemEpochInfoEventV1` predates the indexed history on mainnet —
    // only V2 (which added `tips_amount`) is emitted on current epochs.
    Fixture {
        file: "system_epoch_info_event_v2",
        source: Source::Event {
            event_type: "0x3::iota_system_state_inner::SystemEpochInfoEventV2",
            tx_digest: "DvsQrzbjgdK6YYH9AhQkfuSZgDbDS6F16LAi16jXrrmk",
        },
    },
    Fixture {
        file: "display_created",
        source: Source::Event {
            event_type: "0x2::display::DisplayCreated<0x2e7abccf796c9075298992a98ce7c07b909be253353d79f274ce835034dbb4a9::tangle_therapy::TangleTherapyNft>",
            tx_digest: "E1ESQfAcq1BsLoe9KYc42eYxsysuWMFAWH99CFAhfszp",
        },
    },
    Fixture {
        file: "version_updated",
        source: Source::Event {
            event_type: "0x2::display::VersionUpdated<0x2e7abccf796c9075298992a98ce7c07b909be253353d79f274ce835034dbb4a9::tangle_therapy::TangleTherapyNft>",
            tx_digest: "E1ESQfAcq1BsLoe9KYc42eYxsysuWMFAWH99CFAhfszp",
        },
    },
    Fixture {
        file: "transfer_policy_created",
        source: Source::Event {
            event_type: "0x2::transfer_policy::TransferPolicyCreated<0x2e7abccf796c9075298992a98ce7c07b909be253353d79f274ce835034dbb4a9::tangle_therapy::TangleTherapyNft>",
            tx_digest: "E1ESQfAcq1BsLoe9KYc42eYxsysuWMFAWH99CFAhfszp",
        },
    },
    Fixture {
        file: "token_policy_created",
        source: Source::Event {
            event_type: "0x2::token::TokenPolicyCreated<0x93da2fbb33fb1a947564f527524e8386bb1518585bf95acd147675404461708b::oid_credit::OID_CREDIT>",
            tx_digest: "2JUVWaHq8bjq2rC6zbnE71brWahZzxx2bKYpZNVDC6oS",
        },
    },
    Fixture {
        file: "coin_managed",
        source: Source::Event {
            event_type: "0x2::coin_manager::CoinManaged",
            tx_digest: "A4dkiMBnbs2CHGmcQ1kbTqjhbLmEk6zvshx6s64DPd2z",
        },
    },
    Fixture {
        file: "per_type_config_created",
        source: Source::Event {
            event_type: "0x2::deny_list::PerTypeConfigCreated",
            tx_digest: "436dyPHXfLADoyawqM1QZtKir3SykmN4neLcpKMHxQ4V",
        },
    },
    // -- Policy rule keys (dynamic-field names) -----------------------------
    // `transfer_policy::RuleKey<T>` / `token::RuleKey<T>` only exist as the
    // *names* of the dynamic fields under which a policy stores its per-rule
    // config. The parents below are shared policies carrying a stable rule.
    Fixture {
        file: "transfer_policy_rule_key",
        // `0x2::transfer_policy::RuleKey<…::kiosk_lock_rule::Rule>` on a
        // shared `TransferPolicy` enforcing a kiosk-lock rule.
        source: Source::DynamicFieldName {
            parent: "0x012e588fa67529383bc0be142f73dde76a44e1d2bd343574d0fd33acd6a035db",
            name_type: "0x2::transfer_policy::RuleKey<0xe49f2f23baf6c88a4c18478ac375033eea1f5609f2be6359b417208ea96f555d::kiosk_lock_rule::Rule>",
        },
    },
    Fixture {
        file: "token_rule_key",
        // `0x2::token::RuleKey<…::allowlist_rule::Allowlist>` on a shared
        // `TokenPolicy` enforcing an allowlist rule.
        source: Source::DynamicFieldName {
            parent: "0xa10b50fb6e9b582eebb2b7b156a68c48489525f26022d6e877f63732292812af",
            name_type: "0x2::token::RuleKey<0x229b368f5086b9030778f54dd123bb2e8debb8da559658f21f4a6fd11083e7d7::allowlist_rule::Allowlist>",
        },
    },
];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let network = std::env::var("IOTA_NETWORK").unwrap_or_else(|_| "mainnet".to_string());
    let client = match network.as_str() {
        "testnet" => Client::new_testnet(),
        "devnet" => Client::new_devnet(),
        "mainnet" => Client::new_mainnet(),
        other => {
            return Err(format!(
                "unknown IOTA_NETWORK={other}; expected one of: testnet, devnet, mainnet"
            )
            .into());
        }
    };

    // Discovery mode: when `IOTA_DISCOVER_TYPE` is set to a fully-qualified
    // Move type tag, find one live object of that type and print its ID so it
    // can be pinned in FIXTURES as a `Source::ObjectId`. This is a local,
    // ad-hoc workflow that writes no fixture file.
    if let Ok(type_str) = std::env::var("IOTA_DISCOVER_TYPE") {
        // The process exits right after, so leaking the single string that the
        // `Source::TypeFilter` borrow needs is harmless.
        let type_str: &'static str = Box::leak(type_str.into_boxed_str());
        let bytes = capture(&client, &Source::TypeFilter(type_str)).await?;
        eprintln!(
            "  ({} bytes; not written — pin the discovered ID above)",
            bytes.len()
        );
        return Ok(());
    }

    // The fixtures belong to `iota-sdk-move-types`; this generator is a
    // standalone package under that crate's `examples/` to keep its
    // GraphQL/`tokio` dependencies out of the crate's own graph.
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    std::fs::create_dir_all(&out_dir)?;

    eprintln!("network: {network}");
    eprintln!("writing fixtures to {}", out_dir.display());
    eprintln!();

    let mut failures = 0;
    for fixture in FIXTURES {
        let path = out_dir.join(format!("{}.bcs", fixture.file));
        match capture(&client, &fixture.source).await {
            Ok(bytes) => {
                std::fs::write(&path, &bytes)?;
                eprintln!(
                    "  {:32} {:>6} bytes  →  {}",
                    fixture.file,
                    bytes.len(),
                    path.display()
                );
            }
            Err(e) => {
                failures += 1;
                eprintln!("  {:32} FAILED: {e}", fixture.file);
            }
        }
    }

    eprintln!();
    if failures > 0 {
        eprintln!(
            "{failures} of {} fixtures failed to capture; a pinned object may have been spent/deleted",
            FIXTURES.len()
        );
        std::process::exit(1);
    }

    eprintln!("captured {} fixtures", FIXTURES.len());
    Ok(())
}

/// Resolve a [`Source`] into the raw BCS bytes of the Move struct
/// contents.
async fn capture(
    client: &Client,
    source: &Source,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>> {
    match source {
        Source::TypeFilter(type_str) => {
            let filter = iota_sdk::graphql_client::query_types::ObjectFilter {
                type_: Some((*type_str).to_string()),
                owner: None,
                object_ids: None,
            };
            let page = client
                .objects(
                    filter,
                    iota_sdk::graphql_client::PaginationFilter::default(),
                )
                .await?;
            let object = page
                .data()
                .first()
                .ok_or_else(|| format!("no objects of type `{type_str}` on this network"))?;
            // Print the discovered ID so an operator can copy-paste it
            // into FIXTURES as a `Source::ObjectId` pin.
            eprintln!("    └─ discovered: {}", object.id());
            let move_struct = object
                .as_struct_opt()
                .ok_or("object is not a Move struct")?;
            Ok(move_struct.contents().to_vec())
        }
        Source::ObjectId(id_str) => {
            let id: ObjectId = id_str.parse()?;
            let object = client
                .object(id, None)
                .await?
                .ok_or_else(|| format!("object `{id_str}` not found on this network"))?;
            let move_struct = object
                .as_struct_opt()
                .ok_or("object is not a Move struct")?;
            Ok(move_struct.contents().to_vec())
        }
        Source::Event {
            event_type,
            tx_digest,
        } => {
            use base64ct::Encoding as _;
            let filter = iota_sdk::graphql_client::query_types::EventFilter {
                event_type: Some((*event_type).to_string()),
                transaction_digest: Some((*tx_digest).to_string()),
                ..Default::default()
            };
            let page = client
                .events(
                    filter,
                    iota_sdk::graphql_client::PaginationFilter::default(),
                )
                .await?;
            let event = page
                .data()
                .first()
                .ok_or_else(|| format!("no `{event_type}` event in transaction `{tx_digest}`"))?;
            Ok(base64ct::Base64::decode_vec(&event.bcs.0)?)
        }
        Source::DynamicField {
            parent,
            name_type,
            name_bcs,
        } => {
            let parent_addr: Address = parent.parse::<ObjectId>()?.into();
            let type_tag: TypeTag = name_type.parse()?;
            let df = client
                .dynamic_field(
                    parent_addr,
                    type_tag,
                    iota_sdk::graphql_client::BcsName(name_bcs.to_vec()),
                )
                .await?
                .ok_or_else(|| format!("dynamic field `{name_type}` on `{parent}` not found"))?;
            let value = df
                .value
                .ok_or("dynamic field has no value (was it removed?)")?;
            Ok(value.bcs)
        }
        Source::DynamicFieldName { parent, name_type } => {
            let parent_addr: Address = parent.parse::<ObjectId>()?.into();
            let want: TypeTag = name_type.parse()?;
            let page = client
                .dynamic_fields(
                    parent_addr,
                    iota_sdk::graphql_client::PaginationFilter::default(),
                )
                .await?;
            let df = page
                .data()
                .iter()
                .find(|df| df.name.type_ == want)
                .ok_or_else(|| {
                    format!("no dynamic field of name type `{name_type}` on `{parent}`")
                })?;
            Ok(df.name.bcs.clone())
        }
    }
}
