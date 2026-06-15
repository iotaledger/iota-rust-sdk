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
//! This lives in `iota-sdk` (not `iota-sdk-move-types`) because it only
//! needs the GraphQL client and core types — keeping the GraphQL/`tokio`
//! dependencies out of `iota-sdk-move-types` lets that crate run its tests
//! under wasm.
//!
//! Invocation:
//!
//! ```bash
//! cargo run -p iota-sdk --example capture_move_type_fixtures
//! # optional: pick a different network (defaults to mainnet)
//! IOTA_NETWORK=testnet cargo run …
//! IOTA_NETWORK=devnet cargo run …
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
        // Wraps an inner `Versioned`; `RandomInner` lives off the
        // `Versioned`'s UID (not the wrapper's), so we skip it for now —
        // capturing it would need a nested dynamic-field walk.
        source: Source::ObjectId("0x8"),
    },
    Fixture {
        file: "deny_list",
        source: Source::ObjectId("0x403"),
    },
    // -- Validator / staking auxiliary -------------------------------------
    Fixture {
        file: "timelocked_staked_iota",
        // mainnet `0x3::timelocked_staking::TimelockedStakedIota`
        source: Source::ObjectId(
            "0x000526665a4137147b17cf4ea84d6df809ef28b0586b6c497423ce866b57dabc",
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

    // The fixtures belong to the sibling `iota-sdk-move-types` crate; this
    // example only lives in `iota-sdk` for its GraphQL/`tokio` dependencies.
    let out_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../iota-sdk-move-types/tests/fixtures");
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
    }
}
