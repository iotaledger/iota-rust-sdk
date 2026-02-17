// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Milestone scaffold for issue #808 (iota-dca):
//! - deterministic treasury allocation planning
//! - transaction-intent modeling for later builder integration
//! - typed IDs using SDK primitives (`Address`, `ObjectId`)
//!
//! This is intentionally execution-safe and offline: it does not broadcast,
//! query network state, or require key material.

use std::str::FromStr;

use eyre::{Result, ensure};
use iota_sdk::types::{Address, ObjectId};

#[derive(Debug, Clone, Copy)]
struct AllocationRule {
    /// Destination account for treasury flow.
    destination: Address,
    /// Percentage in basis points (10_000 = 100%).
    bps: u16,
}

#[derive(Debug, Clone)]
enum TreasuryIntent {
    SendIota {
        from: Address,
        to: Address,
        amount_mist: u64,
    },
    Stake {
        from: Address,
        validator: Address,
        amount_mist: u64,
        gas_coin: ObjectId,
    },
}

fn compute_allocations(total_mist: u64, rules: &[AllocationRule]) -> Result<Vec<(Address, u64)>> {
    let total_bps: u32 = rules.iter().map(|r| u32::from(r.bps)).sum();
    ensure!(
        total_bps == 10_000,
        "allocation rules must sum to exactly 10_000 bps"
    );

    // Round down each leg and send remainder to the final leg for conservation.
    let mut remaining = total_mist;
    let mut out = Vec::with_capacity(rules.len());

    for (idx, rule) in rules.iter().enumerate() {
        let amount = if idx == rules.len() - 1 {
            remaining
        } else {
            (u128::from(total_mist) * u128::from(rule.bps) / 10_000u128) as u64
        };

        remaining = remaining.saturating_sub(amount);
        out.push((rule.destination, amount));
    }

    Ok(out)
}

fn build_treasury_intents(
    treasury: Address,
    gas_coin: ObjectId,
    allocations: &[(Address, u64)],
) -> Vec<TreasuryIntent> {
    allocations
        .iter()
        .enumerate()
        .map(|(idx, (to, amount_mist))| {
            if idx == 0 {
                // First leg demonstrates staking intent, subsequent legs are transfers.
                TreasuryIntent::Stake {
                    from: treasury,
                    validator: *to,
                    amount_mist: *amount_mist,
                    gas_coin,
                }
            } else {
                TreasuryIntent::SendIota {
                    from: treasury,
                    to: *to,
                    amount_mist: *amount_mist,
                }
            }
        })
        .collect()
}

fn main() -> Result<()> {
    let treasury =
        Address::from_str("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")?;
    let validator =
        Address::from_str("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")?;
    let operations =
        Address::from_str("0x7f4d1d19d8f53d6854cb8e487ad32f03a96f3e448f53165f9fdf5f78c8c35f11")?;
    let reserves =
        Address::from_str("0x9f2212992c3af6f9392f7ff65c3f85a67613918f4f6779ddff0f4d0b4f8a7f88")?;

    let rules = vec![
        AllocationRule {
            destination: validator,
            bps: 5_000,
        },
        AllocationRule {
            destination: operations,
            bps: 3_000,
        },
        AllocationRule {
            destination: reserves,
            bps: 2_000,
        },
    ];

    let total_mist = 25_000_000_000u64;
    let allocations = compute_allocations(total_mist, &rules)?;

    let gas_coin =
        ObjectId::from_str("0x6c72ec6c7f3def4be0f13250bbebf4da3a6ad6abc82ff5a58a7f8d2a8ea01234")?;

    let intents = build_treasury_intents(treasury, gas_coin, &allocations);

    println!("DCA treasury scaffold generated {} intents", intents.len());
    for intent in intents {
        match intent {
            TreasuryIntent::SendIota {
                from,
                to,
                amount_mist,
            } => println!("SEND from={from} to={to} amount={amount_mist} mist"),
            TreasuryIntent::Stake {
                from,
                validator,
                amount_mist,
                gas_coin,
            } => println!(
                "STAKE from={from} validator={validator} amount={amount_mist} mist gas_coin={gas_coin}"
            ),
        }
    }

    Ok(())
}
