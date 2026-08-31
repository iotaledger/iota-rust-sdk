// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Calling Move view functions over gRPC.
//!
//! Only a function declared with the `#[view]` attribute can be called this
//! way, so the example uses the `view_demo` package published on testnet.
//! Repoint the constants below to run it against a package of your own.
//!
//! The point of the batched form is that the server runs each call in its own
//! transaction, so the calls do not share a fate. This example sends three
//! calls where only the first one produces a value, and shows it still coming
//! back with its return values.
//!
//! There are two distinct ways a call can not produce a value, and they land in
//! different places:
//! - the node refuses to run it (not a `#[view]` function, unknown function,
//!   wrong argument count) — that call's slot holds an `Err`;
//! - it runs and aborts — that call's slot holds `Ok`, and the abort is read
//!   off `execution_error()`.

use eyre::Result;
use iota_sdk::{
    grpc_client::{Client, read_mask_fields::ViewFunctionCallReadMask},
    grpc_types::{
        proto::json_to_prost,
        v1::{command::InputArgument, transaction_execution_service::ViewFunctionCallItem},
    },
};
use serde_json::json;

/// The `view_demo` package published on testnet, as in the `move_view_call`
/// example.
const PACKAGE: &str = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";
/// A shared `view_demo::shop::Shop` created when the package was published.
const SHOP: &str = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20";

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    // A single call, with arguments as JSON.
    let outputs = client
        .view_function_call(
            &format!("{PACKAGE}::shop::discounted_price"),
            &[],
            &[json!(100), json!(25)],
            ViewFunctionCallReadMask::default(),
        )
        .await?;

    match outputs.body().return_values() {
        Some(values) => println!(
            "discounted_price returned {} value(s)",
            values.outputs.len()
        ),
        None => println!(
            "discounted_price aborted: {:?}",
            outputs.body().execution_error()
        ),
    }

    // Three calls in one request: the call from above, the same function with a
    // discount over 100% so that it aborts, and a function that is not declared
    // `#[view]`.
    let results = client
        .view_function_calls(
            vec![
                view_call(
                    &format!("{PACKAGE}::shop::discounted_price"),
                    vec![json!(100), json!(25)],
                ),
                view_call(
                    &format!("{PACKAGE}::shop::discounted_price"),
                    vec![json!(100), json!(200)],
                ),
                view_call(
                    &format!("{PACKAGE}::shop::record_sale"),
                    vec![json!(SHOP), json!(5)],
                ),
            ],
            ViewFunctionCallReadMask::default(),
        )
        .await?;

    for (call, result) in ["priced", "over-discounted", "record_sale"]
        .iter()
        .zip(results.body())
    {
        match result {
            Ok(outputs) => match outputs.return_values() {
                Some(values) => println!("{call}: returned {} value(s)", values.outputs.len()),
                None => println!("{call}: aborted ({:?})", outputs.execution_error()),
            },
            Err(e) => println!("{call}: rejected by the node ({e})"),
        }
    }

    Ok(())
}

fn view_call(fq_function_name: &str, args: Vec<serde_json::Value>) -> ViewFunctionCallItem {
    ViewFunctionCallItem::default()
        .with_fq_function_name(fq_function_name)
        .with_inputs(
            args.iter()
                .map(|arg| InputArgument::default().with_json(json_to_prost(arg)))
                .collect(),
        )
}
