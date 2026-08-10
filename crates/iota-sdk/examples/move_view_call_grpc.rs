// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

//! Calling Move view functions over gRPC.
//!
//! The point of the batched form is that the server runs each call in its own
//! transaction, so the calls do not share a fate. This example sends two calls
//! where the second one cannot work, and shows the first one still coming back
//! with its return values.
//!
//! There are two distinct ways a call can not produce a value, and they land in
//! different places:
//! - the node refuses to run it (unknown function, wrong argument count) — that
//!   call's slot holds an `Err`;
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

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new_testnet()?;

    // A single call, with arguments as JSON.
    let outputs = client
        .view_function_call(
            "0x2::hash::blake2b256",
            &[],
            &[json!([0, 1, 2])],
            ViewFunctionCallReadMask::default(),
        )
        .await?;

    match outputs.body().return_values() {
        Some(values) => println!("blake2b256 returned {} value(s)", values.outputs.len()),
        None => println!("blake2b256 aborted: {:?}", outputs.body().execution_error()),
    }

    // Two calls in one request: the first is the same working call, the second
    // names a function that does not exist.
    let results = client
        .view_function_calls(
            vec![
                view_call("0x2::hash::blake2b256", json!([0, 1, 2])),
                view_call("0x2::hash::not_a_function", json!([0, 1, 2])),
            ],
            ViewFunctionCallReadMask::default(),
        )
        .await?;

    for (call, result) in ["blake2b256", "not_a_function"].iter().zip(results.body()) {
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

fn view_call(fq_function_name: &str, arg: serde_json::Value) -> ViewFunctionCallItem {
    ViewFunctionCallItem::default()
        .with_fq_function_name(fq_function_name)
        .with_inputs(vec![
            InputArgument::default().with_json(json_to_prost(&arg)),
        ])
}
