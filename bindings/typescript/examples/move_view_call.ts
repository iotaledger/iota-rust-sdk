// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: https://github.com/iotaledger/iota-rust-sdk/issues/1000

import { GraphQlClient, MoveViewArg } from "../lib";

async function main() {
  const client = GraphQlClient.newDevnet();

  // ===========================================================================
  // Example 1: Using moveViewCall() with typed arguments (blake2b256)
  // ===========================================================================
  console.log("=== Example 1: moveViewCall() with typed arguments (blake2b256) ===");
  console.log();

  // Using typed arguments: an array of u8 values using the u8Vec constructor
  const hashArgs = [MoveViewArg.u8Vec(new Uint8Array([0, 1, 2]))];

  const result = await client.moveViewCall("0x2::hash::blake2b256", undefined, hashArgs);

  if (result.error !== undefined) {
    console.log("Error:", result.error);
  } else if (result.results !== undefined) {
    console.log("Results:", result.results);
  } else {
    console.log("No results");
  }

  // ===========================================================================
  // Example 2: Using moveViewCallJson() with JSON values (blake2b256)
  // ===========================================================================
  console.log();
  console.log("=== Example 2: moveViewCallJson() with JSON values (blake2b256) ===");
  console.log();

  const jsonResult = await client.moveViewCallJson("0x2::hash::blake2b256", undefined, ["[0, 1, 2]"]);

  if (jsonResult.error !== undefined) {
    console.log("JSON Error:", jsonResult.error);
  } else if (jsonResult.results !== undefined) {
    console.log("JSON Results:", jsonResult.results);
  } else {
    console.log("No JSON results");
  }
}

main();
