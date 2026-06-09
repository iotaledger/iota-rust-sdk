// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: https://github.com/iotaledger/iota-rust-sdk/issues/1000

import { GraphQlClient, MoveViewArg, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newDevnet();

// === Example 1: moveViewCall() with typed arguments (blake2b256) ===
console.log(
  "=== Example 1: moveViewCall() with typed arguments (blake2b256) ===\n",
);

const hashArgs = [MoveViewArg.u8Vec(new Uint8Array([0, 1, 2]))];
const result = await client.moveViewCall(
  "0x2::hash::blake2b256",
  undefined,
  hashArgs,
);

if (result.error) {
  console.log("Error:", result.error);
} else if (result.results !== null) {
  console.log("Results:", result.results);
} else {
  console.log("No results");
}

// === Example 2: moveViewCallJson() with JSON values (blake2b256) ===
console.log(
  "\n=== Example 2: moveViewCallJson() with JSON values (blake2b256) ===\n",
);

const jsonResult = await client.moveViewCallJson(
  "0x2::hash::blake2b256",
  undefined,
  ["[0, 1, 2]"],
);

if (jsonResult.error) {
  console.log("JSON Error:", jsonResult.error);
} else if (jsonResult.results !== null) {
  console.log("JSON Results:", jsonResult.results);
} else {
  console.log("No JSON results");
}
