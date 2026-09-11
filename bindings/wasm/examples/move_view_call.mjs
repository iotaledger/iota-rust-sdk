// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  MoveViewArg,
  ObjectId,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

// The `view_demo` package published on testnet.
const PACKAGE =
  "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4";
// A shared `view_demo::shop::Shop` created when the package was published.
const SHOP =
  "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20";

const client = GraphQlClient.newTestnet();

// === Example 1: moveViewCall() with typed arguments (primitives) ===
console.log(
  "=== Example 1: moveViewCall() with typed arguments (primitives) ===\n",
);

const priceArgs = [MoveViewArg.u64(100n), MoveViewArg.u64(25n)];
const result = await client.moveViewCall(
  `${PACKAGE}::shop::discounted_price`,
  undefined,
  priceArgs,
);

if (result.error) {
  console.log("Error:", result.error);
} else if (result.results !== null) {
  console.log("Results:", result.results);
} else {
  console.log("No results");
}

// === Example 2: moveViewCallJson() with JSON values (primitives) ===
console.log(
  "\n=== Example 2: moveViewCallJson() with JSON values (primitives) ===\n",
);

// `u64` is passed as a string so large values survive JSON.
const jsonResult = await client.moveViewCallJson(
  `${PACKAGE}::shop::discounted_price`,
  undefined,
  ['"100"', '"25"'],
);

if (jsonResult.error) {
  console.log("JSON Error:", jsonResult.error);
} else if (jsonResult.results !== null) {
  console.log("JSON Results:", jsonResult.results);
} else {
  console.log("No JSON results");
}

// === Example 3: moveViewCall() with typed arguments (shared object) ===
console.log(
  "\n=== Example 3: moveViewCall() with typed arguments (shared object) ===\n",
);

const shopArgs = [
  MoveViewArg.objectId(ObjectId.fromHex(SHOP)),
  MoveViewArg.u64(1n),
];
const shopResult = await client.moveViewCall(
  `${PACKAGE}::shop::sale_at`,
  undefined,
  shopArgs,
);

if (shopResult.error) {
  console.log("Shop Error:", shopResult.error);
} else if (shopResult.results !== null) {
  console.log("Shop Results:", shopResult.results);
} else {
  console.log("No shop results");
}

// === Example 4: moveViewCallJson() with JSON values (shared object) ===
console.log(
  "\n=== Example 4: moveViewCallJson() with JSON values (shared object) ===\n",
);

const shopJsonResult = await client.moveViewCallJson(
  `${PACKAGE}::shop::sale_at`,
  undefined,
  [`"${SHOP}"`, '"1"'],
);

if (shopJsonResult.error) {
  console.log("Shop JSON Error:", shopJsonResult.error);
} else if (shopJsonResult.results !== null) {
  console.log("Shop JSON Results:", shopJsonResult.results);
} else {
  console.log("No shop JSON results");
}

// === Example 5: moveViewCallBuilder() ===
console.log("\n=== Example 5: moveViewCallBuilder() ===\n");

const builder = client
  .moveViewCallBuilder(ObjectId.fromHex(PACKAGE), "shop", "sale_at")
  .arguments([
    MoveViewArg.objectId(ObjectId.fromHex(SHOP)),
    MoveViewArg.u64(1n),
  ]);

console.log("Builder Results:", await builder.execute());
