// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  Identifier,
  PtbArgument,
  TypeTag,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const sender = Address.fromHex(
  "0x71b4b4f171b4355ff691b7c470579cf1a926f96f724e5f9a30efc4b5f75d085e",
);

const builder = client.transactionBuilder(sender);

const addr1 = Address.fromHex(
  "0xde49ea53fbadee67d3e35a097cdbea210b659676fc680a0b0c5f11d0763d375e",
);
const addr2 = Address.fromHex(
  "0xe512234aa4ef6184c52663f09612b68f040dd0c45de037d96190a071ca5525b3",
);

builder.moveCall(
  Address.framework(),
  new Identifier("vec_map"),
  new Identifier("from_keys_values"),
  [
    PtbArgument.addressVec([addr1, addr2]),
    PtbArgument.u64Vec([10000000n, 20000000n]),
  ],
  [TypeTag.newAddress(), TypeTag.newU64()],
);

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to call generic Move function: ${res.error}`);
}

console.log("Successfully called generic Move function!");
