// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  PtbArgument,
  TransactionBuilder,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const myAddress = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);

const validators = await client.activeValidators();
if (validators.data.length === 0) {
  throw new Error("no validators found");
}
const validator = validators.data[0];

console.log("Staking to validator", validator.name ?? "with no name");

const builder = new TransactionBuilder(myAddress).withClient(client);
builder.stake(PtbArgument.u64(1000000000n), validator.address);

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to stake: ${res.error}`);
}

console.log("Stake dry run was successful!");
