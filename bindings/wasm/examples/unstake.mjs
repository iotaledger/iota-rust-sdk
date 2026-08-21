// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  ObjectFilter,
  PtbArgument,
  StructTag,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const owner = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);

const stakedIotas = await client.objects(
  ObjectFilter.new({ typeTag: String(StructTag.newStakedIota()), owner }),
);
if (stakedIotas.data.length === 0) {
  throw new Error("no staked iotas found");
}
const stakedIota = stakedIotas.data[0];

const builder = client.transactionBuilder(stakedIota.owner().asAddress());

builder.unstake(PtbArgument.objectId(stakedIota.id()));

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to unstake: ${res.error}`);
}

console.log("Unstake dry run was successful!");
