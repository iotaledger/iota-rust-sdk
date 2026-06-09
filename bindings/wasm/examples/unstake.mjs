// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  ObjectFilter,
  PtbArgument,
  StructTag,
  TransactionBuilder,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const stakedIotas = await client.objects(
  ObjectFilter.new({ typeTag: String(StructTag.newStakedIota()) }),
);
if (stakedIotas.data.length === 0) {
  throw new Error("no staked iotas found");
}
const stakedIota = stakedIotas.data[0];

const builder = new TransactionBuilder(
  stakedIota.owner().asAddress(),
).withClient(client);

builder.unstake(PtbArgument.objectId(stakedIota.id()));

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to unstake: ${res.error}`);
}

console.log("Unstake dry run was successful!");
