// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  TransactionBuilder,
  PtbArgument,
  ObjectFilter,
  StructTag,
} from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const stakedIotas = await client.objects(
    ObjectFilter.create({ typeTag: String(StructTag.newStakedIota()) }),
  );
  if (stakedIotas.data.length === 0) {
    throw new Error("no staked iotas found");
  }
  const stakedIota = stakedIotas.data[0];

  const builder = new TransactionBuilder(stakedIota.owner().asAddress()).withClient(client);

  builder.unstake(PtbArgument.objectId(stakedIota.objectId()));

  const res = await builder.dryRun();
  if (res.error !== undefined) {
    throw new Error(`Failed to unstake: ${res.error}`);
  }

  console.log("Unstake dry run was successful!");
}

main();
