// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  Address,
  TransactionBuilder,
  Identifier,
  PtbArgument,
} from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const sender = Address.fromHex(
    "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
  );

  const builder = new TransactionBuilder(sender).withClient(client);

  const packageAddr = Address.std();
  const moduleName = new Identifier("u64");
  const functionName = new Identifier("max");

  builder.moveCall(
    packageAddr,
    moduleName,
    functionName,
    [PtbArgument.u64(0n), PtbArgument.u64(1000n)],
    [],
    // Assign a name to the result of this command
    ["res0"],
  );

  builder.moveCall(
    packageAddr,
    moduleName,
    functionName,
    [PtbArgument.u64(1000n), PtbArgument.u64(2000n)],
    [],
    // Assign a name to the result of this command
    ["res1"],
  );

  builder.splitCoins(
    PtbArgument.gas(),
    // Use the assigned results of previous commands as arguments
    [PtbArgument.assigned("res0"), PtbArgument.assigned("res1")],
    // For nested results, a tuple or vec can be used to assign them
    ["coin0", "coin1"],
  );

  // Use assigned results as arguments
  builder.transferObjects(sender, [PtbArgument.assigned("coin0"), PtbArgument.assigned("coin1")]);

  const txn = await builder.finish();

  console.log("Signing Digest:", txn.signingDigestHex());
  console.log("Txn Bytes:", txn.toBase64());

  const res = await client.dryRunTx(txn, false);
  if (res.error !== undefined) {
    throw new Error(`Failed to send tx: ${res.error}`);
  }

  console.log("Tx dry run was successful!");
}

main();
