// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Address, TransactionBuilder, Identifier, PtbArgument } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const sender = Address.fromHex(
    "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900",
  );
  const sponsor = Address.fromHex(
    "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
  );

  const builder = new TransactionBuilder(sender).withClient(client);

  const packageAddr = Address.std();
  const moduleName = new Identifier("u8");
  const functionName = new Identifier("max");

  builder.moveCall(packageAddr, moduleName, functionName, [
    PtbArgument.u8(0),
    PtbArgument.u8(1),
  ], [], []);

  builder.sponsor(sponsor);

  const txn = await builder.finish();

  console.log("Signing Digest:", txn.signingDigestHex());
  console.log("Txn Bytes:", txn.toBase64());

  const res = await client.dryRunTx(txn);
  if (res.error !== undefined) {
    throw new Error(`Failed to send gas sponsor tx: ${res.error}`);
  }

  console.log("Gas sponsor tx dry run was successful!");
}

main();
