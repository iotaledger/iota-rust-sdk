// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { Address, GraphQlClient, PtbArgument, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const sender = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);

const coin0 = PtbArgument.objectIdFromHex(
  "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
);
const coin1 = PtbArgument.objectIdFromHex(
  "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db",
);

const builder = client.transactionBuilder(sender);
builder.mergeCoins(coin0, [coin1]);

const txn = await builder.finish();
console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to merge coins: ${res.error}`);
}
console.log("Merge coins dry run was successful!");
