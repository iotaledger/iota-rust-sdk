// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  Address,
  GraphQlClient,
  ObjectId,
  PtbArgument,
  TransactionBuilder,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const sender = Address.fromHex(
  "0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151",
);
const coinId = ObjectId.fromHex(
  "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc",
);

const builder = new TransactionBuilder(sender).withClient(client);

builder
  .splitCoins(
    PtbArgument.objectId(coinId),
    [PtbArgument.u64(1000n), PtbArgument.u64(2000n), PtbArgument.u64(3000n)],
    ["coin1", "coin2", "coin3"],
  )
  .transferObjects(sender, [
    PtbArgument.assigned("coin1"),
    PtbArgument.assigned("coin2"),
    PtbArgument.assigned("coin3"),
  ]);

const txn = await builder.finish();
console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await builder.dryRun();
if (res.error) {
  throw new Error(`Failed to split coins: ${res.error}`);
}
console.log("Split coins dry run was successful!");
