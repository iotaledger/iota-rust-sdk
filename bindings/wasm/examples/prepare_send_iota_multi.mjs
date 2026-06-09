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

// Recipients and amounts
const recipients = [
  [
    "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
    1000000000n,
  ],
  [
    "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
    2000000000n,
  ],
];

// Extract amounts from recipients
const amounts = recipients.map(([, amount]) => PtbArgument.u64(amount));
const labels = recipients.map((_, i) => `coin${i}`);

const builder = new TransactionBuilder(sender).withClient(client);

builder.splitCoins(PtbArgument.objectId(coinId), amounts, labels);
// Transfer each split coin to the corresponding recipient
for (let i = 0; i < recipients.length; i++) {
  builder.transferObjects(Address.fromHex(recipients[i][0]), [
    PtbArgument.assigned(labels[i]),
  ]);
}

const txn = await builder.finish();
console.log("Signing Digest:", txn.signingDigestHex());
console.log("Txn Bytes:", txn.toBase64());

const res = await client.dryRunTx(txn);
if (res.error) {
  throw new Error(`Failed to send IOTA: ${res.error}`);
}
console.log("Send IOTA dry run was successful!");
