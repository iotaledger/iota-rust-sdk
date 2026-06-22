// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
  GraphQlClient,
  ObjectId,
  TransactionsFilter,
  initAsync,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();

const sharedObjId = ObjectId.fromHex(
  "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec",
);

const transactions = await client.transactions(
  TransactionsFilter.new({ inputObject: sharedObjId }),
);

for (const transaction of transactions.data) {
  console.log("Digest:", transaction.transaction.digest().toBase58());
}
