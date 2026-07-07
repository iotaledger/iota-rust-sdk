// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, TransactionsFilter, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const transactions = await client.transactions(
  TransactionsFilter.new({ function: "0x3::iota_system::request_add_stake" }),
);
for (const transaction of transactions.data) {
  console.log("Digest:", transaction.transaction.digest().toBase58());
}
