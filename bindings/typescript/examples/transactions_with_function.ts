// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, TransactionsFilter } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();
  const transactions = await client.transactions(
    TransactionsFilter.create({ function: "0x3::iota_system::request_add_stake" }),
  );
  for (const transaction of transactions.data) {
    console.log("Digest:", transaction.transaction.digest().toBase58());
  }
}

main();
