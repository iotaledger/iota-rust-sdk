// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, ObjectId, TransactionsFilter } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();

  const sharedObjId = ObjectId.fromHex(
    "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec",
  );

  const transactions = await client.transactions(
    TransactionsFilter.create({ inputObject: sharedObjId }),
  );

  for (const transaction of transactions.data) {
    console.log("Digest:", transaction.transaction.digest().toBase58());
  }
}

main();
