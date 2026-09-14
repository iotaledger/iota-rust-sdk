// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Fetch all transactions for an address (outgoing and incoming).
//
// The GraphQL service does not have a single filter that returns transactions
// in both directions for an address. To get the full history, run two queries
// and merge the results.

import {
  Address,
  GraphQlClient,
  initAsync,
  TransactionsFilter,
} from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();
const address = Address.fromHex(
  "0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa",
);

const outgoing = await client.transactions(
  new TransactionsFilter().withSentAddress(address),
);
const incoming = await client.transactions(
  new TransactionsFilter().withRecvAddress(address),
);

console.log(`Transactions for ${address.toHex()}`);

console.log(`\nOutgoing (sent by address): ${outgoing.data.length}`);
for (const tx of outgoing.data) {
  console.log(`  - ${tx.transaction.digest().toBase58()}`);
}

console.log(`\nIncoming (received by address): ${incoming.data.length}`);
for (const tx of incoming.data) {
  console.log(`  - ${tx.transaction.digest().toBase58()}`);
}
