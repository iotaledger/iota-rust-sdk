// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, initAsync, TransactionDigest } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newTestnet();
const digest = TransactionDigest.fromBase58(
  "3wN9oLKfvCjCd7uFW1D6fp1uSEsD3wJ2cU61YULNKzFh",
);

const signedTransaction = await client.transaction(digest);
console.log(`Signed Transaction: \`${signedTransaction}\`\n`);

const transactionEffects = await client.transactionEffects(digest);
console.log(`Transaction Effects: \`${transactionEffects}\`\n`);

const transactionDataEffects = await client.transactionDataEffects(digest);
console.log(`Transaction Data Effects: \`${transactionDataEffects}\`\n`);
