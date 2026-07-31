// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, initAsync } from "@iota/sdk-wasm";

await initAsync();

const client = GraphQlClient.newLocalnet();

const transactions = await client.transactions();
if (transactions.data.length === 0) {
  throw new Error("No transactions found");
}
const digest = transactions.data[0].transaction.digest();

const signedTransaction = await client.transaction(digest);
console.log(`Signed Transaction: \`${signedTransaction}\`\n`);

const transactionEffects = await client.transactionEffects(digest);
console.log(`Transaction Effects: \`${transactionEffects}\`\n`);

const transactionDataEffects = await client.transactionDataEffects(digest);
console.log(`Transaction Data Effects: \`${transactionDataEffects}\`\n`);
