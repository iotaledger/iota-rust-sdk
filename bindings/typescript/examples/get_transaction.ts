// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Digest } from "../lib";

async function main() {
  const client = GraphQlClient.newTestnet();
  const digest = Digest.fromBase58("CY14gCcLcVuSMN9Hq7Ya6vEhBAzSzciNw47togWXJAZ8");

  const signedTransaction = await client.transaction(digest);
  console.log(`Signed Transaction: \`${signedTransaction}\`\n`);

  const transactionEffects = await client.transactionEffects(digest);
  console.log(`Transaction Effects: \`${transactionEffects}\`\n`);

  const transactionDataEffects = await client.transactionDataEffects(digest);
  console.log(`Transaction Data Effects: \`${transactionDataEffects}\`\n`);
}

main();
