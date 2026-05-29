// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query } from "./_iota_sdk.mjs";

const client = GraphQlClient.newTestnet();

const queryEpochDataStr = `
  query MyQuery($id: UInt53) {
    epoch(id: $id) {
      epochId
      referenceGasPrice
      totalGasFees
      totalCheckpoints
      totalTransactions
    }
  }
`;

const queryEpochData = new Query({ query: queryEpochDataStr });
console.log(await client.runQuery(queryEpochData));

const queryEpochDataWithVariables = new Query({
  query: queryEpochDataStr,
  variables: JSON.stringify({ id: 1 }),
});
console.log(await client.runQuery(queryEpochDataWithVariables));

const queryChainId = new Query({ query: "query MyQuery { chainIdentifier }" });
console.log(await client.runQuery(queryChainId));
