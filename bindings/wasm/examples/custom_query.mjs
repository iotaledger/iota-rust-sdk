// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query, initAsync } from "@iota/sdk-wasm";

await initAsync();

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

// Query the data for the last known epoch. Note that id variable is not set, so
// last epoch data will be returned.
const queryEpochData = Query.new({ queryText: queryEpochDataStr });
console.log(await client.runQuery(queryEpochData));

// Query the data for epoch 1.
const queryEpochDataWithVariables = Query.new({
  queryText: queryEpochDataStr,
  variables: JSON.stringify({ id: 1 }),
});
console.log(await client.runQuery(queryEpochDataWithVariables));

// When the query has no variables, just omit them.
const queryChainId = Query.new({
  queryText: "query MyQuery { chainIdentifier }",
});
console.log(await client.runQuery(queryChainId));
