// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query, uniffiInitAsync } from "@iota/sdk-wasm";

await uniffiInitAsync();

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

const queryEpochData = Query.new({ query: queryEpochDataStr });
console.log(await client.runQuery(queryEpochData));

const queryEpochDataWithVariables = Query.new({
  query: queryEpochDataStr,
  variables: JSON.stringify({ id: 1 }),
});
console.log(await client.runQuery(queryEpochDataWithVariables));

const queryChainId = Query.new({ query: "query MyQuery { chainIdentifier }" });
console.log(await client.runQuery(queryChainId));
