// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import { GraphQlClient, Query } from "../lib";

async function main() {
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
  const queryEpochData = Query.create({ query: queryEpochDataStr });
  let res = await client.runQuery(queryEpochData);
  console.log(res);

  const variables = { id: 1 };
  const queryEpochDataWithVariables = Query.create({
    query: queryEpochDataStr,
    variables: JSON.stringify(variables),
  });
  res = await client.runQuery(queryEpochDataWithVariables);
  console.log(res);

  const queryChainIdStr = `
    query MyQuery {
        chainIdentifier
    }
    `;
  const queryChainId = Query.create({ query: queryChainIdStr });
  res = await client.runQuery(queryChainId);
  console.log(res);
}

main();
