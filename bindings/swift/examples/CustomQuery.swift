// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import IotaSDK

@main
struct CustomQueryExample {
  static func main() async throws {
    let client = GraphQlClient.newTestnet()

    let queryEpochDataStr = """
      query MyQuery($id: UInt53) {
          epoch(id: $id) {
              epochId
              referenceGasPrice
              totalGasFees
              totalCheckpoints
              totalTransactions
          }
      }
      """
    let queryEpochData = Query(queryText: queryEpochDataStr)
    let res = try await client.runQuery(query: queryEpochData)
    print(res)

    let variables = "{\"id\": 1}"
    let queryEpochDataWithVariables = Query(queryText: queryEpochDataStr, variables: variables)
    let res2 = try await client.runQuery(query: queryEpochDataWithVariables)
    print(res2)

    let queryChainIdStr = """
      query MyQuery {
          chainIdentifier
      }
      """
    let queryChainId = Query(queryText: queryChainIdStr)
    let res3 = try await client.runQuery(query: queryChainId)
    print(res3)
  }
}
