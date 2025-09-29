// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.Query
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

fun main() = runBlocking {
    val client = GraphQlClient.newDevnet()

    val queryEpochDataStr =
            """
        query MyQuery(${'$'}id: UInt53) {
            epoch(id: ${'$'}id) {
                epochId
                referenceGasPrice
                totalGasFees
                totalCheckpoints
                totalTransactions
            }
        }
    """.trimIndent()

    val queryEpochData = Query(queryEpochDataStr)
    val res1 = client.runQuery(queryEpochData)
    println(res1)

    val variables = mapOf("id" to 1)
    val queryEpochDataWithVariables = Query(queryEpochDataStr, Json.encodeToString(variables))

    val res2 = client.runQuery(queryEpochDataWithVariables)
    println(res2)

    val queryChainIdStr =
            """
        query MyQuery {
            chainIdentifier
        }
    """.trimIndent()
    val queryChainId = Query(queryChainIdStr)
    val res3 = client.runQuery(queryChainId)
    println(res3)
}
