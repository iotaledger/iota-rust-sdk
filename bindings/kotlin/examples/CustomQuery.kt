// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.CustomQuery
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

fun main() = runBlocking {
    val client = GraphQlClient.newDevnet()

    val query_epoch_data_str =
            """
        query CustomQuery(${'$'}id: UInt53) {
            epoch(id: ${'$'}id) {
                epochId
                referenceGasPrice
                totalGasFees
                totalCheckpoints
                totalTransactions
            }
        }
    """.trimIndent()

    val queryEpochData = CustomQuery(query_epoch_data_str)
    val res1 = client.runCustomQuery(queryEpochData)
    println(res1)

    val variablesMap = mapOf("id" to 1)
    val variables = Json.encodeToString(variablesMap)
    val queryEpochDataWithVariables = CustomQuery(query_epoch_data_str, variables)
    val res2 = client.runCustomQuery(queryEpochDataWithVariables)
    println(res2)

    val query_chain_id_str =
            """
        query CustomQuery {
            chainIdentifier
        }
    """.trimIndent()
    val queryChainIdentifier = CustomQuery(query_chain_id_str)
    val res3 = client.runCustomQuery(queryChainIdentifier)
    println(res3)
}
