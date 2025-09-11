// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.CustomQuery
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

fun main() = runBlocking {
    val client = GraphQlClient.newDevnet()

    val query =
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

    val variables = mapOf("id" to 1)

    val jsonVariables = Json.encodeToString(variables)

    val payload = CustomQuery(query = query, variables = jsonVariables)

    val res = client.runCustomQuery(payload)

    println(res)
}
