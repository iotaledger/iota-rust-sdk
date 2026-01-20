// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val arguments =
            listOf("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b", "auc.iota")

        val result =
            client.moveViewCall(
                "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
                null,
                arguments,
            )

        if (result.error != null) {
            println("Error: ${result.error}")
        } else if (result.results != null) {
            println("Results: ${result.results}")
        } else {
            println("No results")
        }

        val hashArgs = listOf("[0,1,2]")

        val hashResult = client.moveViewCall("0x2::hash::blake2b256", null, hashArgs)

        if (hashResult.error != null) {
            println("Hash Error: ${hashResult.error}")
        } else if (hashResult.results != null) {
            println("Hash Results: ${hashResult.results}")
        } else {
            println("No hash results")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
