// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.GraphQlObjectFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val coins =
            client.objects(GraphQlObjectFilter(typeTag = "0x2::coin::Coin<0x2::iota::IOTA>"))

        if (coins.data.isEmpty()) {
            println("No IOTA coin objects found")
        } else {
            println("IOTA coin object IDs:")
            for (coin in coins.data) {
                println(coin.id())
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
