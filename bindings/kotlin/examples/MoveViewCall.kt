// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        // ===========================================================================
        // Example 1: Using moveViewCall() for blake2b256 hash function
        // ===========================================================================
        println("=== Example 1: moveViewCall() for blake2b256 ===")
        println()

        val hashArgs = listOf("[0,1,2]")

        val hashResult = client.moveViewCall("0x2::hash::blake2b256", null, hashArgs)

        if (hashResult.error != null) {
            println("Error: ${hashResult.error}")
        } else if (hashResult.results != null) {
            println("Results: ${hashResult.results}")
        } else {
            println("No results")
        }

        // ===========================================================================
        // Example 2: Using moveViewCall() for auction metadata
        // ===========================================================================
        println()
        println("=== Example 2: moveViewCall() for auction ===")
        println()

        val auctionArgs =
            listOf("0x31deb8cbd320867089d52c37fed2d443520aac0fc5a957de1f64f9135b83f42b", "auc.iota")

        val auctionResult =
            client.moveViewCall(
                "0x5e7a300e640f645a4030aeb507c7be16909e6fa9711e7ca2d4397bbd967d5c50::auction::get_auction_metadata",
                null,
                auctionArgs,
            )

        if (auctionResult.error != null) {
            println("Auction Error: ${auctionResult.error}")
        } else if (auctionResult.results != null) {
            println("Auction Results: ${auctionResult.results}")
        } else {
            println("No auction results")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
