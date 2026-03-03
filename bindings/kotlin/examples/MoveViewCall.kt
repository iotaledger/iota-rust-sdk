// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// TODO: https://github.com/iotaledger/iota-rust-sdk/issues/1000

import iota_sdk.GraphQlClient
import iota_sdk.MoveViewArg
import iota_sdk.ObjectId
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        // ===========================================================================
        // Example 1: Using moveViewCall() with typed arguments (blake2b256)
        // ===========================================================================
        println("=== Example 1: moveViewCall() with typed arguments (blake2b256) ===")
        println()

        // Using typed arguments: an array of u8 values using the u8Vec constructor
        val hashArgs = listOf(MoveViewArg.u8Vec(byteArrayOf(0, 1, 2)))

        val hashResult = client.moveViewCall("0x2::hash::blake2b256", null, hashArgs)

        if (hashResult.error != null) {
            println("Error: ${hashResult.error}")
        } else if (hashResult.results != null) {
            println("Results: ${hashResult.results}")
        } else {
            println("No results")
        }

        // ===========================================================================
        // Example 2: Using moveViewCallJson() with JSON values (blake2b256)
        // ===========================================================================
        println()
        println("=== Example 2: moveViewCallJson() with JSON values (blake2b256) ===")
        println()

        val jsonHashResult =
            client.moveViewCallJson("0x2::hash::blake2b256", null, listOf("[0, 1, 2]"))

        if (jsonHashResult.error != null) {
            println("JSON Error: ${jsonHashResult.error}")
        } else if (jsonHashResult.results != null) {
            println("JSON Results: ${jsonHashResult.results}")
        } else {
            println("No JSON results")
        }

        // ===========================================================================
        // Example 3: Using moveViewCall() with typed arguments (auction)
        // ===========================================================================
        // println()
        // println("=== Example 3: moveViewCall() with typed arguments (auction) ===")
        // println()

        // val objectId =
        //     ObjectId.fromHex("0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050")

        // val auctionArgs = listOf(MoveViewArg.objectId(objectId), MoveViewArg.string("auc.iota"))

        // val auctionResult =
        //     client.moveViewCall(
        //         "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
        //         null,
        //         auctionArgs,
        //     )

        // if (auctionResult.error != null) {
        //     println("Auction Error: ${auctionResult.error}")
        // } else if (auctionResult.results != null) {
        //     println("Auction Results: ${auctionResult.results}")
        // } else {
        //     println("No auction results")
        // }

        // ===========================================================================
        // Example 4: Using moveViewCallJson() with JSON values (auction)
        // ===========================================================================
        // println()
        // println("=== Example 4: moveViewCallJson() with JSON values (auction) ===")
        // println()

        // val auctionJsonResult =
        //     client.moveViewCallJson(
        //         "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d::auction::get_auction_metadata",
        //         null,
        //         listOf(
        //             "\"0x2292ea885039babe8c320f19e0b7546ebdef2b2f6cf2be600bf994cdb51e0050\"",
        //             "\"auc.iota\"",
        //         ),
        //     )

        // if (auctionJsonResult.error != null) {
        //     println("Auction JSON Error: ${auctionJsonResult.error}")
        // } else if (auctionJsonResult.results != null) {
        //     println("Auction JSON Results: ${auctionJsonResult.results}")
        // } else {
        //     println("No auction JSON results")
        // }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
