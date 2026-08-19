// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.MoveViewArg
import iota_sdk.ObjectId
import kotlinx.coroutines.runBlocking

// The `view_demo` package published on testnet.
const val VIEW_DEMO_PACKAGE = "0x533074f8e22e8ce1330d7e9d67c18966abb5a3d58dc2e2deea50e50bea4e87f4"

// A shared `view_demo::shop::Shop` created when the package was published.
const val VIEW_DEMO_SHOP = "0x9d5ce0da7531d56ffecced5efb7e19ccad0e191071041267cc8134a3e5a6cd20"

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        // ===========================================================================
        // Example 1: Using moveViewCall() with typed arguments (primitives)
        // ===========================================================================
        println("=== Example 1: moveViewCall() with typed arguments (primitives) ===")
        println()

        val priceArgs = listOf(MoveViewArg.u64(100uL), MoveViewArg.u64(25uL))

        val priceResult =
            client.moveViewCall("$VIEW_DEMO_PACKAGE::shop::discounted_price", null, priceArgs)

        if (priceResult.error != null) {
            println("Error: ${priceResult.error}")
        } else if (priceResult.results != null) {
            println("Results: ${priceResult.results}")
        } else {
            println("No results")
        }

        // ===========================================================================
        // Example 2: Using moveViewCallJson() with JSON values (primitives)
        // ===========================================================================
        println()
        println("=== Example 2: moveViewCallJson() with JSON values (primitives) ===")
        println()

        // `u64` is passed as a string so large values survive JSON.
        val priceJsonResult =
            client.moveViewCallJson(
                "$VIEW_DEMO_PACKAGE::shop::discounted_price",
                null,
                listOf("\"100\"", "\"25\""),
            )

        if (priceJsonResult.error != null) {
            println("JSON Error: ${priceJsonResult.error}")
        } else if (priceJsonResult.results != null) {
            println("JSON Results: ${priceJsonResult.results}")
        } else {
            println("No JSON results")
        }

        // ===========================================================================
        // Example 3: Using moveViewCall() with typed arguments (shared object)
        // ===========================================================================
        println()
        println("=== Example 3: moveViewCall() with typed arguments (shared object) ===")
        println()

        val objectId = ObjectId.fromHex(VIEW_DEMO_SHOP)

        val shopArgs = listOf(MoveViewArg.objectId(objectId), MoveViewArg.u64(1uL))

        val shopResult = client.moveViewCall("$VIEW_DEMO_PACKAGE::shop::sale_at", null, shopArgs)

        if (shopResult.error != null) {
            println("Shop Error: ${shopResult.error}")
        } else if (shopResult.results != null) {
            println("Shop Results: ${shopResult.results}")
        } else {
            println("No shop results")
        }

        // ===========================================================================
        // Example 4: Using moveViewCallJson() with JSON values (shared object)
        // ===========================================================================
        println()
        println("=== Example 4: moveViewCallJson() with JSON values (shared object) ===")
        println()

        val shopJsonResult =
            client.moveViewCallJson(
                "$VIEW_DEMO_PACKAGE::shop::sale_at",
                null,
                listOf("\"$VIEW_DEMO_SHOP\"", "\"1\""),
            )

        if (shopJsonResult.error != null) {
            println("Shop JSON Error: ${shopJsonResult.error}")
        } else if (shopJsonResult.results != null) {
            println("Shop JSON Results: ${shopJsonResult.results}")
        } else {
            println("No shop JSON results")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
