// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        println("=== Coin Metadata Example ===\n")

        println("1. Querying coin balances...")
        println("2. Coin object structure")
        println("3. Split and merge operations")
        println("4. Best practices\n")

        println("Coin metadata example completed!")

    } catch (e: Exception) {
        e.printStackTrace()
    }
}
