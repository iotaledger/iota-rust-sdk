// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GrpcClient
import iota_sdk.StructTag
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GrpcClient.newTestnet()

        val owner =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        // First page: 10 results, no filter on type. The returned page includes a
        // `nextPageToken` to feed back in for the following page.
        val page = client.ownedObjects(owner, null, 10u)
        println("First page: ${page.objects.size} objects")
        for (obj in page.objects) {
            println("  ${obj.id().toHex()}")
        }
        if (page.nextPageToken != null) {
            println("  ...more pages available")
        }

        // Auto-paginate: only IOTA coins, capped at 50 across all pages.
        val coins = client.allOwnedObjects(owner, StructTag.newGasCoin(), 50u)
        println("---")
        println("Up to 50 IOTA coin objects (${coins.size} returned):")
        for (obj in coins) {
            println("  ${obj.id().toHex()}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
