// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.Object
import iota_sdk.ObjectFilter
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val address =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
        val allObjects = mutableListOf<Object>()
        var nextCursor: String? = null
        while (true) {
            println("Fetching page with cursor: $nextCursor")
            val page =
                client.objects(
                    ObjectFilter(owner = address),
                    PaginationFilter(
                        direction = Direction.FORWARD,
                        cursor = nextCursor,
                        // Limit to 1 to demonstrate pagination
                        limit = 1,
                    ),
                )
            allObjects.addAll(page.data)
            if (page.pageInfo.hasNextPage) {
                nextCursor = page.pageInfo.endCursor
            } else {
                break
            }
        }
        println("${allObjects.size} objects fetched:")
        for (obj in allObjects) {
            println(obj.id().toHex())
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
