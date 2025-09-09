// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val parentObjectId =
                iota_sdk.Address.fromHex(
                        "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"
                )
        val pagination =
                iota_sdk.PaginationFilter(
                        direction = iota_sdk.Direction.FORWARD,
                )
        val page = client.dynamicFields(parentObjectId, pagination)
        println("Page size: ${page.data.size}")
        if (page.data.isNotEmpty()) {
            println("First field name:\n${page.data.first().name}")
            println("First field value:\n${page.data.first().valueAsJson}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
