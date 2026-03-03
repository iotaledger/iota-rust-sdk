// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Direction
import iota_sdk.EventFilter
import iota_sdk.GraphQlClient
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val events =
            client.events(
                filter =
                    EventFilter(
                        eventType =
                            "0x7aec8176867a0c8d2803d758ebf98226d301ef0f00393879ea718f6bd1554f16::registry::NameRecordAddedEvent"
                    ),
                paginationFilter = PaginationFilter(direction = Direction.FORWARD, limit = 10),
            )

        for (event in events.data) {
            println("Type: ${event.type}")
            println("Sender: ${event.sender}")
            println("Module: ${event.module}")
            println("JSON: ${event.json}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
