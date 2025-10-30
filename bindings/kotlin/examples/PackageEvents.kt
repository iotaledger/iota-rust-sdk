// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Direction
import iota_sdk.EventFilter
import iota_sdk.GraphQlClient
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val events =
                client.events(
                        filter =
                                EventFilter(
                                        eventType =
                                                "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba::registry::NameRecordAddedEvent"
                                ),
                        paginationFilter =
                                PaginationFilter(direction = Direction.FORWARD, limit = 10),
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
