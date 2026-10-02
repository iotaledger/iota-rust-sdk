// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.GraphQlDirection
import iota_sdk.GraphQlEventFilter
import iota_sdk.GraphQlPaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val events =
            client.events(
                filter =
                    GraphQlEventFilter(
                        eventType =
                            "0x7fff6e95f385349bec98d17121ab2bfa3e134f2f0b1ccefc270313415f7835ea::registry::NameRecordAddedEvent"
                    ),
                paginationFilter =
                    GraphQlPaginationFilter(direction = GraphQlDirection.FORWARD, limit = 10),
            )

        for (event in events.data) {
            // Sender and module are optional: some events (such as system- or
            // genesis-emitted ones) carry neither.
            println("Type: ${event.moveType}")
            println("Sender: ${event.sender?.toHex() ?: "none"}")
            println("Module: ${event.module ?: "none"}")
            println("JSON: ${event.json}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
