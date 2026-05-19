// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Direction
import iota_sdk.EventFilter
import iota_sdk.GraphQlClient
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        // Query events emitted by the validator-set module in the IOTA system
        // framework (0x3). These fire on every epoch change so they are
        // reliably present on every network including localnet.
        val events =
            client.events(
                filter = EventFilter(eventType = "0x3::validator::StakingRequestEvent"),
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
