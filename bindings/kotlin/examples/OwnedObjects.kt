// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val address = Address.fromHex("0x0")
        val objectFilter = ObjectFilter(owner = address)
        val paginationFilter = PaginationFilter(direction = Direction.FORWARD)
        val objectsPage = client.objects(paginationFilter, objectFilter)
        println("Owned objects (${objectsPage.data.size}):")
        for (obj in objectsPage.data) {
            println(obj.objectId().toHex())
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
