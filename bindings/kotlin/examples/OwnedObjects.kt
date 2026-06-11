// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val address = Address.zero()
        val objectFilter = ObjectFilter(owner = address)
        val objectsPage = client.objects(objectFilter)
        println("Owned objects (${objectsPage.data.size}):")
        for (obj in objectsPage.data) {
            println(obj.id().toHex())
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
