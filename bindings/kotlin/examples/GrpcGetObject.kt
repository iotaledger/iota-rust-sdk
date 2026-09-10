// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GrpcClient
import iota_sdk.ObjectId
import iota_sdk.ObjectRequest
import iota_sdk.hexEncode
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GrpcClient.newTestnet()

        val objectId =
            ObjectId.fromHex("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

        // `objects` is batched: it takes a list of requests and returns the objects
        // in the same order.
        val obj = client.objects(listOf(ObjectRequest(objectId)))[0]

        println("Object ID: ${obj.id().toHex()}")
        println("Version: ${obj.version()}")
        println("Previous transaction: ${obj.previousTransaction().toBase58()}")
        println("Owner: ${obj.owner()}")
        println("Storage rebate: ${obj.storageRebate()}")
        println("Type: ${obj.objectType()}")
        println("BCS bytes: ${hexEncode(obj.asStruct().contents)}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
