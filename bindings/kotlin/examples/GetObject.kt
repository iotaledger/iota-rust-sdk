// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.hexEncode
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {

        val client = GraphQlClient.newTestnet()

        val objectId =
            ObjectId.fromHex("0x541b117cac18fb1c07a293db300acd12b05c01fa81232b37151b005ca7d4f755")

        val obj = client.`object`(objectId)!!

        println("Object ID: ${obj.id().toHex()}")
        println("Version: ${obj.version()}")
        println("Previous transaction: ${obj.previousTransaction().toBase58()}")
        println("Owner: ${obj.owner().toString()}")
        println("Storage rebate: ${obj.storageRebate()}")
        println("Type: ${obj.objectType().toString()}")
        @OptIn(kotlin.ExperimentalStdlibApi::class)
        println("BCS bytes: ${hexEncode(obj.asStruct().contents)}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
