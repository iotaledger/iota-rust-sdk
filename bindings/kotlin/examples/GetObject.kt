// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.hexEncode
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val objectId =
                ObjectId.fromHex(
                        "0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e"
                )

        val obj = client.`object`(objectId)!!

        println("Object ID: ${obj.objectId().toHex()}")
        println("Version: ${obj.version()}")
        println("Previous transaction: ${obj.previousTransaction().toBase58()}")
        println("Owner: ${obj.owner().toString()}")
        println("Storage rebate: ${obj.storageRebate()}")
        println("Type: ${obj.objectType().toString()}")
        @OptIn(kotlin.ExperimentalStdlibApi::class)
        println("BCS bytes: ${hexEncode(obj.asStruct().contents)}")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
