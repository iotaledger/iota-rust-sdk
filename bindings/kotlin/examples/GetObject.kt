// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val objectId =
                ObjectId.fromHex(
                        "0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e"
                )

        val obj = client.`object`(objectId)!!

        val objType =
                if (obj.objectType().isPackage()) {
                    "Package"
                } else {
                    obj.objectType().asStruct().toString()
                }

        val objOwner =
                if (obj.owner().isAddress()) {
                    "Address(${obj.owner().asAddress().toHex()})"
                } else if (obj.owner().isObject()) {
                    "Object(${obj.owner().asObject().toHex()})"
                } else if (obj.owner().isShared()) {
                    "Shared(${obj.owner().asShared()})"
                } else {
                    "Immutable"
                }

        println("Object ID: ${obj.objectId().toHex()}")
        println("Version: ${obj.version()}")
        println("Previous transaction: ${obj.previousTransaction().toBase58()}")
        println("Owner: $objOwner")
        println("Storage rebate: ${obj.storageRebate()}")
        println("Type: $objType")
        @OptIn(kotlin.ExperimentalStdlibApi::class)
        println("BCS bytes: ${obj.asStruct().contents.toHexString()}")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
