// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.EventFilter
import iota_sdk.GraphQlClient
import iota_sdk.ObjectId
import iota_sdk.PaginationFilter
import iota_sdk.TransactionsFilter
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.*
import kotlinx.serialization.json.*

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val objectId = ObjectId.fromHex("0x20c056090c3dd1604fcfd7ea759781de650aa45323738e799365d0c28bebeb1e")

        val obj = client.moveObjectContents(objectId)!!

        val objJson = Json.parseToJsonElement(obj).jsonObject

        println("Domain: ${objJson.get("domain_name")}");
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
