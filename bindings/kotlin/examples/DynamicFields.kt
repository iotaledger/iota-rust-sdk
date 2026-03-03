// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()
        val parentObjectId =
            iota_sdk.Address.fromHex(
                "0x7cab491740d51e0d75b26bf9984e49ba2e32a2d0694cabcee605543ed13c7dec"
            )
        val page = client.dynamicFields(parentObjectId)
        println("Page size: ${page.data.size}")
        if (page.data.isNotEmpty()) {
            println("First field name:\n${page.data.first().name}")
            println("First field value:\n${page.data.first().valueAsJson}")
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
