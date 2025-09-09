// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val chainId = client.chainId()
        println("Chain ID: $chainId")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
