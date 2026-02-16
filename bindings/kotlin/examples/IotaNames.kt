// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

const val IOTA_NAMES_PACKAGE = "0xb9d617f24c84826bf660a2f4031951678cc80c264aebc4413459fb2a95ada9ba"
const val IOTA_NAMES_REGISTRY = "0x07c59b37bd7d036bf78fa30561a2ab9f7a970837487656ec29466e817f879342"

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        println("=== IOTA Names Example ===\n")
        println("1. Resolving name 'name.iota'")
        println("2. Checking availability of 'test123.iota'")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
