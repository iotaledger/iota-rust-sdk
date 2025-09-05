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

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val packageAddress = Address.fromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

        val pkg = client.`package`(packageAddress, null)
        if (pkg == null) {
            println("No package found")
            return@runBlocking
        }

        for ((moduleId, _) in pkg.modules()) {
            var module = client.normalizedMoveModule(
                packageAddress,
                moduleId.asStr(),
            )
            if (module == null) {
                println("module `${moduleId.asStr()}` not found")
                return@runBlocking
            }
            val fns = module.functions
            if (fns != null) {
                println("Module: ${moduleId.asStr()}")
                for (func in fns.nodes) {
                    println("- ${func.toString()}")
                }
                println()
            }
        }

    } catch (e: Exception) {
        e.printStackTrace()
    }
}
