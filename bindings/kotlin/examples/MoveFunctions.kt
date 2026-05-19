// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        // Inspect the IOTA framework package (0x2). It is present on every
        // network including localnet.
        val packageAddress = Address.framework()

        val pkg = client.`package`(packageAddress, null)
        if (pkg == null) {
            println("No package found")
            return@runBlocking
        }

        for ((moduleId, _) in pkg.modules()) {
            var module = client.normalizedMoveModule(packageAddress, moduleId.asStr())
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
        kotlin.system.exitProcess(1)
    }
}
