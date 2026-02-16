// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import kotlinx.coroutines.runBlocking

/**
 * Example: Query Move Package Information
 *
 * This example demonstrates how to fetch and display comprehensive information
 * about a Move package, including:
 * - Package versions
 * - Modules and their functions
 * - Dependencies
 * - Types defined in the package
 * - Example objects of those types
 */
fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        // Example package ID (replace with actual package ID)
        val packageId =
            Address.fromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

        println("Fetching information for package: ${packageId.toHex()}\n")

        // Fetch the package object
        val pkg = client.`package`(packageId, null)
        if (pkg == null) {
            println("Package not found at address: ${packageId.toHex()}")
            return@runBlocking
        }

        // Display package version
        println("=== Package Version ===")
        println("Current version: ${pkg.version}")
        println()

        // Display modules and their functions
        println("=== Modules ===")
        for ((moduleId, _) in pkg.modules()) {
            println("Module: ${moduleId.asStr()}")

            // Fetch detailed module information
            val normalizedModule = client.normalizedMoveModule(
                packageId,
                moduleId.asStr(),
                null,
                null,
                null,
                null,
                null,
                null
            )

            if (normalizedModule != null) {
                // Display functions
                normalizedModule.functions?.let { functions ->
                    println("  Functions:")
                    for (fun_ in functions.nodes) {
                        println("    - ${fun_.name}")
                    }
                }

                // Display structs/types
                normalizedModule.structs?.let { structs ->
                    println("  Types:")
                    for (structDef in structs.nodes) {
                        println("    - ${structDef.name}")

                        // Try to find example objects of this type
                        try {
                            val typeStr = "${packageId.toHex()}::${moduleId.asStr()}::${structDef.name}"
                            val objects = client.objectsByType(typeStr, 3, null)
                            if (objects != null && objects.isNotEmpty()) {
                                println("      Example objects:")
                                for (obj in objects) {
                                    println("        - Object ID: ${obj.objectId().toHex()}")
                                }
                            }
                        } catch (e: Exception) {
                            // Ignore errors when fetching objects
                        }
                    }
                }
            }
            println()
        }

        // Display dependencies (from package's previous transaction)
        pkg.previousTransaction?.let { prevTx ->
            println("=== Previous Transaction ===")
            println("Transaction digest: ${prevTx.toBase58()}")
        }

        println()
        println("Package information fetched successfully!")

    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
