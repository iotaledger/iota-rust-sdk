// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

private const val PACKAGE_ADDRESS = "0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f"

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()
        val packageAddress = Address.fromHex(PACKAGE_ADDRESS)

        val pkg = client.`package`(packageAddress, null)
        if (pkg == null) {
            println("No package found for $PACKAGE_ADDRESS")
            return@runBlocking
        }

        val packageId = pkg.id().toHex()
        val packageVersion = pkg.version()

        println("Package ID: $packageId")
        println("Current version: $packageVersion")
        println()

        val versions = client.`packageVersions`(packageAddress, null, null, null).data.sortedBy { it.version() }
        println("Package versions:")
        versions.forEach { versionedPackage ->
            val marker =
                if (versionedPackage.id().toHex() == packageId && versionedPackage.version() == packageVersion) {
                    " (current)"
                } else {
                    ""
                }
            println("- id=${versionedPackage.id().toHex()} version=${versionedPackage.version()}$marker")
        }
        println()

        println("Dependencies:")
        val dependencies = pkg.linkageTable()
        if (dependencies.isEmpty()) {
            println("- none")
        } else {
            dependencies.forEach { (originalId, info) ->
                println("- ${originalId.toHex()} -> ${info.upgradedId.toHex()} (version ${info.upgradedVersion})")
            }
        }
        println()

        val modules = pkg.modules().keys.map { it.asStr() }.sorted()
        for (moduleName in modules) {
            val module = client.normalizedMoveModule(packageAddress, moduleName, packageVersion)
            if (module == null) {
                println("Module: $moduleName (not found)")
                continue
            }

            println("Module: $moduleName")
            println("Functions:")
            val functions = module.functions?.nodes ?: emptyList()
            if (functions.isEmpty()) {
                println("- none")
            } else {
                functions.forEach { fn ->
                    println("- $fn")
                }
            }

            println("Types (with sample object if available):")
            val structs = module.structs?.nodes ?: emptyList()
            if (structs.isEmpty()) {
                println("- none")
            } else {
                structs.forEach { struct ->
                    val typeTag = "$packageId::$moduleName::${struct.name}"
                    val objects = client.objects(
                        ObjectFilter(typeTag = typeTag),
                        PaginationFilter(direction = Direction.FORWARD, limit = 1),
                    )
                    if (objects.data.isNotEmpty()) {
                        println("- ${struct.name} (example object: ${objects.data[0].objectId().toHex()})")
                    } else {
                        println("- ${struct.name} (no example object found)")
                    }
                }
            }

            println()
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
