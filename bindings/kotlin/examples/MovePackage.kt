// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.GraphQlClient
import iota_sdk.ObjectFilter
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val packageAddress =
            Address.fromHex("0x3ec4826f1d6e0d9f00680b2e9a7a41f03788ee610b3d11c24f41ab0ae71da39f")

        val packageVersions = client.`packageVersions`(packageAddress)
        if (packageVersions.data.isEmpty()) {
            println("No package versions found")
            return@runBlocking
        }

        val versions = packageVersions.data.map { pkg -> pkg.version() }.sorted()
        println("Versions: $versions")

        val latestPackage = client.`packageLatest`(packageAddress)
        if (latestPackage == null) {
            println("Latest package not found")
            return@runBlocking
        }

        println("Latest package id: ${latestPackage.id().toHex()}")
        println("Latest package version: ${latestPackage.version()}")

        val dependencies = latestPackage.linkageTable()
        if (dependencies.isEmpty()) {
            println("Dependencies: none")
        } else {
            println("Dependencies:")
            for ((dependency, _) in dependencies) {
                println("- ${dependency.toHex()}")
            }
        }

        for ((moduleId, _) in latestPackage.modules()) {
            val module = client.normalizedMoveModule(
                packageAddress,
                moduleId.asStr(),
                latestPackage.version(),
            )
            if (module == null) {
                continue
            }

            println("\nModule: ${moduleId.asStr()}")
            module.functions?.let { functions ->
                println("Functions: ${functions.nodes.size}")
            }

            module.structs?.let { structs ->
                println("Structs: ${structs.nodes.size}")
                for (moveStruct in structs.nodes.take(2)) {
                    val structType =
                        "${latestPackage.id().toHex()}::${moduleId.asStr()}::${moveStruct.name}"
                    val typedObjects = client.objects(ObjectFilter(typeTag = structType))
                    if (typedObjects.data.isNotEmpty()) {
                        println("- ${moveStruct.name} -> example object ${typedObjects.data[0].objectId().toHex()}")
                    } else {
                        println("- ${moveStruct.name} -> no objects found")
                    }
                }
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
