// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.MovePackage
import iota_sdk.ObjectFilter
import iota_sdk.PaginationFilter
import kotlinx.coroutines.runBlocking

private fun forwardPage(cursor: String? = null): PaginationFilter =
    PaginationFilter(direction = Direction.FORWARD, cursor = cursor)

private suspend fun fetchPackageVersions(
    client: GraphQlClient,
    packageAddress: Address,
): List<MovePackage> {
    val versions = mutableListOf<MovePackage>()
    var cursor: String? = null

    while (true) {
        val page = client.packageVersions(packageAddress, paginationFilter = forwardPage(cursor))
        versions.addAll(page.data)
        if (page.pageInfo.hasNextPage) {
            cursor = page.pageInfo.endCursor
        } else {
            break
        }
    }

    return versions.sortedBy { it.version().toLong() }
}

private suspend fun printObjectSamples(client: GraphQlClient, typeTag: String, isGeneric: Boolean) {
    if (isGeneric) {
        println("    sample objects: skipped for generic type")
        return
    }

    val objects = client.objects(ObjectFilter(typeTag = typeTag), forwardPage())

    if (objects.data.isEmpty()) {
        println("    sample objects: none found")
        return
    }

    println("    sample objects:")
    for (obj in objects.data) {
        println("      - ${obj.objectId().toHex()} (version ${obj.version()})")
    }
    if (objects.pageInfo.hasNextPage) {
        println("      - ...")
    }
}

fun main(args: Array<String>) = runBlocking {
    try {
        val packageId =
            if (args.isNotEmpty()) {
                args[0]
            } else {
                throw IllegalArgumentException(
                    "Usage: ./gradlew example -Pexample=package_inspect --args=\"<PACKAGE_ID>\""
                )
            }

        val packageAddress = Address.fromHex(packageId)
        val client = GraphQlClient.newTestnet()

        val pkg = client.`package`(packageAddress, null) ?: error("missing package")
        val latestPackage = client.packageLatest(packageAddress) ?: error("missing latest package")
        val versions = fetchPackageVersions(client, packageAddress)
        val packagePrefix = pkg.id().toHex()

        println("Requested package id: $packageId")
        println("Resolved package id: $packagePrefix")
        println("Resolved version: ${pkg.version()}")
        println("Latest version: ${latestPackage.version()} (${latestPackage.id().toHex()})")
        println()

        println("Versions:")
        for (version in versions) {
            val labels = mutableListOf<String>()
            if (version.id() == pkg.id()) {
                labels.add("requested")
            }
            if (version.id() == latestPackage.id()) {
                labels.add("latest")
            }

            val suffix = if (labels.isEmpty()) "" else " [${labels.joinToString(", ")}]"
            println("- v${version.version()} -> ${version.id().toHex()}$suffix")
        }
        println()

        println("Dependencies:")
        val linkageTable = pkg.linkageTable().toList().sortedBy { it.first.toHex() }
        if (linkageTable.isEmpty()) {
            println("- none")
        } else {
            for ((originalId, upgrade) in linkageTable) {
                println(
                    "- ${originalId.toHex()} -> ${upgrade.upgradedId.toHex()} @ v${upgrade.upgradedVersion}"
                )
            }
        }
        println()

        println("Modules, functions, and types:")
        val moduleNames = pkg.modules().keys.map { it.asStr() }.sorted()
        for (moduleName in moduleNames) {
            println("Module: $moduleName")

            val module =
                client.normalizedMoveModule(
                    packageAddress,
                    moduleName,
                    null,
                    forwardPage(),
                    forwardPage(),
                    forwardPage(),
                    forwardPage(),
                )

            if (module == null) {
                println("  metadata: missing")
                println()
                continue
            }

            val functions = module.functions
            if (functions == null || functions.nodes.isEmpty()) {
                println("  functions: none")
            } else {
                println("  functions:")
                for (function in functions.nodes) {
                    println("    - ${function.toString()}")
                }
                if (functions.pageInfo.hasNextPage) {
                    println("    - ...")
                }
            }

            val structs = module.structs
            if (structs == null || structs.nodes.isEmpty()) {
                println("  types: none")
            } else {
                println("  types:")
                for (structType in structs.nodes) {
                    val typeTag = "$packagePrefix::$moduleName::${structType.name}"
                    println("    - $typeTag")
                    val isGeneric =
                        structType.typeParameters != null &&
                            structType.typeParameters!!.isNotEmpty()
                    printObjectSamples(client, typeTag, isGeneric)
                }
                if (structs.pageInfo.hasNextPage) {
                    println("    - ...")
                }
            }

            println()
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
