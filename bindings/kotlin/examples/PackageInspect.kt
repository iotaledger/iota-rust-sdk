// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * This example inspects a published Move package on testnet and prints its upgrade policy, version
 * history, dependencies, functions, types, and sample objects.
 */
import iota_sdk.Address
import iota_sdk.Direction
import iota_sdk.GraphQlClient
import iota_sdk.MoveAbility
import iota_sdk.MovePackage
import iota_sdk.ObjectFilter
import iota_sdk.ObjectId
import iota_sdk.ObjectOut
import iota_sdk.PaginationFilter
import iota_sdk.StructTag
import iota_sdk.Transaction
import iota_sdk.TransactionsFilter
import iota_sdk.Value
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private fun forwardPage(cursor: String? = null): PaginationFilter =
    PaginationFilter(direction = Direction.FORWARD, cursor = cursor)

private val frameworkPackageId = Address.framework().toHex()
private val jsonParser = Json { ignoreUnknownKeys = true }

fun main() = runBlocking {
    try {
        val packageId = "0x6f727ea576a00036657fff0ae3a6d7c8171b178bf35112d6b83b2a6272cc5f0d"

        val packageAddress = Address.fromHex(packageId)
        val client = GraphQlClient.newTestnet()

        // Fetch package metadata and version history.
        val pkg = client.`package`(packageAddress, null) ?: error("missing package")
        val latestPackage = client.packageLatest(packageAddress) ?: error("missing latest package")
        val versions = fetchPackageVersions(client, packageAddress)
        val packagePrefix = pkg.id().toHex()
        println(
            "Latest version: ${latestPackage.version().asU64()} (${latestPackage.id().toHex()})"
        )
        // Resolve the current upgrade policy.
        println("Current package policy: ${currentPackagePolicy(client, pkg.id())}")
        println()

        // Print the package version history.
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
            println("- v${version.version().asU64()} -> ${version.id().toHex()}$suffix")
        }
        println()

        // Print package dependencies and their linked versions.
        println("Dependencies:")
        val linkageTable = pkg.linkageTable().values.sortedBy { it.upgradedId.toHex() }
        if (linkageTable.isEmpty()) {
            println("- none")
        } else {
            for (upgrade in linkageTable) {
                println("- ${upgrade.upgradedId.toHex()} @ v${upgrade.upgradedVersion.asU64()}")
            }
        }
        println()

        // Inspect normalized modules, functions, types, and sample key objects.
        println("Package contents:")
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
                    println("    - ${formatFunctionSignature(function.toString(), packagePrefix)}")
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
                    val hasKeyAbility = structType.abilities?.contains(MoveAbility.KEY) == true
                    val isGeneric =
                        structType.typeParameters != null &&
                            structType.typeParameters!!.isNotEmpty()
                    printObjectSamples(client, typeTag, hasKeyAbility, isGeneric)
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

private fun shortenPackageIds(signature: String): String {
    val shortened = StringBuilder(signature.length)
    var index = 0

    while (index < signature.length) {
        if (
            signature[index] == '0' && index + 1 < signature.length && signature[index + 1] == 'x'
        ) {
            var end = index + 2
            while (end < signature.length && signature[end].digitToIntOrNull(16) != null) {
                end++
            }

            if (end > index + 2) {
                val candidate = signature.substring(index, end)
                val shortAddress =
                    runCatching { Address.fromHex(candidate).toShortHex() }.getOrNull()
                shortened.append(shortAddress ?: candidate)
                index = end
                continue
            }
        }

        shortened.append(signature[index])
        index++
    }

    return shortened.toString()
}

private fun formatFunctionSignature(signature: String, packagePrefix: String): String =
    shortenPackageIds(signature.replace("$packagePrefix::", ""))

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

    return versions.sortedBy { it.version().asU64() }
}

private suspend fun printObjectSamples(
    client: GraphQlClient,
    typeTag: String,
    hasKeyAbility: Boolean,
    isGeneric: Boolean,
) {
    if (!hasKeyAbility) {
        return
    }

    if (isGeneric) {
        println("    sample objects: skipped for generic type")
        return
    }

    val objects =
        client.objects(
            ObjectFilter(typeTag = typeTag),
            PaginationFilter(direction = Direction.FORWARD, limit = 3),
        )

    if (objects.data.isEmpty()) {
        println("    sample objects: none found")
        return
    }

    println("    sample objects:")
    for (obj in objects.data) {
        println("      - ${obj.id().toHex()} (version ${obj.version().asU64()})")
    }
    if (objects.pageInfo.hasNextPage) {
        println("      - ...")
    }
}

private fun formatPolicyName(policy: Int): String =
    when (policy) {
        0 -> "Compatible"
        128 -> "Additive"
        192 -> "Dependency-only"
        else -> "Unknown ($policy)"
    }

private fun extractPolicy(contents: Value): Int? =
    runCatching {
            jsonParser.parseToJsonElement(contents).jsonObject["policy"]?.jsonPrimitive?.intOrNull
        }
        .getOrNull()

private suspend fun resolveUpgradeCapId(client: GraphQlClient, packageId: ObjectId): ObjectId? {
    val page =
        client.transactionsEffects(
            TransactionsFilter(changedObject = packageId),
            PaginationFilter(direction = Direction.FORWARD, limit = 1),
        )

    for (effects in page.data) {
        val effectsV1 = effects.asV1()
        for (changedObj in effectsV1.changedObjects()) {
            if (changedObj.outputState !is ObjectOut.ObjectWrite) {
                continue
            }

            val obj = client.`object`(changedObj.objectId, effectsV1.lamportVersion()) ?: continue
            if (obj.asStructOpt()?.structType == StructTag.newUpgradeCap()) {
                return changedObj.objectId
            }
        }
    }

    return null
}

private fun sameObjectId(left: String?, right: String?): Boolean =
    left != null && right != null && left.equals(right, ignoreCase = true)

private fun programmableTransactionJson(tx: Transaction): JsonObject? {
    val root = jsonParser.parseToJsonElement(tx.toJson()).jsonObject
    val txV1 = root["1"]?.jsonObject ?: return null
    val kind = txV1["kind"]?.jsonObject ?: return null
    return kind.takeIf { it["kind"]?.jsonPrimitive?.contentOrNull == "programmable_transaction" }
}

private fun isPackageMakeImmutableCall(command: JsonObject): Boolean =
    command["command"]?.jsonPrimitive?.contentOrNull == "move_call" &&
        sameObjectId(command["package"]?.jsonPrimitive?.contentOrNull, frameworkPackageId) &&
        command["module"]?.jsonPrimitive?.contentOrNull == "package" &&
        command["function"]?.jsonPrimitive?.contentOrNull == "make_immutable"

private fun inputMatchesObjectId(input: JsonObject, objectId: String): Boolean =
    input["type"]?.jsonPrimitive?.contentOrNull in
        setOf("immutable_or_owned", "receiving", "shared") &&
        sameObjectId(input["object_id"]?.jsonPrimitive?.contentOrNull, objectId)

private fun publishesPackageAsImmutable(tx: Transaction): Boolean {
    val programmableTx = programmableTransactionJson(tx) ?: return false
    val commands = programmableTx["commands"] as? JsonArray ?: return false

    val publishIndexes =
        commands.mapIndexedNotNull { index, command ->
            val commandObject = command as? JsonObject ?: return@mapIndexedNotNull null
            if (commandObject["command"]?.jsonPrimitive?.contentOrNull == "publish") {
                index
            } else {
                null
            }
        }
    if (publishIndexes.size != 1) {
        return false
    }

    val publishIndex = publishIndexes.single()
    for (command in commands.drop(publishIndex + 1)) {
        val commandObject = command as? JsonObject ?: continue
        val arguments = commandObject["arguments"] as? JsonArray ?: continue
        if (!isPackageMakeImmutableCall(commandObject) || arguments.size != 1) {
            continue
        }

        val argument = arguments.first() as? JsonObject ?: continue
        if (argument["result"]?.jsonPrimitive?.intOrNull == publishIndex) {
            return true
        }
    }

    return false
}

private fun usesUpgradeCapForMakeImmutable(tx: Transaction, upgradeCapId: ObjectId): Boolean {
    val programmableTx = programmableTransactionJson(tx) ?: return false
    val inputs = programmableTx["inputs"] as? JsonArray ?: return false
    val commands = programmableTx["commands"] as? JsonArray ?: return false

    val upgradeCapInputs =
        inputs.mapIndexedNotNull { index, input ->
            val inputObject = input as? JsonObject ?: return@mapIndexedNotNull null
            if (inputMatchesObjectId(inputObject, upgradeCapId.toHex())) {
                index
            } else {
                null
            }
        }
    if (upgradeCapInputs.isEmpty()) {
        return false
    }

    for (command in commands) {
        val commandObject = command as? JsonObject ?: continue
        val arguments = commandObject["arguments"] as? JsonArray ?: continue
        if (!isPackageMakeImmutableCall(commandObject) || arguments.size != 1) {
            continue
        }

        val argument = arguments.first() as? JsonObject ?: continue
        val inputIndex = argument["input"]?.jsonPrimitive?.intOrNull ?: continue
        if (inputIndex in upgradeCapInputs) {
            return true
        }
    }

    return false
}

private suspend fun wasPackagePublishedAsImmutable(
    client: GraphQlClient,
    packageId: ObjectId,
): Boolean {
    var cursor: String? = null

    while (true) {
        val page =
            client.transactionsDataEffects(
                TransactionsFilter(changedObject = packageId),
                forwardPage(cursor),
            )

        for (txData in page.data) {
            if (publishesPackageAsImmutable(txData.tx.transaction)) {
                return true
            }
        }

        if (!page.pageInfo.hasNextPage) {
            return false
        }

        cursor = page.pageInfo.endCursor
    }
}

private suspend fun wasUpgradeCapUsedForMakeImmutable(
    client: GraphQlClient,
    upgradeCapId: ObjectId,
): Boolean {
    var cursor: String? = null

    while (true) {
        val page =
            client.transactionsDataEffects(
                TransactionsFilter(inputObject = upgradeCapId),
                forwardPage(cursor),
            )

        for (txData in page.data) {
            if (usesUpgradeCapForMakeImmutable(txData.tx.transaction, upgradeCapId)) {
                return true
            }
        }

        if (!page.pageInfo.hasNextPage) {
            return false
        }

        cursor = page.pageInfo.endCursor
    }
}

private suspend fun currentPackagePolicy(client: GraphQlClient, packageId: ObjectId): String {
    val upgradeCapId = resolveUpgradeCapId(client, packageId)
    if (upgradeCapId == null) {
        return if (wasPackagePublishedAsImmutable(client, packageId)) "Immutable" else "Unavailable"
    }

    val contents = client.moveObjectContents(upgradeCapId, null)
    if (contents == null) {
        return if (wasUpgradeCapUsedForMakeImmutable(client, upgradeCapId)) "Immutable"
        else "Unavailable"
    }

    val policy = extractPolicy(contents) ?: return "Unavailable"
    return formatPolicyName(policy)
}
