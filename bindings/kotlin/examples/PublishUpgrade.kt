// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * This example allows you to publish any Move package by compiling it first using the `iota`
 * binary. For demonstration purposes this example immediately upgrades the package after publishing
 * it.
 *
 * bash:
 * ```
 * cd /path/to/your/move/package
 * export COMPILED_PACKAGE=$(iota move build --dump-bytecode-as-base64)
 * ```
 *
 * fish:
 * ```
 * cd /path/to/your/move/package
 * set -x COMPILED_PACKAGE (iota move build --dump-bytecode-as-base64)
 * ```
 *
 * With this example it is necessary to run a localnet:
 * ```sh
 * iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
 * ```
 */
import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        var compiledPackageJson: String? = System.getenv("COMPILED_PACKAGE")
        if (compiledPackageJson == null) {
            println("No compiled package found in env var. Using default.")
            compiledPackageJson = PRECOMPILED_PACKAGE.toString()
        } else {
            println("Using custom Move package found in env var.")
        }

        val packageData = MovePackageData.fromJson(compiledPackageJson)
        val modules = packageData.modules()
        println("Modules: ${modules.size}")
        val dependencies = packageData.dependencies()
        println("Dependencies: ${dependencies.size}")
        val digest = packageData.digest()
        println("Digest: ${digest.toBase58()}")

        // Create a random private key to derive a sender address and for signing
        val privateKey = Ed25519PrivateKey.random()
        val sender = privateKey.publicKey().deriveAddress()
        println("Sender: ${sender.toHex()}")

        val client = GraphQlClient.newLocalnet()

        // Fund the sender address for gas payment
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWaitForFinalized(sender, client)
            ?: throw Exception("Failed to request coins from faucet")

        // Build the `publish` PTB
        val builderPublish = client.transactionBuilder(sender)
        // Publish the package and receive the upgrade cap in return
        builderPublish.publishPackage(packageData, "upgrade_cap")
        // Transfer the upgrade cap to the sender address
        builderPublish.transferObjects(sender, listOf(PtbArgument.assigned("upgrade_cap")))
        val txPublish = builderPublish.finish()

        // Perform a dry-run first to check if everything is correct
        println("> Publishing package (dry run):")
        val resultPublish = client.dryRunTx(txPublish, false)
        resultPublish.error?.let { throw Exception("Dry run failed: $it") }
        resultPublish.effects ?: throw Exception("Dry run failed: no effects")
        println("Success")

        // Sign and execute the transaction (publish the package)
        println("> Publishing package:")
        val sigPublish = privateKey.signTransaction(txPublish)
        val effectsPublish = client.executeTx(listOf(sigPublish), txPublish, WaitForTx.FINALIZED)
        println("Success")

        // Resolve UpgradeCap and PackageId via the client
        var upgradeCap: ObjectId? = null
        var packageId: ObjectId? = null
        for (changedObj in effectsPublish.asV1().changedObjects) {
            if (changedObj.outputState is ObjectOut.ObjectWrite) {
                val objectId = changedObj.objectId
                val obj: Object =
                    client.`object`(objectId, null)
                        ?: throw Exception("Missing object ${objectId.toHex()}")
                val upgradeCapType = StructTag.newUpgradeCap()
                if (obj.asStruct().structType == upgradeCapType) {
                    println("UpgradeCap: ${objectId.toHex()}")
                    println(
                        "UpgradeCapOwner: ${(changedObj.outputState as ObjectOut.ObjectWrite).owner.asAddress().toHex()}"
                    )
                    upgradeCap = objectId
                }
            } else if (changedObj.outputState is ObjectOut.PackageWrite) {
                val pkgId = changedObj.objectId
                println("Package ID: ${pkgId.toHex()}")
                val version = (changedObj.outputState as ObjectOut.PackageWrite).version
                println("Package version: ${version}")
                packageId = pkgId
            }
        }
        if (upgradeCap == null) {
            throw Exception("Missing upgrade cap")
        }
        if (packageId == null) {
            throw Exception("Missing package id")
        }

        // Build the `upgrade` PTB, that consists of 3 steps
        val builderUpgrade = client.transactionBuilder(sender)

        // Authorize the upgrade by providing the upgrade cap object id to receive an upgrade
        // ticket
        val upgradeCapArg = PtbArgument.objectId(upgradeCap)
        val upgradePolicyArg = PtbArgument.u8(UpgradePolicy.compatible().asU8())
        val compiledPackageDigestArg = PtbArgument.u8Vec(digest.toBytes())
        builderUpgrade.moveCall(
            `package` = Address.framework(),
            module = Identifier("package"),
            function = Identifier("authorize_upgrade"),
            arguments = listOf(upgradeCapArg, upgradePolicyArg, compiledPackageDigestArg),
            names = listOf("upgrade_ticket"),
        )

        // Upgrade the package to receive an upgrade receipt
        builderUpgrade.upgrade(
            packageId = packageId,
            packageData = packageData,
            upgradeTicket = PtbArgument.assigned("upgrade_ticket"),
            name = "upgrade_receipt",
        )

        // Commit the upgrade using the receipt
        builderUpgrade.moveCall(
            `package` = Address.framework(),
            module = Identifier("package"),
            function = Identifier("commit_upgrade"),
            arguments = listOf(upgradeCapArg, PtbArgument.assigned("upgrade_receipt")),
        )

        // Finalize the PTB
        val txUpgrade = builderUpgrade.finish()

        // Perform a dry-run to check if everything is fine
        println("> Upgrading package (dry run):")
        val resultUpgrade = client.dryRunTx(txUpgrade, false)
        resultUpgrade.error?.let { throw Exception("Dry run failed: $it") }
        resultUpgrade.effects ?: throw Exception("Dry run failed: no effects")
        println("Success")

        // Sign and execute the transaction (upgrade the package)
        println("> Upgrading package:")
        val sigUpgrade = privateKey.signTransaction(txUpgrade)
        val effectsUpgrade = client.executeTx(listOf(sigUpgrade), txUpgrade)
        println("Success")

        // Print the new package version (should now be 2)
        for (changedObj in effectsUpgrade.asV1().changedObjects) {
            if (changedObj.outputState is ObjectOut.PackageWrite) {
                val pkgId = changedObj.objectId
                println("New Package ID: ${pkgId.toHex()}")
                val version = (changedObj.outputState as ObjectOut.PackageWrite).version
                println("New Package version: $version")
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}

const val PRECOMPILED_PACKAGE =
    """{"modules":["oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[246,127,102,77,186,19,68,12,161,181,56,248,210,0,91,211,245,251,165,152,0,197,250,135,171,37,177,240,133,76,122,124]}"""
