// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import java.util.Base64
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        // Hardcoded values
        val dataString =
                "oRzrCwYAAAAKAQAIAggUAxw+BFoGBWBBB6EBwQEI4gJACqIDGgy8A5cBDdMEBgAKAQ0BEwEUAAIMAAABCAAAAAgAAQQEAAMDAgAACAABAAAJAgMAABACAwAAEgQDAAAMBQYAAAYHAQAAEQgBAAAFCQoAAQsACwACDg8BAQwCEw8BAQgDDwwNAAoOCgYJBgEHCAQAAQYIAAEDAQYIAQQHCAEDAwcIBAEIAAQDAwUHCAQDCAAFBwgEAgMHCAQBCAIBCAMBBggEAQUBCAECCQAFBkNvbmZpZwVGb3JnZQVTd29yZAlUeENvbnRleHQDVUlEDWNyZWF0ZV9jb25maWcMY3JlYXRlX3N3b3JkAmlkBGluaXQFbWFnaWMJbXlfbW9kdWxlA25ldwluZXdfc3dvcmQGb2JqZWN0D3B1YmxpY190cmFuc2ZlcgZzZW5kZXIIc3RyZW5ndGgOc3dvcmRfdHJhbnNmZXIOc3dvcmRzX2NyZWF0ZWQIdHJhbnNmZXIKdHhfY29udGV4dAV2YWx1ZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAgMHCAMJAxADAQICBwgDEgMCAgIHCAMVAwAAAAABCQoAEQgGAAAAAAAAAAASAQsALhELOAACAQEAAAEECwAQABQCAgEAAAEECwAQARQCAwEAAAEECwAQAhQCBAEAAAEOCgAQAhQGAQAAAAAAAAAWCwAPAhULAxEICwELAhIAAgUBAAABCAsDEQgLAAsBEgALAjgBAgYBAAABBAsACwE4AgIHAQAAAQULAREICwASAgIAAQACAQEA|f67f664dba13440ca1b538f8d2005bd3f5fba59800c5fa87ab25b1f0854c7a7c"
        val parts = dataString.split("|")
        val modulesBase64 = parts[0]
        val digestHex = parts[1]
        val modules = listOf(Base64.getDecoder().decode(modulesBase64))
        val dependencies =
                listOf(
                        ObjectId.fromHex(
                                "0x0000000000000000000000000000000000000000000000000000000000000002"
                        ),
                        ObjectId.fromHex(
                                "0x0000000000000000000000000000000000000000000000000000000000000001"
                        )
                )
        val compiledPackageDigest = digestHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        println(
                "Compiled Package Digest: ${compiledPackageDigest.joinToString("") { "%02x".format(it) }}"
        )

        // Create a random private key to derive a sender address and for signing
        val privateKey = Ed25519PrivateKey.generate()
        val publicKey = privateKey.publicKey()
        val sender = publicKey.deriveAddress()
        println("Sender: ${sender.toHex()}")

        // Fund the sender address for gas payment
        val faucet = FaucetClient.newLocalnet()
        val faucetReceipt =
                faucet.requestAndWait(sender)
                        ?: throw Exception("Failed to request coins from faucet")
        val totalBalance = faucetReceipt.sent.sumOf { it.amount.toLong() }
        println("Available Balance: $totalBalance")

        val client = GraphQlClient.newLocalnet()

        // Build the `publish` PTB, that consists of 2 steps
        val builder = TransactionBuilder.init(sender, client)

        // 1. Create the upgrade cap
        builder.publish(modules, dependencies, "upgrade_cap")

        // 2. Transfer the upgrade cap to the sender address
        builder.transferObjects(sender, listOf(PtbArgument.res("upgrade_cap")))

        // Finalize the PTB
        val tx = builder.finish()

        // Perform a dry-run to check if everything is fine
        val result = client.dryRunTx(tx, false)
        result.error?.let { throw Exception("Dry run failed: $it") }
        val effectsPublish = result.effects ?: throw Exception("Dry run failed: no effects")
        println("Effects status (dry run): ${effectsPublish.asV1().status}")

        // Sign and execute the transaction (publish the package)
        println("Publishing package")
        val signature = privateKey.trySignSimple(tx.signingDigest())
        val userSignature = UserSignature.newSimple(signature)
        val effects =
                client.executeTx(listOf(userSignature), tx)
                        ?: throw Exception("Transaction failed: no effects")
        println("Effects status (publish): ${effects.asV1().status}")

        // Wait some time for the indexer to process the tx
        kotlinx.coroutines.delay(3000)

        // Resolve UpgradeCap and PackageId via the client
        var upgradeCap: ObjectId? = null
        var packageId: ObjectId? = null

        for (changedObj in effects.asV1().changedObjects) {
            if (changedObj.outputState is ObjectOut.ObjectWrite) {
                val obj: Object =
                        client.`object`(changedObj.objectId, null)
                                ?: throw Exception("Missing object ${changedObj.objectId.toHex()}")
                val upgradeCapType =
                        StructTag(
                                address = Address.framework(),
                                module = Identifier("package"),
                                name = Identifier("UpgradeCap"),
                                typeParams = emptyList<TypeTag>()
                        )
                if (obj.asStruct().structType.toString() == upgradeCapType.toString()) {
                    upgradeCap = changedObj.objectId
                }
            } else if (changedObj.outputState is ObjectOut.PackageWrite) {
                if (packageId == null) {
                    packageId = changedObj.objectId
                }
            }
        }

        upgradeCap ?: throw Exception("Missing upgrade cap")
        packageId ?: throw Exception("Missing package id")

        // Build the `upgrade` PTB, that consists of 3 steps
        val builder2 = TransactionBuilder.init(sender, client)

        val packageIdent = Identifier("package")
        val authorizeUpgrade = Identifier("authorize_upgrade")
        val commitUpgrade = Identifier("commit_upgrade")

        val upgradeCapArg = PtbArgument.objectId(upgradeCap)
        val upgradePolicyArg = PtbArgument.u8(0u)
        val compiledPackageDigestArg = PtbArgument.u8Vec(compiledPackageDigest)

        // 1. Create the upgrade ticket
        builder2.moveCall(
                `package` = Address.framework(),
                module = packageIdent,
                function = authorizeUpgrade,
                arguments = listOf(upgradeCapArg, upgradePolicyArg, compiledPackageDigestArg),
                typeArgs = listOf(),
                names = listOf("upgrade_ticket")
        )

        // 2. Get the upgrade receipt
        builder2.upgrade(
                modules,
                dependencies,
                packageId,
                PtbArgument.res("upgrade_ticket"),
                "upgrade_receipt"
        )

        // 3. Finalize the upgrade
        builder2.moveCall(
                `package` = Address.framework(),
                module = packageIdent,
                function = commitUpgrade,
                arguments = listOf(upgradeCapArg, PtbArgument.res("upgrade_receipt")),
                typeArgs = listOf(),
                names = listOf()
        )

        // Finalize the PTB
        val tx2 = builder2.finish()

        // Perform a dry-run to check if everything is fine
        val result2 = client.dryRunTx(tx, false)
        result2.error?.let { throw Exception("Dry run failed: $it") }
        val effectsUpgrade = result2.effects ?: throw Exception("Dry run failed: no effects")
        println("Effects status (dry run): ${effectsUpgrade.asV1().status}")

        // Sign and execute the transaction (upgrade the package)
        println("Upgrading package")
        val signature2 = privateKey.trySignSimple(tx2.signingDigest())
        val userSignature2 = UserSignature.newSimple(signature2)
        val effectsUpgrade2 =
                client.executeTx(listOf(userSignature2), tx2)
                        ?: throw Exception("Transaction failed: no effects")
        println("Effects status (upgrade): ${effectsUpgrade2.asV1().status}")

        // Wait some time for the indexer to process the tx
        kotlinx.coroutines.delay(3000)

        // Print the new package version (should now be 2)
        for (changedObj in effectsUpgrade2.asV1().changedObjects) {
            if (changedObj.outputState is ObjectOut.PackageWrite) {
                val pkgId = changedObj.objectId
                val version = (changedObj.outputState as ObjectOut.PackageWrite).version
                println("PackageId: ${pkgId.toHex()}")
                println("Package version: $version")
            }
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
