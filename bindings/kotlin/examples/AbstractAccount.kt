// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

/**
 * This example demonstrates the Abstract Account feature which allows
 * authentication through Move code instead of traditional signatures.
 *
 * With this example it is necessary to run a localnet:
 * ```sh
 * iota start --with-faucet --with-graphql --committee-size 1 --force-regenesis
 * ```
 */

import iota_sdk.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val accountId = setupAccount()
        val fromAddress = accountId.toAddress()
        val toAddress = Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        // Fund the sender address for gas payment
        val faucet = FaucetClient.newLocalnet()
        faucet.requestAndWait(fromAddress) ?: throw Exception("Failed to request coins from faucet")

        val client = GraphQlClient.newLocalnet()

        val builder = TransactionBuilder(fromAddress).withClient(client)
        builder.sendIota(toAddress, PtbArgument.u64(5000000000uL))

        val moveAuthenticator = MoveAuthenticatorBuilder(
            accountId,
            listOf(
                PtbArgument.string("hello"),
                PtbArgument.shared(ObjectId.clock())
            ),
            listOf()
        ).finish(client)

        val signer = TransactionSigner.fromMoveAuthenticator(moveAuthenticator)
        val effects = builder.execute(signer, WaitForTx.FINALIZED)

        println("Sending IOTA via abstract account: ${effects.asV1().status}")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}

suspend fun setupAccount(): ObjectId {
    // Parse the precompiled move package
    val packageData = MovePackageData.fromJson(PRECOMPILED_AA_PACKAGE)

    // Create a random private key to derive a sender address
    val privateKey = Ed25519PrivateKey.generate()
    val sender = privateKey.publicKey().deriveAddress()

    // Fund the sender address for gas payment
    val faucet = FaucetClient.newLocalnet()
    faucet.requestAndWait(sender) ?: throw Exception("Failed to request coins from faucet")

    val client = GraphQlClient.newLocalnet()

    // Build the `publish` PTB
    var builder = TransactionBuilder(sender).withClient(client)
    // Publish the package and receive the upgrade cap
    builder.publish(packageData, "upgrade_cap")
    // Transfer the upgrade cap to the sender address
    builder.transferObjects(sender, listOf(PtbArgument.assigned("upgrade_cap")))

    var tx = builder.finish()

    // Sign and execute the transaction (publish the package)
    var sig = privateKey.signTransaction(tx)
    var effects = client.executeTx(listOf(sig), tx, WaitForTx.FINALIZED)

    println("Publishing package: ${effects.asV1().status}\n")

    // Wait some time for the indexer to process the tx
    delay(3000)

    // Get package, package metadata and account IDs from the effects
    var packageId: ObjectId? = null
    var packageMetadataId: ObjectId? = null
    var accountId: ObjectId? = null

    for (changedObj in effects.asV1().changedObjects) {
        if (changedObj.outputState is ObjectOut.PackageWrite) {
            packageId = changedObj.objectId
        } else if (changedObj.outputState is ObjectOut.ObjectWrite) {
            val objectId = changedObj.objectId
            val obj = client.`object`(objectId, null) ?: continue

            val typeName = obj.asStruct().structType.name().toString()
            if (typeName == "PackageMetadataV1") {
                packageMetadataId = objectId
            }
            if (typeName == "Account") {
                accountId = objectId
            }
        }
    }

    if (packageId == null) {
        throw Exception("Missing package id")
    }
    if (packageMetadataId == null) {
        throw Exception("Missing package metadata id")
    }
    if (accountId == null) {
        throw Exception("Missing account id")
    }

    println("Package ID: ${packageId.toHex()}")
    println("PackageMetadataV1 ID: ${packageMetadataId.toHex()}")
    println("Account ID: ${accountId.toHex()}\n")

    // Build the `link_auth` PTB
    builder = TransactionBuilder(sender).withClient(client)
    builder.moveCall(
        `package` = packageId.toAddress(),
        module = Identifier("account"),
        function = Identifier("link_auth"),
        arguments = listOf(
            PtbArgument.sharedMut(accountId),
            PtbArgument.objectId(packageMetadataId),
            PtbArgument.string("account"),
            PtbArgument.string("authenticate")
        )
    )

    tx = builder.finish()

    // Sign and execute the transaction (link the authenticator)
    sig = privateKey.signTransaction(tx)
    effects = client.executeTx(listOf(sig), tx, WaitForTx.FINALIZED)

    println("Linking account to authenticate method: ${effects.asV1().status}\n")

    return accountId
}

// The package below, compiled and exported using --dump-bytecode-as-base64
const val PRECOMPILED_AA_PACKAGE = """{"modules":["oRzrCwYAAAALAQAUAhQmAzorBGUGBWtPB7oBwAII+gNgBtoECRDjBCoKjQULDJgFQgAJAgkCCwINAg4CFgIXAhoCGwEKAAEMAAAAAgACAgIAAwMHAQgBBAQIAAUIBAAGBQgACAcCAAkGBwAAEwABAAAUAgEAAAwDAQABDwsBAQgDEAkKAQgFFQQFAAcYBwEBDAkZDA0ABgYEBgMGAggBBwgHAAQIAAYIBggICAgFBggACAgGCAQGCAIGCAcBBwgHAQgFAQgAAQkAAQsDAQgAAwYIBggICAgBCwMBCQACCQALAwEJAAEKAgEICAdBQ0NPVU5UB0FjY291bnQLQXV0aENvbnRleHQaQXV0aGVudGljYXRvckZ1bmN0aW9uUmVmVjEFQ2xvY2sRUGFja2FnZU1ldGFkYXRhVjEGU3RyaW5nCVR4Q29udGV4dANVSUQHYWNjb3VudAVhc2NpaQxhdXRoX2NvbnRleHQMYXV0aGVudGljYXRlFmF1dGhlbnRpY2F0b3JfZnVuY3Rpb24FY2xvY2sRY3JlYXRlX2FjY291bnRfdjEbY3JlYXRlX2F1dGhfZnVuY3Rpb25fcmVmX3YxC2R1bW15X2ZpZWxkAmlkBGluaXQJbGlua19hdXRoA25ldwZvYmplY3QQcGFja2FnZV9tZXRhZGF0YRNwdWJsaWNfc2hhcmVfb2JqZWN0BnN0cmluZwh0cmFuc2Zlcgp0eF9jb250ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCgIGBWhlbGxvDmlvdGE6Om1ldGFkYXRhGgEAAAAAAAAAEQEMYXV0aGVudGljYXRlAQABAAIBEggFAQIBEQEAAAAAAQULAREFEgA4AAIBAQAACAkLAQsCCwM4AQwECwALBDgCAgIBAAABCQsBBwARByEEBgUIBgAAAAAAAAAAJwIA"],"dependencies":["0x0000000000000000000000000000000000000000000000000000000000000002","0x0000000000000000000000000000000000000000000000000000000000000001"],"digest":[236,68,86,252,91,28,224,206,146,112,120,93,47,52,14,168,169,132,252,75,45,104,10,116,171,91,155,100,66,111,66,147]}"""
