// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newLocalnet()

        val sender =
            Address.fromHex("0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522")

        FaucetClient.newLocalnet().requestAndWaitForFinalized(sender, client)

        val builder = TransactionBuilder(sender).withClient(client)

        val packageAddr = Address.std()
        val moduleName = Identifier("u64")
        val functionName = Identifier("max")

        builder.moveCall(
            packageAddr,
            moduleName,
            functionName,
            listOf(PtbArgument.u64(0u), PtbArgument.u64(1000u)),
            // Assign a name to the result of this command
            names = listOf("res0"),
        )

        builder.moveCall(
            packageAddr,
            moduleName,
            functionName,
            listOf(PtbArgument.u64(1000u), PtbArgument.u64(2000u)),
            // Assign a name to the result of this command
            names = listOf("res1"),
        )

        builder.splitCoins(
            PtbArgument.gas(),
            // Use the assigned results of previous commands to use as arguments
            listOf(PtbArgument.assigned("res0"), PtbArgument.assigned("res1")),
            // For nested results, a tuple or vec can be used to assign them
            listOf("coin0", "coin1"),
        )

        // Use assigned results as arguments
        builder.transferObjects(
            sender,
            listOf(PtbArgument.assigned("coin0"), PtbArgument.assigned("coin1")),
        )

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = client.dryRunTx(txn, false)
        if (res.error != null) {
            throw Exception("Failed to send tx: ${res.error}")
        }

        println("Tx dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
