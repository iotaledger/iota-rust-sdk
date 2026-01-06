// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sender =
            Address.fromHex("0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c")

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
            listOf(PtbArgument.res("res0"), PtbArgument.res("res1")),
            // For nested results, a tuple or vec can be used to assign them
            listOf("coin0", "coin1"),
        )

        // Use assigned results as arguments
        builder.transferObjects(sender, listOf(PtbArgument.res("coin0"), PtbArgument.res("coin1")))

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
