// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val sender =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val builder = client.transactionBuilder(sender)

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

        val res = client.dryRunTransaction(txn, false)
        if (res.error != null) {
            throw Exception("Failed to send tx: ${res.error}")
        }

        println("Tx dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
