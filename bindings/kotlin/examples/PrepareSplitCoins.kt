// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val sender =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val coinId =
            ObjectId.fromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

        val builder = client.transactionBuilder(sender)

        builder
            .splitCoins(
                PtbArgument.objectId(coinId),
                listOf(PtbArgument.u64(1000uL), PtbArgument.u64(2000uL), PtbArgument.u64(3000uL)),
                listOf("coin1", "coin2", "coin3"),
            )
            .transferObjects(
                sender,
                listOf(
                    PtbArgument.assigned("coin1"),
                    PtbArgument.assigned("coin2"),
                    PtbArgument.assigned("coin3"),
                ),
            )

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to split coins: ${res.error}")
        }

        println("Split coins dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
