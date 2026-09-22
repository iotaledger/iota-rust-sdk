// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val sender =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")

        val coin0 =
            PtbArgument.objectIdFromHex(
                "0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc"
            )
        val coin1 =
            PtbArgument.objectIdFromHex(
                "0x65beb18e282d1f33a39bffa84ff92ec4d2fec0350ba6f7e5a568afff72d651db"
            )

        val builder = client.transactionBuilder(sender)

        builder.mergeCoins(coin0, listOf(coin1))

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to merge coins: ${res.error}")
        }

        println("Merge coins dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
