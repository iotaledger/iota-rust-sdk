// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val sender =
                Address.fromHex(
                        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
                )

        val coinId =
                ObjectId.fromHex(
                        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                )

        val builder = TransactionBuilder.init(sender, client)

        builder.splitCoins(
                        PtbArgument.objectId(coinId),
                        listOf(
                                PtbArgument.u64(1000uL),
                                PtbArgument.u64(2000uL),
                                PtbArgument.u64(3000uL)
                        ),
                        listOf("coin1", "coin2", "coin3")
                )
                .transferObjects(
                        sender,
                        listOf(
                                PtbArgument.res("coin1"),
                                PtbArgument.res("coin2"),
                                PtbArgument.res("coin3")
                        )
                )
                .gas(coinId)
                .gasBudget(1000000000uL)

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
    }
}
