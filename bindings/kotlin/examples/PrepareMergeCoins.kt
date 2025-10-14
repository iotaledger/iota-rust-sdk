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

        val coin0 =
                PtbArgument.objectIdFromHex(
                        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                )
        val coin1 =
                PtbArgument.objectIdFromHex(
                        "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                )

        val builder = TransactionBuilder.init(sender, client)

        builder.mergeCoins(coin0, listOf(coin1))

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.toBytes())}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to merge coins: ${res.error}")
        }

        println("Merge coins dry run was successful!")
    } catch (e: Exception) {
        println("Error: $e")
    }
}
