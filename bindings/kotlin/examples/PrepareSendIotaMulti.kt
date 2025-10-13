// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

// Helper to convert ULong to little-endian ByteArray
fun ULong.toLeByteArray(): ByteArray {
    val result = ByteArray(8)
    var value = this
    for (i in 0 until 8) {
        result[i] = (value and 0xFFu).toByte()
        value = value shr 8
    }
    return result
}

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

        val recipients =
                listOf(
                        Pair(
                                "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
                                1_000_000_000UL
                        ),
                        Pair(
                                "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
                                2_000_000_000UL
                        )
                )

        val builder = TransactionBuilder.init(sender, client)

        val labels = recipients.indices.map { "coin${it}" }
        val amounts = recipients.map { it.second }

        builder.splitCoins(
                coinId,
                amounts,
                labels,
        )

        for ((i, r) in recipients.withIndex()) {
            builder.transferObjects(Address.fromHex(r.first), listOf(PtbArgument.res(labels[i])))
        }

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${txn.bcsSerializeBase64()}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to send IOTA: ${res.error}")
        }

        println("Send IOTA dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
