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
        val client = GraphQlClient.newTestnet()
        val sender =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
        val coinId =
            ObjectId.fromHex("0xdc956de89b914e6a7fbd83caebefc8ec91be1207667ea5576386391aa82449cc")

        val recipients =
            listOf(
                Pair(
                    "0x111173a14c3d402c01546c54265c30cc04414c7b7ec1732412bb19066dd49d11",
                    1_000_000_000UL,
                ),
                Pair(
                    "0x2222b466a24399ebcf5ec0f04820812ae20fea1037c736cfec608753aa38b522",
                    2_000_000_000UL,
                ),
            )

        val builder = client.transactionBuilder(sender)

        val labels = recipients.indices.map { "coin${it}" }
        val amounts = recipients.map { PtbArgument.u64(it.second) }

        builder.splitCoins(PtbArgument.objectId(coinId), amounts, labels)

        for ((i, r) in recipients.withIndex()) {
            builder.transferObjects(
                Address.fromHex(r.first),
                listOf(PtbArgument.assigned(labels[i])),
            )
        }

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to send IOTA: ${res.error}")
        }

        println("Send IOTA dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
