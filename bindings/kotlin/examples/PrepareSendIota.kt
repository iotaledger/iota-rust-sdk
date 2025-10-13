// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newDevnet()

        val fromAddress =
                Address.fromHex(
                        "0x611830d3641a68f94a690dcc25d1f4b0dac948325ac18f6dd32564371735f32c"
                )

        val toAddress =
                Address.fromHex(
                        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
                )

        val builder = TransactionBuilder.init(fromAddress, client)

        builder.sendIota(
                toAddress,
                5000000000uL,
        )

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.toBytes())}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to send IOTA: ${res.error}")
        }

        println("Send IOTA dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
