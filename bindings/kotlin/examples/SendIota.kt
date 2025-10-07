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
        val recipient =
                Address.fromHex(
                        "0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900"
                )

        val builder = TransactionBuilder.init(sender, client)

        builder.sendIota(recipient, 1_000_000_000UL)

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.bcsSerialize())}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to dry run the command `send_iota`: ${res.error}")
        }

        println("Dry run of `send_iota` command successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
