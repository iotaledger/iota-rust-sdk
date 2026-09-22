// Copyright (c) 2025 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import iota_sdk.*
import kotlinx.coroutines.runBlocking

fun main() = runBlocking {
    try {
        val client = GraphQlClient.newTestnet()

        val fromAddress =
            Address.fromHex("0xda1820edf693ee32b5729907b9b2ec8e64980ee8c008c17e89cfb4e5ecd72151")
        val toAddress =
            Address.fromHex("0x0000a4984bd495d4346fa208ddff4f5d5e5ad48c21dec631ddebc99809f16900")

        // This is a coin of type
        // 0xfce9c14e5f0c2b65787debb8145a33a4a2fc83152e8939000b862e174bc86bb8::cert::CERT
        val coinId =
            PtbArgument.objectIdFromHex(
                "0xe0e45ecb12ddca5f0d5192d2ee9e7f711959aa98614f9905e1e25c612ffd99a2"
            )

        val builder = client.transactionBuilder(fromAddress)

        builder.sendCoins(listOf(coinId), toAddress, PtbArgument.u64(50000000000uL))

        val txn = builder.finish()

        println("Signing Digest: ${txn.signingDigestHex()}")
        println("Txn Bytes: ${txn.toBase64()}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to send coins: ${res.error}")
        }

        println("Send coins dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
        kotlin.system.exitProcess(1)
    }
}
