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

                // This is a coin of type
                // 0x3358bea865960fea2a1c6844b6fc365f662463dd1821f619838eb2e606a53b6a::cert::CERT
                val coinId =
                        ObjectId.fromHex(
                                "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
                        )
                val gasCoinId =
                        ObjectId.fromHex(
                                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                        )

                val builder = TransactionBuilder.init(fromAddress, client)

                builder.sendCoins(listOf(coinId), toAddress, 50000000000uL)
                builder.gas(gasCoinId).gasBudget(1000000000uL)

                val txn = builder.finish()

                println("Signing Digest: ${hexEncode(txn.signingDigest())}")
                println("Txn Bytes: ${base64Encode(txn.toBytes())}")

                val res = builder.dryRun()

                if (res.error != null) {
                        throw Exception("Failed to send coins: ${res.error}")
                }

                println("Send coins dry run was successful!")
        } catch (e: Exception) {
                e.printStackTrace()
        }
}
