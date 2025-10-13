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
        val objsToTransfer =
                listOf(
                        PtbArgument.objectId(
                                ObjectId.fromHex(
                                        "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                                )
                        ),
                        PtbArgument.objectId(
                                ObjectId.fromHex(
                                        "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                                )
                        ),
                        PtbArgument.objectId(
                                ObjectId.fromHex(
                                        "0x8ef4259fa2a3499826fa4b8aebeb1d8e478cf5397d05361c96438940b43d28c9"
                                )
                        )
                )

        val builder = TransactionBuilder.init(fromAddress, client)

        builder.transferObjects(toAddress, objsToTransfer)

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.toBytes())}")

        val res = builder.dryRun()

        if (res.error != null) {
            throw Exception("Failed to transfer objects: ${res.error}")
        }

        println("Transfer objects dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
