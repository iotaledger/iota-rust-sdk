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

        val coin =
                client.`object`(
                        ObjectId.fromHex(
                                "0xd04077fe3b6fad13b3d4ed0d535b7ca92afcac8f0f2a0e0925fb9f4f0b30c699"
                        )
                )
        if (coin == null) {
            throw Exception("missing coin")
        }

        val gasCoin =
                client.`object`(
                        ObjectId.fromHex(
                                "0x0b0270ee9d27da0db09651e5f7338dfa32c7ee6441ccefa1f6e305735bcfc7ab"
                        )
                )
        if (gasCoin == null) {
            throw Exception("missing gas coin")
        }

        val builder = TransactionBuilder()

        builder.transferObjects(
                listOf(builder.input(UnresolvedInput.fromObject(coin).withOwnedKind())),
                builder.input(UnresolvedInput.newPure(toAddress.toBytes()))
        )

        builder.setSender(fromAddress)
        builder.setGasBudget(50000000u)
        val refGasPrice = client.referenceGasPrice(null)
        if (refGasPrice == null) {
            throw Exception("missing ref gas price")
        }
        builder.setGasPrice(refGasPrice)
        builder.addGasObjects(listOf(UnresolvedInput.fromObject(gasCoin).withOwnedKind()))

        val txn = builder.finish()

        println("Signing Digest: ${hexEncode(txn.signingDigest())}")
        println("Txn Bytes: ${base64Encode(txn.bcsSerialize())}")

        val res = client.dryRunTx(txn, false)

        if (res.error != null) {
            throw Exception("Failed to send IOTA: ${res.error}")
        }

        println("Send IOTA dry run was successful!")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
